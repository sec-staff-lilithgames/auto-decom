import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from cleanup import parallel_rmtree


class GhidraMissingError(RuntimeError):
    """Raised when the Ghidra headless executable cannot be located."""


@dataclass
class DecompileResult:
    so_path: Path
    success: bool
    message: str
    engine: Optional[str] = None
    warnings: Optional[List[str]] = None


@dataclass
class EngineOutput:
    success: bool
    message: str = ""
    c_path: Optional[Path] = None
    asm_path: Optional[Path] = None
    lines: int = 0


RADARE_MAX_FUNCTIONS = 200


class Decompiler:
    """
    Uses Ghidra headless mode to decompile .so files located under the provided directory.
    Produces a mirror directory named so_decomp that contains the original .so alongside
    generated .c and .asm files.
    """

    def __init__(
        self,
        workspace: Path,
        logger: logging.Logger,
        ghidra_headless: Optional[str] = None,
        radare2_bin: Optional[str] = None,
        script_dir: Optional[Path] = None,
        input_root: Optional[Path] = None,
        output_root: Optional[Path] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> None:
        self.workspace = workspace
        self.logger = logger
        self.input_root = input_root if input_root is not None else (self.workspace / "so")
        self.output_root = output_root if output_root is not None else (self.workspace / "so_decomp")
        self.script_dir = script_dir or (self.workspace / "ghidra_scripts")
        self.ghidra_headless = self._discover_headless(ghidra_headless)
        self.java_home = self._discover_java_home()
        self.radare2_bin, self.radare2_env = self._discover_radare(radare2_bin)
        self.progress_callback = progress_callback
        self.warnings: List[str] = []
        if not self.radare2_bin:
            self.logger.warning("radare2/r2dec engine disabled (binary not found)")

    def _discover_headless(self, override: Optional[str]) -> str:
        candidates: List[str] = []

        def add_path(value: Optional[str]) -> None:
            if value:
                candidates.append(value)

        add_path(override)
        add_path(os.environ.get("GHIDRA_HEADLESS_PATH"))
        for path in self._workspace_headless_paths():
            candidates.append(str(path))
        candidates.append("analyzeHeadless")

        for candidate in candidates:
            resolved = shutil.which(candidate)
            if resolved:
                self.logger.debug("Using Ghidra headless: %s", resolved)
                return resolved
            expanded = Path(candidate).expanduser()
            if expanded.exists() and os.access(expanded, os.X_OK):
                self.logger.debug("Using Ghidra headless: %s", expanded)
                return str(expanded)

        fallback = candidates[0] if candidates else "analyzeHeadless"
        self.logger.debug("Falling back to Ghidra headless: %s", fallback)
        return fallback

    def _discover_java_home(self) -> Optional[str]:
        env_java_home = os.environ.get("JAVA_HOME")
        if env_java_home:
            home_path = Path(env_java_home).expanduser()
            if self._is_supported_java_path(home_path):
                self.logger.debug("Using JAVA_HOME from environment: %s", home_path)
                return str(home_path)
            self.logger.debug("Ignoring unsupported JAVA_HOME from environment: %s", home_path)

        for candidate in self._workspace_java_homes():
            if self._is_supported_java_path(candidate):
                self.logger.debug("Using JAVA_HOME from workspace: %s", candidate)
                return str(candidate)

        self.logger.debug("JAVA_HOME not set; relying on system Java")
        return None

    def _discover_radare(self, override: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
        candidates: List[str] = []

        def add_candidate(value: Optional[str]) -> None:
            if value:
                candidates.append(value)

        add_candidate(override)
        add_candidate(os.environ.get("RADARE2_BIN"))
        tools_radare = self.workspace / "tools" / "radare2" / "bin" / "radare2"
        if tools_radare.exists():
            add_candidate(str(tools_radare))
        candidates.append("radare2")

        for candidate in candidates:
            resolved = shutil.which(candidate)
            if not resolved:
                path_candidate = Path(candidate)
                if path_candidate.exists() and os.access(path_candidate, os.X_OK):
                    resolved = str(path_candidate)
            if not resolved:
                continue

            bin_path = Path(resolved).resolve()
            base_dir = bin_path.parent.parent
            lib_dir = base_dir / "lib"
            plugin_root = lib_dir / "radare2"
            plugin_dir = None
            if plugin_root.exists():
                versions = [p for p in plugin_root.glob("*") if p.is_dir()]
                if versions:
                    plugin_dir = max(versions, key=lambda p: p.name)
                else:
                    plugin_dir = plugin_root

            env_updates: Dict[str, str] = {
                "RADARE2_BIN": str(bin_path),
                "PATH": str(bin_path.parent),
            }
            if lib_dir.exists():
                env_updates["DYLD_LIBRARY_PATH"] = str(lib_dir)
            if plugin_dir and plugin_dir.exists():
                env_updates["R2_PLUGIN_PATH"] = str(plugin_dir)
                env_updates["R2_PLUGINPATH"] = str(plugin_dir)
                env_updates["R2_LIBR_PLUGINS"] = str(plugin_dir)

            self.logger.debug("Using radare2 binary at %s", bin_path)
            return str(bin_path), env_updates

        self.logger.warning("radare2 binary not found; radare2 engine will be disabled")
        return None, None

    def _workspace_headless_paths(self) -> List[Path]:
        tools_dir = self.workspace / "tools"
        if not tools_dir.exists():
            return []
        paths: List[Path] = []
        for candidate in sorted(tools_dir.glob("ghidra_*_PUBLIC")):
            headless = candidate / "support" / "analyzeHeadless"
            paths.append(headless)
        return paths

    def _workspace_java_homes(self) -> List[Path]:
        tools_dir = self.workspace / "tools"
        if not tools_dir.exists():
            return []
        homes: List[Tuple[int, Path]] = []
        seen: set[str] = set()
        for candidate in sorted(tools_dir.glob("jdk-*")):
            potential = []
            contents_home = candidate / "Contents" / "Home"
            if contents_home.exists():
                potential.append(contents_home)
            potential.append(candidate)
            for path in potential:
                resolved = path.resolve()
                key = str(resolved)
                if key in seen:
                    continue
                seen.add(key)
                version = self._parse_java_version(resolved)
                homes.append((version, resolved))
        homes.sort(key=lambda item: item[0], reverse=True)
        return [path for _, path in homes]

    def run(self, so_root: Path) -> Path:
        if not so_root.exists():
            raise FileNotFoundError(f"so directory not found: {so_root}")
        if not self._ghidra_exists():
            raise GhidraMissingError(
                "Ghidra headless executable not found. "
                "Set GHIDRA_HEADLESS_PATH environment variable or adjust configuration."
            )

        self.logger.info("Preparing workspace for decompilation")
        if self.output_root.exists():
            parallel_rmtree(self.output_root)
        shutil.copytree(so_root, self.output_root)

        so_files = sorted(self.output_root.rglob("*.so"))
        if not so_files:
            self.logger.warning("No .so files found under %s", self.output_root)
            return self.output_root

        total = len(so_files)
        completed = 0
        self._notify_progress(completed, total, "Queued shared libraries for analysis")

        if not self._java_exists():
            raise RuntimeError("Java runtime not found. Install a compatible JDK or set JAVA_HOME.")

        jobs = [
            (
                str(path),
                self.ghidra_headless,
                str(self.script_dir),
                str(self.workspace),
                self.java_home,
                self.radare2_bin,
                self.radare2_env,
            )
            for path in so_files
        ]

        self.logger.info("Dispatching decompilation jobs for %d shared libraries", len(so_files))
        self.warnings = []
        results: List[DecompileResult] = []
        max_workers = min(len(jobs), (os.cpu_count() or 4))
        if max_workers <= 0:
            max_workers = 1

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(_decompile_worker, job): Path(job[0]) for job in jobs
            }
            for future in as_completed(future_to_path):
                so_path = future_to_path[future]
                try:
                    result_data = future.result()
                    result = DecompileResult(
                        so_path=so_path,
                        success=result_data[0],
                        message=result_data[1],
                        engine=result_data[2],
                        warnings=result_data[3],
                    )
                except Exception as exc:  # noqa: BLE001
                    result = DecompileResult(so_path=so_path, success=False, message=str(exc))
                results.append(result)
                completed += 1
                if result.success:
                    self.logger.debug("Decompiled %s using %s", so_path, result.engine)
                    detail = f"{so_path.name} ({result.engine or 'OK'})"
                else:
                    self.logger.error("Failed to decompile %s: %s", so_path, result.message)
                    detail = f"{so_path.name} (FAIL)"
                self._notify_progress(completed, total, detail)
                if result.warnings:
                    self.warnings.extend(result.warnings)

        failures = [r for r in results if not r.success]
        if failures:
            raise RuntimeError(f"Decompilation failed for {len(failures)} shared libraries")

        if so_root.exists():
            parallel_rmtree(so_root)

        self.logger.info("Decompilation completed successfully into %s", self.output_root)
        return self.output_root

    def _ghidra_exists(self) -> bool:
        if shutil.which(self.ghidra_headless):
            return True
        possible = Path(self.ghidra_headless)
        return possible.exists() and os.access(possible, os.X_OK)

    def _java_exists(self) -> bool:
        if self.java_home:
            java_bin = Path(self.java_home) / "bin" / "java"
            if java_bin.exists():
                return True
        return shutil.which("java") is not None

    def _build_environment(self) -> Optional[dict]:
        if not self.java_home:
            return None
        env = os.environ.copy()
        env["JAVA_HOME"] = self.java_home
        java_bin = Path(self.java_home) / "bin"
        existing_path = env.get("PATH", "")
        env["PATH"] = f"{java_bin}{os.pathsep}{existing_path}"
        return env

    def _notify_progress(self, current: int, total: int, detail: str) -> None:
        if self.progress_callback:
            self.progress_callback(current, total, detail)

    def _parse_java_version(self, path: Path) -> int:
        release_file = path / "release"
        if release_file.exists():
            try:
                text = release_file.read_text(errors="ignore")
            except OSError:
                text = ""
            match = re.search(r'JAVA_VERSION="(\d+)', text)
            if match:
                return int(match.group(1))
        match = re.search(r"jdk-(\d+)", path.name)
        if match:
            return int(match.group(1))
        return 0

    def _is_supported_java_path(self, path: Path) -> bool:
        java_bin = path / "bin" / "java"
        if not java_bin.exists():
            return False
        major = self._parse_java_version(path)
        if major == 0:
            return True
        return major >= 21


def _update_env(base: Dict[str, str], updates: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not updates:
        return base.copy()
    env = base.copy()
    for key, value in updates.items():
        if not value:
            continue
        if key in {"PATH", "DYLD_LIBRARY_PATH"}:
            existing = env.get(key, "")
            env[key] = f"{value}:{existing}" if existing else value
        else:
            env[key] = value
    return env


def _count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as reader:
            return sum(1 for _ in reader)
    except OSError:
        return 0


def _run_ghidra_engine(
    so_path: Path,
    ghidra_headless: str,
    script_dir: str,
    workspace_path: Path,
    java_home: Optional[str],
    output_dir: Path,
) -> EngineOutput:
    temp_project_dir = Path(tempfile.mkdtemp(prefix="ghidra_proj_", dir=str(workspace_path)))
    env = os.environ.copy()
    if java_home:
        env["JAVA_HOME"] = java_home
        java_bin = Path(java_home) / "bin"
        existing = env.get("PATH", "")
        env["PATH"] = f"{java_bin}{os.pathsep}{existing}" if existing else str(java_bin)

    cmd = [
        ghidra_headless,
        str(temp_project_dir),
        so_path.stem,
        "-import",
        str(so_path),
        "-scriptPath",
        script_dir,
        "-postScript",
        "export_decomp.py",
        str(output_dir),
        so_path.stem,
        "-deleteProject",
    ]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env,
            timeout=120,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "Ghidra error"
            return EngineOutput(False, message)

        c_path = output_dir / f"{so_path.stem}.c"
        asm_path = output_dir / f"{so_path.stem}.asm"
        if not c_path.exists() or not asm_path.exists():
            return EngineOutput(False, "Ghidra output missing")
        return EngineOutput(True, "ok", c_path, asm_path, _count_lines(c_path))
    except subprocess.TimeoutExpired:
        return EngineOutput(False, "Ghidra timeout after 120s")
    except FileNotFoundError as exc:
        return EngineOutput(False, str(exc))
    finally:
        shutil.rmtree(temp_project_dir, ignore_errors=True)


def _run_radare_engine(
    so_path: Path,
    radare2_bin: str,
    radare2_env: Optional[Dict[str, str]],
    workspace_path: Path,
    output_dir: Path,
) -> EngineOutput:
    env = _update_env(os.environ, radare2_env)
    r2_home = Path(tempfile.mkdtemp(prefix="r2home_", dir=str(workspace_path)))
    env["R2HOMEDIR"] = str(r2_home)
    env.setdefault("HOME", str(r2_home))
    c_path = (output_dir / f"{so_path.stem}.c").resolve()
    asm_path = (output_dir / f"{so_path.stem}.asm").resolve()
    for target in (c_path, asm_path):
        if target.exists():
            target.unlink()

    functions = _radare_list_functions(radare2_bin, so_path, env)
    script_lines: List[str] = ["aaa"]
    if functions:
        for index, offset in enumerate(functions[:RADARE_MAX_FUNCTIONS]):
            redirect = ">" if index == 0 else ">>"
            script_lines.append(f"s 0x{offset:x}")
            script_lines.append(f"pdd {redirect} {c_path}")
    else:
        script_lines.append(f"pdd > {c_path}")

    script_lines.append(f"pd -1 > {asm_path}")
    script_lines.append("q")

    script_path = output_dir / "radare_script.r2"
    script_path.write_text("\n".join(script_lines), encoding="utf-8")
    try:
        completed = subprocess.run(
            [
                radare2_bin,
                "-q0",
                "-n",
                "-e",
                "scr.color=false",
                "-e",
                "scr.utf8=false",
                "-e",
                "scr.interactive=false",
                "-i",
                str(script_path),
                str(so_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env,
            timeout=120,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "radare2 error"
            return EngineOutput(False, message)
        if not c_path.exists() or not asm_path.exists():
            return EngineOutput(False, "radare2 output missing")
        return EngineOutput(True, "ok", c_path, asm_path, _count_lines(c_path))
    except subprocess.TimeoutExpired:
        return EngineOutput(False, "radare2 timeout after 120s")
    except FileNotFoundError as exc:
        return EngineOutput(False, str(exc))
    finally:
        if script_path.exists():
            script_path.unlink()
        shutil.rmtree(r2_home, ignore_errors=True)


def _radare_list_functions(
    radare2_bin: str,
    so_path: Path,
    env: Dict[str, str],
) -> List[int]:
    env_copy = env.copy()
    try:
        completed = subprocess.run(
            [
                radare2_bin,
                "-q0",
                "-n",
                "-e",
                "scr.color=false",
                "-e",
                "scr.utf8=false",
                "-e",
                "scr.interactive=false",
                "-c",
                "aaa; aflj; q",
                str(so_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            env=env_copy,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return []

    if completed.returncode != 0:
        return []

    try:
        data = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError:
        return []

    offsets: List[int] = []
    for entry in data:
        try:
            offset = int(entry.get("offset"))
        except (TypeError, ValueError):
            continue
        offsets.append(offset)
    return sorted(set(offsets))


def _decompile_worker(
    job: Tuple[
        str,
        str,
        str,
        str,
        Optional[str],
        Optional[str],
        Optional[Dict[str, str]],
    ]
) -> Tuple[bool, str, Optional[str], List[str]]:
    (
        so_path_str,
        ghidra_headless,
        script_dir,
        workspace,
        java_home,
        radare2_bin,
        radare2_env,
    ) = job

    so_path = Path(so_path_str)
    output_dir = so_path.parent
    base_name = so_path.stem
    workspace_path = Path(workspace)

    ghidra_dir = output_dir / "__ghidra_tmp"
    radare_dir = output_dir / "__radare_tmp"
    final_c = output_dir / f"{base_name}.c"
    final_asm = output_dir / f"{base_name}.asm"

    for temp_dir in (ghidra_dir, radare_dir):
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        temp_dir.mkdir(parents=True, exist_ok=True)

    warnings: List[str] = []

    ghidra_result = _run_ghidra_engine(
        so_path,
        ghidra_headless,
        script_dir,
        workspace_path,
        java_home,
        ghidra_dir,
    )
    if not ghidra_result.success:
        if ghidra_result.message:
            warnings.append(f"Ghidra({so_path.name}): {ghidra_result.message}")

    radare_result: Optional[EngineOutput] = None
    if radare2_bin:
        radare_result = _run_radare_engine(
            so_path,
            radare2_bin,
            radare2_env,
            workspace_path,
            radare_dir,
        )
        if not radare_result.success and radare_result.message:
            warnings.append(f"radare2({so_path.name}): {radare_result.message}")

    chosen_engine = None
    selected = None
    decision_message = ""

    if ghidra_result.success and radare_result and radare_result.success:
        if radare_result.lines > ghidra_result.lines:
            chosen_engine = "radare2"
            selected = radare_result
            decision_message = (
                f"Selected radare2 ({radare_result.lines} lines vs Ghidra {ghidra_result.lines})"
            )
        else:
            chosen_engine = "ghidra"
            selected = ghidra_result
            decision_message = (
                f"Selected Ghidra ({ghidra_result.lines} lines vs radare2 {radare_result.lines})"
            )
    elif ghidra_result.success:
        chosen_engine = "ghidra"
        selected = ghidra_result
        if radare_result:
            decision_message = "Selected Ghidra (radare2 unavailable or failed)"
        else:
            decision_message = "Selected Ghidra"
    elif radare_result and radare_result.success:
        chosen_engine = "radare2"
        selected = radare_result
        decision_message = "Selected radare2 (Ghidra unavailable or failed)"

    if selected:
        try:
            if final_c.exists():
                final_c.unlink()
            if final_asm.exists():
                final_asm.unlink()
            shutil.copy2(selected.c_path, final_c)
            shutil.copy2(selected.asm_path, final_asm)
        except OSError as exc:
            warnings.append(f"Copy failed for {so_path.name}: {exc}")
            chosen_engine = None

    for temp_dir in (ghidra_dir, radare_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

    if chosen_engine:
        return True, decision_message or "ok", chosen_engine, warnings

    for leftover in (final_c, final_asm):
        if leftover.exists():
            leftover.unlink()
    message = ", ".join(warnings) or "No decompilation engines succeeded"
    return False, message, None, warnings
