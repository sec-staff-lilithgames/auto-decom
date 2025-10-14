import logging
import os
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from cleanup import parallel_rmtree


@dataclass
class DexResult:
    dex_path: Path
    success: bool
    message: str


class DexDecompiler:
    """Runs JADX in parallel to produce Java sources for extracted dex files."""

    def __init__(
        self,
        workspace: Path,
        logger: logging.Logger,
        jadx_path: Optional[str] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> None:
        self.workspace = workspace
        self.logger = logger
        self.input_root = self.workspace / "dex"
        self.output_root = self.workspace / "dex_decomp"
        self.jadx_path, self.jadx_env = self._discover_jadx(jadx_path)
        self.java_home = self._discover_java_home()
        if not self.jadx_env:
            self.jadx_env = {}
        self.jadx_env.setdefault("JADX_DISABLE_PLUGINS", "1")

        if self.java_home:
            java_bin = Path(self.java_home) / "bin"
            existing_path = self.jadx_env.get("PATH")
            java_bin_str = str(java_bin)
            if existing_path:
                self.jadx_env["PATH"] = f"{java_bin_str}:{existing_path}"
            else:
                self.jadx_env["PATH"] = java_bin_str
            self.jadx_env["JAVA_HOME"] = self.java_home
        self.progress_callback = progress_callback
        self.warnings: List[str] = []

    def run(self, dex_root: Path) -> Path:
        if not dex_root.exists():
            raise FileNotFoundError(f"dex directory not found: {dex_root}")
        if not self.jadx_path:
            raise RuntimeError(
                "jadx executable not found. Install JADX or set JADX_PATH environment variable."
            )

        self.logger.info("Preparing workspace for dex decompilation")
        if self.output_root.exists():
            parallel_rmtree(self.output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)

        dex_files = sorted(dex_root.rglob("*.dex"))
        if not dex_files:
            self.logger.warning("No dex files found under %s", dex_root)
            return self.output_root

        total = len(dex_files)
        completed = 0
        self._notify_progress(completed, total, "Queued dex files for analysis")

        threads = os.cpu_count() or 4
        max_workers = min(total, threads)
        max_workers = max(1, max_workers)

        jobs = [
            (
                str(dex_path),
                str(self.output_root / dex_path.parent.name),
                self.jadx_path,
                threads,
                self.jadx_env,
            )
            for dex_path in dex_files
        ]

        results: List[DexResult] = []
        self.warnings = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(_run_jadx, job): Path(job[0]) for job in jobs
            }
            for future in as_completed(future_to_path):
                dex_path = future_to_path[future]
                try:
                    success, message = future.result()
                    result = DexResult(dex_path=dex_path, success=success, message=message)
                except Exception as exc:  # noqa: BLE001
                    result = DexResult(dex_path=dex_path, success=False, message=str(exc))
                results.append(result)
                completed += 1
                if result.success:
                    detail = f"{dex_path.name} (jadx)"
                    self.logger.debug("Decompiled %s", dex_path)
                else:
                    detail = f"{dex_path.name} (FAIL)"
                    self.logger.error("Failed to decompile %s: %s", dex_path, result.message)
                    if result.message:
                        self.warnings.append(f"jadx({dex_path.name}): {result.message}")
                self._notify_progress(completed, total, detail)

        failures = [r for r in results if not r.success]
        if failures:
            raise RuntimeError(f"JADX failed for {len(failures)} dex files")

        if dex_root.exists():
            parallel_rmtree(dex_root)

        self.logger.info("Dex decompilation completed into %s", self.output_root)
        return self.output_root

    def _discover_jadx(self, override: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
        candidates: List[str] = []

        def add_candidate(value: Optional[str]) -> None:
            if value:
                candidates.append(value)

        add_candidate(override)
        add_candidate(os.environ.get("JADX_PATH"))
        tools_jadx = self.workspace / "tools" / "jadx" / "bin" / "jadx"
        if tools_jadx.exists():
            add_candidate(str(tools_jadx))
        candidates.append("jadx")

        for candidate in candidates:
            resolved = shutil.which(candidate)
            if not resolved:
                path_candidate = Path(candidate)
                if path_candidate.exists() and os.access(path_candidate, os.X_OK):
                    resolved = str(path_candidate)
            if not resolved:
                continue

            bin_path = Path(resolved).resolve()
            base_dir = bin_path.parent.parent if bin_path.parent.name == "bin" else bin_path.parent
            env_updates: Dict[str, str] = {
                "PATH": str(bin_path.parent),
                "JADX_PATH": str(bin_path),
            }
            env_updates["JADX_HOME"] = str(base_dir)
            self.logger.debug("Using jadx binary at %s", bin_path)
            return str(bin_path), env_updates

        self.logger.warning("jadx binary not found; Java decompile mode unavailable")
        return None, None

    def _notify_progress(self, current: int, total: int, detail: str) -> None:
        if self.progress_callback:
            self.progress_callback(current, total, detail)

    def _discover_java_home(self) -> Optional[str]:
        env_java_home = os.environ.get("JAVA_HOME")
        if env_java_home:
            home_path = Path(env_java_home).expanduser()
            if (home_path / "bin" / "java").exists():
                self.logger.debug("Using JAVA_HOME from environment for JADX: %s", home_path)
                return str(home_path)

        tools_dir = self.workspace / "tools"
        if not tools_dir.exists():
            return None
        candidates: List[Path] = []
        for entry in sorted(tools_dir.glob("jdk-*")):
            contents = entry / "Contents" / "Home"
            if contents.exists():
                candidates.append(contents)
            elif entry.exists():
                candidates.append(entry)

        for candidate in candidates:
            if (candidate / "bin" / "java").exists():
                self.logger.debug("Using JAVA_HOME from workspace for JADX: %s", candidate)
                return str(candidate)
        return None


def _run_jadx(job: Tuple[str, str, Optional[str], int, Optional[Dict[str, str]]]) -> Tuple[bool, str]:
    dex_path, output_dir, jadx_path, threads, env_updates = job
    if not jadx_path:
        return False, "jadx executable missing"

    out_path = Path(output_dir)
    if out_path.exists():
        shutil.rmtree(out_path, ignore_errors=True)
    out_path.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    if env_updates:
        for key, value in env_updates.items():
            if not value:
                continue
            if key in {"PATH"}:
                existing = env.get(key, "")
                env[key] = f"{value}:{existing}" if existing else value
            else:
                env[key] = value

    cmd = [
        jadx_path,
        "--threads-count",
        str(threads),
        "--no-res",
        "--deobf",
        "-d",
        str(out_path),
        dex_path,
    ]
    try:
        completed = subprocess.run(
            cmd,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            timeout=120,
        )
        if completed.returncode != 0:
            message = completed.stderr.strip() or completed.stdout.strip() or "jadx error"
            return False, message
        if not any(out_path.iterdir()):
            return False, "jadx produced no output"
        return True, "ok"
    except subprocess.TimeoutExpired:
        return False, "jadx timeout after 120s"
    except FileNotFoundError as exc:
        return False, str(exc)
