import argparse
import logging
import os
import shutil
import sys
from pathlib import Path
from typing import List, Optional

from cleanup import parallel_rmtree
from decompiler import Decompiler, GhidraMissingError
from dexdecompiler import DexDecompiler
from dexfinder import DexFinder
from dexpackager import DexPackager
from sofinder import SoFinder
from tui import PipelineDisplay
from zipper import Zipper


def configure_logging() -> logging.Logger:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )
    return logging.getLogger("autode")


def locate_apk(workspace: Path) -> Path:
    candidates: List[Path] = []

    env_path = os.environ.get("AUTODE_APK_PATH")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    cwd_candidates = list(workspace.glob("*.apk"))
    candidates.extend(sorted(cwd_candidates))

    download_variants = ["Downloads", "downloads"]
    for directory in download_variants:
        default_dir = Path.home() / directory
        if default_dir.exists():
            default_mt = default_dir / "mt.apk"
            if default_mt.exists():
                candidates.append(default_mt)
            else:
                candidates.extend(sorted(default_dir.glob("*.apk")))

    seen = set()
    unique_candidates = []
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved not in seen and resolved.exists():
            seen.add(resolved)
            unique_candidates.append(resolved)

    if not unique_candidates:
        raise FileNotFoundError(
            "No APK input found. Place an APK in the workspace or set AUTODE_APK_PATH."
        )

    if len(unique_candidates) > 1:
        logging.getLogger("autode").warning(
            "Multiple APK candidates detected; defaulting to %s", unique_candidates[0]
        )

    return unique_candidates[0]


def run_pipeline(workspace: Path, apk_path: Path, mode: str) -> Path:
    logger = configure_logging()
    label_overrides = None
    if mode == "java":
        label_overrides = {
            "sofinder": "Dex Extractor",
            "decompiler": "JADX",
            "zipper": "Packager",
        }
    display = PipelineDisplay(module_labels=label_overrides)
    cleanup_targets: List[Path] = []
    output_dir: Optional[Path] = None
    final_archive: Optional[Path] = None

    apk_path = apk_path.expanduser().resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")

    residuals = [workspace / "so", workspace / "so_decomp", workspace / "output"]
    if mode == "java":
        residuals.extend([workspace / "dex", workspace / "dex_decomp", workspace / "dex_packages"])
    for residual in residuals:
        parallel_rmtree(residual)

    try:
        with display:
            display.set_status("pipeline", "running", "Validating input")
            display.log(f"Using APK: {apk_path}")

            if mode == "java":
                display.set_status("sofinder", "running", f"Extracting dex from {apk_path.name}")
                dexfinder = DexFinder(workspace=workspace, logger=logger)
                try:
                    dex_dir = dexfinder.run(
                        apk_path,
                        progress_callback=lambda current, total, detail: display.set_progress(
                            "sofinder", current, total, detail
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    display.set_status("sofinder", "failed", str(exc))
                    display.set_status("pipeline", "failed", "Extraction stage failed")
                    raise
                cleanup_targets.append(dex_dir)

                dex_count = sum(1 for _ in dex_dir.rglob("*.dex"))
                display.set_status("sofinder", "completed", f"{dex_count} dex files extracted")

                display.set_status("decompiler", "running", "Running JADX analysis")
                dex_decompiler = DexDecompiler(
                    workspace=workspace,
                    logger=logger,
                    progress_callback=lambda current, total, detail: display.set_progress(
                        "decompiler", current, total, detail
                    ),
                )
                try:
                    dex_decomp_dir = dex_decompiler.run(dex_dir)
                except Exception as exc:  # noqa: BLE001
                    display.set_status("decompiler", "failed", str(exc))
                    display.set_status("pipeline", "failed", "Decompiler stage failed")
                    raise
                else:
                    produced = sum(1 for _ in dex_decomp_dir.iterdir())
                    display.set_status("decompiler", "completed", f"Dex outputs: {produced}")
                    for warning in dex_decompiler.warnings:
                        display.log(f"Warning: {warning}")
                cleanup_targets.append(dex_decomp_dir)

                display.set_status("zipper", "running", "Packaging Java artifacts")
                packager = DexPackager(workspace=workspace, logger=logger)
                try:
                    archive_path = packager.run(
                        dex_decomp_dir,
                        progress_callback=lambda current, total, detail: display.set_progress(
                            "zipper", current, total, detail
                        ),
                    )
                except Exception as exc:  # noqa: BLE001
                    display.set_status("zipper", "failed", str(exc))
                    display.set_status("pipeline", "failed", "Packaging stage failed")
                    raise
                cleanup_targets.append(packager.packages_dir)
                final_archive = archive_path
                display.set_status("zipper", "completed", f"Archive: {final_archive.name}")
                display.set_status("pipeline", "completed", "Pipeline finished successfully")
                display.log(f"Result archive ready at {final_archive}")
                logger.info("Pipeline completed; output archive ready at %s", final_archive)
                return final_archive

            # Native (so) pipeline
            display.set_status("sofinder", "running", f"Extracting from {apk_path.name}")
            sofinder = SoFinder(workspace=workspace, logger=logger)
            try:
                so_dir = sofinder.run(
                    apk_path,
                    progress_callback=lambda current, total, detail: display.set_progress(
                        "sofinder", current, total, detail
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                display.set_status("sofinder", "failed", str(exc))
                display.set_status("pipeline", "failed", "Extraction stage failed")
                raise
            cleanup_targets.append(so_dir)

            so_count = sum(1 for _ in so_dir.rglob("*.so"))
            display.set_status("sofinder", "completed", f"{so_count} libraries extracted")

            display.set_status("decompiler", "running", "Starting Ghidra headless analysis")
            decompiler = Decompiler(
                workspace=workspace,
                logger=logger,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "decompiler", current, total, detail
                ),
            )
            try:
                so_decomp_dir = decompiler.run(so_dir)
            except GhidraMissingError as exc:
                display.set_status("decompiler", "failed", "Ghidra headless executable missing")
                display.set_status("pipeline", "failed", "Decompiler stage failed")
                logger.error("%s", exc)
                raise
            except Exception as exc:  # noqa: BLE001
                display.set_status("decompiler", "failed", str(exc))
                display.set_status("pipeline", "failed", "Decompiler stage failed")
                raise
            else:
                produced = sum(1 for _ in so_decomp_dir.rglob("*.c"))
                display.set_status("decompiler", "completed", f"Pseudo-C files: {produced}")
                for warning in decompiler.warnings:
                    display.log(f"Warning: {warning}")

            cleanup_targets.append(so_decomp_dir)

            display.set_status("zipper", "running", "Packaging analysis artifacts")
            zipper = Zipper(workspace=workspace, logger=logger)
            try:
                archive_path = zipper.run(
                    so_decomp_dir,
                    progress_callback=lambda current, total, detail: display.set_progress(
                        "zipper", current, total, detail
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                display.set_status("zipper", "failed", str(exc))
                display.set_status("pipeline", "failed", "Packaging stage failed")
                raise

            final_archive = workspace / archive_path.name
            if final_archive.exists():
                final_archive.unlink()
            shutil.move(str(archive_path), final_archive)
            output_dir = archive_path.parent
            display.set_status("zipper", "completed", f"Archive: {final_archive.name}")
            display.set_status("pipeline", "completed", "Pipeline finished successfully")
            display.log(f"Result archive ready at {final_archive}")
            logger.info("Pipeline completed; output archive ready at %s", final_archive)
            return final_archive
    finally:
        for target in cleanup_targets:
            parallel_rmtree(target)
        if output_dir:
            parallel_rmtree(output_dir)
        else:
            parallel_rmtree(workspace / "output")
        for temp in workspace.glob("ghidra_proj_*"):
            parallel_rmtree(temp)
        for temp in workspace.glob("gh_proj_*"):
            parallel_rmtree(temp)
        for temp in workspace.glob("r2home_*"):
            parallel_rmtree(temp)


def main() -> int:
    parser = argparse.ArgumentParser(description="AutoDe pipeline")
    parser.add_argument("apk", help="Path to APK file to process")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--so", action="store_true", help="Run native shared-object pipeline")
    group.add_argument("--java", action="store_true", help="Run JADX-based Java pipeline")
    args = parser.parse_args()
    mode = "java" if args.java else "so"

    workspace = Path(__file__).resolve().parent
    try:
        run_pipeline(workspace, Path(args.apk), mode)
        return 0
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("autode").exception("Pipeline failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
