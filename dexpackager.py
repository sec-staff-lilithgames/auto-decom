import logging
import zipfile
from pathlib import Path
from typing import Callable, Optional

from cleanup import parallel_rmtree


class DexPackager:
    """Packages per-dex decompilation outputs into individual archives and a final bundle."""

    def __init__(self, workspace: Path, logger: logging.Logger) -> None:
        self.workspace = workspace
        self.logger = logger
        self.packages_dir = self.workspace / "dex_packages"

    def run(
        self,
        decomp_dir: Path,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Path:
        if not decomp_dir.exists():
            raise FileNotFoundError(f"Dex decompilation directory not found: {decomp_dir}")

        if self.packages_dir.exists():
            parallel_rmtree(self.packages_dir)
        self.packages_dir.mkdir(parents=True, exist_ok=True)

        dex_dirs = [p for p in sorted(decomp_dir.iterdir()) if p.is_dir()]
        total_steps = len(dex_dirs) + 1  # include final bundle
        completed = 0
        if progress_callback:
            progress_callback(completed, total_steps, "Preparing dex packages")

        for dex_dir in dex_dirs:
            zip_path = self.packages_dir / f"{dex_dir.name}.zip"
            self._zip_directory(dex_dir, zip_path)
            completed += 1
            if progress_callback:
                progress_callback(completed, total_steps, zip_path.name)

        final_zip = self.workspace / f"{self.packages_dir.name}.zip"
        if final_zip.exists():
            final_zip.unlink()
        with zipfile.ZipFile(final_zip, "w", zipfile.ZIP_DEFLATED) as archive:
            for package in sorted(self.packages_dir.glob("*.zip")):
                archive.write(package, arcname=package.name)
        completed += 1
        if progress_callback:
            progress_callback(completed, total_steps, final_zip.name)

        self.logger.info("Dex archives ready at %s", final_zip)
        return final_zip

    def _zip_directory(self, source_dir: Path, archive_path: Path) -> None:
        if archive_path.exists():
            archive_path.unlink()
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(source_dir.rglob("*")):
                if path.is_file():
                    archive.write(path, arcname=path.relative_to(source_dir).as_posix())
