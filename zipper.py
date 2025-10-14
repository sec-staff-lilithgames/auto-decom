import logging
import zipfile
from pathlib import Path
from typing import Callable, Optional


class Zipper:
    """Compresses the fully decompiled directory tree into a single zip archive."""

    def __init__(self, workspace: Path, logger: logging.Logger) -> None:
        self.workspace = workspace
        self.logger = logger

    def run(
        self,
        source_dir: Path,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Path:
        if not source_dir.exists():
            raise FileNotFoundError(f"Source directory not found: {source_dir}")

        output_dir = self.workspace / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        archive_path = output_dir / f"{source_dir.name}.zip"
        if archive_path.exists():
            archive_path.unlink()

        self.logger.info("Creating archive %s", archive_path)
        files = [path for path in sorted(source_dir.rglob("*")) if path.is_file()]
        total = len(files)
        if progress_callback:
            progress_callback(0, total, "Initializing archive")

        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for index, path in enumerate(files, start=1):
                relative = path.relative_to(source_dir)
                archive.write(path, arcname=relative.as_posix())
                if progress_callback:
                    progress_callback(index, total, relative.as_posix())
        self.logger.info("Archive ready: %s", archive_path)
        return archive_path
