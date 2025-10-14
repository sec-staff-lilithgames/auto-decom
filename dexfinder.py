import logging
import os
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Tuple
from zipfile import ZipFile

from cleanup import parallel_rmtree


class DexFinder:
    """
    Extracts .dex files from an APK into a normalized directory tree.
    Each dex is placed under dex/<name>/<original>.dex
    """

    def __init__(self, workspace: Path, logger: logging.Logger) -> None:
        self.workspace = workspace
        self.logger = logger
        self.output_root = self.workspace / "dex"

    def run(
        self,
        apk_path: Path,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Path:
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")
        self.logger.info("Extracting dex files from %s", apk_path)
        if self.output_root.exists():
            parallel_rmtree(self.output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)

        with ZipFile(apk_path) as archive:
            entries = tuple(name for name in archive.namelist() if name.lower().endswith(".dex"))
            total = len(entries)
            extracted = 0
            if progress_callback:
                progress_callback(0, total, "Initializing extraction")

            counter: Dict[str, int] = defaultdict(int)
            for entry in entries:
                target_dir, target_file = self._destination_for(entry, counter)
                target_dir.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as src, open(target_file, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                os.chmod(target_file, 0o644)
                extracted += 1
                if progress_callback:
                    progress_callback(extracted, total, entry)

        if extracted == 0:
            self.logger.warning("No dex files found in %s", apk_path)
        else:
            self.logger.info("Extracted %d dex files into %s", extracted, self.output_root)
        return self.output_root

    def _destination_for(
        self,
        entry: str,
        counter: Dict[str, int],
    ) -> Tuple[Path, Path]:
        filename = Path(entry).name
        stem = filename[:-4] if filename.lower().endswith(".dex") else filename
        key = stem.lower()
        index = counter[key]
        counter[key] += 1
        directory_name = stem if index == 0 else f"{stem}_{index}"
        target_dir = self.output_root / directory_name
        target_file = target_dir / filename
        return target_dir, target_file
