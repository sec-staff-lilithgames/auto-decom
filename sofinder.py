import logging
import os
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional, Tuple
from zipfile import ZipFile

from cleanup import parallel_rmtree


class SoFinder:
    """
    Extracts shared libraries from an APK into a structured directory tree.
    - lib/arm64*/*.so files are placed under so/lib/<soname>/
    - assets/**/*.so files are placed under so/assets/<soname>/
    Each .so sits alone in its own directory named after the base filename.
    """

    def __init__(self, workspace: Path, logger: logging.Logger) -> None:
        self.workspace = workspace
        self.logger = logger
        self.output_root = self.workspace / "so"

    def run(
        self,
        apk_path: Path,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> Path:
        if not apk_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")
        self.logger.info("Extracting shared objects from %s", apk_path)
        if self.output_root.exists():
            parallel_rmtree(self.output_root)
        (self.output_root / "lib").mkdir(parents=True, exist_ok=True)
        (self.output_root / "assets").mkdir(parents=True, exist_ok=True)

        with ZipFile(apk_path) as archive:
            entries = archive.namelist()
            lib_entries = self._filter_entries(entries, prefix="lib", matcher=self._is_arm64_so)
            asset_entries = self._filter_entries(entries, prefix="assets", matcher=self._is_asset_so)

            extracted = 0
            total = len(lib_entries) + len(asset_entries)

            if progress_callback:
                progress_callback(0, total, "Initializing extraction")

            extracted += self._extract_group(
                archive,
                lib_entries,
                self.output_root / "lib",
                source_label="lib",
                progress_callback=progress_callback,
                total=total,
                counter_start=extracted,
            )
            extracted += self._extract_group(
                archive,
                asset_entries,
                self.output_root / "assets",
                source_label="assets",
                progress_callback=progress_callback,
                total=total,
                counter_start=extracted,
            )

        if extracted == 0:
            self.logger.warning("No shared libraries found in %s", apk_path)
        else:
            self.logger.info("Extracted %d shared libraries into %s", extracted, self.output_root)
        return self.output_root

    def _filter_entries(
        self,
        entries: Iterable[str],
        prefix: str,
        matcher,
    ) -> Tuple[str, ...]:
        prefix_with_sep = prefix.rstrip("/") + "/"
        selected = []
        for name in entries:
            if not name.lower().endswith(".so"):
                continue
            if name.endswith("/"):
                continue
            if not name.startswith(prefix_with_sep):
                continue
            if matcher(name):
                selected.append(name)
        return tuple(selected)

    @staticmethod
    def _is_arm64_so(entry_name: str) -> bool:
        parts = entry_name.split("/")
        if len(parts) < 3:
            return False
        arch_part = parts[1].lower()
        return arch_part.startswith("arm64")

    @staticmethod
    def _is_asset_so(entry_name: str) -> bool:
        return True  # all .so files under assets qualify

    def _extract_group(
        self,
        archive: ZipFile,
        entries: Iterable[str],
        destination_root: Path,
        *,
        source_label: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        total: int,
        counter_start: int,
    ) -> int:
        counter: Dict[str, int] = defaultdict(int)
        extracted = counter_start
        for entry in entries:
            soname = Path(entry).name
            base = soname[:-3] if soname.lower().endswith(".so") else soname
            key = base.lower()
            suffix = counter[key]
            counter[key] += 1
            directory_name = base if suffix == 0 else f"{base}_{suffix}"
            target_dir = destination_root / directory_name
            target_dir.mkdir(parents=True, exist_ok=True)
            target_file = target_dir / soname
            with archive.open(entry) as src, open(target_file, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.chmod(target_file, 0o644)
            extracted += 1
            self.logger.debug("Extracted %s to %s", entry, target_file)
            if progress_callback:
                detail = f"{source_label}/{soname}"
                progress_callback(extracted, total, detail)
        return extracted - counter_start
