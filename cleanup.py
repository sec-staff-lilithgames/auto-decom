import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Iterable, List, Optional


def _default_workers() -> int:
    return max(os.cpu_count() or 4, 4)


def parallel_unlink(paths: Iterable[Path], *, max_workers: Optional[int] = None) -> None:
    pool_size = max_workers or _default_workers()
    to_process = [Path(p) for p in paths]
    if not to_process:
        return

    def _unlink(target: Path) -> None:
        try:
            if target.exists() or target.is_symlink():
                target.unlink()
        except FileNotFoundError:
            pass

    with ThreadPoolExecutor(max_workers=pool_size) as executor:
        for _ in executor.map(_unlink, to_process):
            pass


def parallel_rmdir(paths: Iterable[Path], *, max_workers: Optional[int] = None) -> None:
    # Removing directories sequentially (deepest first) avoids race conditions but keeps logic simple.
    to_process = sorted((Path(p) for p in paths), key=lambda p: len(p.parts), reverse=True)
    for target in to_process:
        try:
            target.rmdir()
        except FileNotFoundError:
            continue
        except OSError:
            # Directory may still contain hidden files; fall back to recursive walk.
            if target.exists():
                parallel_rmtree(target, max_workers=max_workers)


def parallel_rmtree(path: Path, *, max_workers: Optional[int] = None) -> None:
    target = Path(path)
    if not target.exists():
        return
    if target.is_file() or target.is_symlink():
        target.unlink(missing_ok=True)  # type: ignore[attr-defined]
        return

    files: List[Path] = []
    dirs: List[Path] = []
    for root, dirnames, filenames in os.walk(target, topdown=False):
        root_path = Path(root)
        files.extend(root_path / name for name in filenames)
        dirs.extend(root_path / name for name in dirnames)

    if files:
        parallel_unlink(files, max_workers=max_workers)
    if dirs:
        parallel_rmdir(dirs, max_workers=max_workers)

    try:
        target.rmdir()
    except FileNotFoundError:
        pass
