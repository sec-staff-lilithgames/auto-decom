import curses
import queue
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple


MODULE_ORDER: Tuple[Tuple[str, str], ...] = (
    ("pipeline", "Pipeline"),
    ("sofinder", "Extractor"),
    ("decompiler", "Decompiler"),
    ("zipper", "Zipper"),
)


@dataclass
class ModuleState:
    status: str = "pending"
    detail: str = ""
    current: int = 0
    total: int = 0


class PipelineDisplay:
    """Simple TUI to surface pipeline progress in real-time."""

    def __init__(self, module_labels: Optional[Dict[str, str]] = None) -> None:
        self._is_tty = sys.stdout.isatty()
        self._queue: "queue.Queue[Tuple]" = queue.Queue()
        self._states: Dict[str, ModuleState] = {
            key: ModuleState() for key, _ in MODULE_ORDER
        }
        self._logs: Deque[str] = deque(maxlen=8)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        default_labels = {key: label for key, label in MODULE_ORDER}
        if module_labels:
            default_labels.update(module_labels)
        self._labels = default_labels

    def __enter__(self) -> "PipelineDisplay":
        if self._is_tty:
            self._thread = threading.Thread(target=self._run_curses, daemon=True)
            self._thread.start()
        else:
            self._print_banner()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def stop(self) -> None:
        if self._is_tty and not self._stop_event.is_set():
            self._queue.put(("stop",))
            if self._thread:
                self._thread.join()
            self._stop_event.set()
            self._print_summary()
        elif not self._is_tty and not self._stop_event.is_set():
            self._stop_event.set()
            self._print_summary()

    def set_status(self, module: str, status: str, detail: str = "") -> None:
        if self._is_tty:
            self._queue.put(("status", module, status, detail))
        else:
            self._states[module].status = status
            if detail:
                self._states[module].detail = detail
            self._emit_line(module, status, detail)

    def set_progress(
        self,
        module: str,
        current: int,
        total: int,
        detail: str = "",
    ) -> None:
        if self._is_tty:
            self._queue.put(("progress", module, current, total, detail))
        else:
            state = self._states[module]
            state.current = current
            state.total = total
            if not state.status or state.status == "pending":
                state.status = "running"
            if detail:
                state.detail = detail
            progress_text = f"{current}/{total}" if total else f"{current}"
            self._emit_line(module, f"{state.status or 'running'} {progress_text}", detail)

    def log(self, message: str) -> None:
        if self._is_tty:
            self._queue.put(("log", message))
        else:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")

    # Internal helpers -----------------------------------------------------

    def _run_curses(self) -> None:
        try:
            curses.wrapper(self._curses_main)
        except Exception:  # noqa: BLE001
            self._is_tty = False
            self._stop_event.set()
            self._print_banner()
            self.log("TUI disabled; falling back to plain output.")

    def _curses_main(self, stdscr) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        last_render = 0.0

        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.1)
            except queue.Empty:
                pass
            else:
                kind = item[0]
                if kind == "stop":
                    self._stop_event.set()
                    break
                if kind == "status":
                    _, module, status, detail = item
                    state = self._states.get(module)
                    if state:
                        state.status = status
                        if detail:
                            state.detail = detail
                elif kind == "progress":
                    _, module, current, total, detail = item
                    state = self._states.get(module)
                    if state:
                        state.current = max(0, current)
                        state.total = max(0, total)
                        if detail:
                            state.detail = detail
                        if not state.status or state.status == "pending":
                            state.status = "running"
                elif kind == "log":
                    _, message = item
                    self._logs.appendleft(message)

            now = time.time()
            if now - last_render > 0.05:
                self._render(stdscr)
                last_render = now

        # Final render before exit
        self._render(stdscr)
        time.sleep(0.05)

    def _render(self, stdscr) -> None:
        height, width = stdscr.getmaxyx()
        stdscr.erase()
        stdscr.addnstr(0, 0, "AutoDe Pipeline Monitor", width - 1, curses.A_BOLD)
        stdscr.addnstr(
            1,
            0,
            time.strftime("Updated at %Y-%m-%d %H:%M:%S"),
            width - 1,
            curses.A_DIM,
        )
        line = 3
        for module, label in MODULE_ORDER:
            state = self._states[module]
            status = state.status or "pending"
            progress = ""
            if state.total:
                progress = f"[{state.current}/{state.total}]"
            detail = state.detail or ""
            text = f"{label:<12} {status:<10} {progress:<13} {detail}"
            stdscr.addnstr(line, 0, text, width - 1)
            line += 1

        line += 1
        stdscr.addnstr(line, 0, "Recent events:", width - 1, curses.A_UNDERLINE)
        line += 1
        for message in self._logs:
            if line >= height - 1:
                break
            stdscr.addnstr(line, 0, message[: width - 1], width - 1)
            line += 1
        stdscr.refresh()

    def _emit_line(self, module: str, status: str, detail: str) -> None:
        label = self._labels.get(module, module)
        timestamp = time.strftime("%H:%M:%S")
        progress = ""
        state = self._states.get(module)
        if state and state.total:
            progress = f"[{state.current}/{state.total}] "
        detail_part = f" - {detail}" if detail else ""
        print(f"[{timestamp}] {label}: {status} {progress}{detail_part}")

    def _print_banner(self) -> None:
        print("== AutoDe Pipeline Monitor ==")

    def _print_summary(self) -> None:
        print("\nFinal Status:")
        for module, label in MODULE_ORDER:
            state = self._states[module]
            progress = ""
            if state.total:
                progress = f"[{state.current}/{state.total}] "
            detail = f" - {state.detail}" if state.detail else ""
            print(f"  {label:<12} {state.status:<10} {progress}{detail}")
        if self._logs:
            print("  Notes:")
            for message in self._logs:
                print(f"    - {message}")
