#!/usr/bin/env python3
"""AutoDe cloud panel service exposing a web UI for managing pipeline jobs."""

import argparse
import asyncio
import json
import logging
import os
import shutil
import time
import uuid
from collections import deque
from contextlib import redirect_stderr, redirect_stdout
from io import TextIOBase
from pathlib import Path
from typing import Deque, Dict, List, Optional, Set, Tuple

from aiohttp import web

from cleanup import parallel_rmtree
from decompiler import Decompiler
from dexdecompiler import DexDecompiler
from dexfinder import DexFinder
from dexpackager import DexPackager
from run import configure_logging
from sofinder import SoFinder
from tui import PipelineDisplay
from zipper import Zipper


WORKSPACE = Path(__file__).resolve().parent
SESSION_ROOT = WORKSPACE / "panel_sessions"
SESSION_ROOT.mkdir(exist_ok=True)

if hasattr(asyncio, "create_task"):
    create_async_task = asyncio.create_task
else:
    def create_async_task(coro):
        loop = asyncio.get_event_loop()
        return loop.create_task(coro)


def safe_filename(name: str) -> str:
    candidate = Path(name).name or "upload.apk"
    if not candidate.lower().endswith(".apk"):
        candidate = f"{candidate}.apk"
    return candidate


class QueueStream(TextIOBase):
    """Stream that forwards writes to a task's log broadcast."""

    def __init__(self, task: "Task") -> None:
        super().__init__()
        self._task = task

    def write(self, data: str) -> int:  # type: ignore[override]
        if data:
            self._task.push_log(data)
        return len(data)

    def flush(self) -> None:  # type: ignore[override]
        return None


class Task:
    """Represents a single pipeline job within the panel."""

    def __init__(self, task_id: str, filename: str, mode: str, apk_path: Path) -> None:
        self.id = task_id
        self.filename = filename
        self.mode = mode
        self.apk_path = apk_path
        self.session_dir = apk_path.parent
        self.workspace = self.session_dir / "workspace"
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.status = "pending"
        self.error: Optional[str] = None
        self.available_artifacts: List[str] = []
        self.selected_artifacts: List[str] = []
        self.result_path: Optional[Path] = None
        self.source_root: Optional[Path] = None
        self.created_at = time.time()
        self.loop = asyncio.get_event_loop()
        self.log_queue: "asyncio.Queue[str]" = asyncio.Queue()
        self.log_history: Deque[str] = deque(maxlen=2000)
        self.clients: Set[web.WebSocketResponse] = set()
        self.dispatch_task = create_async_task(self._dispatch_logs())

    async def _dispatch_logs(self) -> None:
        while True:
            chunk = await self.log_queue.get()
            if chunk is None:  # type: ignore[comparison-overlap]
                break
            self.log_history.append(chunk)
            dead: List[web.WebSocketResponse] = []
            for client in self.clients:
                if client.closed:
                    dead.append(client)
                    continue
                try:
                    await client.send_str(chunk)
                except Exception:  # noqa: BLE001
                    dead.append(client)
            for client in dead:
                self.clients.discard(client)

    def push_log(self, text: str) -> None:
        if not text:
            return
        for part in text.splitlines(True):
            self.loop.call_soon_threadsafe(self.log_queue.put_nowait, part)

    def stop(self) -> None:
        if not self.dispatch_task.done():
            self.loop.call_soon_threadsafe(self.log_queue.put_nowait, None)  # type: ignore[arg-type]

    def add_client(self, client: web.WebSocketResponse) -> None:
        self.clients.add(client)

    async def replay_logs(self, client: web.WebSocketResponse) -> None:
        for item in self.log_history:
            await client.send_str(item)

    def set_status(self, value: str) -> None:
        self.status = value

    def set_error(self, message: str) -> None:
        self.error = message

    def to_dict(self, include_artifacts: bool = False) -> Dict[str, object]:
        data: Dict[str, object] = {
            "id": self.id,
            "filename": self.filename,
            "mode": self.mode,
            "status": self.status,
            "error": self.error,
            "created_at": self.created_at,
            "selected": list(self.selected_artifacts),
        }
        if include_artifacts:
            data["artifacts"] = list(self.available_artifacts)
        if self.result_path and self.result_path.exists():
            data["result"] = self.result_path.name
        return data

    async def prepare(self) -> None:
        self.set_status("extracting")
        try:
            if self.mode == "so":
                artifacts, root = await self._run_blocking(self._extract_so)
            else:
                artifacts, root = await self._run_blocking(self._extract_java)
            self.available_artifacts = artifacts
            self.source_root = Path(root)
            self.set_status("awaiting_selection")
            if not artifacts:
                self.push_log("未找到可用的目标文件，请检查 APK。\n")
        except Exception as exc:  # noqa: BLE001
            self.fail(str(exc))

    async def start_selection(self, artifacts: List[str]) -> None:
        if self.status in {"extracting", "running"}:
            raise RuntimeError("任务仍在进行中，请稍后再试")
        if not artifacts:
            raise ValueError("请选择至少一个目标后再运行")
        if self.mode == "so":
            missing = [item for item in artifacts if item not in self.available_artifacts]
        else:
            missing = [item for item in artifacts if item not in self.available_artifacts]
        if missing:
            raise ValueError("存在无效的选择: %s" % ", ".join(missing))

        self.selected_artifacts = list(artifacts)
        self.set_status("running")
        try:
            if self.mode == "so":
                result = await self._run_blocking(self._run_so_pipeline, artifacts)
            else:
                result = await self._run_blocking(self._run_java_pipeline, artifacts)
            self.result_path = Path(result)
            self.set_status("completed")
            self.push_log("任务已完成，可以下载结果。\n")
        except Exception as exc:  # noqa: BLE001
            self.fail(str(exc))
            raise

    def fail(self, message: str) -> None:
        self.set_status("failed")
        self.set_error(message)
        self.push_log(f"[error] {message}\n")

    async def _run_blocking(self, func, *args) -> object:
        loop = asyncio.get_event_loop()
        stream = QueueStream(self)
        logger = logging.getLogger(f"autode.task.{self.id}")
        logger.setLevel(logging.INFO)
        logger.propagate = False

        def runner():
            handler = logging.StreamHandler(stream)
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            logger.handlers = []
            logger.addHandler(handler)
            try:
                with redirect_stdout(stream), redirect_stderr(stream):
                    return func(logger, stream, *args)
            finally:
                logger.removeHandler(handler)

        return await loop.run_in_executor(None, runner)

    # Blocking helpers -------------------------------------------------

    def _extract_so(self, logger: logging.Logger, stream: TextIOBase) -> Tuple[List[str], str]:
        display = PipelineDisplay()
        with display:
            display.set_status("pipeline", "running", "Validating input")
            display.log(f"Using APK: {self.apk_path}")
            display.set_status("sofinder", "running", f"Extracting from {self.apk_path.name}")
            sofinder = SoFinder(workspace=self.workspace, logger=logger)
            so_dir = sofinder.run(
                self.apk_path,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "sofinder", current, total, detail
                ),
            )
            artifacts = [
                path.relative_to(so_dir).as_posix()
                for path in sorted(so_dir.rglob("*.so"))
            ]
            display.set_status("sofinder", "completed", f"{len(artifacts)} libraries extracted")
            display.log("选择需要反编译的库后点击开始进行分析。")
            display.set_status("pipeline", "completed", "Extraction complete; awaiting selection")
        return artifacts, str(so_dir)

    def _extract_java(self, logger: logging.Logger, stream: TextIOBase) -> Tuple[List[str], str]:
        display = PipelineDisplay(module_labels={
            "sofinder": "Dex Extractor",
            "decompiler": "JADX",
            "zipper": "Packager",
        })
        with display:
            display.set_status("pipeline", "running", "Validating input")
            display.log(f"Using APK: {self.apk_path}")
            display.set_status("sofinder", "running", f"Extracting dex from {self.apk_path.name}")
            dexfinder = DexFinder(workspace=self.workspace, logger=logger)
            dex_dir = dexfinder.run(
                self.apk_path,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "sofinder", current, total, detail
                ),
            )
            artifacts = [
                path.relative_to(dex_dir).as_posix()
                for path in sorted(dex_dir.rglob("*.dex"))
            ]
            display.set_status("sofinder", "completed", f"{len(artifacts)} dex files extracted")
            display.log("选择需要反编译的 dex 文件后点击开始进行分析。")
            display.set_status("pipeline", "completed", "Extraction complete; awaiting selection")
        return artifacts, str(dex_dir)

    def _run_so_pipeline(
        self,
        logger: logging.Logger,
        stream: TextIOBase,
        artifacts: List[str],
    ) -> str:
        if not self.source_root:
            raise RuntimeError("共享库尚未解析完成")
        selected_root = self.workspace / "selected_so"
        if selected_root.exists():
            parallel_rmtree(selected_root)
        selected_root.mkdir(parents=True, exist_ok=True)

        for item in artifacts:
            source_path = self.source_root / item
            if not source_path.exists():
                raise FileNotFoundError(f"选定的库不存在: {item}")
            destination = selected_root / item
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)

        task_workspace = self.workspace
        display = PipelineDisplay()
        with display:
            display.set_status("pipeline", "running", "Preparing selected libraries")
            display.log(f"Selected {len(artifacts)} libraries")
            display.set_status("sofinder", "completed", f"{len(artifacts)} libraries ready")

            output_root = task_workspace / "selected_so_decomp"
            decompiler = Decompiler(
                workspace=WORKSPACE,
                logger=logger,
                input_root=selected_root,
                output_root=output_root,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "decompiler", current, total, detail
                ),
            )
            display.set_status("decompiler", "running", "Starting Ghidra headless analysis")
            so_decomp_dir = decompiler.run(selected_root)
            produced = sum(1 for _ in so_decomp_dir.rglob("*.c"))
            display.set_status("decompiler", "completed", f"Pseudo-C files: {produced}")
            for warning in decompiler.warnings:
                display.log(f"Warning: {warning}")

            zipper = Zipper(workspace=task_workspace, logger=logger)
            display.set_status("zipper", "running", "Packaging analysis artifacts")
            archive_path = zipper.run(
                so_decomp_dir,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "zipper", current, total, detail
                ),
            )
            display.set_status("zipper", "completed", f"Archive: {archive_path.name}")
            display.set_status("pipeline", "completed", "Pipeline finished successfully")
            display.log(f"Result archive ready at {archive_path}")
        return str(archive_path)

    def _run_java_pipeline(
        self,
        logger: logging.Logger,
        stream: TextIOBase,
        artifacts: List[str],
    ) -> str:
        if not self.source_root:
            raise RuntimeError("dex 文件尚未解析完成")
        selected_root = self.workspace / "selected_dex"
        if selected_root.exists():
            parallel_rmtree(selected_root)
        selected_root.mkdir(parents=True, exist_ok=True)

        for item in artifacts:
            source_path = self.source_root / item
            if not source_path.exists():
                raise FileNotFoundError(f"选定的 dex 不存在: {item}")
            destination = selected_root / item
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_path, destination)

        task_workspace = self.workspace
        display = PipelineDisplay(module_labels={
            "sofinder": "Dex Extractor",
            "decompiler": "JADX",
            "zipper": "Packager",
        })
        with display:
            display.set_status("pipeline", "running", "Preparing selected dex files")
            display.log(f"Selected {len(artifacts)} dex files")
            display.set_status("sofinder", "completed", f"{len(artifacts)} dex ready")

            output_root = task_workspace / "selected_dex_decomp"
            dex_decompiler = DexDecompiler(
                workspace=WORKSPACE,
                logger=logger,
                input_root=selected_root,
                output_root=output_root,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "decompiler", current, total, detail
                ),
            )
            display.set_status("decompiler", "running", "Running JADX analysis")
            dex_decomp_dir = dex_decompiler.run(selected_root)
            produced = sum(1 for _ in dex_decomp_dir.iterdir())
            display.set_status("decompiler", "completed", f"Dex outputs: {produced}")
            for warning in dex_decompiler.warnings:
                display.log(f"Warning: {warning}")

            packager = DexPackager(workspace=task_workspace, logger=logger)
            display.set_status("zipper", "running", "Packaging Java artifacts")
            archive_path = packager.run(
                dex_decomp_dir,
                progress_callback=lambda current, total, detail: display.set_progress(
                    "zipper", current, total, detail
                ),
            )
            display.set_status("zipper", "completed", f"Archive: {archive_path.name}")
            display.set_status("pipeline", "completed", "Pipeline finished successfully")
            display.log(f"Result archive ready at {archive_path}")
        return str(archive_path)


class TaskManager:
    """In-memory registry holding active tasks."""

    def __init__(self) -> None:
        self.tasks: Dict[str, Task] = {}
        self.lock = asyncio.Lock()

    async def register(self, task: Task) -> None:
        async with self.lock:
            self.tasks[task.id] = task

    def list_tasks(self) -> List[Task]:
        return sorted(self.tasks.values(), key=lambda item: item.created_at, reverse=True)

    def get(self, task_id: str) -> Optional[Task]:
        return self.tasks.get(task_id)


PANEL_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <title>AutoDe Cloud Panel</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #12141a; color: #f3f4f6; margin: 0; }
    header { padding: 16px 24px; background: #1f2937; border-bottom: 1px solid #111827; }
    h1 { margin: 0; font-size: 20px; }
    main { display: flex; height: calc(100vh - 64px); }
    .sidebar { width: 320px; border-right: 1px solid #1f2937; overflow-y: auto; padding: 16px; background: #111827; }
    .content { flex: 1; padding: 16px; display: flex; flex-direction: column; }
    form { display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px; }
    input[type="file"] { color: #f3f4f6; }
    .radio-group { display: flex; gap: 16px; }
    button { background: #2563eb; color: #fff; border: none; padding: 10px 16px; border-radius: 6px; cursor: pointer; }
    button:disabled { background: #374151; cursor: not-allowed; }
    .task { border: 1px solid #1f2937; border-radius: 6px; padding: 12px; margin-bottom: 12px; cursor: pointer; background: #1f2937; }
    .task.active { border-color: #2563eb; }
    .status { font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #9ca3af; }
    .logs { flex: 1; background: #0b1120; border: 1px solid #1f2937; border-radius: 6px; padding: 12px; overflow-y: auto; white-space: pre-wrap; font-family: monospace; font-size: 13px; margin-bottom: 16px; }
    .artifacts { border: 1px solid #1f2937; border-radius: 6px; padding: 12px; max-height: 200px; overflow-y: auto; background: #0f172a; }
    .error { color: #f87171; margin-top: 8px; }
    a.download { color: #34d399; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <header>
    <h1>AutoDe Cloud Panel</h1>
  </header>
  <main>
    <aside class="sidebar">
      <form id="upload-form">
        <label>上传 APK
          <input id="upload-file" type="file" accept=".apk" required />
        </label>
        <div class="radio-group">
          <label><input type="radio" name="mode" value="so" checked /> Native</label>
          <label><input type="radio" name="mode" value="java" /> Java</label>
        </div>
        <button type="submit">提交任务</button>
        <span id="upload-error" class="error"></span>
      </form>
      <div id="task-list"></div>
    </aside>
    <section class="content">
      <div class="logs" id="logs"></div>
      <div>
        <h2 id="detail-title"></h2>
        <p id="detail-status"></p>
        <div class="artifacts" id="artifact-container"></div>
        <button id="run-selected" disabled>开始分析所选目标</button>
        <div id="detail-error" class="error"></div>
        <p id="download-link"></p>
      </div>
    </section>
  </main>
  <script>
    const taskListEl = document.getElementById("task-list");
    const logsEl = document.getElementById("logs");
    const detailTitleEl = document.getElementById("detail-title");
    const detailStatusEl = document.getElementById("detail-status");
    const detailErrorEl = document.getElementById("detail-error");
    const artifactContainer = document.getElementById("artifact-container");
    const runSelectedBtn = document.getElementById("run-selected");
    const downloadLinkEl = document.getElementById("download-link");
    const uploadForm = document.getElementById("upload-form");
    const uploadErrorEl = document.getElementById("upload-error");

    let currentTaskId = null;
    let logSocket = null;
    let taskCache = {};

    function renderTasks(tasks) {
      taskListEl.innerHTML = "";
      tasks.forEach(task => {
        const div = document.createElement("div");
        div.className = "task" + (task.id === currentTaskId ? " active" : "");
        div.dataset.id = task.id;
        div.innerHTML = `
          <div class="status">${task.status}</div>
          <div>${task.filename}</div>
          <div>${task.mode.toUpperCase()} • ${new Date(task.created_at * 1000).toLocaleString()}</div>
        `;
        div.addEventListener("click", () => {
          selectTask(task.id);
        });
        taskListEl.appendChild(div);
      });
    }

    async function fetchTasks() {
      const res = await fetch("/api/tasks");
      const data = await res.json();
      renderTasks(data.tasks);
      data.tasks.forEach(task => taskCache[task.id] = task);
      if (currentTaskId && !taskCache[currentTaskId]) {
        clearDetails();
      }
    }

    function clearDetails() {
      currentTaskId = null;
      logsEl.textContent = "";
      detailTitleEl.textContent = "";
      detailStatusEl.textContent = "";
      artifactContainer.innerHTML = "";
      runSelectedBtn.disabled = true;
      downloadLinkEl.innerHTML = "";
      detailErrorEl.textContent = "";
      if (logSocket) {
        logSocket.close();
        logSocket = null;
      }
    }

    async function selectTask(id) {
      currentTaskId = id;
      const res = await fetch(`/api/tasks/${id}`);
      if (!res.ok) {
        clearDetails();
        return;
      }
      const task = await res.json();
      detailTitleEl.textContent = `${task.filename} (${task.mode.toUpperCase()})`;
      detailStatusEl.textContent = `状态: ${task.status}` + (task.error ? ` • ${task.error}` : "");
      detailErrorEl.textContent = "";
      renderArtifacts(task);
      renderDownload(task);
      setupLogSocket(id);
      updateRunButton(task);
      fetchTasks();
    }

    function renderArtifacts(task) {
      artifactContainer.innerHTML = "";
      if (!task.artifacts || task.artifacts.length === 0) {
        artifactContainer.textContent = "暂无可选目标。";
        return;
      }
      task.artifacts.forEach(item => {
        const id = `artifact-${task.id}-${item.replace(/[^a-zA-Z0-9]+/g, "_")}`;
        const wrapper = document.createElement("div");
        wrapper.innerHTML = `<label><input type="checkbox" value="${item}" id="${id}"> ${item}</label>`;
        artifactContainer.appendChild(wrapper);
      });
      if (task.selected) {
        task.selected.forEach(val => {
          const el = artifactContainer.querySelector(`input[value="${val}"]`);
          if (el) {
            el.checked = true;
          }
        });
      }
    }

    function renderDownload(task) {
      if (task.result) {
        downloadLinkEl.innerHTML = `<a class="download" href="/api/tasks/${task.id}/download" target="_blank">下载 ${task.result}</a>`;
      } else {
        downloadLinkEl.innerHTML = "";
      }
    }

    function updateRunButton(task) {
      const canRun = task.status === "awaiting_selection" || task.status === "completed";
      runSelectedBtn.disabled = !canRun;
    }

    function setupLogSocket(id) {
      if (logSocket) {
        logSocket.close();
        logSocket = null;
      }
      logsEl.textContent = "";
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      logSocket = new WebSocket(`${protocol}://${window.location.host}/ws/tasks/${id}`);
      logSocket.onmessage = (event) => {
        logsEl.textContent += event.data;
        logsEl.scrollTop = logsEl.scrollHeight;
      };
    }

    uploadForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      uploadErrorEl.textContent = "";
      const fileInput = document.getElementById("upload-file");
      if (!fileInput.files.length) {
        uploadErrorEl.textContent = "请选择一个 APK 文件。";
        return;
      }
      const mode = uploadForm.querySelector("input[name='mode']:checked").value;
      const form = new FormData();
      form.append("file", fileInput.files[0]);
      form.append("mode", mode);
      const res = await fetch("/api/tasks", { method: "POST", body: form });
      if (!res.ok) {
        const err = await res.json();
        uploadErrorEl.textContent = err.error || "上传失败";
        return;
      }
      const data = await res.json();
      fileInput.value = "";
      await fetchTasks();
      selectTask(data.id);
    });

    runSelectedBtn.addEventListener("click", async () => {
      if (!currentTaskId) return;
      const selected = Array.from(artifactContainer.querySelectorAll("input:checked")).map(el => el.value);
      detailErrorEl.textContent = "";
      const res = await fetch(`/api/tasks/${currentTaskId}/run`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifacts: selected })
      });
      if (!res.ok) {
        const err = await res.json();
        detailErrorEl.textContent = err.error || "任务启动失败";
      } else {
        selectTask(currentTaskId);
      }
    });

    setInterval(fetchTasks, 4000);
    fetchTasks();
  </script>
</body>
</html>
"""


async def handle_index(request: web.Request) -> web.Response:
    return web.Response(text=PANEL_HTML, content_type="text/html")


async def handle_list_tasks(request: web.Request) -> web.Response:
    manager: TaskManager = request.app["manager"]
    tasks = [task.to_dict() for task in manager.list_tasks()]
    return web.json_response({"tasks": tasks})


async def handle_task_detail(request: web.Request) -> web.Response:
    manager: TaskManager = request.app["manager"]
    task = manager.get(request.match_info["task_id"])
    if not task:
        return web.json_response({"error": "任务不存在"}, status=404)
    return web.json_response(task.to_dict(include_artifacts=True))


async def handle_download(request: web.Request) -> web.StreamResponse:
    manager: TaskManager = request.app["manager"]
    task = manager.get(request.match_info["task_id"])
    if not task or not task.result_path or not task.result_path.exists():
        return web.json_response({"error": "结果文件不存在"}, status=404)
    headers = {
        "Content-Disposition": f'attachment; filename="{task.result_path.name}"'
    }
    return web.FileResponse(path=task.result_path, headers=headers)


async def handle_create_task(request: web.Request) -> web.Response:
    reader = await request.multipart()
    file_field = None
    mode = "so"
    filename = "upload.apk"

    while True:
        field = await reader.next()
        if field is None:
            break
        if field.name == "mode":
            mode = (await field.text()).strip().lower() or "so"
        elif field.name == "file":
            file_field = field
            filename = safe_filename(field.filename or "upload.apk")
            break

    if file_field is None:
        return web.json_response({"error": "缺少文件上传字段"}, status=400)
    if mode not in {"so", "java"}:
        return web.json_response({"error": "不支持的模式"}, status=400)
    if not filename.lower().endswith(".apk"):
        return web.json_response({"error": "仅支持 APK 文件上传"}, status=400)

    task_id = f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
    session_dir = SESSION_ROOT / task_id
    session_dir.mkdir(parents=True, exist_ok=True)
    apk_path = session_dir / filename

    with apk_path.open("wb") as handle:
        while True:
            chunk = await file_field.read_chunk()
            if not chunk:
                break
            handle.write(chunk)

    manager: TaskManager = request.app["manager"]
    task = Task(task_id, filename, mode, apk_path)
    await manager.register(task)
    create_async_task(task.prepare())
    return web.json_response({"id": task.id})


async def handle_run_task(request: web.Request) -> web.Response:
    manager: TaskManager = request.app["manager"]
    task = manager.get(request.match_info["task_id"])
    if not task:
        return web.json_response({"error": "任务不存在"}, status=404)
    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "请求体需为 JSON"}, status=400)
    artifacts = payload.get("artifacts") or []
    if not isinstance(artifacts, list):
        return web.json_response({"error": "artifacts 字段格式不正确"}, status=400)
    artifacts = [str(item) for item in artifacts]
    try:
        await task.start_selection(artifacts)
    except ValueError as exc:
        return web.json_response({"error": str(exc)}, status=400)
    except RuntimeError as exc:
        return web.json_response({"error": str(exc)}, status=409)
    except Exception as exc:  # noqa: BLE001
        return web.json_response({"error": str(exc)}, status=500)
    return web.json_response(task.to_dict(include_artifacts=True))


async def handle_task_logs(request: web.Request) -> web.StreamResponse:
    manager: TaskManager = request.app["manager"]
    task = manager.get(request.match_info["task_id"])
    if not task:
        return web.Response(status=404, text="task not found")

    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    task.add_client(ws)
    await task.replay_logs(ws)

    try:
        async for _ in ws:
            pass
    finally:
        task.clients.discard(ws)
    return ws


async def handle_task_log_dump(request: web.Request) -> web.Response:
    manager: TaskManager = request.app["manager"]
    task = manager.get(request.match_info["task_id"])
    if not task:
        return web.json_response({"error": "任务不存在"}, status=404)
    return web.json_response({"logs": list(task.log_history)})


def create_app() -> web.Application:
    configure_logging()
    app = web.Application()
    app["manager"] = TaskManager()
    app.add_routes(
        [
            web.get("/", handle_index),
            web.get("/api/tasks", handle_list_tasks),
            web.get("/api/tasks/{task_id}", handle_task_detail),
            web.post("/api/tasks", handle_create_task),
            web.post("/api/tasks/{task_id}/run", handle_run_task),
            web.get("/api/tasks/{task_id}/download", handle_download),
            web.get("/api/tasks/{task_id}/logs", handle_task_log_dump),
            web.get("/ws/tasks/{task_id}", handle_task_logs),
        ]
    )
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="AutoDe cloud panel service")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=40101, help="Listening port (default: 40101)")
    args = parser.parse_args()

    app = create_app()
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
