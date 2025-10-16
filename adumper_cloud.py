#!/usr/bin/env python3
"""CLI wrapper that drives the AutoDe cloud panel service via its REST API."""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

import requests

DEFAULT_HOST = os.environ.get("AUTODE_CLOUD_HOST", "172.28.217.102")
DEFAULT_PORT = int(os.environ.get("AUTODE_CLOUD_PORT", "40101"))
POLL_INTERVAL_SECONDS = 2
REQUEST_TIMEOUT = 60
RUN_TIMEOUT = 900


class CloudError(RuntimeError):
    """Raised when the cloud panel reports an error."""


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="adumper-cloud",
        description="Run the AutoDe pipeline on the cloud panel service.",
    )
    parser.add_argument("apk", help="Path to the APK file to analyse")
    parser.add_argument(
        "output",
        nargs="?",
        help="Directory to store the resulting archive (default: current directory)",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--so", action="store_true", help="Force native shared-object pipeline")
    group.add_argument("--java", action="store_true", help="Force JADX-based pipeline")
    parser.add_argument(
        "--select-so",
        action="append",
        dest="select_so",
        metavar="NAME",
        help="Select specific shared libraries for analysis (repeatable, matches filename or path fragment)",
    )
    parser.add_argument(
        "--select-dex",
        action="append",
        dest="select_dex",
        metavar="NAME",
        help="Select specific dex files for analysis (repeatable, matches filename or path fragment)",
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="Cloud panel host (default: %(default)s)")
    parser.add_argument(
        "--port",
        default=DEFAULT_PORT,
        type=int,
        help="Cloud panel port (default: %(default)s)",
    )
    return parser.parse_args(argv)


def create_task(host: str, port: int, apk_path: Path, mode: str) -> str:
    url = f"http://{host}:{port}/api/tasks"
    with apk_path.open("rb") as handle:
        files = {"file": (apk_path.name, handle, "application/vnd.android.package-archive")}
        data = {"mode": mode}
        response = requests.post(url, files=files, data=data, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        raise CloudError(f"Failed to create cloud task: {response.text}")
    payload = response.json()
    task_id = payload.get("id")
    if not task_id:
        raise CloudError("Cloud task creation did not return an id")
    print(f"[cloud] session {task_id} created", flush=True)
    return task_id


def fetch_task(host: str, port: int, task_id: str) -> dict:
    url = f"http://{host}:{port}/api/tasks/{task_id}"
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        raise CloudError(f"Failed to fetch task {task_id}: {response.text}")
    return response.json()


def fetch_logs(host: str, port: int, task_id: str) -> List[str]:
    url = f"http://{host}:{port}/api/tasks/{task_id}/logs"
    response = requests.get(url, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        raise CloudError(f"Failed to fetch logs for {task_id}: {response.text}")
    payload = response.json()
    return payload.get("logs", [])


def print_new_logs(host: str, port: int, task_id: str, seen: int) -> int:
    logs = fetch_logs(host, port, task_id)
    if seen < len(logs):
        for line in logs[seen:]:
            if line.endswith("\n"):
                print(line, end="")
            else:
                print(line)
        sys.stdout.flush()
    return len(logs)


def resolve_selection(artifacts: Iterable[str], patterns: Optional[Iterable[str]]) -> List[str]:
    if not patterns:
        return list(artifacts)

    artifacts_list = list(artifacts)
    chosen: List[str] = []
    for pattern in patterns:
        matches = [
            item
            for item in artifacts_list
            if pattern == item
            or pattern == Path(item).name
            or pattern.lower() in item.lower()
        ]
        if not matches:
            raise CloudError(f"No artifact matches selection '{pattern}'")
        for match in matches:
            if match not in chosen:
                chosen.append(match)
    return chosen


def run_task(
    host: str,
    port: int,
    task_id: str,
    artifacts: List[str],
) -> dict:
    url = f"http://{host}:{port}/api/tasks/{task_id}/run"
    response = requests.post(url, json={"artifacts": artifacts}, timeout=RUN_TIMEOUT)
    if response.status_code == 200:
        return response.json()
    message = response.json().get("error") if response.headers.get("Content-Type", "").startswith("application/json") else response.text
    raise CloudError(f"Failed to start cloud task: {message}")


def download_result(host: str, port: int, task_id: str, filename: str, destination: Path) -> Path:
    url = f"http://{host}:{port}/api/tasks/{task_id}/download"
    response = requests.get(url, stream=True, timeout=REQUEST_TIMEOUT)
    if response.status_code != 200:
        raise CloudError(f"Failed to download result: {response.text}")

    header_name = None
    disposition = response.headers.get("Content-Disposition")
    if disposition:
        parts = disposition.split(";")
        for part in parts:
            part = part.strip()
            if part.lower().startswith("filename="):
                header_name = part.split("=", 1)[1].strip('"')
                break
    final_name = header_name or filename or "autode-output.zip"
    target_path = destination / final_name

    with target_path.open("wb") as handle:
        for chunk in response.iter_content(chunk_size=65536):
            if chunk:
                handle.write(chunk)
    print(f"[cloud] saved to {target_path}", flush=True)
    return target_path


def wait_for_status(host: str, port: int, task_id: str, desired: Sequence[str], seen: int) -> Tuple[dict, int]:
    while True:
        detail = fetch_task(host, port, task_id)
        seen = print_new_logs(host, port, task_id, seen)
        status = (detail.get("status") or "").lower()
        if status in (value.lower() for value in desired):
            return detail, seen
        if status == "failed":
            message = detail.get("error") or "cloud task failed"
            raise CloudError(message)
        time.sleep(POLL_INTERVAL_SECONDS)


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.exists():
        print(f"[cloud] error: APK not found: {apk_path}", file=sys.stderr)
        return 1

    if args.output:
        output_dir = Path(args.output).expanduser()
        if not output_dir.is_absolute():
            output_dir = (Path.cwd() / output_dir).resolve()
    else:
        output_dir = Path.cwd()
    output_dir.mkdir(parents=True, exist_ok=True)

    mode = "java" if args.java else "so"
    if mode == "so" and args.select_dex:
        print("[cloud] warning: --select-dex ignored for native pipeline", file=sys.stderr)
    if mode == "java" and args.select_so:
        print("[cloud] warning: --select-so ignored for Java pipeline", file=sys.stderr)

    try:
        task_id = create_task(args.host, args.port, apk_path, mode)
        seen_logs = 0

        detail, seen_logs = wait_for_status(
            args.host,
            args.port,
            task_id,
            desired=("awaiting_selection", "completed"),
            seen=seen_logs,
        )

        artifacts = detail.get("artifacts") or []
        if not artifacts and detail.get("status") == "completed":
            print("[cloud] pipeline completed during extraction stage", flush=True)
            result_name = detail.get("result")
            if not result_name:
                raise CloudError("Cloud task finished without providing a result archive")
            download_result(args.host, args.port, task_id, result_name, output_dir)
            return 0

        if not artifacts:
            raise CloudError("No artifacts available for selection. The APK may not contain matching content.")

        if mode == "so":
            selected = resolve_selection(artifacts, args.select_so)
        else:
            selected = resolve_selection(artifacts, args.select_dex)

        print(f"[cloud] selected {len(selected)} artifact(s)", flush=True)
        run_task(args.host, args.port, task_id, selected)

        detail, seen_logs = wait_for_status(
            args.host,
            args.port,
            task_id,
            desired=("completed",),
            seen=seen_logs,
        )
        result_name = detail.get("result")
        if not result_name:
            raise CloudError("Cloud task completed without returning a result archive")
        download_result(args.host, args.port, task_id, result_name, output_dir)
        return 0
    except CloudError as exc:
        print(f"[cloud] error: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"[cloud] network error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(run())
