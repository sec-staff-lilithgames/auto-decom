#!/usr/bin/env python3
"""Local CLI helper to interact with the AutoDe cloud microservice."""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_PORT = 40100


async def _send_handshake(
    writer: asyncio.StreamWriter,
    mode: str,
    apk_path: Path,
    size: int,
    session_id: Optional[str],
) -> None:
    payload = {
        "mode": mode,
        "apk_name": apk_path.name,
        "size": size,
    }
    if session_id:
        payload["session_id"] = session_id
    writer.write((json.dumps(payload) + "\n").encode("utf-8"))
    await writer.drain()


async def _await_ready(reader: asyncio.StreamReader) -> Dict[str, str]:
    while True:
        line = await reader.readline()
        if not line:
            raise RuntimeError("connection closed before ready message")
        try:
            message = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid message from server: {line!r}") from exc
        if message.get("type") == "status" and message.get("event") == "ready":
            return message
        if message.get("type") == "status" and message.get("event") == "failed":
            raise RuntimeError(message.get("error", "remote failure"))
        if message.get("type") == "log":
            print(message.get("data", ""), end="", flush=True)
        else:
            print(f"[cloud] {message}", flush=True)


async def _download_bytes(
    reader: asyncio.StreamReader,
    destination: Path,
    size: int,
) -> None:
    remaining = size
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as handle:
        while remaining > 0:
            chunk = await reader.read(min(65536, remaining))
            if not chunk:
                raise RuntimeError("connection closed while receiving result payload")
            handle.write(chunk)
            remaining -= len(chunk)


async def run_client(args: argparse.Namespace) -> None:
    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    apk_bytes = apk_path.read_bytes()

    reader, writer = await asyncio.open_connection(args.host, args.port)
    try:
        await _send_handshake(writer, args.mode, apk_path, len(apk_bytes), args.session_id)
        ready = await _await_ready(reader)
        session = ready.get("session")
        if session:
            print(f"[cloud] session {session} acknowledged", flush=True)

        writer.write(apk_bytes)
        await writer.drain()

        output_dir = Path(args.output).expanduser().resolve()
        archive_destination: Optional[Path] = None

        while True:
            line = await reader.readline()
            if not line:
                break
            try:
                message = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"invalid message from server: {line!r}") from exc
            mtype = message.get("type")
            if mtype == "log":
                print(message.get("data", ""), end="", flush=True)
                continue
            if mtype == "status":
                event = message.get("event")
                if event == "failed":
                    raise RuntimeError(message.get("error", "cloud pipeline failure"))
                if event == "completed":
                    name = message.get("archive")
                    if name:
                        archive_destination = output_dir / name
                        print(f"[cloud] pipeline completed, preparing to download {name}", flush=True)
                    else:
                        print("[cloud] pipeline completed", flush=True)
                    continue
                if event == "done":
                    print("[cloud] session finished", flush=True)
                    break
                if event == "ready":
                    continue
                print(f"[cloud] status: {event}", flush=True)
                continue
            if mtype == "result":
                filename = message.get("filename") or "autode-output.zip"
                size_value = int(message.get("size") or 0)
                if size_value <= 0:
                    raise RuntimeError("invalid result size announced by server")
                archive_destination = output_dir / filename
                print(f"[cloud] downloading {filename} ({size_value} bytes)", flush=True)
                await _download_bytes(reader, archive_destination, size_value)
                print(f"[cloud] saved to {archive_destination}", flush=True)
                continue
            print(f"[cloud] unhandled message: {message}", flush=True)
    finally:
        writer.close()
        await writer.wait_closed()

    if archive_destination is None:
        raise RuntimeError("cloud pipeline did not return an artifact")


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AutoDe cloud client")
    parser.add_argument("apk", help="APK file to process")
    parser.add_argument("--host", required=True, help="Cloud service host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Cloud service port")
    parser.add_argument("--mode", choices=["so", "java"], default="so", help="Pipeline mode")
    parser.add_argument("--output", default=".", help="Directory to store results")
    parser.add_argument("--session-id", help="Optional session identifier override")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        asyncio.run(run_client(args))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"[cloud] error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
