#!/usr/bin/env python3
"""Smoke-test the headless WinDbg MCP server over stdio.

This helper intentionally depends only on the Python standard library. It is
meant for local validation of the MCP protocol path and optional live KDNET
session operations without baking secrets into the repository.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


KEY_RE = re.compile(r"(key=)[^,\s\"]+", re.IGNORECASE)


def redact(value: str) -> str:
    return KEY_RE.sub(r"\1<redacted>", value)


class McpStdioClient:
    def __init__(self, exe: Path) -> None:
        self.proc = subprocess.Popen(
            [str(exe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.next_id = 1

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def send(self, method: str, params: dict[str, Any] | None = None) -> int:
        request_id = self.next_id
        self.next_id += 1
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        self._write(payload)
        return request_id

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        self._write(payload)

    def response(self, request_id: int, timeout_secs: float = 30.0) -> dict[str, Any]:
        deadline = time.time() + timeout_secs
        assert self.proc.stdout is not None
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"MCP server exited with code {self.proc.returncode}")
                time.sleep(0.05)
                continue

            payload = json.loads(line)
            if payload.get("id") == request_id:
                return payload

        raise TimeoutError(f"Timed out waiting for MCP response id {request_id}")

    def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        timeout_secs: float = 60.0,
    ) -> dict[str, Any]:
        request_id = self.send(
            "tools/call",
            {
                "name": name,
                "arguments": arguments,
            },
        )
        response = self.response(request_id, timeout_secs)
        if "error" in response:
            raise RuntimeError(response["error"])
        return response["result"].get("structuredContent", {})

    def _write(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()


def default_exe() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "windbg_mcp_headless.exe"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", help="Optional KDNET -k connection string")
    parser.add_argument("--session-id", default="smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=30)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=5)
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Debugger command to run after opening the session; can be repeated",
    )
    parser.add_argument(
        "--skip-close",
        action="store_true",
        help="Leave the session open for manual MCP inspection",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    try:
        init_id = client.send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "headless-mcp-smoke", "version": "0"},
            },
        )
        init = client.response(init_id, 10)
        print("initialize:", "ok" if "result" in init else init)
        client.notify("notifications/initialized", {})

        tools_id = client.send("tools/list", {})
        tools = client.response(tools_id, 10)["result"]["tools"]
        tool_names = {tool["name"] for tool in tools}
        print("tools:", len(tool_names), "recover=", "windbg_recover_session" in tool_names)

        if not args.connection:
            return 0

        print("opening:", redact(args.connection))
        session = client.call_tool(
            "windbg_open_session",
            {
                "connection": args.connection,
                "session_id": args.session_id,
                "attach_timeout_secs": args.attach_timeout_secs,
            },
            timeout_secs=args.attach_timeout_secs + 20,
        )["session"]
        state = session.get("state") or {}
        print("opened:", session["session_id"], state.get("status_name"))

        for command in args.command:
            result = client.call_tool(
                "windbg_execute_command",
                {"session_id": args.session_id, "command": command},
                timeout_secs=120,
            )
            print(f"command: {command}")
            print(result.get("output", "").rstrip())

        if not args.skip_close:
            closed = client.call_tool(
                "windbg_close_session",
                {
                    "session_id": args.session_id,
                    "shutdown_timeout_secs": args.shutdown_timeout_secs,
                },
                timeout_secs=args.shutdown_timeout_secs + 20,
            )
            print("closed:", json.dumps(closed, ensure_ascii=False))

        return 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
