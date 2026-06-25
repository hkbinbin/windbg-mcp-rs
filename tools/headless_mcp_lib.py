#!/usr/bin/env python3
"""Shared helpers for driving the thin WinDbg MCP server over stdio.

The MCP server now exposes only three tools:

  - windbg_open_session  (mode=launch|attach|kernel) -> returns daemon `name`
  - windbg_close_session (name, force?)
  - windbg_use_help      (topic?)

All detailed debugging is performed by running the `windbg_cli` executable
directly. The `CliDriver` helper wraps `windbg_cli do --name <name> ...`.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any


KEY_RE = re.compile(r"(key=)[^,\s\"]+", re.IGNORECASE)


def redact(value: str) -> str:
    return KEY_RE.sub(r"\1<redacted>", value)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_exe() -> Path:
    return repo_root() / "target" / "release" / "windbg_mcp_headless.exe"


def default_cli() -> Path:
    return repo_root() / "target" / "release" / "windbg_cli.exe"


def registry_dir_path() -> Path:
    """Mirror of the Rust `daemon::registry_dir()` resolution."""
    base = os.environ.get("TEMP") or os.environ.get("TMP") or "."
    return Path(base) / "windbg_cli_daemons"


def tcp_probe(host: str, port: int, timeout_secs: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_secs):
            return True
    except OSError:
        return False


class McpStdioClient:
    def __init__(self, exe: Path, forward_stderr: bool = False) -> None:
        stderr = None if forward_stderr else subprocess.PIPE
        self.proc = subprocess.Popen(
            [str(exe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.next_id = 1

    def close(self, timeout_secs: float = 30.0) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=timeout_secs)
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

    def initialize(self, name: str) -> set[str]:
        init_id = self.send(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": name, "version": "0"},
            },
        )
        init = self.response(init_id, 10)
        print("initialize:", "ok" if "result" in init else init)
        self.notify("notifications/initialized", {})

        tools_id = self.send("tools/list", {})
        tools = self.response(tools_id, 10)["result"]["tools"]
        tool_names = {tool["name"] for tool in tools}
        print("tools:", len(tool_names), sorted(tool_names))
        return tool_names

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


# ---------------------------------------------------------------------------
# Thin MCP session management (open/close return/accept a daemon `name`).
# ---------------------------------------------------------------------------


def open_kernel_session(
    client: McpStdioClient,
    connection: str,
    name: str | None,
    attach_timeout_secs: int,
    startup_command: str | None = None,
) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "mode": "kernel",
        "connection": connection,
        "attach_timeout_secs": attach_timeout_secs,
    }
    if name:
        arguments["name"] = name
    if startup_command:
        arguments["startup_command"] = startup_command

    print("opening kernel:", redact(connection))
    info = client.call_tool(
        "windbg_open_session",
        arguments,
        timeout_secs=attach_timeout_secs + 30,
    )
    print("opened:", json.dumps(info, ensure_ascii=False))
    return info


def open_user_launch_session(
    client: McpStdioClient,
    command_line: str,
    name: str | None,
    attach_timeout_secs: int,
    follow_children: bool = False,
    startup_command: str | None = None,
) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "mode": "launch",
        "command_line": command_line,
        "follow_children": follow_children,
        "attach_timeout_secs": attach_timeout_secs,
    }
    if name:
        arguments["name"] = name
    if startup_command:
        arguments["startup_command"] = startup_command

    print("launching user-mode debuggee:", command_line)
    info = client.call_tool(
        "windbg_open_session",
        arguments,
        timeout_secs=attach_timeout_secs + 30,
    )
    print("opened:", json.dumps(info, ensure_ascii=False))
    return info


def open_user_attach_session(
    client: McpStdioClient,
    pid: int,
    name: str | None,
    attach_timeout_secs: int,
    non_invasive: bool = False,
    startup_command: str | None = None,
) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "mode": "attach",
        "pid": pid,
        "non_invasive": non_invasive,
        "attach_timeout_secs": attach_timeout_secs,
    }
    if name:
        arguments["name"] = name
    if startup_command:
        arguments["startup_command"] = startup_command

    print("attaching to pid:", pid)
    info = client.call_tool(
        "windbg_open_session",
        arguments,
        timeout_secs=attach_timeout_secs + 30,
    )
    print("opened:", json.dumps(info, ensure_ascii=False))
    return info


def close_session(
    client: McpStdioClient,
    name: str,
    force: bool = False,
    label: str = "closed",
) -> dict[str, Any]:
    payload = client.call_tool(
        "windbg_close_session",
        {"name": name, "force": force},
        timeout_secs=30,
    )
    print(f"{label}:", json.dumps(payload, ensure_ascii=False))
    return payload


# ---------------------------------------------------------------------------
# CLI driver: run `windbg_cli do --name <name> <action>` for debugging.
# ---------------------------------------------------------------------------


class CliDriver:
    """Drive a daemon-backed session via the `windbg_cli do` observer CLI."""

    def __init__(self, name: str, cli: Path | None = None) -> None:
        self.name = name
        self.cli = cli or default_cli()

    def do(self, *action: str, timeout_secs: float = 120.0) -> subprocess.CompletedProcess:
        cmd = [str(self.cli), "do", "--name", self.name, *action]
        print("cli:", " ".join(cmd))
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_secs,
        )
        if proc.stdout.strip():
            print(proc.stdout.rstrip())
        if proc.returncode != 0 and proc.stderr.strip():
            print("stderr:", proc.stderr.rstrip())
        return proc

    def exec(self, command: str, timeout_secs: float = 120.0) -> subprocess.CompletedProcess:
        return self.do("exec", command, timeout_secs=timeout_secs)

    def state(self) -> subprocess.CompletedProcess:
        return self.do("state")
