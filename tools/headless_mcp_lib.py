#!/usr/bin/env python3
"""Shared helpers for driving the headless WinDbg MCP server over stdio."""

from __future__ import annotations

import json
import re
import socket
import subprocess
import time
from pathlib import Path
from typing import Any


KEY_RE = re.compile(r"(key=)[^,\s\"]+", re.IGNORECASE)


def redact(value: str) -> str:
    return KEY_RE.sub(r"\1<redacted>", value)


def default_exe() -> Path:
    return (
        Path(__file__).resolve().parents[1]
        / "target"
        / "release"
        / "windbg_mcp_headless.exe"
    )


def tcp_probe(host: str, port: int, timeout_secs: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_secs):
            return True
    except OSError:
        return False


def print_command_result(command: str, result: dict[str, Any], max_chars: int | None = None) -> None:
    print(f"command: {command}")
    output = str(result.get("output", "")).rstrip()
    if max_chars is not None and len(output) > max_chars:
        output = output[:max_chars] + "\n... <truncated>"
    print(output)


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
        print("tools:", len(tool_names), "recover=", "windbg_recover_session" in tool_names)
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


def state_name(state: dict[str, Any]) -> str:
    return str(state.get("status_name") or "unknown")


def query_state(client: McpStdioClient, session_id: str) -> dict[str, Any]:
    payload = client.call_tool(
        "windbg_get_execution_state",
        {"session_id": session_id},
        timeout_secs=20,
    )
    return payload.get("state", {})


def wait_for_attached_state(
    client: McpStdioClient,
    session_id: str,
    timeout_secs: int,
) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    last_state: dict[str, Any] = {}
    while time.time() < deadline:
        last_state = query_state(client, session_id)
        if state_name(last_state) != "no_debuggee":
            return last_state
        time.sleep(1)

    return last_state


def ensure_command_ready(
    client: McpStdioClient,
    session_id: str,
    timeout_secs: int,
) -> dict[str, Any]:
    state = wait_for_attached_state(client, session_id, timeout_secs)
    if state.get("ready_for_commands"):
        return state

    if state.get("running"):
        print("interrupting:", state_name(state))
        payload = client.call_tool(
            "windbg_interrupt_target",
            {"session_id": session_id},
            timeout_secs=timeout_secs,
        )
        state = payload.get("state", {})

    deadline = time.time() + timeout_secs
    while not state.get("ready_for_commands") and time.time() < deadline:
        time.sleep(1)
        state = query_state(client, session_id)

    if not state.get("ready_for_commands"):
        raise RuntimeError(
            "session is not ready for commands "
            f"(status={state_name(state)}, raw={state.get('raw_status')})"
        )

    return state


def open_kernel_session(
    client: McpStdioClient,
    connection: str,
    session_id: str,
    attach_timeout_secs: int,
    startup_command: str | None = None,
) -> str:
    arguments: dict[str, Any] = {
        "connection": connection,
        "session_id": session_id,
        "attach_timeout_secs": attach_timeout_secs,
    }
    if startup_command:
        arguments["startup_command"] = startup_command

    print("opening:", redact(connection))
    session = client.call_tool(
        "windbg_open_session",
        arguments,
        timeout_secs=attach_timeout_secs + 20,
    )["session"]
    opened_session_id = session["session_id"]
    state = session.get("state") or {}
    print("opened:", opened_session_id, state_name(state))
    return opened_session_id


def close_kernel_session(
    client: McpStdioClient,
    session_id: str,
    shutdown_timeout_secs: int,
    resume_before_close: bool = True,
    label: str = "closed",
) -> dict[str, Any]:
    payload = client.call_tool(
        "windbg_close_session",
        {
            "session_id": session_id,
            "shutdown_timeout_secs": shutdown_timeout_secs,
            "resume_before_close": resume_before_close,
        },
        timeout_secs=shutdown_timeout_secs + 20,
    )
    print(f"{label}:", json.dumps(payload, ensure_ascii=False))
    return payload
