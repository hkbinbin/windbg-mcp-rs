#!/usr/bin/env python3
"""Validate MCP-driven breakpoint tracing over the headless WinDbg MCP server.

This helper avoids WinDbg command-breakpoint strings such as
`bp addr ".echo ...; r; g"`. Instead it calls `windbg_trace_breakpoint`, which
sets the breakpoint, resumes the target, waits for a stable hit, runs capture
commands synchronously through MCP, and then optionally clears/resumes.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from headless_mcp_lib import (
    McpStdioClient,
    close_kernel_session,
    default_exe,
    ensure_command_ready,
    open_kernel_session,
    query_state,
    state_name,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="trace-breakpoint-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--hit-timeout-secs", type=int, default=30)
    parser.add_argument("--location", required=True, help="Breakpoint location or address")
    parser.add_argument("--kind", default="bp", help="Software breakpoint kind: bp, bu, or bm")
    parser.add_argument("--hardware", action="store_true", help="Use hardware `ba` instead of software `bp`")
    parser.add_argument("--access", default="execute", help="Hardware access: execute/read/write/io")
    parser.add_argument("--size", type=int, default=1, help="Hardware breakpoint size")
    parser.add_argument("--process-name", help="Optional process image for /p scoping")
    parser.add_argument("--pid", help="Optional PID for /p scoping")
    parser.add_argument("--eprocess", help="Optional EPROCESS for /p scoping")
    parser.add_argument("--ethread", help="Optional ETHREAD for /t scoping")
    parser.add_argument("--hits", type=int, default=1)
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Extra debugger command to run at each stable hit. Can be repeated.",
    )
    parser.add_argument("--no-default-snapshot", action="store_true")
    parser.add_argument("--no-auto-resume", action="store_true")
    parser.add_argument("--keep-breakpoint", action="store_true")
    parser.add_argument(
        "--trigger-command",
        help="Optional host-side command to start before tracing, e.g. an ssh command that launches the guest workload.",
    )
    return parser.parse_args()


def compact_trace_summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "breakpoint_command": payload.get("breakpoint_command"),
        "created_breakpoints": payload.get("created_breakpoints"),
        "requested_hits": payload.get("requested_hits"),
        "captured_hits": payload.get("captured_hits"),
        "timed_out": payload.get("timed_out"),
        "auto_resume": payload.get("auto_resume"),
        "clear_after": payload.get("clear_after"),
        "final_resume": payload.get("final_resume"),
    }


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    trigger: subprocess.Popen[str] | None = None
    try:
        client.initialize("headless-trace-breakpoint-smoke")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )

        state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
        print("ready:", state_name(state))

        if args.trigger_command:
            trigger = subprocess.Popen(args.trigger_command, shell=True, text=True)
            print("trigger_started:", args.trigger_command)

        payload = client.call_tool(
            "windbg_trace_breakpoint",
            {
                "session_id": opened_session_id,
                "location": args.location,
                "kind": args.kind,
                "hardware": args.hardware,
                "access": args.access,
                "size": args.size,
                "process_name": args.process_name,
                "pid": args.pid,
                "eprocess": args.eprocess,
                "ethread": args.ethread,
                "hits": args.hits,
                "timeout_secs": args.hit_timeout_secs,
                "commands": args.command,
                "include_default_snapshot": not args.no_default_snapshot,
                "auto_resume": not args.no_auto_resume,
                "clear_after": not args.keep_breakpoint,
            },
            timeout_secs=args.hit_timeout_secs * max(args.hits, 1) + 180,
        )
        print("trace_summary:", json.dumps(compact_trace_summary(payload), ensure_ascii=False))
        print("hit_count:", len(payload.get("hits", [])))
        for hit in payload.get("hits", []):
            print(
                "hit:",
                hit.get("index"),
                "timed_out=",
                hit.get("timed_out"),
                "steps=",
                len(hit.get("steps", [])),
            )

        if trigger:
            try:
                trigger.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("trigger_still_running")

        close_kernel_session(client, opened_session_id, args.shutdown_timeout_secs)
        closed = True
        return 0
    finally:
        if trigger and trigger.poll() is None:
            trigger.terminate()
        if opened_session_id and not closed:
            try:
                state = query_state(client, opened_session_id)
                if not state.get("ready_for_commands"):
                    client.call_tool(
                        "windbg_interrupt_target",
                        {"session_id": opened_session_id},
                        timeout_secs=30,
                    )
                client.call_tool(
                    "windbg_clear_breakpoint",
                    {"session_id": opened_session_id},
                    timeout_secs=30,
                )
            except Exception as exc:
                print(f"trace_cleanup_failed: {exc}", file=sys.stderr)
            try:
                close_kernel_session(
                    client,
                    opened_session_id,
                    args.shutdown_timeout_secs,
                    label="closed_after_error",
                )
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
