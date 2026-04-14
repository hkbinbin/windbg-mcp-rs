#!/usr/bin/env python3
"""Validate process-scoped syscall breakpoint setup over the headless MCP server.

The helper does not store KDNET secrets. Pass the connection string at runtime.
If --trigger-command is provided, the script resumes the target, starts that
host-side command, waits for a breakpoint hit, collects a snapshot, then clears
the breakpoints and closes the session.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from headless_mcp_lib import (
    McpStdioClient,
    close_kernel_session,
    default_exe,
    ensure_command_ready,
    open_kernel_session,
    print_command_result,
    query_state,
    state_name,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="syscall-breakpoint-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--hit-timeout-secs", type=int, default=30)
    parser.add_argument("--process-name", help="Target process image, for example ShadowGateApp.exe")
    parser.add_argument("--pid", help="Target PID, decimal by default or 0x-prefixed hex")
    parser.add_argument("--eprocess", help="Known EPROCESS address. Skips !process resolution")
    parser.add_argument(
        "--syscall",
        action="append",
        default=[],
        help="Syscall symbol to break on. Can be repeated. Defaults to NtCreateFile and NtDeviceIoControlFile.",
    )
    parser.add_argument(
        "--trigger-command",
        help="Optional host-side command to run after the target is resumed, such as an ssh command that launches the guest harness.",
    )
    return parser.parse_args()


def require_process_selector(args: argparse.Namespace) -> None:
    if not (args.process_name or args.pid or args.eprocess):
        raise SystemExit("provide --process-name, --pid, or --eprocess")


def wait_for_break(client: McpStdioClient, session_id: str, timeout_secs: int) -> dict[str, object]:
    deadline = time.time() + timeout_secs
    last_state: dict[str, object] = {}
    while time.time() < deadline:
        last_state = query_state(client, session_id)
        if last_state.get("ready_for_commands"):
            return last_state
        time.sleep(0.25)
    return last_state


def main() -> int:
    args = parse_args()
    require_process_selector(args)
    syscalls = args.syscall or ["NtCreateFile", "NtDeviceIoControlFile"]

    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("headless-syscall-breakpoint-smoke")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )

        state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
        print("ready:", state_name(state))

        for syscall in syscalls:
            payload = client.call_tool(
                "windbg_set_syscall_breakpoint",
                {
                    "session_id": opened_session_id,
                    "syscall": syscall,
                    "process_name": args.process_name,
                    "pid": args.pid,
                    "eprocess": args.eprocess,
                },
                timeout_secs=180,
            )
            process = payload.get("process", {})
            command = payload.get("breakpoint", {}).get("command", "")
            print(
                "set_syscall:",
                syscall,
                "eprocess=",
                process.get("eprocess"),
                "image=",
                process.get("image"),
                "command=",
                command,
            )

        breakpoints = client.call_tool(
            "windbg_list_breakpoints",
            {"session_id": opened_session_id},
            timeout_secs=30,
        )
        print_command_result("bl", breakpoints, max_chars=4000)

        if args.trigger_command:
            resumed = client.call_tool(
                "windbg_resume_target",
                {"session_id": opened_session_id},
                timeout_secs=30,
            ).get("state", {})
            print("resumed:", state_name(resumed))

            trigger = subprocess.Popen(args.trigger_command, shell=True)
            state = wait_for_break(client, opened_session_id, args.hit_timeout_secs)
            trigger.poll()
            if not state.get("ready_for_commands"):
                raise RuntimeError(
                    "syscall breakpoint was not hit before timeout "
                    f"(status={state_name(state)}, raw={state.get('raw_status')})"
                )

            print("hit:", state_name(state))
            snapshot = client.call_tool(
                "windbg_breakpoint_snapshot",
                {"session_id": opened_session_id, "stack_count": 16},
                timeout_secs=120,
            )
            print("snapshot_steps:", len(snapshot.get("steps", [])))

        client.call_tool(
            "windbg_clear_breakpoint",
            {"session_id": opened_session_id},
            timeout_secs=30,
        )
        close_kernel_session(client, opened_session_id, args.shutdown_timeout_secs)
        closed = True
        return 0
    finally:
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
                print(f"breakpoint_cleanup_failed: {exc}", file=sys.stderr)
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
