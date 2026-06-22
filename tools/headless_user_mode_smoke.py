#!/usr/bin/env python3
"""Smoke-test the headless WinDbg MCP server against a local user-mode binary.

This verifies the new `windbg_open_user_process` MCP tool by either spawning a
debuggee binary (default: a user-supplied .exe such as Crackme.exe) or
attaching to an existing PID, then exercising a small batch of standard
WinDbg commands and tearing the session down.

Example:

    python tools\\headless_user_mode_smoke.py \
        --target "C:\\Users\\theoou\\Downloads\\Crackme.exe"

Pass --skip-close to leave the session open for manual MCP inspection.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from headless_mcp_lib import (
    McpStdioClient,
    close_kernel_session,
    default_exe,
    ensure_command_ready,
    open_user_attach_session,
    open_user_launch_session,
    print_command_result,
    state_name,
    wait_for_attached_state,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exe",
        type=Path,
        default=default_exe(),
        help="Path to windbg_mcp_headless.exe (defaults to ../target/release)",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        type=Path,
        help="Path to a user-mode binary to spawn under the debugger",
    )
    target_group.add_argument(
        "--target-pid",
        type=int,
        help="PID of an already-running process to attach to",
    )
    parser.add_argument(
        "--target-args",
        default="",
        help="Optional argument string appended to the spawned command line",
    )
    parser.add_argument(
        "--session-id",
        default="user-smoke",
        help="Logical session id to assign",
    )
    parser.add_argument(
        "--attach-timeout-secs",
        type=int,
        default=30,
        help="Maximum time to wait for the initial attach",
    )
    parser.add_argument(
        "--ready-timeout-secs",
        type=int,
        default=30,
        help="Maximum time to wait for command-ready state after attach",
    )
    parser.add_argument(
        "--shutdown-timeout-secs",
        type=int,
        default=10,
        help="How long to wait for `windbg_close_session`",
    )
    parser.add_argument(
        "--non-invasive",
        action="store_true",
        help="When attaching to a PID, request a non-invasive attach",
    )
    parser.add_argument(
        "--terminate-on-exit",
        action="store_true",
        help="Terminate the debuggee on session close instead of detaching",
    )
    parser.add_argument(
        "--follow-children",
        action="store_true",
        help="When launching, also debug child processes",
    )
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Optional debugger command to run after attach (repeatable). When omitted, a default suite is executed.",
    )
    parser.add_argument(
        "--skip-default-commands",
        action="store_true",
        help="Skip the built-in command suite even when no --command is given",
    )
    parser.add_argument(
        "--skip-close",
        action="store_true",
        help="Leave the session open for manual MCP inspection",
    )
    return parser.parse_args()


def default_command_suite(target_label: str) -> list[str]:
    """Light-weight command suite suitable for any local user-mode debuggee."""
    return [
        ".lastevent",
        "vertarget",
        "|.",
        "lm m *",
        "r",
        "k",
        ".symfix",
        f".echo headless user-mode smoke target: {target_label}",
    ]


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe, forward_stderr=True)
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("headless-user-mode-smoke")

        if args.target is not None:
            target_path = args.target.resolve()
            if not target_path.exists():
                print(f"target binary not found: {target_path}", file=sys.stderr)
                return 1
            command_line = f'"{target_path}"'
            if args.target_args:
                command_line = f"{command_line} {args.target_args}"
            opened_session_id = open_user_launch_session(
                client,
                command_line=command_line,
                session_id=args.session_id,
                attach_timeout_secs=args.attach_timeout_secs,
                only_this_process=not args.follow_children,
                detach_on_exit=not args.terminate_on_exit,
            )
            target_label = str(target_path)
        else:
            opened_session_id = open_user_attach_session(
                client,
                pid=int(args.target_pid),
                session_id=args.session_id,
                attach_timeout_secs=args.attach_timeout_secs,
                non_invasive=args.non_invasive,
                detach_on_exit=not args.terminate_on_exit,
            )
            target_label = f"pid:{args.target_pid}"

        state = wait_for_attached_state(client, opened_session_id, args.ready_timeout_secs)
        print("attached:", state_name(state))

        commands: list[str] = list(args.command)
        if not commands and not args.skip_default_commands:
            commands = default_command_suite(target_label)

        for command in commands:
            state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
            print("ready:", state_name(state))
            result = client.call_tool(
                "windbg_execute_command",
                {"session_id": opened_session_id, "command": command},
                timeout_secs=120,
            )
            print_command_result(command, result, max_chars=4000)

        if not args.skip_close:
            close_kernel_session(
                client,
                opened_session_id,
                args.shutdown_timeout_secs,
                resume_before_close=False,
            )
            closed = True

        return 0
    finally:
        if opened_session_id and not args.skip_close and not closed:
            try:
                close_kernel_session(
                    client,
                    opened_session_id,
                    args.shutdown_timeout_secs,
                    resume_before_close=False,
                    label="closed_after_error",
                )
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
