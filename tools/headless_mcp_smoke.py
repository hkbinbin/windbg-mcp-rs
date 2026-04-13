#!/usr/bin/env python3
"""Smoke-test the headless WinDbg MCP server over stdio.

This helper intentionally depends only on the Python standard library. It is
meant for local validation of the MCP protocol path and optional live KDNET
session operations without baking secrets into the repository.
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
    open_kernel_session,
    print_command_result,
    state_name,
    wait_for_attached_state,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", help="Optional KDNET -k connection string")
    parser.add_argument("--session-id", default="smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=30)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=5)
    parser.add_argument(
        "--ready-timeout-secs",
        type=int,
        default=60,
        help="How long to wait for a live session to become attached/command-ready",
    )
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
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("headless-mcp-smoke")

        if not args.connection:
            return 0

        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )

        if not args.command:
            state = wait_for_attached_state(client, opened_session_id, args.ready_timeout_secs)
            print("attached:", state_name(state))

        for command in args.command:
            state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
            print("ready:", state_name(state))
            result = client.call_tool(
                "windbg_execute_command",
                {"session_id": opened_session_id, "command": command},
                timeout_secs=120,
            )
            print_command_result(command, result)

        if not args.skip_close:
            close_kernel_session(
                client,
                opened_session_id,
                args.shutdown_timeout_secs,
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
                    label="closed_after_error",
                )
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
