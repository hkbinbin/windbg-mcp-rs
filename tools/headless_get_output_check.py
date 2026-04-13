#!/usr/bin/env python3
"""Check cursor-based windbg_get_output behavior against a live KDNET session."""

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
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="get-output-check")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--command", default="vertarget")
    parser.add_argument("--expect", default="Kernel Version")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("headless-get-output-check")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )
        ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)

        before = client.call_tool(
            "windbg_get_output",
            {"session_id": opened_session_id},
            timeout_secs=20,
        )
        cursor = before.get("next_cursor")
        print("cursor_before:", cursor)

        client.call_tool(
            "windbg_execute_command",
            {"session_id": opened_session_id, "command": args.command},
            timeout_secs=120,
        )

        after = client.call_tool(
            "windbg_get_output",
            {"session_id": opened_session_id, "cursor": cursor},
            timeout_secs=20,
        )
        entries = after.get("entries", [])
        print("entries_after:", len(entries), "next_cursor:", after.get("next_cursor"))
        joined = "\n".join(str(entry.get("text", "")) for entry in entries)
        if args.expect and args.expect not in joined:
            raise RuntimeError(
                f"expected output marker `{args.expect}` was not present in cursor delta"
            )

        close_kernel_session(client, opened_session_id, args.shutdown_timeout_secs)
        closed = True
        return 0
    finally:
        if opened_session_id and not closed:
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
