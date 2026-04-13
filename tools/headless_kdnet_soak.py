#!/usr/bin/env python3
"""Run a repeatable interrupt -> command -> resume soak against live KDNET."""

from __future__ import annotations

import argparse
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
    tcp_probe,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="kdnet-soak")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--delay-secs", type=float, default=10.0)
    parser.add_argument("--command", default="vertarget")
    parser.add_argument("--tcp-host", help="Optional host to probe after each resume")
    parser.add_argument("--tcp-port", type=int, default=22)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("headless-kdnet-soak")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )

        for index in range(1, args.iterations + 1):
            print(f"iteration: {index}/{args.iterations}")
            state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
            print("ready:", state_name(state))

            result = client.call_tool(
                "windbg_execute_command",
                {"session_id": opened_session_id, "command": args.command},
                timeout_secs=120,
            )
            print_command_result(args.command, result, max_chars=3000)

            resumed = client.call_tool(
                "windbg_resume_target",
                {"session_id": opened_session_id},
                timeout_secs=30,
            ).get("state", {})
            print("resumed:", state_name(resumed))

            if args.delay_secs > 0:
                time.sleep(args.delay_secs)

            state = query_state(client, opened_session_id)
            print("state_after_delay:", state_name(state))

            if args.tcp_host:
                reachable = tcp_probe(args.tcp_host, args.tcp_port)
                print(f"tcp_probe: {args.tcp_host}:{args.tcp_port} reachable={reachable}")
                if not reachable:
                    raise RuntimeError("TCP probe failed after resume")

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
