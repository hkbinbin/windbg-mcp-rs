#!/usr/bin/env python3
"""Validate process-scoped user-VA breakpoints over a thin-MCP daemon session.

Opens a kernel daemon via the MCP `windbg_open_session` tool, then sets a
process-scoped user-VA breakpoint through the `windbg_cli do` CLI. The default
path uses a hardware execute breakpoint (`ba e 1`) because live KDNET testing
showed software `bp /p <EPROCESS> <user_va>` can create a breakpoint ID without
hitting reliably.

You must supply --eprocess; resolve it via
`windbg_cli do exec "!process 0 0 <image>"`.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from headless_mcp_lib import (
    CliDriver,
    McpStdioClient,
    close_session,
    default_cli,
    default_exe,
    open_kernel_session,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--cli", type=Path, default=default_cli())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--name", default="user-va-breakpoint-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--hit-timeout-secs", type=int, default=30)
    parser.add_argument("--location", required=True, help="User VA or symbol, e.g. 00007ff6`12345678")
    parser.add_argument(
        "--eprocess",
        required=True,
        help="Target EPROCESS address for /p scoping (resolve via !process 0 0 <image>)",
    )
    parser.add_argument(
        "--software",
        action="store_true",
        help="Use software `bp /p` instead of the default hardware execute breakpoint.",
    )
    parser.add_argument(
        "--trigger-command",
        help="Optional host-side command to start before waiting.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    trigger: subprocess.Popen[str] | None = None
    try:
        client.initialize("thin-user-va-breakpoint-smoke")
        info = open_kernel_session(
            client,
            args.connection,
            args.name,
            args.attach_timeout_secs,
            startup_command=".symfix; .reload",
        )
        opened_name = info["name"]
        driver = CliDriver(opened_name, cli=args.cli)

        driver.do("interrupt")
        # Switch into the target process context, then set the breakpoint.
        driver.exec(f".process /i /p {args.eprocess}")
        if args.software:
            driver.exec(f"bp /p {args.eprocess} {args.location}")
        else:
            driver.do("ba", args.location, "--access", "e", "--size", "1")
        driver.do("bl")

        if args.trigger_command:
            trigger = subprocess.Popen(args.trigger_command, shell=True, text=True)
            print("trigger_started:", args.trigger_command)

        driver.do("go")
        wb = driver.do("wait-break", "--timeout-secs", str(args.hit_timeout_secs))
        if wb.returncode != 0:
            raise RuntimeError("user-VA breakpoint did not hit before timeout")
        driver.do("snapshot")

        driver.do("bc", "*")
        close_session(client, opened_name)
        closed = True
        return 0
    finally:
        if trigger and trigger.poll() is None:
            trigger.terminate()
        if opened_name and not closed:
            try:
                d = CliDriver(opened_name, cli=args.cli)
                d.do("interrupt")
                d.do("bc", "*")
            except Exception as exc:
                print(f"user_va_breakpoint_cleanup_failed: {exc}", file=sys.stderr)
            try:
                close_session(client, opened_name, force=True, label="closed_after_error")
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
