#!/usr/bin/env python3
"""Validate breakpoint tracing over a thin-MCP daemon via the windbg_cli CLI.

Opens a kernel daemon via the MCP `windbg_open_session` tool, sets a breakpoint
through the `windbg_cli do` CLI (`bp`/`ba`), resumes, waits for a hit, captures
a snapshot, then clears the breakpoint and closes the daemon.
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
    parser.add_argument("--name", default="trace-breakpoint-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--hit-timeout-secs", type=int, default=30)
    parser.add_argument("--location", required=True, help="Breakpoint location or address")
    parser.add_argument("--hardware", action="store_true", help="Use hardware `ba` instead of software `bp`")
    parser.add_argument("--access", default="e", help="Hardware access: e/r/w/io")
    parser.add_argument("--size", type=int, default=1, help="Hardware breakpoint size")
    parser.add_argument("--hits", type=int, default=1)
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Extra raw command to run at each hit (repeatable).",
    )
    parser.add_argument("--keep-breakpoint", action="store_true")
    parser.add_argument(
        "--trigger-command",
        help="Optional host-side command to start before tracing.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    trigger: subprocess.Popen[str] | None = None
    try:
        client.initialize("thin-trace-breakpoint-smoke")
        info = open_kernel_session(
            client,
            args.connection,
            args.name,
            args.attach_timeout_secs,
        )
        opened_name = info["name"]
        driver = CliDriver(opened_name, cli=args.cli)

        driver.do("interrupt")
        if args.hardware:
            driver.do("ba", args.location, "--access", args.access, "--size", str(args.size))
        else:
            driver.do("bp", args.location)
        driver.do("bl")

        if args.trigger_command:
            trigger = subprocess.Popen(args.trigger_command, shell=True, text=True)
            print("trigger_started:", args.trigger_command)

        for index in range(1, max(args.hits, 1) + 1):
            driver.do("go")
            wb = driver.do("wait-break", "--timeout-secs", str(args.hit_timeout_secs))
            if wb.returncode != 0:
                raise RuntimeError(f"breakpoint was not hit before timeout (hit #{index})")
            print(f"hit: {index}")
            driver.do("snapshot")
            for command in args.command:
                driver.exec(command)

        if trigger:
            try:
                trigger.wait(timeout=10)
            except subprocess.TimeoutExpired:
                print("trigger_still_running")

        if not args.keep_breakpoint:
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
                print(f"trace_cleanup_failed: {exc}", file=sys.stderr)
            try:
                close_session(client, opened_name, force=True, label="closed_after_error")
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
