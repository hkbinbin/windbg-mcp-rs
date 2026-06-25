#!/usr/bin/env python3
"""Validate process-scoped syscall breakpoint setup over a thin-MCP daemon.

Opens a kernel daemon via the MCP `windbg_open_session` tool, then sets syscall
breakpoints scoped to a process through the `windbg_cli do` CLI (`bp /p
<EPROCESS> nt!<Syscall>`), optionally triggers a host-side workload, waits for a
hit, captures a snapshot, clears breakpoints, and closes the daemon.

You must supply --eprocess (the thin server no longer resolves a process for
you); obtain it via `windbg_cli do exec "!process 0 0 <image>"`.
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
    parser.add_argument("--name", default="syscall-breakpoint-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--hit-timeout-secs", type=int, default=30)
    parser.add_argument(
        "--eprocess",
        required=True,
        help="Target EPROCESS address for /p scoping (resolve via !process 0 0 <image>)",
    )
    parser.add_argument(
        "--syscall",
        action="append",
        default=[],
        help="Syscall symbol to break on (repeatable). Defaults to NtCreateFile and NtDeviceIoControlFile.",
    )
    parser.add_argument(
        "--trigger-command",
        help="Optional host-side command to run after the target is resumed.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    syscalls = args.syscall or ["NtCreateFile", "NtDeviceIoControlFile"]

    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        client.initialize("thin-syscall-breakpoint-smoke")
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
        for syscall in syscalls:
            driver.exec(f"bp /p {args.eprocess} nt!{syscall}")
        driver.do("bl")

        if args.trigger_command:
            driver.do("go")
            subprocess.Popen(args.trigger_command, shell=True)
            wb = driver.do("wait-break", "--timeout-secs", str(args.hit_timeout_secs))
            if wb.returncode != 0:
                raise RuntimeError("syscall breakpoint was not hit before timeout")
            driver.do("snapshot")

        driver.do("bc", "*")
        close_session(client, opened_name)
        closed = True
        return 0
    finally:
        if opened_name and not closed:
            try:
                d = CliDriver(opened_name, cli=args.cli)
                d.do("interrupt")
                d.do("bc", "*")
            except Exception as exc:
                print(f"breakpoint_cleanup_failed: {exc}", file=sys.stderr)
            try:
                close_session(client, opened_name, force=True, label="closed_after_error")
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
