#!/usr/bin/env python3
"""Validate extension-backed commands in a live headless KDNET daemon session.

Opens a kernel daemon via the thin MCP `windbg_open_session` tool, then drives
symbol preparation and extension commands through the `windbg_cli do exec`
observer CLI, and closes the daemon via `windbg_close_session`.
"""

from __future__ import annotations

import argparse
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
    parser.add_argument("--name", default="extension-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument(
        "--skip-symfix",
        action="store_true",
        help="Skip the `.symfix; .reload` symbol preparation step",
    )
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Extension-backed command to execute; defaults to !process 0 0",
    )
    parser.add_argument(
        "--drvobj",
        help="Append a !drvobj <name> 7 command, for example ShadowGate",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        client.initialize("thin-extension-smoke")
        info = open_kernel_session(
            client,
            args.connection,
            args.name,
            args.attach_timeout_secs,
            startup_command=None if args.skip_symfix else ".symfix; .reload",
        )
        opened_name = info["name"]
        driver = CliDriver(opened_name, cli=args.cli)

        driver.do("interrupt")

        commands = list(args.command) or ["!process 0 0"]
        if args.drvobj:
            commands.append(f"!drvobj {args.drvobj} 7")

        for command in [".load kdexts", ".chain", *commands]:
            driver.exec(command, timeout_secs=180)

        close_session(client, opened_name)
        closed = True
        return 0
    finally:
        if opened_name and not closed:
            try:
                close_session(client, opened_name, force=True, label="closed_after_error")
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
