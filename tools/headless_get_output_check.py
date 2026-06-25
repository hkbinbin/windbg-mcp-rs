#!/usr/bin/env python3
"""Check `windbg_cli do get-output`-style behavior against a live KDNET session.

With the thin MCP server, buffered-output cursors are a CLI concern. This script
opens a kernel daemon via MCP, runs a command through the CLI, and verifies the
command output contains an expected marker.
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
    parser.add_argument("--name", default="get-output-check")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--command", default="vertarget")
    parser.add_argument("--expect", default="Kernel Version")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        client.initialize("thin-get-output-check")
        info = open_kernel_session(
            client,
            args.connection,
            args.name,
            args.attach_timeout_secs,
        )
        opened_name = info["name"]
        driver = CliDriver(opened_name, cli=args.cli)

        driver.do("interrupt")
        proc = driver.exec(args.command)
        if args.expect and args.expect not in proc.stdout:
            raise RuntimeError(
                f"expected output marker `{args.expect}` was not present in `{args.command}` output"
            )
        print("OK: marker present")

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
