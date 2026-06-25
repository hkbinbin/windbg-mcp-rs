#!/usr/bin/env python3
"""Run a repeatable interrupt -> command -> resume soak against live KDNET.

Opens a kernel daemon via the thin MCP `windbg_open_session` tool, then drives
each iteration through the `windbg_cli do` observer CLI (interrupt, exec, go),
and finally closes the daemon via `windbg_close_session`.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from headless_mcp_lib import (
    CliDriver,
    McpStdioClient,
    close_session,
    default_cli,
    default_exe,
    open_kernel_session,
    tcp_probe,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--cli", type=Path, default=default_cli())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--name", default="kdnet-soak")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--delay-secs", type=float, default=10.0)
    parser.add_argument("--command", default="vertarget")
    parser.add_argument("--tcp-host", help="Optional host to probe after each resume")
    parser.add_argument("--tcp-port", type=int, default=22)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        client.initialize("thin-kdnet-soak")
        info = open_kernel_session(
            client,
            args.connection,
            args.name,
            args.attach_timeout_secs,
        )
        opened_name = info["name"]
        driver = CliDriver(opened_name, cli=args.cli)

        for index in range(1, args.iterations + 1):
            print(f"iteration: {index}/{args.iterations}")
            driver.do("interrupt")
            driver.exec(args.command)
            driver.do("go")

            if args.delay_secs > 0:
                time.sleep(args.delay_secs)

            driver.state()

            if args.tcp_host:
                reachable = tcp_probe(args.tcp_host, args.tcp_port)
                print(f"tcp_probe: {args.tcp_host}:{args.tcp_port} reachable={reachable}")
                if not reachable:
                    raise RuntimeError("TCP probe failed after resume")

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
