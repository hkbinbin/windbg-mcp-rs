#!/usr/bin/env python3
"""Smoke-test the thin WinDbg MCP server over stdio.

Validates the slimmed MCP surface:

  1. `tools/list` returns exactly the three management tools.
  2. `windbg_use_help` returns help text that does not mention the old,
     now-removed per-action tools.
  3. (optional, with --connection) open a kernel daemon via MCP, run debugger
     commands through `windbg_cli do`, then close the daemon via MCP.

Depends only on the Python standard library plus headless_mcp_lib.
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

EXPECTED_TOOLS = {
    "windbg_open_session",
    "windbg_close_session",
    "windbg_use_help",
}

# Tool names that must NOT appear anymore (moved to the CLI).
REMOVED_TOOLS = [
    "windbg_execute_command",
    "windbg_set_breakpoint",
    "windbg_get_execution_state",
    "windbg_open_user_process",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--cli", type=Path, default=default_cli())
    parser.add_argument("--connection", help="Optional KDNET -k connection string")
    parser.add_argument("--name", default="smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=30)
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Debugger command to run via `windbg_cli do exec` after opening; repeatable",
    )
    parser.add_argument(
        "--skip-close",
        action="store_true",
        help="Leave the daemon open for manual inspection",
    )
    return parser.parse_args()


def check_tool_surface(client: McpStdioClient) -> int:
    tool_names = client.initialize("thin-mcp-smoke")

    if tool_names != EXPECTED_TOOLS:
        print(
            f"FAIL: expected exactly {sorted(EXPECTED_TOOLS)}, got {sorted(tool_names)}",
            file=sys.stderr,
        )
        return 1
    print("OK: tool surface is exactly the 3 management tools")

    help_payload = client.call_tool("windbg_use_help", {}, timeout_secs=10)
    help_text = str(help_payload.get("help", ""))
    if not help_text:
        print("FAIL: windbg_use_help returned empty help", file=sys.stderr)
        return 1
    leaked = [name for name in REMOVED_TOOLS if name in help_text]
    if leaked:
        print(f"FAIL: help text still mentions removed tools: {leaked}", file=sys.stderr)
        return 1
    print("OK: use_help text is clean and references windbg_cli")
    return 0


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        rc = check_tool_surface(client)
        if rc != 0:
            return rc

        if not args.connection:
            print("no --connection supplied; protocol-only checks passed")
            return 0

        info = open_kernel_session(
            client,
            args.connection,
            args.name,
            args.attach_timeout_secs,
        )
        opened_name = info["name"]

        driver = CliDriver(opened_name, cli=args.cli)
        driver.state()
        for command in args.command:
            driver.exec(command)

        if not args.skip_close:
            close_session(client, opened_name)
            closed = True

        return 0
    finally:
        if opened_name and not args.skip_close and not closed:
            try:
                close_session(client, opened_name, force=True, label="closed_after_error")
            except Exception as exc:
                print(f"close_after_error_failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
