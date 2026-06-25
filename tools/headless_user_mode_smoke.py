#!/usr/bin/env python3
"""Smoke-test the thin WinDbg MCP server against a local user-mode binary.

Opens a debugger daemon via the MCP `windbg_open_session` tool (mode=launch or
mode=attach), then exercises a small batch of WinDbg commands through the
`windbg_cli do` observer CLI, and finally tears the daemon down via
`windbg_close_session`.

Example:

    python tools\\headless_user_mode_smoke.py \
        --target "C:\\Users\\theoou\\Downloads\\Crackme.exe"

Pass --skip-close to leave the daemon open for manual inspection.
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
    open_user_attach_session,
    open_user_launch_session,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exe",
        type=Path,
        default=default_exe(),
        help="Path to windbg_mcp_headless.exe (defaults to ../target/release)",
    )
    parser.add_argument(
        "--cli",
        type=Path,
        default=default_cli(),
        help="Path to windbg_cli.exe (defaults to ../target/release)",
    )
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument(
        "--target",
        type=Path,
        help="Path to a user-mode binary to spawn under the debugger",
    )
    target_group.add_argument(
        "--target-pid",
        type=int,
        help="PID of an already-running process to attach to",
    )
    parser.add_argument(
        "--target-args",
        default="",
        help="Optional argument string appended to the spawned command line",
    )
    parser.add_argument(
        "--name",
        default="user-smoke",
        help="Daemon name to assign",
    )
    parser.add_argument(
        "--attach-timeout-secs",
        type=int,
        default=30,
        help="Maximum time to wait for the initial attach",
    )
    parser.add_argument(
        "--non-invasive",
        action="store_true",
        help="When attaching to a PID, request a non-invasive attach",
    )
    parser.add_argument(
        "--follow-children",
        action="store_true",
        help="When launching, also debug child processes",
    )
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Raw WinDbg command to run via `do exec` after attach (repeatable). When omitted, a default suite is executed.",
    )
    parser.add_argument(
        "--skip-default-commands",
        action="store_true",
        help="Skip the built-in command suite even when no --command is given",
    )
    parser.add_argument(
        "--skip-close",
        action="store_true",
        help="Leave the daemon open for manual inspection",
    )
    return parser.parse_args()


def default_command_suite(target_label: str) -> list[str]:
    """Light-weight command suite suitable for any local user-mode debuggee."""
    return [
        ".lastevent",
        "vertarget",
        "|.",
        "lm m *",
        "r",
        "k",
        ".symfix",
        f".echo thin user-mode smoke target: {target_label}",
    ]


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe, forward_stderr=True)
    opened_name: str | None = None
    closed = False
    try:
        client.initialize("thin-user-mode-smoke")

        if args.target is not None:
            target_path = args.target.resolve()
            if not target_path.exists():
                print(f"target binary not found: {target_path}", file=sys.stderr)
                return 1
            command_line = str(target_path)
            if args.target_args:
                command_line = f"{command_line} {args.target_args}"
            info = open_user_launch_session(
                client,
                command_line=command_line,
                name=args.name,
                attach_timeout_secs=args.attach_timeout_secs,
                follow_children=args.follow_children,
            )
            target_label = str(target_path)
        else:
            info = open_user_attach_session(
                client,
                pid=int(args.target_pid),
                name=args.name,
                attach_timeout_secs=args.attach_timeout_secs,
                non_invasive=args.non_invasive,
            )
            target_label = f"pid:{args.target_pid}"

        opened_name = info["name"]
        driver = CliDriver(opened_name, cli=args.cli)
        driver.state()

        commands: list[str] = list(args.command)
        if not commands and not args.skip_default_commands:
            commands = default_command_suite(target_label)

        for command in commands:
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
