#!/usr/bin/env python3
"""Validate extension-backed commands in a live headless KDNET MCP session."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from headless_mcp_lib import (
    McpStdioClient,
    close_kernel_session,
    default_exe,
    ensure_command_ready,
    open_kernel_session,
    print_command_result,
    state_name,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="extension-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--module", default="nt", help="Module to prepare symbols for")
    parser.add_argument("--symbol-cache", help="Optional symbol cache directory")
    parser.add_argument("--symbol-server", help="Optional symbol server URL")
    parser.add_argument(
        "--skip-prepare-symbols",
        action="store_true",
        help="Skip windbg_prepare_symbols and use the session's existing symbol path",
    )
    parser.add_argument(
        "--skip-diagnose",
        action="store_true",
        help="Skip windbg_diagnose_extensions after symbol preparation",
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


def prepare_symbols(client: McpStdioClient, session_id: str, args: argparse.Namespace) -> None:
    if args.skip_prepare_symbols:
        return

    arguments: dict[str, object] = {
        "session_id": session_id,
        "module": args.module,
    }
    if args.symbol_cache:
        arguments["symbol_cache"] = args.symbol_cache
    if args.symbol_server:
        arguments["symbol_server"] = args.symbol_server

    payload = client.call_tool("windbg_prepare_symbols", arguments, timeout_secs=180)
    print(
        "prepare_symbols:",
        json.dumps(
            {
                "success": payload.get("success"),
                "module": payload.get("module"),
                "symbol_status": payload.get("symbol_status"),
                "pdb": payload.get("pdb", {}).get("local_path"),
            },
            ensure_ascii=False,
        ),
    )
    if not payload.get("success"):
        raise RuntimeError("windbg_prepare_symbols did not load full PDB symbols")


def diagnose_extensions(
    client: McpStdioClient,
    session_id: str,
    probe_command: str,
    args: argparse.Namespace,
) -> None:
    if args.skip_diagnose:
        return

    payload = client.call_tool(
        "windbg_diagnose_extensions",
        {
            "session_id": session_id,
            "extension": "kdexts",
            "probe_command": probe_command,
            "module": args.module,
            "prepare_symbols": False,
        },
        timeout_secs=180,
    )
    print(
        "diagnose_extensions:",
        json.dumps(
            {
                "extension_loaded": payload.get("extension_loaded"),
                "symbol_problem": payload.get("symbol_problem"),
                "recommendations": payload.get("recommendations"),
            },
            ensure_ascii=False,
        ),
    )
    if not payload.get("extension_loaded"):
        raise RuntimeError("windbg_diagnose_extensions did not observe the extension in .chain")


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("headless-extension-smoke")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )
        state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
        print("ready:", state_name(state))

        prepare_symbols(client, opened_session_id, args)

        commands = list(args.command) or ["!process 0 0"]
        if args.drvobj:
            commands.append(f"!drvobj {args.drvobj} 7")

        diagnose_extensions(client, opened_session_id, commands[0], args)

        for command in [".load kdexts", ".chain", *commands]:
            result = client.call_tool(
                "windbg_execute_command",
                {"session_id": opened_session_id, "command": command},
                timeout_secs=180,
            )
            print_command_result(command, result, max_chars=12000)

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
