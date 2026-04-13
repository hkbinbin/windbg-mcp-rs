#!/usr/bin/env python3
"""Run a reproducible ShadowGate-oriented headless KDNET validation."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from headless_mcp_lib import (
    McpStdioClient,
    close_kernel_session,
    default_exe,
    ensure_command_ready,
    open_kernel_session,
    print_command_result,
    query_state,
    state_name,
)


DEFAULT_COMMANDS = [
    ".lastevent",
    "lm m ShadowGate*",
    "bl",
    "~",
    "r rip",
    "k",
    "!process 0 0",
    "!drvobj ShadowGate 7",
]


LOAD_BREAK_COMMANDS = [
    ".lastevent",
    "lm m ShadowGate*",
    "lmv m ShadowGate*",
    "bl",
    "~",
    "r rip",
    "k",
    "!drvobj ShadowGate 7",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="shadowgate-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--guest", help="SSH target, for example administrator@<guest-ip>")
    parser.add_argument("--ssh", default="ssh", help="SSH executable")
    parser.add_argument("--ssh-timeout-secs", type=int, default=45)
    parser.add_argument("--service", default="ShadowGate")
    parser.add_argument("--driver-image", default="ShadowGateSys.sys")
    parser.add_argument("--probe-command", help="Optional guest-side probe command to run")
    parser.add_argument("--skip-guest-actions", action="store_true")
    parser.add_argument("--driver-load-break", action="store_true")
    parser.add_argument("--skip-prepare-symbols", action="store_true")
    parser.add_argument("--stop-service-after", action="store_true")
    parser.add_argument(
        "--command",
        action="append",
        default=[],
        help="Debugger command to run during inspection; overrides defaults when supplied",
    )
    return parser.parse_args()


def run_guest(args: argparse.Namespace, command: str, check: bool = True) -> None:
    if args.skip_guest_actions:
        print("guest_skip:", command)
        return
    if not args.guest:
        raise RuntimeError("--guest is required unless --skip-guest-actions is set")

    print("guest:", command)
    result = subprocess.run(
        [args.ssh, args.guest, command],
        timeout=args.ssh_timeout_secs,
        check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"guest command failed with exit code {result.returncode}: {command}")


def run_guest_async(args: argparse.Namespace, command: str) -> None:
    wrapped = (
        "powershell -NoProfile -WindowStyle Hidden -Command "
        f"\"Start-Process cmd.exe -WindowStyle Hidden -ArgumentList '/c {command}'\""
    )
    run_guest(args, wrapped)


def wait_for_break(
    client: McpStdioClient,
    session_id: str,
    timeout_secs: int,
) -> dict[str, Any]:
    deadline = time.time() + timeout_secs
    state: dict[str, Any] = {}
    while time.time() < deadline:
        state = query_state(client, session_id)
        if state.get("ready_for_commands"):
            return state
        time.sleep(1)
    raise RuntimeError(f"target did not break before timeout; last state={state_name(state)}")


def execute(client: McpStdioClient, session_id: str, command: str) -> None:
    result = client.call_tool(
        "windbg_execute_command",
        {"session_id": session_id, "command": command},
        timeout_secs=180,
    )
    print_command_result(command, result, max_chars=12000)


def prepare_extensions(client: McpStdioClient, session_id: str, skip_symbols: bool) -> None:
    if not skip_symbols:
        payload = client.call_tool(
            "windbg_prepare_symbols",
            {"session_id": session_id, "module": "nt"},
            timeout_secs=180,
        )
        print(
            "prepare_symbols:",
            payload.get("success"),
            payload.get("symbol_status"),
            payload.get("pdb", {}).get("local_path"),
        )
    execute(client, session_id, ".load kdexts")


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    try:
        client.initialize("shadowgate-smoke")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )
        ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
        prepare_extensions(client, opened_session_id, args.skip_prepare_symbols)

        commands = args.command or (
            LOAD_BREAK_COMMANDS if args.driver_load_break else DEFAULT_COMMANDS
        )

        if args.driver_load_break:
            run_guest(args, f"sc stop {args.service}", check=False)
            execute(client, opened_session_id, f"sxe ld:{args.driver_image}")
            client.call_tool(
                "windbg_resume_target",
                {"session_id": opened_session_id},
                timeout_secs=30,
            )
            run_guest_async(args, f"sc start {args.service}")
            state = wait_for_break(client, opened_session_id, args.ready_timeout_secs)
            print("load_break:", state_name(state))
        else:
            client.call_tool(
                "windbg_resume_target",
                {"session_id": opened_session_id},
                timeout_secs=30,
            )
            run_guest(args, f"sc start {args.service}", check=False)
            run_guest(args, f"sc query {args.service}", check=False)
            if args.probe_command:
                run_guest(args, args.probe_command)
            state = client.call_tool(
                "windbg_interrupt_target",
                {"session_id": opened_session_id},
                timeout_secs=args.ready_timeout_secs,
            ).get("state", {})
            print("interrupted:", state_name(state))

        for command in commands:
            execute(client, opened_session_id, command)

        client.call_tool(
            "windbg_resume_target",
            {"session_id": opened_session_id},
            timeout_secs=30,
        )

        if args.stop_service_after:
            time.sleep(2)
            run_guest(args, f"sc stop {args.service}", check=False)

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
