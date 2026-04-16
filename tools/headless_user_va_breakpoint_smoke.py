#!/usr/bin/env python3
"""Validate process-scoped user-VA breakpoints over a live KDNET MCP session.

Use this when you need to confirm that `/p <EPROCESS> <user_va>` style
breakpoints work for a user-mode process while attached through kernel debug.
The default path uses hardware execute breakpoints (`ba e 1`) because live
KDNET testing showed software `bp /p <EPROCESS> <user_va>` can create a
breakpoint ID without hitting reliably.
The script intentionally keeps KDNET secrets and guest credentials out of the
repository; pass connection strings and trigger commands at runtime.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from headless_mcp_lib import (
    McpStdioClient,
    close_kernel_session,
    default_exe,
    ensure_command_ready,
    open_kernel_session,
    query_state,
    state_name,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--session-id", default="user-va-breakpoint-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--ready-timeout-secs", type=int, default=60)
    parser.add_argument("--shutdown-timeout-secs", type=int, default=12)
    parser.add_argument("--hit-timeout-secs", type=int, default=30)
    parser.add_argument("--location", required=True, help="User VA or symbol, e.g. 00007ff6`12345678")
    parser.add_argument("--process-name", help="Target process image, e.g. challenge.exe")
    parser.add_argument("--pid", help="Target PID, decimal by default or 0x-prefixed hex")
    parser.add_argument("--eprocess", help="Known EPROCESS address. Skips !process resolution")
    parser.add_argument(
        "--persistent",
        action="store_false",
        dest="one_shot",
        default=True,
        help="Use a persistent breakpoint instead of the default one-shot breakpoint.",
    )
    parser.add_argument(
        "--software",
        action="store_true",
        help="Experiment with software `bp /p` instead of the default hardware execute breakpoint.",
    )
    parser.add_argument(
        "--trigger-command",
        help="Optional host-side command to start before waiting, such as ssh launching the guest app.",
    )
    return parser.parse_args()


def require_process_selector(args: argparse.Namespace) -> None:
    if not (args.process_name or args.pid or args.eprocess):
        raise SystemExit("provide --process-name, --pid, or --eprocess")


def main() -> int:
    args = parse_args()
    require_process_selector(args)

    client = McpStdioClient(args.exe)
    opened_session_id: str | None = None
    closed = False
    trigger: subprocess.Popen[str] | None = None
    try:
        client.initialize("headless-user-va-breakpoint-smoke")
        opened_session_id = open_kernel_session(
            client,
            args.connection,
            args.session_id,
            args.attach_timeout_secs,
        )

        state = ensure_command_ready(client, opened_session_id, args.ready_timeout_secs)
        print("ready:", state_name(state))

        if args.software:
            payload = client.call_tool(
                "windbg_set_process_breakpoint",
                {
                    "session_id": opened_session_id,
                    "location": args.location,
                    "process_name": args.process_name,
                    "pid": args.pid,
                    "eprocess": args.eprocess,
                    "kind": "bp",
                    "one_shot": args.one_shot,
                    "set_context": True,
                    "allow_user_software": True,
                },
                timeout_secs=180,
            )
            created = payload.get("created_breakpoints")
        else:
            payload = client.call_tool(
                "windbg_set_hardware_breakpoint",
                {
                    "session_id": opened_session_id,
                    "address": args.location,
                    "process_name": args.process_name,
                    "pid": args.pid,
                    "eprocess": args.eprocess,
                    "access": "execute",
                    "size": 1,
                    "set_context": True,
                },
                timeout_secs=180,
            )
            created = payload.get("created_breakpoints")
        process = payload.get("process", {})
        print(
            "set_user_va_breakpoint:",
            "mode=",
            "software" if args.software else "hardware",
            "eprocess=",
            process.get("eprocess"),
            "image=",
            process.get("image"),
            "location=",
            args.location,
            "created=",
            created,
        )

        if args.trigger_command:
            trigger = subprocess.Popen(args.trigger_command, shell=True, text=True)
            print("trigger_started:", args.trigger_command)

        hit = client.call_tool(
            "windbg_continue_until_break",
            {"session_id": opened_session_id, "timeout_secs": args.hit_timeout_secs},
            timeout_secs=args.hit_timeout_secs + 60,
        )
        print("hit_timed_out:", hit.get("timed_out"))
        if hit.get("timed_out"):
            raise RuntimeError("user-VA breakpoint did not hit before timeout")

        snapshot = client.call_tool(
            "windbg_breakpoint_snapshot",
            {"session_id": opened_session_id, "stack_count": 24, "disassemble_count": 16},
            timeout_secs=120,
        )
        print("snapshot_steps:", len(snapshot.get("steps", [])))

        client.call_tool(
            "windbg_clear_breakpoint",
            {"session_id": opened_session_id},
            timeout_secs=30,
        )
        close_kernel_session(client, opened_session_id, args.shutdown_timeout_secs)
        closed = True
        return 0
    finally:
        if trigger and trigger.poll() is None:
            trigger.terminate()
        if opened_session_id and not closed:
            try:
                state = query_state(client, opened_session_id)
                if not state.get("ready_for_commands"):
                    client.call_tool(
                        "windbg_interrupt_target",
                        {"session_id": opened_session_id},
                        timeout_secs=30,
                    )
                client.call_tool(
                    "windbg_clear_breakpoint",
                    {"session_id": opened_session_id},
                    timeout_secs=30,
                )
            except Exception as exc:
                print(f"user_va_breakpoint_cleanup_failed: {exc}", file=sys.stderr)
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
