#!/usr/bin/env python3
"""Run a reproducible ShadowGate-oriented thin-MCP KDNET validation.

Opens a kernel daemon via the MCP `windbg_open_session` tool, then drives all
debugger inspection through the `windbg_cli do` CLI (exec/go/interrupt/
wait-break), coordinating optional guest-side service actions over SSH.
"""

from __future__ import annotations

import argparse
import subprocess
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
    parser.add_argument("--cli", type=Path, default=default_cli())
    parser.add_argument("--connection", required=True, help="KDNET -k connection string")
    parser.add_argument("--name", default="shadowgate-smoke")
    parser.add_argument("--attach-timeout-secs", type=int, default=60)
    parser.add_argument("--hit-timeout-secs", type=int, default=60)
    parser.add_argument("--guest", help="SSH target, for example administrator@<guest-ip>")
    parser.add_argument("--ssh", default="ssh", help="SSH executable")
    parser.add_argument("--ssh-timeout-secs", type=int, default=45)
    parser.add_argument("--service", default="ShadowGate")
    parser.add_argument("--driver-image", default="ShadowGateSys.sys")
    parser.add_argument("--probe-command", help="Optional guest-side probe command to run")
    parser.add_argument("--skip-guest-actions", action="store_true")
    parser.add_argument("--driver-load-break", action="store_true")
    parser.add_argument("--skip-symfix", action="store_true")
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


def main() -> int:
    args = parse_args()
    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        client.initialize("shadowgate-smoke")
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
        driver.exec(".load kdexts")

        commands = args.command or (
            LOAD_BREAK_COMMANDS if args.driver_load_break else DEFAULT_COMMANDS
        )

        if args.driver_load_break:
            run_guest(args, f"sc stop {args.service}", check=False)
            driver.exec(f"sxe ld:{args.driver_image}")
            driver.do("go")
            run_guest_async(args, f"sc start {args.service}")
            wb = driver.do("wait-break", "--timeout-secs", str(args.hit_timeout_secs))
            if wb.returncode != 0:
                raise RuntimeError("driver load break did not fire before timeout")
            print("load_break: hit")
        else:
            driver.do("go")
            run_guest(args, f"sc start {args.service}", check=False)
            run_guest(args, f"sc query {args.service}", check=False)
            if args.probe_command:
                run_guest(args, args.probe_command)
            driver.do("interrupt")

        for command in commands:
            driver.exec(command, timeout_secs=180)

        driver.do("go")

        if args.stop_service_after:
            time.sleep(2)
            run_guest(args, f"sc stop {args.service}", check=False)

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
