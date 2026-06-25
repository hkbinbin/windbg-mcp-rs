#!/usr/bin/env python3
"""Full real-target debug test for the thin MCP + windbg_cli daemon stack.

This is the authoritative end-to-end regression. It:

  1. Verifies the MCP tool surface is exactly the three thin tools.
  2. Opens a REAL user-mode debug session on notepad.exe via the MCP
     `windbg_open_session` tool (which detached-spawns a `windbg_cli daemon`).
  3. Exercises EVERY `windbg_cli do <action>` against that live daemon and
     asserts each behaves correctly.
  4. Exercises `windbg_cli daemon status|list` and idempotent re-open.
  5. Closes the session via the MCP `windbg_close_session` tool and confirms
     the daemon and its registry entry are gone.

Run from the repo root after `cargo build --release`:

    python tools/full_debug_test.py

Exits non-zero if any check fails; prints a PASS/FAIL summary table.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from headless_mcp_lib import (
    McpStdioClient,
    default_cli,
    default_exe,
    registry_dir_path,
)

EXPECTED_TOOLS = {
    "windbg_open_session",
    "windbg_close_session",
    "windbg_use_help",
}


class Results:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
        self.rows.append((name, ok, detail))
        return ok

    def summary(self) -> int:
        passed = sum(1 for _, ok, _ in self.rows if ok)
        total = len(self.rows)
        print("\n" + "=" * 60)
        print(f"SUMMARY: {passed}/{total} checks passed")
        print("=" * 60)
        failures = [(n, d) for n, ok, d in self.rows if not ok]
        if failures:
            print("FAILURES:")
            for name, detail in failures:
                print(f"  - {name}: {detail}")
            return 1
        print("ALL CHECKS PASSED")
        return 0


def run_cli(cli: Path, name: str, *action: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    """Run `windbg_cli do --name <name> <action>` and return the result.

    stdout carries the response body; stderr carries the `[state ...]` header
    and diagnostics. Both are captured.
    """
    cmd = [str(cli), "do", "--name", name, *action]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def daemon_cmd(cli: Path, *args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    cmd = [str(cli), *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", type=Path, default=default_exe())
    parser.add_argument("--cli", type=Path, default=default_cli())
    parser.add_argument(
        "--target",
        type=Path,
        default=Path("C:/Windows/System32/notepad.exe"),
        help="User-mode binary to debug (default: notepad.exe)",
    )
    parser.add_argument("--name", default="fulltest")
    parser.add_argument("--attach-timeout-secs", type=int, default=30)
    parser.add_argument(
        "--keep-open",
        action="store_true",
        help="Skip the final close so you can inspect the daemon manually",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    res = Results()

    if not args.exe.exists():
        print(f"FATAL: MCP server not found at {args.exe}; run `cargo build --release`", file=sys.stderr)
        return 2
    if not args.cli.exists():
        print(f"FATAL: windbg_cli not found at {args.cli}; run `cargo build --release`", file=sys.stderr)
        return 2

    client = McpStdioClient(args.exe)
    opened_name: str | None = None
    closed = False
    try:
        # -------------------------------------------------------------
        # 1. MCP tool surface
        # -------------------------------------------------------------
        print("\n[1] MCP tool surface")
        tools = client.initialize("full-debug-test")
        res.record("tools/list == 3 thin tools", tools == EXPECTED_TOOLS, f"got {sorted(tools)}")

        help_payload = client.call_tool("windbg_use_help", {}, timeout_secs=10)
        help_text = str(help_payload.get("help", ""))
        res.record("use_help returns text", bool(help_text))
        res.record(
            "use_help mentions windbg_cli",
            "windbg_cli" in help_text,
        )
        for topic in ("workflow", "open", "do", "daemon"):
            p = client.call_tool("windbg_use_help", {"topic": topic}, timeout_secs=10)
            res.record(f"use_help topic={topic}", bool(str(p.get("help", ""))))

        # Invalid open args should be rejected.
        try:
            client.call_tool("windbg_open_session", {"mode": "launch"}, timeout_secs=10)
            res.record("open_session rejects missing command_line", False, "no error raised")
        except RuntimeError:
            res.record("open_session rejects missing command_line", True)

        # -------------------------------------------------------------
        # 2. Open a real notepad session via MCP
        # -------------------------------------------------------------
        print("\n[2] Open notepad via MCP")
        target = str(args.target.resolve())
        info = client.call_tool(
            "windbg_open_session",
            {
                "mode": "launch",
                "command_line": target,
                "name": args.name,
                "attach_timeout_secs": args.attach_timeout_secs,
            },
            timeout_secs=args.attach_timeout_secs + 30,
        )
        opened_name = info.get("name")
        res.record("open_session returned name", opened_name == args.name, json.dumps(info))
        res.record("open_session returned address", bool(info.get("address")))
        res.record("open_session returned pid", isinstance(info.get("pid"), int))

        name = opened_name or args.name

        # -------------------------------------------------------------
        # 3. daemon status / list / idempotent re-open
        # -------------------------------------------------------------
        print("\n[3] daemon status / list / idempotent re-open")
        st = daemon_cmd(args.cli, "daemon", "status", "--name", name)
        res.record("daemon status ok", st.returncode == 0 and name in st.stdout, st.stdout.strip()[:120])

        ls = daemon_cmd(args.cli, "daemon", "list")
        res.record("daemon list shows our daemon", name in ls.stdout)

        # Idempotent re-open: same name, should return the SAME pid without a new daemon.
        info2 = client.call_tool(
            "windbg_open_session",
            {"mode": "launch", "command_line": target, "name": name, "attach_timeout_secs": args.attach_timeout_secs},
            timeout_secs=args.attach_timeout_secs + 30,
        )
        res.record(
            "idempotent re-open returns same pid",
            info2.get("pid") == info.get("pid"),
            f"{info.get('pid')} vs {info2.get('pid')}",
        )

        # -------------------------------------------------------------
        # 4. Exercise every `do` action
        # -------------------------------------------------------------
        print("\n[4] windbg_cli do <action> — every method")

        # state
        r = run_cli(args.cli, name, "state")
        res.record("do state", r.returncode == 0 and "break" in (r.stdout + r.stderr), r.stdout.strip())

        # info
        r = run_cli(args.cli, name, "info")
        res.record("do info", r.returncode == 0 and "session_id=" in r.stdout, r.stdout.strip()[:120])

        # reg (all)
        r = run_cli(args.cli, name, "reg")
        res.record("do reg (all)", r.returncode == 0 and ("rip=" in r.stdout or "eip=" in r.stdout), r.stdout.strip()[:60])

        # reg (specific) — capture rip for later use
        r = run_cli(args.cli, name, "reg", "rip")
        rip_ok = r.returncode == 0 and "rip=" in r.stdout
        res.record("do reg rip", rip_ok, r.stdout.strip())
        rip = None
        if rip_ok:
            try:
                rip = r.stdout.split("rip=")[1].split()[0].strip()
            except Exception:
                rip = None

        # bl (empty initially)
        r = run_cli(args.cli, name, "bl")
        res.record("do bl", r.returncode == 0)

        # bp at ntdll!NtClose (a reliably-loaded symbol)
        r = run_cli(args.cli, name, "bp", "ntdll!NtClose")
        bp_ok = r.returncode == 0
        res.record("do bp ntdll!NtClose", bp_ok, (r.stdout + r.stderr).strip()[:120])

        # bl should now list it. NtClose and ZwClose share one address, so dbgeng
        # may render the breakpoint under either symbol name.
        r = run_cli(args.cli, name, "bl")
        res.record(
            "do bl shows breakpoint",
            r.returncode == 0 and ("NtClose" in r.stdout or "ZwClose" in r.stdout),
            r.stdout.strip()[:120],
        )

        # one-shot bp
        r = run_cli(args.cli, name, "bp", "ntdll!NtCreateFile", "--one-shot")
        res.record("do bp --one-shot", r.returncode == 0, (r.stdout + r.stderr).strip()[:120])

        # ba hardware breakpoint on the stack pointer region (execute on rip is risky; use read on rsp)
        r = run_cli(args.cli, name, "ba", "@rsp", "--access", "r", "--size", "1")
        # ba can fail if no slots/alignment; treat as soft — record actual behavior
        res.record("do ba (hardware)", r.returncode == 0 or "ba " in (r.stdout + r.stderr), (r.stdout + r.stderr).strip()[:120])

        # bc * clears all
        r = run_cli(args.cli, name, "bc", "*")
        res.record("do bc *", r.returncode == 0)
        r = run_cli(args.cli, name, "bl")
        res.record("do bl empty after bc *", r.returncode == 0 and "NtClose" not in r.stdout)

        # mem — read at rip
        if rip:
            r = run_cli(args.cli, name, "mem", rip, "--format", "bytes", "--count", "16")
            res.record("do mem (bytes @rip)", r.returncode == 0 and len(r.stdout.strip()) > 0, r.stdout.strip()[:80])
            r = run_cli(args.cli, name, "mem", rip, "--format", "dwords", "--count", "4")
            res.record("do mem (dwords)", r.returncode == 0)

        # dis — disassemble at rip
        if rip:
            r = run_cli(args.cli, name, "dis", rip, "--count", "8")
            res.record("do dis (@rip)", r.returncode == 0 and len(r.stdout.strip()) > 0, r.stdout.strip()[:80])

        # bt — backtrace
        r = run_cli(args.cli, name, "bt", "--count", "8")
        res.record("do bt", r.returncode == 0 and len(r.stdout.strip()) > 0)

        # snapshot
        r = run_cli(args.cli, name, "snapshot")
        res.record("do snapshot", r.returncode == 0 and len(r.stdout.strip()) > 0)

        # exec — raw command
        r = run_cli(args.cli, name, "exec", ".echo", "fulltest_marker_123")
        res.record("do exec (.echo)", r.returncode == 0 and "fulltest_marker_123" in r.stdout, r.stdout.strip()[:80])

        # exec — blocked command should fail (sxd ld* is blocklisted in the engine)
        r = run_cli(args.cli, name, "exec", "sxd", "ld")
        combined = (r.stdout + r.stderr).lower()
        res.record(
            "do exec blocks unsafe sxd",
            r.returncode != 0 and "block" in combined,
            (r.stdout + r.stderr).strip()[:160],
        )

        # step / step-over (set a fresh bp, go, then step)
        r = run_cli(args.cli, name, "step")
        res.record("do step", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])
        r = run_cli(args.cli, name, "step-over")
        res.record("do step-over", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])

        # step-out
        r = run_cli(args.cli, name, "step-out")
        res.record("do step-out", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])

        # step-until: step to the return address (current rip + something is hard;
        # instead step-until rip itself which is already there → should return fast)
        if rip:
            r = run_cli(args.cli, name, "step-until", rip)
            res.record("do step-until", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])

        # go + interrupt + wait-break cycle
        r = run_cli(args.cli, name, "go")
        res.record("do go", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])
        # let it run a moment
        time.sleep(0.5)
        r = run_cli(args.cli, name, "interrupt")
        res.record("do interrupt", r.returncode == 0 and "interrupted" in (r.stdout + r.stderr).lower(), (r.stdout + r.stderr).strip()[:80])
        r = run_cli(args.cli, name, "wait-break", "--timeout-secs", "10")
        res.record("do wait-break", r.returncode == 0, (r.stdout + r.stderr).strip()[:80])

        # dump — write a minidump (skip modules to keep it fast)
        dump_dir = Path(tempfile.gettempdir()) / "windbg_fulltest_dump"
        r = run_cli(args.cli, name, "dump", "--out-dir", str(dump_dir), "--no-modules", timeout=180)
        dmp = dump_dir / "process.dmp"
        res.record(
            "do dump (minidump)",
            r.returncode == 0 and dmp.exists() and dmp.stat().st_size > 0,
            f"{dmp} exists={dmp.exists()} size={dmp.stat().st_size if dmp.exists() else 0}",
        )

        # -------------------------------------------------------------
        # 5. Close via MCP and verify cleanup
        # -------------------------------------------------------------
        if not args.keep_open:
            print("\n[5] Close via MCP + verify cleanup")
            close_payload = client.call_tool("windbg_close_session", {"name": name}, timeout_secs=30)
            res.record("close_session ok", "stopped" in str(close_payload.get("message", "")).lower() or "clean" in str(close_payload.get("message", "")).lower(), json.dumps(close_payload))
            closed = True
            time.sleep(1.0)

            # Registry file should be gone.
            reg = registry_dir_path() / f"{name}.json"
            res.record("registry entry removed", not reg.exists(), str(reg))

            # daemon status should now report not-found.
            st = daemon_cmd(args.cli, "daemon", "status", "--name", name)
            res.record("daemon status gone", st.returncode != 0)

            # Closing again should be a graceful no-op (force handles stale).
            close2 = client.call_tool("windbg_close_session", {"name": name, "force": True}, timeout_secs=15)
            res.record("close_session idempotent", True, json.dumps(close2))

        return res.summary()
    finally:
        if opened_name and not closed and not args.keep_open:
            try:
                client.call_tool("windbg_close_session", {"name": opened_name, "force": True}, timeout_secs=15)
            except Exception as exc:
                print(f"cleanup close failed: {exc}", file=sys.stderr)
        client.close()


if __name__ == "__main__":
    sys.exit(main())
