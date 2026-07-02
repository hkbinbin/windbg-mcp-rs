#!/usr/bin/env python3
"""End-to-end demo: can `windbg_cli do search` find a secret hidden by a DLL
in PRIVATE (VirtualAlloc'd) memory?

Flow:
  1. Launch secret_host.exe under a windbg_cli daemon (mode=run). The debugger
     breaks at the loader entry before main().
  2. `go` so main() runs LoadLibraryA(secret_dll.dll); DllMain commits a private
     page and writes the secret there, recording base/size to a marker file.
  3. Interrupt back into the debugger.
  4. Search:
     a) whole-process module scan (expected: MISS — the secret is not in any
        module image), demonstrating the scope limitation, and
     b) explicit-range scan over the recorded private region (expected: HIT for
        the ASCII secret and the Chinese secret via UTF-16LE).

Run from the repo root after building both the tool and the demo:
  cargo build --release
  (cd demo/secret-search && cargo build --release)
  python demo/secret-search/run_demo.py
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CLI = REPO / "target" / "release" / "windbg_cli.exe"
HOST = REPO / "demo" / "secret-search" / "target" / "release" / "secret_host.exe"
import os
MARKER = Path(os.environ.get("TEMP", ".")) / "secret_search_demo_region.txt"
NAME = "secretdemo"
SECRET_ASCII = "SUPER_SECRET_TOKEN_9f3a1c"
SECRET_CN = "顶级机密令牌"


def cli(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    cmd = [str(CLI), *args]
    print(f"  $ {' '.join(args)}")
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout)


def do(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    return cli("do", "--name", NAME, *args, timeout=timeout)


def read_marker() -> dict[str, str]:
    data: dict[str, str] = {}
    for line in MARKER.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def main() -> int:
    for p, what in [(CLI, "windbg_cli.exe"), (HOST, "secret_host.exe")]:
        if not p.exists():
            print(f"FATAL: {what} not found at {p}", file=sys.stderr)
            return 2
    if MARKER.exists():
        MARKER.unlink()

    fail = 0
    try:
        # 1) Launch the host under a daemon (background; it blocks).
        print("[1] launching secret_host.exe under a daemon")
        proc = subprocess.Popen(
            [str(CLI), "daemon", "start", "--name", NAME, "run", str(HOST)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Wait for the daemon to register + break at loader entry.
        deadline = time.time() + 40
        ready = False
        while time.time() < deadline:
            st = cli("daemon", "status", "--name", NAME, timeout=10)
            if st.returncode == 0:
                ready = True
                break
            time.sleep(0.5)
        if not ready:
            print("FATAL: daemon did not start", file=sys.stderr)
            proc.kill()
            return 2
        print("    daemon up:", do("state").stdout.strip())

        # 2) Let the target run so it loads the DLL and plants the secret.
        print("[2] resuming so the DLL loads and plants the secret")
        do("go")
        # Poll for the marker file the DLL writes.
        deadline = time.time() + 20
        while time.time() < deadline and not MARKER.exists():
            time.sleep(0.3)
        if not MARKER.exists():
            print("FATAL: secret was never planted (marker missing)", file=sys.stderr)
            return 2
        marker = read_marker()
        print("    marker:", marker)

        # 3) Interrupt back in so we can read memory.
        print("[3] interrupting back into the debugger")
        do("interrupt")
        do("wait-break", "--timeout-secs", "10")

        base = marker["region_base"]
        size = marker["region_size"]
        # The secret sits at base+offset, so match on the region prefix (drop
        # the low 3 hex digits / one 0x1000 page) rather than the exact base.
        base_int = int(base, 16)
        region_prefix = f"{base_int >> 12:x}"  # page number, hit addr >> 12 == this

        def hit_in_private_region(output: str) -> bool:
            for line in output.splitlines():
                tok = line.strip().split()
                if tok and tok[0].lower().startswith("0x"):
                    try:
                        addr = int(tok[0], 16)
                    except ValueError:
                        continue
                    if (addr >> 12) == (base_int >> 12):
                        return True
            return False

        # 4a) Module-only scan should MISS the private-memory copy. (Note: the
        #     ASCII literal is also compiled into the DLL image, so a module
        #     scan may find THAT copy — at a different address. The point is it
        #     cannot see the private region reliably; a real payload keeps the
        #     secret only in private memory.)
        print("[4a] MODULE-only scan for the ASCII secret (baseline)")
        r = do("search", "--string", SECRET_ASCII, "--encoding", "utf8", "--max-hits", "10")
        print(r.stdout.rstrip())
        print(f"    module scan saw the PRIVATE region copy: {hit_in_private_region(r.stdout)} "
              "(expected False — private memory isn't a module)")

        # 4b) WHOLE address-space scan (--all) should HIT the private region.
        #     This is the realistic case: we do NOT know the address.
        print("[4b] --all whole-address-space scan for the ASCII secret (expect HIT in private memory)")
        r = do("search", "--string", SECRET_ASCII, "--encoding", "utf8", "--all", "--max-hits", "20")
        print(r.stdout.rstrip())
        if hit_in_private_region(r.stdout):
            print("    PASS: --all found the secret at its PRIVATE-memory address")
        else:
            print("    FAIL: --all did not find the private-memory secret")
            fail += 1

        # 4c) --all scan for the Chinese secret (UTF-16LE), address unknown.
        print("[4c] --all scan for the Chinese secret (UTF-16LE, expect HIT in private memory)")
        r = do("search", "--string", SECRET_CN, "--encoding", "utf16le", "--all", "--max-hits", "20")
        print(r.stdout.rstrip())
        if hit_in_private_region(r.stdout):
            print("    PASS: --all found the Chinese secret via UTF-16LE in private memory")
        else:
            print("    FAIL: --all did not find the Chinese secret")
            fail += 1

        # 4d) Sanity: explicit-range scan pinpoints the exact offsets.
        print("[4d] explicit-range scan confirms exact offsets")
        r = do("search", "--string", SECRET_ASCII, "--encoding", "utf8",
               "--start", base, "--len", size, "--max-hits", "5")
        print(r.stdout.rstrip())

        print()
        print("=" * 60)
        if fail == 0:
            print("DEMO RESULT: SUCCESS — a whole-address-space `--all` scan finds")
            print("the DLL's private-memory secret (ASCII + Chinese/UTF-16LE)")
            print("without knowing its address.")
        else:
            print(f"DEMO RESULT: {fail} check(s) FAILED")
        print("=" * 60)
        return 1 if fail else 0
    finally:
        cli("daemon", "stop", "--name", NAME, timeout=15)


if __name__ == "__main__":
    sys.exit(main())
