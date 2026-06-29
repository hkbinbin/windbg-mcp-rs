---
name: windbg-cli
description: >-
  Drive Windows debugging through the windbg_cli daemon and the thin
  windbg-mcp-rs MCP server. Use this when the user wants to debug a Windows
  user-mode process or kernel (KDNET) target via this project's tools — open a
  session, set breakpoints, step, read registers/memory, disassemble, capture a
  backtrace, dump a process, or run raw WinDbg commands. Triggers include:
  "debug notepad", "attach to PID", "set a breakpoint with windbg_cli",
  "windbg daemon", "open a kernel session", "dump this process", "run a WinDbg
  command through the daemon".
metadata:
  agent_created: true
  project: windbg-mcp-rs
  version: "0.2.1"
---

# windbg-cli

How to debug a Windows target with this project's two binaries.

## Architecture (read first)

This project ships **two** executables that must live in the **same folder**:

| Binary | Role |
|---|---|
| `windbg_mcp_headless.exe` | Thin MCP server. Exposes only 3 tools: `windbg_open_session`, `windbg_close_session`, `windbg_use_help`. |
| `windbg_cli.exe` | The debugger. Owns the live dbgeng session inside a long-running **daemon** process; the `do` subcommand drives it. |

A dbgeng COM session **cannot be shared across processes**, so the session
lives in exactly one place: the `windbg_cli daemon` process. The MCP server
only starts/stops that daemon. An agent can drive debugging two ways:

- **Via MCP**: call `windbg_open_session` → returns a daemon `name` → run
  `windbg_cli do --name <name> <action>` from a shell → `windbg_close_session`.
- **Via CLI only** (no MCP): `windbg_cli daemon start ...` → `windbg_cli do ...`
  → `windbg_cli daemon stop`.

Either way, **all detailed debugging is `windbg_cli do <action>`.**

## Golden-path workflow (CLI-only, most common)

```bash
# 1. Start a daemon that launches notepad as the debuggee. Runs in the
#    foreground and blocks; start it in its own terminal / background job.
windbg_cli daemon start --name dbg run "C:\\Windows\\System32\\notepad.exe"

# 2. In another shell, drive the session by name.
windbg_cli do --name dbg state                 # break / go / no_debuggee
windbg_cli do --name dbg bp ntdll!NtCreateFile # set a breakpoint
windbg_cli do --name dbg go                     # resume
windbg_cli do --name dbg wait-break --timeout-secs 30
windbg_cli do --name dbg bt                     # backtrace at the break
windbg_cli do --name dbg reg rip rsp            # specific registers

# 3. Tear down.
windbg_cli daemon stop --name dbg
```

> When driven by the **MCP** server, step 1 is `windbg_open_session` and step 3
> is `windbg_close_session`; the `do` calls in step 2 are identical.

## Opening a session — three target modes

`windbg_cli daemon start --name <name> [--symfix] [--startup-command "..."] [--attach-timeout-secs N] <TARGET>`

| Mode | Command | Notes |
|---|---|---|
| Launch a binary | `... run <EXE> [ARGS...] [--follow-children]` | Breaks at the loader entry. |
| Attach to a PID | `... attach <PID> [--non-invasive]` | `--non-invasive` = read-only. |
| Kernel (KDNET) | `... kernel "<connection>"` | e.g. `net:port=50000,key=...`. |

Examples:

```bash
# Launch with arguments
windbg_cli daemon start --name app run "C:\\tools\\app.exe" --flag value

# Attach to a running process, read-only
windbg_cli daemon start --name p1 attach 4242 --non-invasive

# Kernel session, fix symbols on attach
windbg_cli daemon start --name kd --symfix kernel "net:port=50000,key=1.2.3.4"
```

Useful `daemon start` flags (also accepted on the start subcommand):
`--symfix` (run `.symfix; .reload` first), `--startup-command "<cmds>"`,
`--attach-timeout-secs <N>` (default 30), `--bind 127.0.0.1:<port>` (control
socket; default ephemeral), `--terminate-on-exit` (kill the debuggee on close).

## Managing daemons

```bash
windbg_cli daemon list                 # JSON array of all known daemons
windbg_cli daemon status --name dbg    # address + PID for one daemon
windbg_cli daemon stop   --name dbg    # graceful shutdown
```

Daemons register at `%TEMP%\windbg_cli_daemons\<name>.json` and log to
`<name>.log` in the same dir. If `--name` is omitted it defaults to `default`.

## `do <action>` — the full debugging surface

Run as `windbg_cli do --name <name> <action> [args]`. The state header
(`[state break/6, ready=true, running=false]`) is printed on stderr; the
command body is on stdout.

### Execution control

| Action | Purpose | Example |
|---|---|---|
| `state` | Current state (break/go/no_debuggee). | `do --name dbg state` |
| `go` | Resume; returns immediately. | `do --name dbg go` |
| `interrupt` | Break in and wait for the stop. | `do --name dbg interrupt` |
| `wait-break --timeout-secs N` | Block until `break` (default 60). | `do --name dbg wait-break --timeout-secs 20` |
| `step [--count N]` | Step into (`t`). | `do --name dbg step --count 3` |
| `step-over [--count N]` | Step over (`p`). | `do --name dbg step-over` |
| `step-out` | Run to return (`gu`). | `do --name dbg step-out` |
| `step-until <ADDR> [--into]` | Step to address (`pa`/`ta`). | `do --name dbg step-until kernel32!CreateFileW` |

### Breakpoints

| Action | Purpose | Example |
|---|---|---|
| `bp <LOCATION> [--one-shot]` | Software breakpoint. | `do --name dbg bp ntdll!NtClose` |
| `ba <ADDR> [--access e\|r\|w\|io] [--size 1\|2\|4\|8]` | Hardware breakpoint/watchpoint. | `do --name dbg ba @rsp --access r --size 8` |
| `bl` | List breakpoints. | `do --name dbg bl` |
| `bc [ID]` | Clear by id, or all (`*`, the default). | `do --name dbg bc *` |

### Inspection

| Action | Purpose | Example |
|---|---|---|
| `reg [REGS...]` | All registers (`r`) or specific ones (read individually). | `do --name dbg reg rip rsp rax` |
| `mem <ADDR> [--format bytes\|words\|dwords\|qwords] [--count N]` | Read memory. | `do --name dbg mem @rip --format bytes --count 16` |
| `dis <ADDR> [--count N]` | Disassemble (default 16). | `do --name dbg dis @rip --count 8` |
| `bt [--format kv] [--count N]` | Stack backtrace (default `kv`, 32). | `do --name dbg bt --count 12` |
| `snapshot` | `.lastevent` + `r` + `u @eip L8` + `kv 16` + `bl` in one shot. | `do --name dbg snapshot` |
| `info` | Session transport / connection / state. | `do --name dbg info` |

### Capture & raw commands

| Action | Purpose | Example |
|---|---|---|
| `dump --out-dir <DIR> [--no-minidump] [--no-modules] [--module-filter <substr>] [--resume-after]` | Full `/ma` minidump (`process.dmp`) + per-module raw bytes under `modules/`. Auto-interrupts if running. | `do --name dbg dump --out-dir C:\\dumps\\app --no-modules` |
| `exec <RAW WINDBG CMD>` | Any raw WinDbg command. Quote if it has spaces. | `do --name dbg exec "u @rip L8"` |

## Important conventions & gotchas

- **`reg` with multiple registers**, not a raw `r rip rax rcx`: the engine
  **blocks** fragile multi-register `r` reads (they cause transient dbgeng
  `0x80040205`). Use `do reg rip rax rcx` — it reads each individually.
- **`sxd ld` / `sxd ld:*` is blocked.** This dbgeng path can access-violate
  after a module-load event. Leave the filter in place; clear normal
  breakpoints with `bc` and resume/close instead.
- **Symbol-dependent commands** (`!process`, `!drvobj`, `bp mod!sym`): if NT
  symbols look wrong, open with `--symfix`, or run
  `do exec ".symfix; .reload"` first.
- **A symbol breakpoint may display under an alias in `bl`** — e.g.
  `bp ntdll!NtClose` shows as `ntdll!ZwClose` (same address). Not an error.
- **Kernel sessions**: right after attach the state is often `no_debuggee`
  until the target reconnects; while broken in, the guest kernel is paused.
  Use `--resume-on-exit` semantics / `go` to leave the VM running.
- **One daemon = one session.** Run multiple targets side-by-side by giving
  each a unique `--name`.

## Self-discovery

The CLI is the source of truth. For exhaustive flags:

```bash
windbg_cli --help
windbg_cli daemon start --help
windbg_cli do --help
windbg_cli do <action> --help
```

When driven by MCP, `windbg_use_help` (optional `topic`: workflow/open/do/daemon)
returns the same guidance.
