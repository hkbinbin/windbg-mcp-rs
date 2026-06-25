# windbg-mcp-rs

`windbg-mcp-rs` is a **thin** stdio MCP server plus a full-featured debugger
**CLI**, both built on a shared headless dbgeng engine.

The design splits responsibilities so the MCP tool surface stays tiny while the
debugging capability stays complete:

- **MCP server (`windbg_mcp_headless`)** exposes only **three** tools —
  `windbg_open_session`, `windbg_close_session`, `windbg_use_help`. It does not
  hold a debugger session itself; it starts/stops `windbg_cli` daemons.
- **CLI (`windbg_cli`)** owns the live dbgeng session inside a long-running
  *daemon* process and performs all detailed debugging (breakpoints, memory,
  registers, stepping, dumps, raw WinDbg commands). The agent runs it directly
  from a shell.

Because a dbgeng COM session cannot be shared across processes, the session
lives in exactly one place — the CLI daemon — and the MCP server only
orchestrates its lifecycle.

## Why this split

- Keeps the MCP tool count to 3, so MCP clients stay fast and uncluttered.
- Preserves full WinDbg capability through `windbg_cli`.
- The session survives across many CLI invocations (it is a persistent daemon),
  so follow-up `windbg_cli do ...` calls inspect the same live target.

## Architecture at a glance

```
MCP client ──stdio──> windbg_mcp_headless          (thin: open/close/help)
                           │ spawns (detached)
                           ▼
                      windbg_cli daemon  ── owns dbgeng session ── target
                           ▲
   agent shell ── windbg_cli do --name <name> <action> ──┘  (bp/go/bt/mem/...)
```

Daemons register themselves under `%TEMP%\windbg_cli_daemons\<name>.json`
(plus a `<name>.log`), and communicate over a loopback TCP control socket.

## Setup

### Prerequisites

- Windows host with Microsoft Debugging Tools / WinDbg installed.
- Rust toolchain with Cargo on `PATH`.
- A writable symbol cache directory, for example `C:\Symbols`.
- For kernel debugging, a target VM configured for KDNET and waiting.
- An MCP client that supports stdio servers.

### Build

```powershell
cargo build --release
```

Resulting binaries:

```text
target\release\windbg_mcp_headless.exe   # thin MCP server
target\release\windbg_cli.exe            # debugger CLI / daemon
```

The MCP server locates `windbg_cli.exe` automatically in this order:

1. `--cli-path <path>` flag.
2. `WINDBG_CLI_PATH` environment variable.
3. The MCP server's own directory (the usual case — keep both binaries together).
4. `windbg_cli` on `PATH`.

### Configure a stdio MCP client

```json
{
  "mcpServers": {
    "windbg_mcp_headless": {
      "command": "C:\\path\\to\\windbg-mcp-rs\\target\\release\\windbg_mcp_headless.exe",
      "args": []
    }
  }
}
```

Codex TOML (`%USERPROFILE%\.codex\config.toml`):

```toml
[mcp_servers.windbg_mcp_headless]
command = 'C:\path\to\windbg-mcp-rs\target\release\windbg_mcp_headless.exe'
args = []
```

Optionally run over Streamable HTTP instead of stdio:

```powershell
cargo run --bin windbg_mcp_headless -- --listen 127.0.0.1:50051
```

## MCP tools

### `windbg_open_session`

Starts (or idempotently reuses) a `windbg_cli` daemon for a target and returns
its daemon `name`, loopback `address`, and `pid`.

| field | type | required | meaning |
|---|---|---|---|
| `mode` | `"launch" \| "attach" \| "kernel"` | yes | target kind |
| `command_line` | string | launch | exe path + args |
| `follow_children` | bool | no | also debug child processes |
| `pid` | u32 | attach | process id to attach to |
| `non_invasive` | bool | no | non-invasive attach |
| `connection` | string | kernel | `-k`-style connection string |
| `name` | string | no | daemon name (auto-generated if omitted) |
| `startup_command` | string | no | run right after the initial break |
| `symfix` | bool | no | run `.symfix; .reload` first |
| `attach_timeout_secs` | u64 | no | initial attach timeout |
| `ready_timeout_secs` | u64 | no | readiness wait timeout |

Reusing a live daemon name returns the existing session (idempotent) without
disturbing the current debugging state.

### `windbg_close_session`

| field | type | required | meaning |
|---|---|---|---|
| `name` | string | yes | daemon name |
| `force` | bool | no | kill an unreachable daemon + clean stale registry |

### `windbg_use_help`

Returns concise usage. Optional `topic`: `"workflow"`, `"open"`, `"do"`,
`"daemon"`. For exhaustive flags, run `windbg_cli --help` and
`windbg_cli do --help`.

The command catalog extracted from `docs/debugger.chm` is also available as MCP
*resources* (`windbg://command/{id}` and the guide) for syntax lookups.

## Workflow

1. Call `windbg_open_session` with a target. Save the returned `name`.
2. Drive debugging from a shell against that daemon:

   ```powershell
   windbg_cli do --name <name> state
   windbg_cli do --name <name> bp nt!NtCreateFile
   windbg_cli do --name <name> go
   windbg_cli do --name <name> wait-break --timeout-secs 30
   windbg_cli do --name <name> bt
   windbg_cli do --name <name> exec "u @rip L8"
   ```
3. Call `windbg_close_session` with the same `name` when finished.

### `windbg_cli do` actions

`state`, `go`, `interrupt`, `wait-break`, `step`, `step-over`, `step-out`,
`step-until`, `bp`, `ba`, `bc`, `bl`, `reg`, `mem`, `dis`, `bt`, `snapshot`,
`dump`, `exec`, `info`. Run `windbg_cli do --help` for exact flags.

`exec` runs any raw WinDbg command; the same unsafe-command blocklist that
applied to the old MCP `execute_command` still applies.

### `windbg_cli` top-level commands

- `daemon start|stop|status|list` — manage persistent debugger daemons.
- `do <action>` — send one action to a running daemon.
- `kernel <connection>` — one-shot kernel session (no daemon).
- `list-tools` — print the legacy tool-name listing.

## Extension loading and symbols

The daemon can use WinDbg extension commands (`.load kdexts`, `!process`, etc.)
without depending on WinDbg's protected `WindowsApps` path. On Windows it
discovers the installed WinDbg package, copies the required `amd64`,
`amd64\winext`, and `amd64\winxp` runtime files into:

```text
%LOCALAPPDATA%\windbg-mcp-rs\dbgeng-cache
```

and appends the cached extension directories to `.extpath`.

Advanced overrides:

- `WINDBG_MCP_DBGENG_PATH` — force a specific `dbgeng.dll`.
- `WINDBG_MCP_DEBUGGER_ROOT` — force a debugger root containing `amd64\dbgeng.dll`.
- `WINDBG_MCP_USE_PREVIEW_DBGENG=1` — opt into the cached WinDbg Preview `dbgeng.dll`.
- `WINDBG_MCP_SYMBOL_CACHE` — override the default `C:\Symbols` cache.

Extension-backed commands depend on symbols. When NT symbols are wrong, run
`windbg_cli do --name <name> exec ".symfix; .reload"` (or open the session with
`symfix: true` / `startup_command`) before commands such as `!process 0 0`.

## Development

```powershell
cargo check
cargo test
```

Protocol smoke test (no target required) — verifies the MCP surface is exactly
the three tools and that `use_help` is clean:

```powershell
python tools\headless_mcp_smoke.py
```

End-to-end user-mode test (spawns a local binary, drives it through the CLI,
closes via MCP):

```powershell
python tools\headless_user_mode_smoke.py --target C:\path\to\app.exe
```

Live KDNET regression helpers (require hardware/VM and a connection string).
Each opens a kernel daemon via MCP and drives it through `windbg_cli do`:

- `tools/headless_kdnet_soak.py` — repeats interrupt/exec/go cycles.
- `tools/headless_get_output_check.py` — verifies command output markers.
- `tools/headless_extension_smoke.py` — loads `kdexts` and runs probes.
- `tools/headless_syscall_breakpoint_smoke.py` — process-scoped syscall breakpoints.
- `tools/headless_trace_breakpoint_smoke.py` — set/resume/wait/snapshot.
- `tools/headless_user_va_breakpoint_smoke.py` — process-scoped user-VA breakpoints.
- `tools/shadowgate_smoke.py` — ShadowGate service/load-break inspection over SSH.

Operating guidance lives in `docs/headless-operator-guide.md`; driver-debugging
details in `docs/kernel-driver-debugging-implementation.md`.

## Notes

- This project was written with a Vibe Coding workflow.
- The MCP server is stateless w.r.t. debugging; the dbgeng session lives only in
  the `windbg_cli` daemon process.
- The runtime does not parse `docs/debugger.chm`; it uses the prebuilt static
  catalog in `src/catalog.json`.
- Default transport is stdio; Streamable HTTP is optional via `--listen`.
- Set your MCP client timeout high — some WinDbg operations take tens of seconds.
- For live KDNET, `no_debuggee` right after opening is expected; wait for the
  target to reconnect. While broken in, the guest kernel is paused.
