# windbg-mcp-rs

`windbg-mcp-rs` can now run in two forms:

- As a pure WinDbg extension DLL that exposes the current debugging session as an MCP server
- As a headless MCP server that owns dbgeng sessions itself and can actively attach to kernel targets using the same `-k` connection options as WinDbg

- Read official WinDbg command documentation extracted from `docs/debugger.chm`
- Execute WinDbg commands through dbgeng
- Read buffered command output history with cursor-based polling
- Interrupt a running target from MCP
- Resume a running target without blocking on a raw `g` command
- Manage headless debugger sessions (`open`, `list`, `switch`, `close`)
- Use the server from any MCP client over Streamable HTTP

## Screenshots

![WinDbg MCP plugin screenshot 1](images/1.png)

![WinDbg MCP plugin screenshot 2](images/2.png)

## Quick Start

### Plugin mode

### 1. Build the DLL

```powershell
cargo build --release
```

### 2. Load it in WinDbg

```text
.load path\to\windbg_mcp_rs.dll
```

### 3. Start the MCP server

```text
!mcp serve 127.0.0.1:50051
```

The MCP endpoint will be:

```text
http://127.0.0.1:50051/mcp
```

### 4. Connect your MCP client

Point your client to:

```text
http://127.0.0.1:50051/mcp
```

### Headless mode

Start a stdio MCP server:

```powershell
cargo run --bin windbg_mcp_headless --
```

Start an HTTP MCP server:

```powershell
cargo run --bin windbg_mcp_headless -- --listen 127.0.0.1:50051
```

Start headless mode and immediately attach to a KDNET target:

```powershell
cargo run --bin windbg_mcp_headless -- `
  --listen 127.0.0.1:50051 `
  --connect-kernel "net:port=50000,key=<your-kdnet-key>" `
  --session-id kdnet-main
```

The `--connect-kernel` value accepts either raw `-k` options such as `net:port=...,key=...` or a full launcher string such as:

```text
windbgx -k net:port=50000,key=...
```

## WinDbg Commands

Use `!mcp help` to list all plugin commands.

Common ones:

```text
!mcp help
!mcp serve 127.0.0.1:50051
!mcp status
!mcp stop
```

## Headless Session Tools

Headless mode adds session-management tools:

- `windbg_open_session`
- `windbg_close_session`
- `windbg_switch_session`
- `windbg_list_sessions`
- `windbg_current_session`

Live-target control is split into explicit tools:

- `windbg_get_execution_state`
- `windbg_get_output`
- `windbg_interrupt_target`
- `windbg_resume_target`
- `windbg_execute_command`

## What MCP Exposes

- `Resources`: a low-context guide resource and compact/full WinDbg command documentation resources
- `Tools`: a compact toolset for catalog search, execution-state query, command execution, target interrupt/resume, and headless session management

Pure UI shortcut topics remain available as documentation, and command execution is exposed through a single `windbg_execute_command` tool.

Recommended agent flow in plugin mode: call `windbg_search_catalog`, read `windbg://command/{id}`, fall back to `windbg://command-full/{id}` only when needed, call `windbg_get_execution_state`, and then call `windbg_execute_command`.

Recommended agent flow in headless mode: call `windbg_open_session`, optionally `windbg_switch_session`, then follow the same command flow. If the debugger is running or busy, call `windbg_interrupt_target` explicitly and verify state again before executing the command. Use `windbg_resume_target` to continue execution without issuing a raw `g` command. Use `windbg_get_output` with the returned `next_cursor` to fetch only newly buffered command output.

## Development

```powershell
cargo check
cargo test
```

## Notes

- This project was written entirely with a Vibe Coding workflow
- The server runs inside the WinDbg process
- Headless mode runs as an ordinary Rust process and owns dbgeng sessions directly
- For live KDNET sessions, the owned dbgeng host now stays broken after a successful break-in and only resumes when `windbg_resume_target` is called
- The runtime does not parse `docs/debugger.chm`; it uses the prebuilt static catalog in `src/catalog.json`
- The transport is Streamable HTTP
- Headless mode also supports stdio transport
- Set your MCP client timeout as high as possible, because some WinDbg operations can take a long time to finish
