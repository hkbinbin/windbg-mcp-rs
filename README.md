# windbg-mcp-rs

`windbg-mcp-rs` is a headless stdio MCP server that owns dbgeng sessions itself and can actively attach to kernel targets using the same `-k` connection options as WinDbg. Streamable HTTP remains available as an optional transport, but the maintained runtime is headless-only and no longer builds a WinDbg GUI extension DLL.

- Read official WinDbg command documentation extracted from `docs/debugger.chm`
- Execute WinDbg commands through dbgeng
- Read buffered command output history with cursor-based polling
- Interrupt a running target from MCP
- Resume a running target without blocking on a raw `g` command
- Manage headless debugger sessions (`open`, `list`, `switch`, `close`)
- Use the server from any MCP client over stdio by default, or Streamable HTTP when `--listen` is passed
- Use higher-level reverse-engineering MCP tools for breakpoints, registers, memory, disassembly, backtraces, expressions, modules, symbols, and driver objects

## Quick Start

Start the default stdio MCP server:

```powershell
cargo run --bin windbg_mcp_headless --
```

Optionally start an HTTP MCP server:

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

## Headless Session Tools

Headless mode adds session-management tools:

- `windbg_open_session`
- `windbg_close_session`
- `windbg_switch_session`
- `windbg_list_sessions`
- `windbg_current_session`
- `windbg_recover_session`

Live-target control is split into explicit tools:

- `windbg_get_execution_state`
- `windbg_get_output`
- `windbg_interrupt_target`
- `windbg_resume_target`
- `windbg_execute_command`
- `windbg_prepare_symbols`
- `windbg_diagnose_extensions`

Reverse-engineering convenience tools:

- `windbg_set_breakpoint`
- `windbg_find_process`
- `windbg_set_process_breakpoint`
- `windbg_set_syscall_breakpoint`
- `windbg_list_breakpoints`
- `windbg_clear_breakpoint`
- `windbg_continue_until_break`
- `windbg_read_registers`
- `windbg_write_register`
- `windbg_read_memory`
- `windbg_disassemble`
- `windbg_backtrace`
- `windbg_breakpoint_snapshot`
- `windbg_evaluate_expression`
- `windbg_list_modules`
- `windbg_search_symbols`
- `windbg_inspect_driver`
- `windbg_set_driver_load_breakpoint`
- `windbg_driver_summary`
- `windbg_set_driver_dispatch_breakpoints`
- `windbg_driver_dispatch_snapshot`
- `windbg_ioctl_snapshot`

`windbg_close_session` tries to resume a broken target before teardown by default; pass `resume_before_close: false` to skip that behavior. For live kernel sessions, close waits briefly before detaching after either an automatic resume or a recently observed running state, so the guest has time to leave the break state. It also accepts an optional `shutdown_timeout_secs` value. The session is removed from the MCP registry first, and the bounded shutdown result reports whether dbgeng teardown completed cleanly or timed out in the background. This keeps live KDNET detach issues from hanging the MCP server.

`windbg_recover_session` is the safe recovery shortcut for long-running KDNET work: by default it checks the session state and resumes a broken target, returning structured before/after state and any recovery error. Set `interrupt_if_running: true` when you intentionally want the recovery action to break into a running target instead.

If a text thread-list command such as `~` hits dbgeng's transient `0x80040205` command-window state after a synthetic load or breakpoint event, headless mode falls back to `IDebugSystemObjects` and returns a compact thread-id list instead of failing outright.

For live KDNET sessions, shutdown is owned by the host client rather than the connected command client. This avoids dbgeng's nested `LoadModule` teardown error (`0x800700D7`) after driver-load breakpoints while keeping the guest running.

### Headless Extension Loading

Headless mode can use WinDbg extension commands such as `.load kdexts` and `!process` without relying on WinDbg Preview's protected `WindowsApps` install path directly. On Windows, the server discovers the installed WinDbg Preview package, copies the required `amd64`, `amd64\winext`, and `amd64\winxp` runtime files into:

```text
%LOCALAPPDATA%\windbg-mcp-rs\dbgeng-cache
```

It then appends the cached extension directories to `.extpath`. Commands such as `.load kdexts` are resolved to the cached DLL path automatically.

By default, live KDNET sessions keep using the system `dbgeng.dll`, which has been more stable for target resume/close behavior, while extensions load from the local cache. Advanced overrides:

- `WINDBG_MCP_DBGENG_PATH`: force a specific `dbgeng.dll`.
- `WINDBG_MCP_DEBUGGER_ROOT`: force a debugger root that contains `amd64\dbgeng.dll`.
- `WINDBG_MCP_USE_PREVIEW_DBGENG=1`: opt into the cached WinDbg Preview `dbgeng.dll`.

Extension-backed commands still depend on symbols. Use `windbg_prepare_symbols` before commands such as `!process 0 0` or `!drvobj ShadowGate 7` when the target reports incorrect NT symbols. The tool reads `!lmi <module>`, downloads the exact CodeView PDB from the configured symbol server, appends the exact PDB directory to `.sympath`, and reloads the module. It defaults to module `nt`, cache directory `C:\Symbols`, and `https://msdl.microsoft.com/download/symbols`; override the cache per call with `symbol_cache` or globally with `WINDBG_MCP_SYMBOL_CACHE`.

If extension loading or an extension-backed command still fails, call `windbg_diagnose_extensions`. It collects the effective `.extpath`, loaded extension chain, optional symbol preparation, extension load output, probe command output, and remediation hints without requiring the client to manually stitch those checks together.

## What MCP Exposes

- `Resources`: a low-context guide resource and compact/full WinDbg command documentation resources
- `Tools`: a compact toolset for catalog search, execution-state query, command execution, target interrupt/resume, exact PDB preparation, extension diagnostics, reverse-engineering convenience actions, and headless session management

Pure UI shortcut topics remain available as documentation, and command execution is exposed through a single `windbg_execute_command` tool.

Recommended agent flow in headless mode: call `windbg_open_session`, optionally `windbg_switch_session`, then follow the same command flow. If extension commands need kernel symbols, call `windbg_prepare_symbols` while broken into the target, and use `windbg_diagnose_extensions` when `.load kdexts` or `!process` is not behaving as expected. If the debugger is running or busy, call `windbg_interrupt_target` explicitly and verify state again before executing the command. Use `windbg_resume_target` to continue execution without issuing a raw `g` command. Use `windbg_get_output` with the returned `next_cursor` to fetch only newly buffered command output.

Recommended breakpoint flow: call `windbg_set_breakpoint`, call `windbg_continue_until_break`, then call `windbg_breakpoint_snapshot` or targeted tools such as `windbg_read_registers`, `windbg_read_memory`, `windbg_disassemble`, and `windbg_backtrace`. For noisy kernel syscalls, call `windbg_find_process` and then `windbg_set_process_breakpoint` or `windbg_set_syscall_breakpoint`; these use WinDbg's native kernel `bp /p <EPROCESS>` support so `NtCreateFile` / `NtDeviceIoControlFile` tracing can be scoped to `ShadowGateApp.exe`, `maze_probe.exe`, or a specific PID.

Recommended kernel-driver flow: call `windbg_set_driver_load_breakpoint` before starting the driver; it prepares `nt` symbols by default before configuring `sxe ld:<image>` so later driver-object inspection avoids dbgeng's unstable "prepare symbols after load-filter mutation" path. Continue until the load event, then call `windbg_driver_summary` to collect `lm`, `!drvobj`, object/device checks, and parsed `IRP_MJ_*` dispatch routines. Use `windbg_set_driver_dispatch_breakpoints` to place breakpoints on dispatch handlers such as `IRP_MJ_DEVICE_CONTROL`, then use `windbg_driver_dispatch_snapshot` at dispatch entry or `windbg_ioctl_snapshot` at IOCTL-specific breakpoints to collect registers, `!irp`, parsed IOCTL input/output lengths and code, SystemBuffer memory and byte prefix, stack, RIP disassembly, and current breakpoints. `windbg_ioctl_snapshot` auto-detects common IRP registers by default, which helps when a handler has cached the IRP after the normal dispatch entry. Use `windbg_evaluate_expression`, `windbg_list_modules`, `windbg_search_symbols`, and `windbg_inspect_driver` for lower-level symbol/module/driver-object checks.

## Development

```powershell
cargo check
cargo test
```

Run the stdio smoke helper after building the release binary:

```powershell
python tools/headless_mcp_smoke.py
```

To validate a live KDNET session, pass your own connection string:

```powershell
python tools/headless_mcp_smoke.py `
  --connection "net:port=50000,key=<your-kdnet-key>" `
  --session-id kdnet-smoke `
  --command vertarget
```

The live smoke helper waits through transient `no_debuggee` states, interrupts a running target before executing commands, and closes the session through MCP cleanup even if a command fails.

Additional tracked validation helpers:

- `tools/headless_extension_smoke.py`: prepares symbols, loads `kdexts`, and runs extension-backed probes.
- `tools/headless_get_output_check.py`: verifies cursor-based `windbg_get_output` reads.
- `tools/headless_kdnet_soak.py`: repeats `interrupt -> execute -> resume` cycles and can probe guest TCP reachability.
- `tools/headless_syscall_breakpoint_smoke.py`: validates process-scoped syscall breakpoint setup and can optionally launch a trigger command.
- `tools/shadowgate_smoke.py`: drives ShadowGate service/load-break inspections when guest SSH is available.

For day-to-day operating guidance, see `docs/headless-operator-guide.md`. Driver-debugging implementation details are tracked in `docs/kernel-driver-debugging-implementation.md`. For output cursor regression coverage, see `docs/get-output-regression-plan.md`.
ShadowGate-specific observations are tracked in `docs/shadowgate-notes.md`.

## Notes

- This project was written entirely with a Vibe Coding workflow
- The server runs as an ordinary Rust process and owns dbgeng sessions directly
- For live KDNET sessions, the owned dbgeng host now stays broken after a successful break-in and only resumes when `windbg_resume_target` is called
- The runtime does not parse `docs/debugger.chm`; it uses the prebuilt static catalog in `src/catalog.json`
- The default transport is stdio
- Streamable HTTP is optional through `--listen`
- Set your MCP client timeout as high as possible, because some WinDbg operations can take a long time to finish
- `no_debuggee` right after opening a live KDNET session is expected; wait for reconnect before executing commands
- While the target is broken, the guest kernel is paused and SSH can appear down until `windbg_resume_target` or `windbg_recover_session`
- Synthetic driver-load handling can still have cosmetic module-display quirks; for ShadowGate, `!drvobj ShadowGate 7` is currently more reliable than `lm m ShadowGate*` after a normal service start
