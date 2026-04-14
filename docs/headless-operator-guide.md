# Headless KDNET Operator Guide

This guide describes the safe rhythm for stdio MCP clients that own a live KDNET session. The server is headless-only: it runs as an ordinary process, owns dbgeng sessions directly, and does not require a WinDbg GUI or in-process extension DLL.

## Core Rhythm

1. Start the stdio MCP server.
2. Call `windbg_open_session` with the KDNET connection string.
3. Poll `windbg_get_execution_state` until the session leaves `no_debuggee`.
4. If the state is `break`, run short inspection commands or call `windbg_resume_target`.
5. Perform guest-side work while the target is running.
6. Call `windbg_interrupt_target` only when debugger inspection is needed.
7. Run focused MCP tools while the target is broken: `windbg_breakpoint_snapshot`, `windbg_driver_summary`, `windbg_driver_dispatch_snapshot`, `windbg_read_registers`, `windbg_read_memory`, `windbg_disassemble`, `windbg_backtrace`, `windbg_evaluate_expression`, `windbg_list_modules`, `windbg_search_symbols`, `windbg_inspect_driver`, `windbg_execute_command`, `windbg_get_output`, `windbg_prepare_symbols`, or extension diagnostics.
8. Call `windbg_resume_target` as soon as the inspection is complete.
9. Call `windbg_close_session` for cleanup; it resumes a broken kernel target before detach by default.

## Important States

- `no_debuggee`: dbgeng is waiting for the target to reconnect. Do not execute commands yet.
- `break`: commands are accepted, but the VM kernel is paused. SSH and guest networking can hang.
- `go`: the target is running. Use `windbg_interrupt_target` before command execution.

## Extension Workflow

Use this sequence before extension-backed commands such as `!process` or `!drvobj`:

```text
windbg_interrupt_target
windbg_prepare_symbols {"module":"nt"}
windbg_execute_command ".load kdexts"
windbg_execute_command "!process 0 0"
windbg_resume_target
```

If extension loading still fails, call `windbg_diagnose_extensions` to collect `.extpath`, `.chain`, symbol status, the load attempt, the probe command, and remediation hints.

## Reverse Engineering Tools

Prefer the higher-level MCP wrappers for common breakpoint-hit work instead of manually stitching raw command strings together:

```text
windbg_set_breakpoint {"location":"nt!DbgBreakPointWithStatus","one_shot":true}
windbg_find_process {"name":"ShadowGateApp.exe"}
windbg_set_syscall_breakpoint {"process_name":"ShadowGateApp.exe","syscall":"NtDeviceIoControlFile"}
windbg_continue_until_break {"timeout_secs":30}
windbg_breakpoint_snapshot
windbg_read_registers {"registers":["rip","rsp","rcx","rdx"]}
windbg_read_memory {"address":"rsp","format":"qwords","count":16}
windbg_disassemble {"address":"rip","count":16}
windbg_backtrace {"format":"kv","count":32}
windbg_evaluate_expression {"expression":"poi(rsp)"}
windbg_list_modules {"pattern":"ShadowGate*","verbose":true}
windbg_search_symbols {"pattern":"nt!*CreateFile*"}
windbg_inspect_driver {"name":"ShadowGate","flags":"7"}
windbg_resume_target
```

`windbg_set_breakpoint` wraps `bp`, `bu`, and `bm`, including one-shot breakpoints, pass counts, and a WinDbg command string. For noisy global kernel breakpoints, prefer `windbg_set_process_breakpoint` or `windbg_set_syscall_breakpoint`; they resolve the target process with `!process`, prepare `nt` symbols on demand, and set WinDbg's native `bp /p <EPROCESS>` breakpoint.

## Kernel Driver Tools

Prefer the driver-aware MCP wrappers when tracing a kernel driver:

```text
windbg_set_driver_load_breakpoint {"image":"ShadowGateSys.sys","clear_existing":true}
windbg_continue_until_break {"timeout_secs":60}
windbg_driver_summary {"name":"ShadowGate","device":"\\Device\\ShadowGate"}
windbg_set_driver_dispatch_breakpoints {"driver":"ShadowGate","functions":["IRP_MJ_CREATE","IRP_MJ_CLOSE","IRP_MJ_DEVICE_CONTROL"]}
windbg_continue_until_break {"timeout_secs":60}
windbg_driver_dispatch_snapshot {"irp":"@rdx","driver_object":"@rcx","stack_count":32,"memory_count":32}
windbg_resume_target
```

`windbg_set_driver_load_breakpoint` prepares `nt` symbols by default before it mutates `sxe/sxd ld:<image>` filters, because some dbgeng builds are unstable when symbol preparation happens after synthetic load-filter changes. `windbg_driver_summary` parses the `!drvobj <name> 7` dispatch table into structured `IRP_MJ_*` entries so an MCP client can choose handlers without scraping raw text. `windbg_set_driver_dispatch_breakpoints` targets create/close/device-control handlers when present and skips default `nt!IopInvalidDeviceRequest` handlers unless `include_default_handlers` is true.

For implementation details, parser behavior, validation notes, and maintenance cautions, see `docs/kernel-driver-debugging-implementation.md`.

## Driver Load Breakpoints

Use `windbg_set_driver_load_breakpoint` for synthetic load-event breakpoints, or use normal WinDbg syntax directly:

```text
sxe ld:ShadowGateSys.sys
g
```

Start the driver from the guest while the target is running. When the load event breaks, keep inspection short and resume quickly:

```text
.lastevent
lm m ShadowGate*
r rip
k
!drvobj ShadowGate 7
g
```

## Recovery

If SSH stops responding after a test, assume the target is broken before assuming the VM is dead. Open or reuse a session and call:

```text
windbg_recover_session
```

The default behavior resumes a broken target and reports before/after state.
