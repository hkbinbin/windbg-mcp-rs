# Headless KDNET Operator Guide

This guide describes the safe rhythm for stdio MCP clients that own a live KDNET session. The server is headless-only: it runs as an ordinary process, owns dbgeng sessions directly, and does not require a WinDbg GUI or in-process extension DLL.

## Core Rhythm

1. Start the stdio MCP server.
2. Call `windbg_open_session` with the KDNET connection string.
3. Poll `windbg_get_execution_state` until the session leaves `no_debuggee`.
4. If the state is `break`, run short inspection commands or call `windbg_resume_target`.
5. Perform guest-side work while the target is running.
6. Call `windbg_interrupt_target` only when debugger inspection is needed.
7. Run focused MCP tools while the target is broken: `windbg_breakpoint_snapshot`, `windbg_trace_breakpoint`, `windbg_driver_summary`, `windbg_driver_dispatch_snapshot`, `windbg_ioctl_snapshot`, `windbg_minifilter_message_snapshot`, `windbg_dbgprint`, `windbg_read_registers`, `windbg_read_memory`, `windbg_disassemble`, `windbg_backtrace`, `windbg_step`, `windbg_step_over`, `windbg_go_up`, `windbg_evaluate_expression`, `windbg_list_modules`, `windbg_search_symbols`, `windbg_inspect_driver`, `windbg_execute_command`, `windbg_get_output`, `windbg_prepare_symbols`, or extension diagnostics.
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
windbg_dbgprint {"lines":100}
windbg_resume_target
```

If extension loading still fails, call `windbg_diagnose_extensions` to collect `.extpath`, `.chain`, symbol status, the load attempt, the probe command, and remediation hints.

`windbg_dbgprint` is the preferred MCP wrapper for kernel `DbgPrint` collection. It runs `!dbgprint`, loads `kdexts` by default, returns only a bounded tail unless `include_raw_output:true` is set, and reports symbol or extension hints in the structured response.

## Reverse Engineering Tools

Prefer the higher-level MCP wrappers for common breakpoint-hit work instead of manually stitching raw command strings together:

```text
windbg_set_breakpoint {"location":"nt!DbgBreakPointWithStatus","one_shot":true}
windbg_set_hardware_breakpoint {"address":"@rip","access":"execute","size":1,"one_shot":true}
windbg_trace_breakpoint {"location":"nt!DbgBreakPointWithStatus","commands":["r","kv 8"],"timeout_secs":30}
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

`windbg_set_hardware_breakpoint` wraps WinDbg `ba` for execute/read/write/io
hardware breakpoints. Prefer it for self-modifying code, packed code, or driver
code pages where software `bp` patching can perturb behavior. Execute
breakpoints must use `size: 1`; read/write watchpoints can use sizes 1, 2, 4,
or 8 and can be scoped with `process_name`, `pid`, `eprocess`, or `ethread`.

`windbg_step`, `windbg_step_over`, and `windbg_go_up` wrap `t`, `p`, and `gu`.
They wait for a stable command-ready break before returning, so clients do not
have to guess whether a temporary step stop is actually usable. For register
subsets, call `windbg_read_registers {"registers":[...]}` instead of raw
`r rip rax rcx`; the MCP intentionally splits those reads into isolated
commands.

Use `windbg_trace_breakpoint` when you want trace-style logging without leaving
capture to a WinDbg command breakpoint. It sets a temporary software or hardware
breakpoint, resumes, waits for stable hit(s), runs default or caller-provided
capture commands synchronously, clears the new breakpoint IDs, and resumes by
default. This is safer than `bp addr ".echo ...; r; dd ...; g"` in headless
mode because the captured output is returned directly in the MCP response.

## Kernel Driver Tools

Prefer the driver-aware MCP wrappers when tracing a kernel driver:

```text
windbg_set_driver_load_breakpoint {"image":"ShadowGateSys.sys","clear_existing":true}
windbg_continue_until_break {"timeout_secs":60}
windbg_driver_summary {"name":"ShadowGate","device":"\\Device\\ShadowGate"}
windbg_set_driver_dispatch_breakpoints {"driver":"ShadowGate","functions":["IRP_MJ_CREATE","IRP_MJ_CLOSE","IRP_MJ_DEVICE_CONTROL"]}
windbg_continue_until_break {"timeout_secs":60}
windbg_driver_dispatch_snapshot {"irp":"@rdx","driver_object":"@rcx","stack_count":32,"memory_count":32}
windbg_ioctl_snapshot {"buffer_count":132}
windbg_resume_target
```

`windbg_set_driver_load_breakpoint` prepares `nt` symbols by default before it mutates `sxe ld:<image>` filters, because some dbgeng builds are unstable when symbol preparation happens after synthetic load-filter changes. Raw `sxd ld*` is blocked in headless mode after live testing showed it can crash dbgeng following a load event. `windbg_driver_summary` parses the `!drvobj <name> 7` dispatch table into structured `IRP_MJ_*` entries so an MCP client can choose handlers without scraping raw text. `windbg_set_driver_dispatch_breakpoints` targets create/close/device-control handlers when present and skips default `nt!IopInvalidDeviceRequest` handlers unless `include_default_handlers` is true. `windbg_ioctl_snapshot` is the preferred quick capture for IOCTL reversing; by default it probes common IRP registers and returns parsed IOCTL lengths/code plus a SystemBuffer byte prefix. Pass `irp` and `system_buffer` explicitly only when auto-detection is not enough for an unusual handler.

For minifilter communication-port drivers that use `FltCreateCommunicationPort`
and `FilterSendMessage`, break at the message callback and call:

```text
windbg_minifilter_message_snapshot {"input_count":256}
```

The defaults match the x64 callback ABI: `InputBuffer=@rdx`,
`InputBufferLength=@r8`, `OutputBuffer=@r9`,
`OutputBufferLength=poi(@rsp+28)`, and
`ReturnOutputBufferLength=poi(@rsp+30)`.

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

Do not run `sxd ld` or `sxd ld:<image>` after a load event in headless mode.
The MCP server rejects those raw commands so an access violation in dbgeng does
not take down the stdio process. Prefer a fresh short session for one load
event, then clear ordinary code/data breakpoints with `windbg_clear_breakpoint`.
`windbg_clear_breakpoint` disables the target breakpoint with `bd` before
clearing it by default; pass `safe:false` only when you explicitly need the raw
`bc` behavior.

## Recovery

If SSH stops responding after a test, assume the target is broken before assuming the VM is dead. Open or reuse a session and call:

```text
windbg_recover_session
```

The default behavior resumes a broken target and reports before/after state.
