# Kernel Driver Debugging Implementation Notes

This document records the current technical design for kernel-driver debugging in the headless MCP runtime. It is intended for maintainers who need to extend or debug the MCP tools without rediscovering the dbgeng/KDNET edge cases.

## Scope

The maintained runtime is `windbg_mcp_headless`, a stdio MCP server that owns dbgeng sessions directly. Kernel targets are opened through `windbg_open_session` with normal WinDbg `-k` connection options, then controlled through MCP tools.

The driver-debugging layer is intentionally a set of higher-level wrappers on top of dbgeng text commands. The goal is to make common reverse-engineering actions available as structured MCP operations:

- Break when a driver image loads.
- Set software or hardware breakpoints without relying on raw WinDbg command strings.
- Capture trace-style breakpoint hits synchronously through MCP instead of relying on command-breakpoint output callbacks.
- Step through code with MCP-managed stable-break polling.
- Inspect a driver object and parse its `IRP_MJ_*` dispatch table.
- Set breakpoints on selected driver dispatch routines.
- Collect a breakpoint-hit snapshot with registers, IRP data, driver object data, stack, disassembly, and memory.
- Collect an IOCTL-focused snapshot with decoded IO stack arguments and buffered I/O memory.
- Collect a minifilter communication-port message snapshot with callback
  registers, stack arguments, input/output buffers, and parsed message header.
- Collect recent kernel `DbgPrint` output without forcing clients to scrape raw
  debugger output history.

## Tool Surface

### `windbg_dbgprint`

Purpose: read kernel `DbgPrint` output through WinDbg's `!dbgprint` extension
command and return a bounded, structured MCP payload.

Important arguments:

- `lines`: optional tail length. Defaults to 200 and clamps to 5000 to avoid
  oversized stdio responses.
- `include_raw_output`: optional. Defaults to false. When true, the response
  includes the complete `!dbgprint` text in `raw_output`.
- `load_extension`: optional. Defaults to true and runs `.load kdexts` before
  `!dbgprint`.
- `prepare_symbols`: optional. Defaults to false. When true, prepares exact
  `nt` symbols before loading the extension.

Implementation details:

- Uses `diagnostic_command_step` for optional `kdexts` loading so extension
  failures are captured as structured steps.
- Executes `!dbgprint` through the normal command path, then returns `lines`,
  `line_count`, `returned_line_count`, `truncated`, and a joined `output` tail.
- Reports `symbol_problem`, `extension_problem`, and remediation
  `recommendations`.
- Does not auto-interrupt a running target; callers should break into the VM
  explicitly with `windbg_interrupt_target` when command execution is needed.

### `windbg_set_hardware_breakpoint`

Purpose: set a hardware execute breakpoint or data watchpoint using WinDbg
`ba`, without patching the target instruction stream.

Important arguments:

- `address`: debugger expression or symbol for the address to monitor.
- `access`: `execute`, `read`, `write`, or `io` plus short aliases `e`, `r`,
  `w`, and `i`.
- `size`: 1, 2, 4, or 8 bytes. Execute breakpoints must use size 1.
- `process_name`, `pid`, or `eprocess`: optional `/p <EPROCESS>` scoping.
- `ethread`: optional `/t <ETHREAD>` scoping.
- `one_shot`, `pass_count`, and `command`: forwarded to WinDbg breakpoint
  creation.

Implementation details:

- Builds commands as `ba <access> <size> [options] <address> [passes] ["cmd"]`.
- Reuses the existing `!process` lookup path when process scoping is requested.
- Lists breakpoints with `bl` after creation.
- Intended for self-modifying code, packed user-mode code, or driver code pages
  where software `bp` patching changes behavior.

### Stable Stepping Tools

`windbg_step`, `windbg_step_over`, and `windbg_go_up` wrap WinDbg `t`, `p`, and
`gu`.

Implementation details:

- Each tool issues the step command through the normal dbgeng command path.
- The shared `poll_until_stable_break` helper then polls
  `windbg_get_execution_state`.
- By default, a break must remain command-ready across the settle window before
  the tool returns success.
- Timeout responses include `transient_breaks`, `last_observed_break_state`,
  and `last_unstable_break_state` to make short-lived stops diagnosable.

This exists because live ACE testing showed raw `gu` can return immediately
while the target is still in `go`, which makes a naive MCP client think it can
read registers when dbgeng is not actually command-ready.

### Register and Breakpoint Safety

`windbg_read_registers` treats multi-register subsets as a sequence of isolated
`r <register>` commands. Raw `windbg_execute_command` blocks fragile
`r rip rax rcx`-style reads because this exact form produced transient
`0x80040205` dbgeng states in live testing.

`windbg_clear_breakpoint` defaults to a safer cleanup path: `bd <breakpoint>`
before `bc <breakpoint>`, then `bl`. This is not a full instruction-pointer
software-breakpoint restoration engine, but it avoids the most abrupt clear
sequence while stopped on or near active breakpoints. Pass `safe:false` to use
plain `bc` directly.

For process-scoped user-mode virtual addresses, prefer
`windbg_set_hardware_breakpoint` with `access:"execute"` and `size:1`. Live
KDNET testing showed software `bp /p <EPROCESS> <user_va>` can create a
breakpoint ID without hitting reliably, even after switching context, while
hardware `ba e 1 /p <EPROCESS> <user_va>` hit correctly. The process-scoped
tools can switch debugger process context with `.process /p /r <EPROCESS>`
before setting the breakpoint. They do this automatically when the address
parses as a low canonical user-mode VA, or callers can force it with
`set_context:true`. `windbg_set_process_breakpoint` rejects low user-mode VA
software breakpoints by default; pass `allow_user_software:true` only for
explicit experiments.

### `windbg_trace_breakpoint`

Purpose: provide a reliable headless replacement for command-breakpoint trace
logging.

Important arguments:

- `location`: software breakpoint location or hardware breakpoint address.
- `hardware`, `access`, and `size`: optional hardware `ba` mode.
- `process_name`, `pid`, `eprocess`, and `ethread`: optional breakpoint scoping.
- `hits`: number of stable hits to capture. Defaults to 1.
- `commands`: extra debugger commands to run at each hit.
- `include_default_snapshot`: defaults to true and captures `.lastevent`, `r`,
  `u @rip L16`, `kv 16`, and `bl`.
- `auto_resume`: defaults to true.
- `clear_after`: defaults to true.

Implementation details:

- Lists `bl` before and after setting the breakpoint, then diffs breakpoint IDs
  so cleanup only targets the breakpoint IDs created by the trace tool.
- Uses `windbg_continue_until_break` semantics for every hit, including stable
  break settling and transient-break diagnostics.
- Runs capture commands synchronously through `diagnostic_command_step`, so each
  command's output is embedded in the MCP response.
- Clears created breakpoints while the target is command-ready, then resumes the
  target when `auto_resume` is true.

This tool is the preferred replacement for raw WinDbg commands like:

```text
bp <addr> ".echo hit; r; dd @rsp L20; g"
```

Live ACE testing showed that self-continuing command breakpoints can lose or
misorder output in a stdio MCP client. `windbg_trace_breakpoint` keeps capture
inside explicit MCP calls, which is slower but much more deterministic.

### `windbg_set_driver_load_breakpoint`

Purpose: configure a synthetic driver-load break event.

Important arguments:

- `image`: driver image name, for example `ShadowGateSys.sys`.
- `clear_existing`: retained for API compatibility, but safely skipped in
  headless mode for `ld` filters.
- `prepare_symbols`: defaults to true.

Implementation details:

- Validates `image` with `debugger_atom` to reject command separators, quotes, and newlines.
- Calls `windbg_prepare_symbols` for `nt` by default before mutating any `sxe ld:<image>` filter.
- Skips raw `sxd ld:<image>` even when `clear_existing` is true, because live
  testing showed that disabling `ld` filters after a load event can
  access-violate inside dbgeng and kill the stdio MCP process.
- Runs `sxe ld:<image>`, then `sx`.
- Returns structured `steps` and the configured `event_filter`.

The symbol-first behavior is deliberate. Live KDNET testing showed dbgeng can crash if exact PDB preparation is attempted after synthetic load-filter mutations. Preparing `nt` symbols before `sxe ld:<image>` avoided that unstable path in testing.

### `windbg_driver_summary`

Purpose: collect a driver-oriented summary and expose dispatch routines as structured data.

Important arguments:

- `name`: driver object name, usually `ShadowGate`, `\Driver\ShadowGate`, or another driver object path.
- `module_pattern`: optional `lm m <pattern>` value. Defaults to `<short-name>*`.
- `device`: optional device object path. When provided, additional device commands are run.
- `prepare_symbols`: defaults to false.

Implementation details:

- Normalizes a short driver name with `driver_short_name`.
- Runs `lm m <module_pattern>`.
- Runs `!drvobj <name> 7` and parses the output with `parse_driver_dispatch_routines`.
- Runs `!object <driver-object-path>`.
- If `device` is provided, also runs `!object <device>`, `!devobj <device>`, and `!devstack <device>`.
- Returns `dispatch_routines`, `symbol_problem`, and remediation `recommendations`.

`prepare_symbols` is opt-in here because the preferred flow is to prepare symbols before configuring load filters through `windbg_set_driver_load_breakpoint`. This avoids repeating the unstable post-filter symbol-preparation sequence.

### `windbg_set_driver_dispatch_breakpoints`

Purpose: set breakpoints on selected IRP major-function dispatch handlers.

Important arguments:

- `driver`: driver object name or path passed to `!drvobj <driver> 7`.
- `functions`: optional list such as `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, `IRP_MJ_DEVICE_CONTROL`, `device_control`, or an index such as `0e`.
- `include_default_handlers`: defaults to false.
- `one_shot`: forwarded to breakpoint creation.
- `command`: optional WinDbg command string attached to each breakpoint.
- `prepare_symbols`: defaults to false.

Implementation details:

- Parses `!drvobj <driver> 7` output using the same dispatch parser as `windbg_driver_summary`.
- If `functions` is omitted, the default selection is `IRP_MJ_CREATE`, `IRP_MJ_CLOSE`, and `IRP_MJ_DEVICE_CONTROL`.
- If that default selection yields no non-default handlers, falls back to all non-default dispatch routines.
- Uses `build_breakpoint_command` to create safe `bp` commands.
- Lists current breakpoints with `bl` after setting them.

Default handlers are detected from either the resolved target text or the optional symbol column. Real WinDbg output can look like this:

```text
[0e] IRP_MJ_DEVICE_CONTROL              fffff805`6a8b9050 nt!IopInvalidDeviceRequest
```

The parser records `target = fffff805\`6a8b9050` and `symbol = nt!IopInvalidDeviceRequest`, so default handlers are skipped unless explicitly requested.

### `windbg_driver_dispatch_snapshot`

Purpose: collect a structured snapshot after a dispatch breakpoint hit.

Important arguments:

- `irp`: defaults to `@rdx`, the typical IRP argument in x64 driver dispatch routines.
- `driver_object`: defaults to `@rcx`, the typical driver/device object argument in x64 dispatch routines.
- `stack_count`: defaults to 32.
- `memory_count`: defaults to 32.

Implementation details:

The tool runs each command through `diagnostic_command_step`, so failures are captured as step errors instead of aborting the whole snapshot. Current commands:

```text
.lastevent
r
!irp <irp>
dt nt!_IRP <irp>
dq <irp> L<count>
dt nt!_DRIVER_OBJECT <driver_object>
!drvobj <driver_object> 7
dq <driver_object> L16
kv <stack_count>
u rip L16
bl
```

The defaults are optimized for common x64 `DRIVER_OBJECT`/`IRP` dispatch handlers. For unusual calling conventions or breakpoints placed deeper inside a handler, callers should pass explicit `irp` and `driver_object` expressions.

### `windbg_ioctl_snapshot`

Purpose: collect the common IRP/IOCTL context needed while reversing buffered driver protocols.

Important arguments:

- `irp`: optional. When omitted, the tool probes common IRP-holding registers such as `@rdx`, `@r15`, `@rsi`, `@rbx`, and friends with `!irp`. It falls back to `@rdx` if no candidate looks like an IRP. Pass an explicit expression when you already know the handler's cached IRP register.
- `auto_detect`: defaults to true. Set false to preserve the older dispatch-entry behavior without candidate probing.
- `candidate_irps`: optional ordered register/expression list for auto-detection.
- `system_buffer`: defaults to a SystemBuffer pointer parsed from the detected `!irp` output when available, otherwise `poi(<irp>+18)`. Pass a register such as `@r14` when a handler has cached the buffer and you want to force that expression.
- `stack_location`: defaults to `poi(<irp>+b8)`, matching `IRP.Tail.Overlay.CurrentStackLocation` on the validated Windows 10 19041 target.
- `buffer_count`: defaults to `0x84`, useful for many small IOCTL protocols.

Implementation details:

The tool runs the standard IOCTL triage cluster: `.lastevent`, `r`, `u @rip`, `kv`, `!irp`, `dt nt!_IRP`, IRP memory, current stack-location qwords, IOCTL/input/output dwords, SystemBuffer bytes/dwords/qwords, and `bl`.

This is deliberately still text-command based, but it packages the exact command cluster we repeatedly need at IOCTL breakpoints. The response now includes `selection_source`, `system_buffer_source`, `auto_detect.steps`, and a parsed `summary` with:

- `irp_valid`
- `ioctl.output_buffer_length`
- `ioctl.input_buffer_length`
- `ioctl.ioctl_code`
- `ioctl.type3_input_buffer`
- `system_buffer_from_irp`
- `system_buffer_first_bytes`
- `system_buffer_first_hex`

This makes ShadowGate-style dispatch internals easier to inspect because clients no longer have to know up front that the handler cached the IRP in `@r15`, nor do they need to scrape `Args:` from raw `!irp` output for common IOCTL metadata.

### `windbg_minifilter_message_snapshot`

Purpose: collect the common context needed while reversing minifilter
communication-port protocols using `FltCreateCommunicationPort` /
`FilterSendMessage`.

Important arguments:

- `input_buffer`: defaults to `@rdx`.
- `input_length`: defaults to `@r8`.
- `output_buffer`: defaults to `@r9`.
- `output_length`: defaults to `poi(@rsp+28)`.
- `return_length_ptr`: defaults to `poi(@rsp+30)`.
- `input_count` and `output_count`: default to 128 bytes.
- `stack_count` and `backtrace_count`: default to 32 entries.

Implementation details:

The defaults match the Windows x64
`PFLT_MESSAGE_NOTIFY`/`MessageNotifyCallback` ABI:

```c
NTSTATUS MessageNotifyCallback(
  PVOID PortCookie,
  PVOID InputBuffer,
  ULONG InputBufferLength,
  PVOID OutputBuffer,
  ULONG OutputBufferLength,
  PULONG ReturnOutputBufferLength
);
```

The tool captures `.lastevent`, registers, `u @rip`, `kv`, stack qwords,
evaluated length/pointer expressions, input bytes/dwords/qwords, output bytes,
and `bl`. The summary parses the first two DWORDs of the input buffer as a
message header. For ACE-style minifilter challenges this surfaced the message
id, transformed payload length, and payload bytes directly from live debugger
state.

## Dispatch Parser

The parser lives in `src/server.rs` as `parse_driver_dispatch_routines`.

It scans lines containing `IRP_MJ_`, splits whitespace, and extracts:

- `index`: optional bracketed dispatch index, for example `0e`.
- `major_function`: the `IRP_MJ_*` name.
- `target`: the first token after the major-function name.
- `symbol`: optional second token after the target, unless it is an offset token such as `+0xffff...`.
- `raw`: the original trimmed line.

Selection helpers:

- `normalize_dispatch_filter` maps `device_control`, `MJ_DEVICE_CONTROL`, and `IRP_MJ_DEVICE_CONTROL` into a comparable form.
- `dispatch_filter_matches` supports matching by major-function name or dispatch index.
- `is_default_dispatch_routine` skips `nt!IopInvalidDeviceRequest` by default.

Unit coverage currently checks parsing of real-style dispatch rows, symbol-column default-handler detection, function-name matching, index matching, and driver-name normalization.

## Recommended Runtime Flow

For a driver that is not loaded yet:

```text
windbg_open_session
windbg_set_driver_load_breakpoint {"image":"ShadowGateSys.sys"}
windbg_continue_until_break
windbg_driver_summary {"name":"ShadowGate"}
windbg_set_driver_dispatch_breakpoints {"driver":"ShadowGate","functions":["IRP_MJ_DEVICE_CONTROL"]}
windbg_resume_target
trigger the user-mode client or service action
windbg_continue_until_break
windbg_driver_dispatch_snapshot {"irp":"@rdx","driver_object":"@rcx"}
windbg_ioctl_snapshot {"irp":"@rdx"}
windbg_resume_target
```

For a minifilter communication-port callback:

```text
windbg_set_breakpoint {"location":"ACEDriver+0x1280"}
windbg_resume_target
trigger FilterSendMessage from the guest
windbg_continue_until_break
windbg_minifilter_message_snapshot {"input_count":256}
windbg_resume_target
```

For an already loaded driver:

```text
windbg_interrupt_target
windbg_prepare_symbols {"module":"nt"}
windbg_driver_summary {"name":"\\Driver\\Null"}
windbg_set_driver_dispatch_breakpoints {"driver":"\\Driver\\Null","functions":["IRP_MJ_CREATE"]}
windbg_resume_target
```

Keep the target running when not actively inspecting. A broken kernel target pauses the whole guest, including SSH and networking.

## Validation Performed

The following validation was performed after adding the driver tools and the
DbgPrint interface:

```powershell
cargo fmt --check
cargo test
cargo build --release --bin windbg_mcp_headless
python tools\headless_mcp_smoke.py
```

For the DbgPrint addition, `cargo test` includes a mock dispatcher regression
that executes `.load kdexts` and `!dbgprint`, then verifies bounded tail output.
The stdio smoke confirmed `windbg_dbgprint` appears in the 43-tool list. A live
KDNET smoke was attempted, but the target remained in `no_debuggee` during the
attach window; the session cleanup path closed cleanly without storing
connection secrets in repository files.

Live KDNET validation used a real VM and did not store connection secrets in repository files. The live-safe chain validated:

- MCP stdio tool listing exposed 43 tools, including
  `windbg_minifilter_message_snapshot` and `windbg_dbgprint`.
- `windbg_set_driver_load_breakpoint` configured a non-matching synthetic load filter after preparing `nt` symbols.
- `windbg_driver_summary` parsed `\Driver\Null` into 28 dispatch routines.
- `windbg_set_driver_dispatch_breakpoints` set one `IRP_MJ_CREATE` dispatch breakpoint and `windbg_clear_breakpoint` removed it.
- `windbg_driver_dispatch_snapshot` returned 11 diagnostic steps.
- `windbg_ioctl_snapshot` was live-validated against ShadowGate `IRP_MJ_DEVICE_CONTROL`, decoding `0x80012004`, input length `0x0c`, output length `0x84`, and the buffered move packet.
- `windbg_minifilter_message_snapshot` was live-validated against ACE
  `ACEDriver.sys`, capturing the `MessageNotifyCallback` input buffer,
  message id, payload length, registers, stack, disassembly, and backtrace.
  At `ACEDriver+0x1280`, the tool parsed `InputBufferLength=1032` and
  message header `{ message_id: 0x00154004, payload_length: 28 }`, with the
  transformed payload beginning `33 1b 4f 4b 32 34 3e 20 ...`.
- `windbg_close_session` resumed the target before detach and guest SSH became reachable afterward.

After hardening `windbg_interrupt_target`, a second live retest left the target
running for a short soak, then broke in again and executed `vertarget`
successfully. This validates the repeated break-in retry path used for
long-running KDNET sessions.

Additional live dynamic validation was performed without using the earlier
ShadowGate helper scripts. A temporary guest-side PowerShell P/Invoke trigger
only opened `\\.\ShadowGate` and issued one `DeviceIoControl` call; the MCP did
all debugger-side observation. That run confirmed:

- A one-shot breakpoint at ShadowGate `base+0x317463` hit on the real MOVE path.
- `windbg_read_registers` returned `rip=base+0x317463`, `r14=SystemBuffer`, `r15=IRP`, and `rdx=0x80012004`.
- `windbg_disassemble`, `windbg_backtrace`, and `windbg_read_memory` worked at the live breakpoint.
- `windbg_ioctl_snapshot {"irp":"@r15","system_buffer":"@r14"}` produced `!irp`, `dt nt!_IRP`, IO stack argument, and SystemBuffer dumps.
- The decoded IO stack arguments were `00000084 0000000c 0x80012004 00000000`.
- The SystemBuffer began with `52 00 00 00 00 00 00 00 65 13 ad de`, matching the encoded `W` MOVE packet.
- After `windbg_resume_target` and `windbg_close_session`, the guest was reachable over SSH again.
- A deeper dynamic run set code breakpoints in the ShadowGate final transform and captured the runtime materialized string block from debugger-side memory reads. The concrete string was `flag{SHAD0WNT_HYPERVMX}`, with the first 16 bytes observed at the XMM source load and output store instructions. See `docs/shadowgate-crypto-reversing.md` for the exact RVAs and memory dumps.

The hardened auto-detection path was then live-validated at the same ShadowGate
MOVE breakpoint by calling `windbg_ioctl_snapshot {"buffer_count":132}` without
explicit `irp` or `system_buffer` arguments. The tool rejected `@rdx` because it
contained the IOCTL code, selected `@r15` as the IRP, parsed the SystemBuffer
pointer from `!irp`, and returned:

```text
selection_source = auto_detect
irp = @r15
system_buffer_source = auto_detect_irp_output
summary.ioctl.input_buffer_length = 12
summary.ioctl.output_buffer_length = 132
summary.ioctl.ioctl_code = 0x80012004
summary.system_buffer_first_hex = 52000000000000006513adde...
```

This is the preferred validation style for future driver work: use a minimal
guest trigger only to create real IO, and collect all protocol, register, stack,
IRP, and memory evidence through MCP tools.

## Known Limitations

- Public Microsoft symbols may still lack private type detail for some extension commands. The tools capture symbol problems and recommendations but cannot invent missing private types.
- Some dbgeng builds are sensitive to command ordering around synthetic load events. Keep symbol preparation before load-filter mutation and avoid raw `sxd ld*`; the MCP server blocks that crash-prone path.
- `lm m <driver>*` may be empty for some drivers even when `!drvobj <driver> 7` resolves the object. Treat `!drvobj` as the stronger signal for ShadowGate-style workflows.
- `windbg_driver_dispatch_snapshot` assumes the breakpoint is at or near a normal x64 dispatch routine entry. If the breakpoint is deeper in the handler, pass explicit IRP and object expressions.
- `windbg_ioctl_snapshot` collects generic buffered-IOCTL context, but protocol-specific decoding is still left to the caller. For example, ShadowGate's move packet fields are documented separately in `docs/shadowgate-crypto-reversing.md`.
- Hardware data breakpoints on kernel stack scratch addresses can be noisy because interrupts and scheduler paths reuse the same stack region. Prefer precise code breakpoints around known transform/load/store instructions when tracing obfuscated driver output materialization.

## Maintenance Checklist

When modifying driver-debugging behavior:

- Add or update unit tests for parser changes.
- Run `cargo fmt --check` and `cargo test`.
- Rebuild the release binary before stdio smoke testing.
- Run `python tools\headless_mcp_smoke.py` and confirm the expected tool count.
- For live KDNET tests, use placeholder documentation only and scan changed docs/source for connection keys, passwords, or VM-specific addresses before committing.
- If a live test leaves the VM unreachable, first assume the kernel is broken in the debugger and recover or close the session with resume enabled.
