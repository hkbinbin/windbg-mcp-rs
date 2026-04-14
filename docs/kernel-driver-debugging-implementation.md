# Kernel Driver Debugging Implementation Notes

This document records the current technical design for kernel-driver debugging in the headless MCP runtime. It is intended for maintainers who need to extend or debug the MCP tools without rediscovering the dbgeng/KDNET edge cases.

## Scope

The maintained runtime is `windbg_mcp_headless`, a stdio MCP server that owns dbgeng sessions directly. Kernel targets are opened through `windbg_open_session` with normal WinDbg `-k` connection options, then controlled through MCP tools.

The driver-debugging layer is intentionally a set of higher-level wrappers on top of dbgeng text commands. The goal is to make common reverse-engineering actions available as structured MCP operations:

- Break when a driver image loads.
- Inspect a driver object and parse its `IRP_MJ_*` dispatch table.
- Set breakpoints on selected driver dispatch routines.
- Collect a breakpoint-hit snapshot with registers, IRP data, driver object data, stack, disassembly, and memory.
- Collect an IOCTL-focused snapshot with decoded IO stack arguments and buffered I/O memory.

## Tool Surface

### `windbg_set_driver_load_breakpoint`

Purpose: configure a synthetic driver-load break event.

Important arguments:

- `image`: driver image name, for example `ShadowGateSys.sys`.
- `clear_existing`: when true, runs `sxd ld:<image>` before `sxe ld:<image>`.
- `prepare_symbols`: defaults to true.

Implementation details:

- Validates `image` with `debugger_atom` to reject command separators, quotes, and newlines.
- Calls `windbg_prepare_symbols` for `nt` by default before mutating any `sxe/sxd ld:<image>` filter.
- Runs `sxd ld:<image>` when requested, then `sxe ld:<image>`, then `sx`.
- Returns structured `steps` and the configured `event_filter`.

The symbol-first behavior is deliberate. Live KDNET testing showed dbgeng can crash if exact PDB preparation is attempted after synthetic load-filter mutations. Preparing `nt` symbols before `sxe/sxd ld:<image>` avoided that unstable path in testing.

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
windbg_set_driver_load_breakpoint {"image":"ShadowGateSys.sys","clear_existing":true}
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

The following validation was performed after adding the driver tools:

```powershell
cargo fmt --check
cargo test
cargo build --release --bin windbg_mcp_headless
python tools\headless_mcp_smoke.py
```

Live KDNET validation used a real VM and did not store connection secrets in repository files. The live-safe chain validated:

- MCP stdio tool listing exposed 36 tools.
- `windbg_set_driver_load_breakpoint` configured a non-matching synthetic load filter after preparing `nt` symbols.
- `windbg_driver_summary` parsed `\Driver\Null` into 28 dispatch routines.
- `windbg_set_driver_dispatch_breakpoints` set one `IRP_MJ_CREATE` dispatch breakpoint and `windbg_clear_breakpoint` removed it.
- `windbg_driver_dispatch_snapshot` returned 11 diagnostic steps.
- `windbg_ioctl_snapshot` was live-validated against ShadowGate `IRP_MJ_DEVICE_CONTROL`, decoding `0x80012004`, input length `0x0c`, output length `0x84`, and the buffered move packet.
- `windbg_close_session` resumed the target before detach and guest SSH became reachable afterward.

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
- Some dbgeng builds are sensitive to command ordering around synthetic load events. Keep symbol preparation before load-filter mutation.
- `lm m <driver>*` may be empty for some drivers even when `!drvobj <driver> 7` resolves the object. Treat `!drvobj` as the stronger signal for ShadowGate-style workflows.
- `windbg_driver_dispatch_snapshot` assumes the breakpoint is at or near a normal x64 dispatch routine entry. If the breakpoint is deeper in the handler, pass explicit IRP and object expressions.
- `windbg_ioctl_snapshot` collects generic buffered-IOCTL context, but protocol-specific decoding is still left to the caller. For example, ShadowGate's move packet fields are documented separately in `docs/shadowgate-crypto-reversing.md`.

## Maintenance Checklist

When modifying driver-debugging behavior:

- Add or update unit tests for parser changes.
- Run `cargo fmt --check` and `cargo test`.
- Rebuild the release binary before stdio smoke testing.
- Run `python tools\headless_mcp_smoke.py` and confirm the expected tool count.
- For live KDNET tests, use placeholder documentation only and scan changed docs/source for connection keys, passwords, or VM-specific addresses before committing.
- If a live test leaves the VM unreachable, first assume the kernel is broken in the debugger and recover or close the session with resume enabled.
