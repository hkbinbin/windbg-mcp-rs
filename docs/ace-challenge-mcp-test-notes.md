# ACE Challenge Dynamic MCP Test Notes

This document tracks defects and workflow gaps observed while using the
headless WinDbg MCP against the 2025 Tencent PC client security challenge.
It intentionally avoids KDNET keys, VM credentials, and challenge secrets.

## Test Target

- Guest: Windows 10 x64 VM over KDNET.
- Challenge files deployed to the guest under an ASCII-only working directory.
- Main binaries:
  - `ACEFirstRound.exe`
  - `ACEDriver.sys`

## Confirmed Working Behaviors

- `windbg_open_session` can attach to the live KDNET target from stdio MCP.
- `windbg_execute_command` works for basic commands such as `vertarget`, `lm`,
  `.lastevent`, `r`, and `kv`.
- `windbg_resume_target` returns the VM to `go` state and restores SSH access
  when the kernel is paused.
- `windbg_set_driver_load_breakpoint` successfully prepares `nt` symbols and
  configures `sxe ld:ACEDriver.sys`.
- `windbg_continue_until_break` successfully catches the `ACEDriver.sys` load
  event.
- At the load event, the following normal inspection tools worked:
  - `windbg_get_output`
  - `windbg_execute_command ".lastevent"`
  - `windbg_execute_command "lm m ACEDriver*"`
  - `windbg_execute_command "r"`
  - `windbg_backtrace`
- Raw code breakpoints on `ACEDriver+0x1280`, `ACEDriver+0x9f83`,
  `ACEDriver+0x1000`, and `ACEDriver+0x1094` worked after parsing the loaded
  module base.
- `windbg_read_memory`, `windbg_disassemble`, and `windbg_backtrace` worked at
  the minifilter message callback and at the TEA-like helper entry/exit.
- Hardware data breakpoints with `ba r4` worked on stack data and static driver
  data, allowing follow-up inspection after the TEA-like helper returned.

## ACE Dynamic Findings

- The user-mode client talks to the driver through Filter Manager
  communication, not through a normal device IOCTL.
- The message callback is registered at `ACEDriver+0x1280`, which jumps into
  virtualized code at `ACEDriver+0x9f83`.
- At the callback, the Filter Manager input buffer observed in `rdx` starts
  with:
  - `0x00154004`: message id.
  - `0x0000001c`: transformed payload length for the tested 20-byte suffix.
  - 28 bytes of transformed candidate data.
- For test input `ACE_12345678901234567890`, the transformed candidate bytes
  observed after the message header were:

```text
33 1b 4f 4b 32 34 3e 20 41 25 33 0d 20 21 29 44
4f 1b 11 2b 0d 46 16 01 21 35 2d 22
```

- The virtualized callback calls a TEA-like helper at `ACEDriver+0x1000`.
- The helper return site is `ACEDriver+0x1094`.
- For the same test input, the observed helper call used key material laid out
  as DWORDs for `A`, `C`, `E`, `6`.
- A data watchpoint after the TEA-like helper showed a real executed code path
  entering the middle of the virtualized region near `ACEDriver+0x9c51`, with
  the useful decoded sequence:

```asm
mov     dword ptr [rsp+24h], eax
call    ACEDriver+0x1000
mov     eax, dword ptr [rsi-4]
cmp     dword ptr [rsp+20h], eax
```

- During that comparison, `rsi` pointed at `ACEDriver+0x4064`, so the first
  comparison target was the DWORD at `ACEDriver+0x4060`.
- Static driver data at `ACEDriver+0x4060` begins with:

```text
b8 67 c3 0e 44 90 da c9 eb 2d 6c da c3 c9 dd 88
75 15 a0 32 b4 d0 1d 23 74 8a 9e 4b 74 3e 5d d7
```

- This initial trace left a static/dynamic helper mismatch. The mismatch was
  resolved later by single-stepping the helper and observing a runtime-generated
  trampoline; see the solution update below.

## ACE Solution Update

- The helper mismatch was resolved dynamically. `ACEDriver+0x1000` starts like a
  TEA helper, but live single-stepping shows the second half of each round jumps
  through runtime-generated code. The effective routine is a mixed TEA/XTEA-like
  32-round transform.
- The runtime trampoline explains why static emulation of the file bytes
  produced `0xbbb25fdc, 0x19a8846b` for `(0x33, 0x1b)`, while the real driver
  produced `0x50a1c8d3, 0x55e2345b`.
- Inverting only the first 32 DWORDs at `ACEDriver+0x4060` produced a short
  binary prefix-collision input that the program also accepts. That was useful
  for proving the dynamic algorithm, but it was not the intended printable
  contest flag.
- Inverting the complete 42-DWORD driver table at `ACEDriver+0x4060` produced
  the intended transformed payload:

```text
33 28 13 00 2d 16 40 41 13 2a 12 4f 45 4b 1f 14
39 49 3b 34 3a 26 3b 19 24 2b 22 05 4c 0e 00 4c
3b 04 2b 1d 05 39 16 22 3d 0b
```

- The EXE transform uses a custom base58 alphabet and a repeating XOR key
  `sxx`. Reversing the complete transform gives the printable 30-byte suffix
  `We1C0me!T0Z0Z5GamESecur1t9*CTf`.
- The intended printable user-mode input is:

```text
ACE_We1C0me!T0Z0Z5GamESecur1t9*CTf
```

- The challenge submission string is:

```text
flag{ACE_We1C0me!T0Z0Z5GamESecur1t9*CTf}
```

- Full write-up: `docs/ace-challenge-solution.md`.

## Fixes Implemented After This Test

- `windbg_execute_command` now rejects raw `sxd ld*` before it reaches dbgeng,
  preventing the observed access violation from taking down the stdio MCP
  process.
- `windbg_set_driver_load_breakpoint` no longer executes `sxd ld:<image>` when
  `clear_existing` is true. It records a skipped diagnostic step instead.
- `windbg_continue_until_break` now waits for a short stable break window before
  returning, which avoids reporting transient break states as command-ready.
- `windbg_close_session` now performs multiple resume/state verification passes
  before detaching live kernel sessions.
- `windbg_interrupt_target` now reissues break-in requests while waiting, so a
  long-running KDNET target that ignores the first active interrupt is not left
  stuck in `go` until timeout.
- `windbg_minifilter_message_snapshot` was added for
  `FltCreateCommunicationPort` / `FilterSendMessage` callbacks.
- `windbg_find_process` keeps preparing `nt` symbols by default, and its tool
  description now makes that default explicit.

## Observed Defects

### P0: `sxd ld` after a driver load event can crash the MCP process

Repro observed during ACE challenge dynamic testing:

1. Open a KDNET session.
2. Configure `sxe ld:ACEDriver.sys`.
3. Start the challenge app from the guest.
4. Wait for the driver load break.
5. Execute either `sxd ld:ACEDriver.sys` or, in a later run, `sxd ld`.

Observed result:

- `windbg_mcp_headless.exe` exits with `0xC0000005`.
- Subsequent tool calls fail with pipe errors such as `OSError [Errno 22]`.
- The VM can remain paused and must be recovered by opening a new MCP session
  and issuing `windbg_resume_target`.

Workaround:

- Do not issue `sxd ld*` immediately after a load-event break. The MCP now
  blocks this raw command path.
- Leave the load filter in place for the short-lived session, set concrete code
  breakpoints after parsing the module base, then clear normal breakpoints with
  `bc *` before resuming/closing.
- Longer term, a stronger isolation model could still put dbgeng in a child
  process so any future native crash cannot kill the stdio MCP server.

### P1: Session close can report success while the VM later reconnects in break

After a load-event debug run, `windbg_close_session` reported a clean shutdown
with `resume_attempted: false` because the last observed state was `go`.
Shortly after, SSH became unreachable. A new MCP session reattached to a
`DbgBreakPointWithStatus` break state and required `windbg_resume_target`.

Impact:

- Automation can mistake a paused VM for an SSH/network failure.
- `close_session` may need an optional post-close/reconnect verification mode,
  or the workflow should prefer explicit `recover/resume` before teardown.

### P2: No minifilter communication snapshot helper

`ACEDriver.sys` is a minifilter that communicates through
`FltCreateCommunicationPort` / `FilterSendMessage`, not an ordinary
`IRP_MJ_DEVICE_CONTROL` path. Existing helpers such as `windbg_ioctl_snapshot`
are useful for device-control drivers but do not directly parse the
`MessageNotifyCallback` ABI:

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

Desired helper:

- `windbg_minifilter_message_snapshot`
- Capture registers, stack arguments, input/output buffers, buffer lengths,
  caller process/thread, backtrace, and RIP disassembly at a Filter Manager
  message callback breakpoint.

Status:

- Implemented as `windbg_minifilter_message_snapshot`.
- Defaults match the x64 callback ABI: `InputBuffer=@rdx`,
  `InputBufferLength=@r8`, `OutputBuffer=@r9`,
  `OutputBufferLength=poi(@rsp+28)`, and
  `ReturnOutputBufferLength=poi(@rsp+30)`.
- Live retest at `ACEDriver+0x1280` captured the real callback stop:
  `rip=ACEDriver+0x1280`, `rdx=InputBuffer`, `r8=0x408`, and the first input
  bytes parsed as message id `0x00154004` with payload length `0x1c`.
  The transformed payload prefix was
  `33 1b 4f 4b 32 34 3e 20 41 25 33 0d 20 21 29 44`.

### P3: Process-scoped user breakpoint hit can lose the break state

`windbg_set_process_breakpoint` successfully set one-shot user-mode breakpoints
for `ACEFirstRound.exe` with WinDbg `bp /1 /p <EPROCESS> <user_va>`.

Observed sequence:

1. Start `ACEFirstRound.exe` under a PowerShell harness that keeps stdin open.
2. Interrupt the VM.
3. Run `windbg_find_process` with `prepare_symbols: true`.
4. Switch process context and parse the user module base.
5. Set process-scoped breakpoints at user addresses.
6. Resume and wait with `windbg_continue_until_break`.

Observed result:

- `windbg_continue_until_break` returned `final_state.status_name = break`.
- The next command, `.lastevent`, timed out waiting for the kernel host.
- Follow-up commands reported the debugger was already back in `go` state.
- The user-mode breakpoint site was not captured.

Impact:

- Process-scoped user breakpoints can be set, but the current event/command
  synchronization is not stable enough for reliable user-mode stack inspection.
- This affects dynamic extraction of EXE-side locals such as the runtime XOR
  key and transformed flag buffer.

Follow-up:

- Retest a user-mode `/p` breakpoint and immediately run `.lastevent`, `r`, and
  memory reads after the new stable-break confirmation. Kernel driver
  breakpoints and minifilter callback breakpoints were retested successfully.
- Investigate whether the command host is auto-continuing, timing out inside
  dbgeng after user-mode break events, or racing state refresh.

### P4: `windbg_find_process` needs symbol-preparation guardrails

Calling `windbg_find_process` with `prepare_symbols: false` returned no matches
and only `NT symbols are incorrect, please fix symbols`. The same call with
`prepare_symbols: true` prepared `nt` and found the process correctly.

This is expected behavior, but the tool UX could be improved:

- Default `prepare_symbols` to true for process lookup, or
- Return an explicit structured hint when the output contains
  `NT symbols are incorrect`.

### P5: Guest orchestration still lives outside MCP

The dynamic workflow needs SSH/SFTP for copying files, starting the user-mode
client, and checking VM liveness. This currently uses external Paramiko scripts.
That is acceptable for manual testing, but long-running challenge workflows
would benefit from documented helper scripts or an explicit non-secret harness.

### P6: Short code breakpoints can be unstable without extra anchors

During ACE solving, `windbg_continue_until_break` sometimes observed a very
short break at `ACEDriver+0x9c51` or at the minifilter callback path, but the
target returned to `go` during the stable-break settle window. The tool correctly
reported timeout/final `go`, but the workflow needs a better way to capture
short-lived stops.

Workaround used:

- Set related anchor breakpoints around the virtualized path
  (`ACEDriver+0x9f83`, `ACEDriver+0x9c51`, `ACEDriver+0x1000`) and branch the
  script based on the actual RIP.
- If raw `gu` is issued, poll `windbg_get_execution_state` until the temporary
  return breakpoint stops the target.

Desired MCP improvement:

- Add `windbg_step`, `windbg_step_over`, and `windbg_go_up` wrappers that issue
  the stepping command and wait for a stable break before returning.

### P7: Breakpoint command logging is not reliable enough for trace capture

Breakpoint command strings such as `.echo ACE_ENTRY; r; dd @rcx L4; g` or
`.echo ACE_ENTRY; ...; gc` were accepted by `bp`, but live testing did not
produce reliable asynchronous log output through `windbg_get_output`, and the
target did not behave like an interactive log-and-continue breakpoint.

Impact:

- Command breakpoints are not yet a dependable replacement for explicit break,
  snapshot, and resume flows.

Desired MCP improvement:

- Add a regression test that sets a command breakpoint, triggers it, verifies
  the output callback/history capture, and verifies the target continues.

### P8: Some raw command forms unsettle the command host

The raw command `r rip rax rcx ...; u @rip L1` triggered an `0x80040205`
unsettled command-host state while stopped at the helper breakpoint. Full `r`
was reliable in the same context.

Impact:

- Scripts should prefer `windbg_read_registers` or full `r` until register
  subset handling is hardened.

Desired MCP improvement:

- Add a structured register-read path for high-frequency stepping workflows, and
  avoid routing register subsets through fragile raw command strings.

## Auxiliary Tooling Issues

- IDA headless timed out opening `ACEFirstRound.exe` during earlier triage.
- PowerShell inline Python heredocs can mangle Chinese paths unless the script
  enumerates directories via ASCII parents and sets UTF-8 output explicitly.
