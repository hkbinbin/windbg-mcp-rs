# Headless KDNET TODO

## P0 Core Reliability

- [x] Add bounded `windbg_close_session` teardown so live KDNET detach cannot hang the MCP server indefinitely.
  The tool now tries to resume a broken target before close, removes the session from the registry first, and reports `resume_error` / `shutdown_error` if dbgeng resume or teardown fails or times out.

- [x] Keep the VM running after `windbg_close_session`.
  Verified with ShadowGate live KDNET regression: guest SSH stayed reachable and the driver could be stopped after MCP session close. Later live regressions showed close could detach too quickly after auto-resume or after a just-observed running state; kernel close now waits briefly before detach in both cases.

- [x] Eliminate the residual `0x800700D7` / `LoadModule` error from live KDNET detach.
  Fixed by letting the kernel host client own transport teardown instead of calling `EndSession` from the connected command client. Verified with plain KDNET close and ShadowGate load-break close: `shutdown_completed=true`, `shutdown_error=null`, and guest SSH stayed reachable.

- [x] Make session lifecycle resilient after tool/client interruption.
  If the client script exits mid-debug, the target should still be resumable and the session should be recoverable or self-cleaning.
  The headless binary now explicitly closes all managed sessions when stdio/HTTP serving returns, and `DbgEngExecutor::drop` also uses the resume-before-host-stop cleanup path for kernel sessions. `tools/headless_mcp_smoke.py --skip-close` can exercise this path.

- [x] Add a long-running KDNET soak test.
  Minimum target: keep the VM running under MCP control for an extended period, periodically `interrupt -> execute_command -> resume`, and verify SSH remains reachable after each cycle.
  Added `tools/headless_kdnet_soak.py`, which repeats interrupt/command/resume cycles and can probe guest TCP reachability after each resume.

- [x] Add an MCP recovery path for "VM paused in debugger" situations.
  `windbg_recover_session` now checks state and resumes a broken target by default, or can intentionally interrupt a running target when requested.

- [x] Add an end-to-end recovery validation that confirms guest SSH is back after `windbg_recover_session`.
  Verified after VM reboot and after ShadowGate load-break regression: `recover_session` resumed the target to `go`, and TCP/22 became reachable again.

- [x] Clean up failed `windbg_open_session` attempts so stale KDNET hosts cannot steal a later VM reconnect.
  If the kernel host attaches the KDNET transport but the command client cannot connect before `attach_timeout_secs`, `attach_kernel` now explicitly stops that host before returning the error. `KernelSessionHost` also requests stop from `Drop`, covering future early-return paths that would otherwise leave an unregistered host alive.

## P0 Dynamic Debugging Usability

- [x] Add high-level reverse-engineering MCP wrappers for common breakpoint-hit work.
  Added `windbg_set_breakpoint`, `windbg_find_process`, `windbg_set_process_breakpoint`, `windbg_set_syscall_breakpoint`, `windbg_list_breakpoints`, `windbg_clear_breakpoint`, `windbg_continue_until_break`, `windbg_read_registers`, `windbg_write_register`, `windbg_read_memory`, `windbg_disassemble`, `windbg_backtrace`, `windbg_breakpoint_snapshot`, `windbg_evaluate_expression`, `windbg_list_modules`, `windbg_search_symbols`, and `windbg_inspect_driver`. Live smoke validation covered breakpoint setup/list/clear, register reads, stack memory reads, disassembly, backtrace, and snapshot collection.

- [x] Add first-class hardware breakpoint/watchpoint support.
  Added `windbg_set_hardware_breakpoint`, wrapping WinDbg `ba` for execute/read/write/io hardware breakpoints. It supports byte sizes 1/2/4/8, one-shot/pass-count command strings, and optional process/thread scoping. This is the preferred path for self-modifying or packed code where software `bp` patching can perturb execution.

- [x] Make `NtCreateFile` / `NtDeviceIoControlFile` breakpoint workflows stable in headless mode.
  Added `windbg_set_syscall_breakpoint`, which resolves a process through `!process`, prepares `nt` symbols on demand, and sets native WinDbg `bp /p <EPROCESS>` breakpoints for syscalls such as `NtCreateFile` and `NtDeviceIoControlFile`. This avoids unrelated system-wide syscall hits.

- [x] Add process-targeted breakpoint support for live kernel sessions.
  Added `windbg_find_process` and `windbg_set_process_breakpoint`. They parse EPROCESS/PID/image blocks from `!process` output and generate native `bp /p <EPROCESS>` commands so `maze_probe.exe`/`ShadowGateApp.exe` can be traced without unrelated system hits.

- [x] Verify core command execution immediately after ShadowGate load breakpoint hits.
  Verified `break -> .lastevent/lm/lmv/~/r/k/bl -> recover_session -> service RUNNING`, including the `~` fallback path.

- [x] Broaden breakpoint-hit stability testing beyond ShadowGate load events.
  Added `tools/headless_syscall_breakpoint_smoke.py` for repeatable process-scoped `NtCreateFile` / `NtDeviceIoControlFile` setup, optional trigger execution, hit waiting, snapshot collection, cleanup, and close. Live validation confirmed process resolution and scoped syscall breakpoint setup against a KDNET session.

- [x] Add driver-centric MCP wrappers for kernel-driver debugging.
  Added tools for driver load events, driver summaries, parsed IRP dispatch tables, dispatch-handler breakpoint setup, and dispatch-hit snapshots so clients can debug kernel drivers without manually stitching `sxe`, `!drvobj`, `!irp`, register, stack, memory, and breakpoint commands together.
  Live validation found dbgeng can crash if symbol preparation is attempted after synthetic load-filter changes. `windbg_set_driver_load_breakpoint` now prepares `nt` symbols before mutating `sxe/sxd ld:<image>` filters, while summary/dispatch tools leave post-filter symbol preparation opt-in.

- [x] Add an IOCTL-focused snapshot tool.
  Added `windbg_ioctl_snapshot`, which collects `.lastevent`, registers, current disassembly, backtrace, `!irp`, `dt nt!_IRP`, IO stack arguments, and SystemBuffer bytes/dwords/qwords in one call. Live validation on ShadowGate's MOVE branch decoded `0x80012004`, input length `0x0c`, output length `0x84`, and the buffered move packet.
  Revalidated with a fresh temporary guest P/Invoke trigger rather than the earlier ShadowGate helper scripts, confirming the MCP can set an internal driver breakpoint, break on real `DeviceIoControl`, collect registers/backtrace/disassembly/memory/IRP data, resume the VM, and leave SSH reachable.
  Follow-up hardening added default IRP auto-detection across common registers, parsed IOCTL metadata in `summary.ioctl`, SystemBuffer byte-prefix extraction, and safer register argument validation.

- [x] Add a thread-list fallback for `~` when dbgeng reports transient `0x80040205`.
  The fallback uses `IDebugSystemObjects` to return current/event thread ids instead of failing outright.

- [x] Block the crash-prone `sxd ld*` path after driver-load events.
  Live ACE testing showed raw `sxd ld:ACEDriver.sys` can access-violate inside dbgeng after an `sxe ld:*` break. `windbg_execute_command` now rejects that command before it reaches dbgeng, and `windbg_set_driver_load_breakpoint` records a skipped clear step instead of executing `sxd`.

- [x] Add a minifilter communication-port snapshot tool.
  Added `windbg_minifilter_message_snapshot` for `FltCreateCommunicationPort` / `FilterSendMessage` callbacks. Live ACE validation at `ACEDriver+0x1280` captured `InputBuffer=@rdx`, `InputBufferLength=@r8`, message id `0x00154004`, payload length `0x1c`, transformed payload bytes, registers, disassembly, stack, and backtrace.

- [x] Harden break waiting and long-running interrupt behavior.
  `windbg_continue_until_break` now confirms a short stable break window before returning, and `windbg_interrupt_target` reissues active break-in requests while waiting. Live retest resumed the VM, kept SSH reachable, then interrupted again and executed `vertarget` successfully.

- [x] Add a repeatable user-mode `/p <EPROCESS> <user_va>` breakpoint regression.
  The new stable-break guard should prevent the earlier false break return, but the latest live retest focused on kernel driver load, driver code, and minifilter callback breakpoints. A dedicated user-mode VA hit should still be scripted before claiming full user-mode process breakpoint coverage.
  Added `tools/headless_user_va_breakpoint_smoke.py`, which resolves a process or accepts a known EPROCESS, sets `windbg_set_process_breakpoint` on an arbitrary user VA/symbol, waits with `windbg_continue_until_break`, captures `windbg_breakpoint_snapshot`, clears breakpoints, and closes the session.

- [x] Switch process context for process-scoped user-mode VA breakpoints.
  Live validation showed `bp /p <EPROCESS> <user_va>` can create a breakpoint ID but never hit if dbgeng has not switched to the target process address context. `windbg_set_process_breakpoint`, `windbg_set_hardware_breakpoint`, and `windbg_trace_breakpoint` now run `.process /p /r <EPROCESS>` automatically for low canonical user-mode addresses, or when callers pass `set_context:true`.
  Follow-up live validation showed software `bp /p <EPROCESS> <user_va>` still did not hit reliably even after context switching, while hardware `ba e 1 /p <EPROCESS> <user_va>` hit the target PowerShell process at `ntdll!NtDelayExecution`. `windbg_set_process_breakpoint` now rejects low user-mode VA software breakpoints by default and points callers to `windbg_set_hardware_breakpoint`; pass `allow_user_software:true` only for explicit experiments.

- [x] Run the user-mode `/p <EPROCESS> <user_va>` regression against a real guest process.
  Live validated with a guest PowerShell process that directly P/Invoked `ntdll!NtDelayExecution`. Hardware `ba e 1 /p <EPROCESS> 0x7ff83ba4dc80` hit successfully and returned `rip=00007ff83ba4dc80`; software `bp /p` timed out and is now guarded by default.

- [x] Add first-class stepping wrappers for headless dynamic reversing.
  ACE live solving showed raw `gu` returns immediately with the target in `go` instead of blocking until the temporary return breakpoint is hit. Add `windbg_step`, `windbg_step_over`, and `windbg_go_up` tools that issue `t` / `p` / `gu`, poll execution state, and only return when a stable break is available.
  Implemented `windbg_step`, `windbg_step_over`, and `windbg_go_up` with the same stable-break polling used by `windbg_continue_until_break`.

- [x] Add structured transient-break diagnostics.
  ACE breakpoints around `ACEDriver+0x9c51` and callback entry sometimes produced transient break states that returned to `go` during the settle window. Add a regression that captures short-lived code stops and verifies `continue_until_break` either returns a command-ready stop or reports a structured transient-break diagnostic with the last observed event.
  `windbg_continue_until_break` now reports `transient_breaks`, `last_observed_break_state`, and `last_unstable_break_state` through the shared stable-break poller. A live short-break regression is still useful, but the MCP now exposes the diagnostic data needed by clients.

- [x] Add a live short-breakpoint stability regression.
  Script a repeatable target that hits and immediately continues or briefly oscillates between `break` and `go`, then assert `windbg_continue_until_break` either returns a stable command-ready stop or a timeout with nonzero `transient_breaks`.
  Live attempted with `bp /1 nt!KeDelayExecutionThread "gc"` plus a guest sleep trigger. On this dbgeng/KDNET path, the command breakpoint did not self-continue; it returned a stable command-ready break, which `windbg_continue_until_break` correctly reported as stable. This did not reproduce a transient break, but it validates the stable-break guard did not falsely report `go` as command-ready and further supports using `windbg_trace_breakpoint` instead of self-continuing command breakpoints.

- [x] Harden command-breakpoint output capture.
  ACE testing showed `bp <addr> ".echo ...; r; dd ...; g/gc"` is accepted but does not reliably capture asynchronous output through `windbg_get_output` or behave like interactive WinDbg log-and-continue tracing. Add an explicit regression and, if dbgeng output callbacks are insufficient, a higher-level MCP trace-breakpoint abstraction.
  Added `windbg_trace_breakpoint`, which sets a temporary software or hardware breakpoint, resumes, waits for stable hit(s), runs capture commands synchronously, clears the newly created breakpoint IDs, and resumes by default. Added `tools/headless_trace_breakpoint_smoke.py` for live validation without storing KDNET secrets.

- [x] Add a live `windbg_trace_breakpoint` regression against a real guest workload.
  Use `tools/headless_trace_breakpoint_smoke.py` with a guest trigger command to confirm trace hits, cleanup, and final resume on ShadowGate/ACE-style targets.
  Live validated both software and hardware trace modes against `nt!KeDelayExecutionThread` with a guest PowerShell `Start-Sleep` trigger. Both modes captured a stable hit, returned `rip` and `kv`, cleaned up the new breakpoint ID, resumed the guest, and left SSH reachable.

- [x] Avoid fragile raw register subset commands in stepping workflows.
  Raw `r rip rax rcx ...; u @rip L1` triggered an `0x80040205` unsettled host state while full `r` was reliable. Prefer `windbg_read_registers` for subsets, add live coverage for register subset reads during breakpoints, and consider blocking or rewriting fragile raw `r <many-registers>` command forms.
  `windbg_execute_command` now rejects raw multi-register `r <reg> <reg>` reads and points callers to `windbg_read_registers`. `windbg_read_registers` executes each requested register as an isolated command.

- [x] Add safer breakpoint cleanup while stopped on a breakpoint.
  ACE helper stepping showed clearing all breakpoints at the current stop can make the next command fragile in some dbgeng states. Add a cleanup helper that detects the current stop address, steps/restores safely if needed, then clears breakpoints.
  `windbg_clear_breakpoint` now defaults to `bd <breakpoint>` before `bc <breakpoint>` and returns disable/clear/list steps. This is a conservative cleanup improvement, not a full software-breakpoint instruction restoration engine.

## P1 WinDbg Extension Support

- [x] Fix extension DLL discovery/loading in headless sessions.
  Headless mode now discovers WinDbg Preview, copies the runtime into a local cache outside `WindowsApps`, adds the cached `amd64\winxp` / `amd64\winext` paths to `.extpath`, and resolves `.load kdexts` to the cached DLL. Live validation shows `kdexts` loaded in `.chain` and `!process 0 0` reaches the extension.

- [x] Add explicit extension search-path setup during headless session initialization.
  The session host configures `.extpath` from discovered/cache debugger directories instead of relying on ambient PATH state.

- [x] Add regression coverage for extension-backed commands.
  Minimum smoke target: `.load kdexts`, `!process 0 0`, `!drvobj ShadowGate 7`.
  Added `tools/headless_extension_smoke.py`, which prepares symbols, calls `windbg_diagnose_extensions`, loads `kdexts`, and runs extension-backed probes including optional `!drvobj`.

- [x] Make extension command failures self-diagnosing.
  If `.load kdexts` or `!process` fails, return the effective extension search path and discovered WinDbg extension directories in the tool output.
  Added `windbg_diagnose_extensions`, which returns `.extpath`, `.chain`, optional symbol preparation, extension load output, probe output, and remediation hints.

- [x] Add a symbol bootstrap workflow for extension-backed commands.
  `windbg_prepare_symbols` now reads `!lmi`, downloads the exact CodeView PDB into the local cache, appends the exact PDB directory to `.sympath`, and reloads the module. Live KDNET validation prepared `nt` symbols, loaded `kdexts`, and then ran `!process 0 0` plus `!drvobj ShadowGate 7` successfully.

- [x] Add a dedicated MCP interface for kernel DbgPrint output.
  Added `windbg_dbgprint`, which loads `kdexts` by default, runs `!dbgprint`, returns a bounded tail of recent lines, and reports symbol/extension remediation hints. This complements generic `windbg_get_output` by exposing DbgPrint collection as a first-class structured tool.

## P1 ShadowGate Validation

- [x] Add a reproducible ShadowGate validation script to the repo.
  It should verify: open session, wait for `break`, resume, `sc start ShadowGate`, run `maze_probe.exe`, interrupt, inspect, resume.
  Added `tools/shadowgate_smoke.py`; guest actions are SSH-driven without storing credentials, and probe execution can be supplied with `--probe-command`.

- [x] Capture a repeatable driver-load breakpoint regression for ShadowGate.
  It should verify `sxe ld:ShadowGateSys.sys`, service start over SSH, load breakpoint hit, `lm m ShadowGate*`, `r rip`, `k`, and clean `recover_session`.
  `tools/shadowgate_smoke.py --driver-load-break` sets the load filter, starts the service asynchronously over SSH, waits for the break, runs the inspection suite, and resumes/cleans up.

- [x] Fix or document synthetic module display quirks after driver-load breaks.
  The entrypoint breakpoint currently works, but stack output can show `<Unloaded_ShadowGateSys.sys>+0x8000`; this should either be corrected with better synthetic module registration or documented as cosmetic.
  Also observed: after a normal service start, `!drvobj ShadowGate 7` resolves the driver object and dispatch table, but `lm m ShadowGate*` can still be empty.
  Documented as a known limitation in `README.md` and `docs/shadowgate-notes.md`.

- [x] Capture and document the ShadowGate protocol observed so far.
  Known facts:
  `IOCTL_MOVE = 0x80012004`
  `IOCTL_RESET = 0x80012008`
  `IOCTL_INFO = 0x8001200C`
  `U/L/D/R -> 0x52/0x53/0xD3/0xD0`
  move packet uses `opIndex` and `0xDEAD1337`
  driver exposes `Global\\MazeMoveOK` and `Global\\MazeMoveWall`
  Captured in `docs/shadowgate-notes.md`.

- [x] Dynamically reverse ShadowGate maze and final transform.
  Dynamic KDNET tracing captured MOVE input packets, output buffers, live state memory, the winning path, and final transform call arguments. The behavior-equivalent final transform, maze grid, path, and flag materialization are documented in `docs/shadowgate-crypto-reversing.md`.

- [x] Add a regression test plan for `windbg_get_output`.
  Already observed working for `vertarget`; we should verify cursor-based reads across multiple commands and breakpoint hits.
  Added `docs/get-output-regression-plan.md` and `tools/headless_get_output_check.py`.

- [x] Add a ShadowGate-specific command smoke suite.
  Minimum commands: `.lastevent`, `lm m ShadowGate*`, `bl`, `~`, `r rip`, `k`, `!process 0 0`, and `!drvobj ShadowGate 7` when extensions are available.
  Added as defaults in `tools/shadowgate_smoke.py`.

## P2 Maintainability

- [x] Move the basic stdio/live validation helper into a tracked `tools/` directory.
  `tools/headless_mcp_smoke.py` can validate initialize/tools-list and optionally open/close a live KDNET session without storing secrets in the repo. It now waits through transient `no_debuggee` states, breaks running targets before command execution, and cleans up via MCP close on errors.

- [x] Promote deeper ShadowGate and breakpoint-hit validation helpers into tracked scripts.
  Current temporary artifacts live outside the repo root and should either be promoted into the project or discarded after capture.
  Added tracked helpers for extension diagnostics, KDNET soak, output cursor checks, and ShadowGate inspection/load-break flows.

- [x] Document real-world known limitations in `README.md`.
  Especially:
  initial `no_debuggee` state is expected
  extension commands currently limited
  long-running live sessions need careful cleanup
  README now documents transient `no_debuggee`, paused-guest SSH behavior, extension diagnostics, cleanup behavior, and ShadowGate module-display quirks.

- [x] Add an operator guide for stdio MCP usage.
  Include the exact call rhythm:
  `open_session -> wait break -> resume -> guest action -> interrupt -> execute_command/get_output -> resume`
  Added `docs/headless-operator-guide.md`.

- [x] Remove legacy GUI/plugin-facing project surface.
  Removed the WinDbg extension DLL entrypoints, in-process plugin server, cdylib build target, and README/plugin screenshot workflow. The maintained binary is now `windbg_mcp_headless`.

## P1 User-Mode Debugging

- [x] Add first-class headless user-mode debugging support.
  Added an `ExecutionMode::UserModeProcess` variant backed by a new
  `UserModeAttach` enum that supports both `CreateProcessAndAttachWide`
  spawn-and-attach and `AttachProcess` PID attaches. The kernel session host
  was generalized to a `HostAttachKind` so kernel and user-mode sessions
  share the dbgeng command/event plumbing, including event callbacks,
  initial-break suppression and command-window retry. Exposed through the
  new `windbg_open_user_process` MCP tool and `--launch-user` /
  `--attach-user-pid` CLI flags. `windbg_set_process_breakpoint` now allows
  software `bp /p <EPROCESS> <user_va>` for user-mode sessions because
  software breakpoints are reliable on a local user-mode debug port.
  Verified end-to-end with `tools/headless_user_mode_smoke.py` against
  `Crackme.exe` (32-bit launch with WoW64 module list, registers, stack
  backtrace) and against an existing notepad PID (`AttachPid` path).
