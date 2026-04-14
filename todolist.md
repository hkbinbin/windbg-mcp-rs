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

## P0 Dynamic Debugging Usability

- [x] Add high-level reverse-engineering MCP wrappers for common breakpoint-hit work.
  Added `windbg_set_breakpoint`, `windbg_find_process`, `windbg_set_process_breakpoint`, `windbg_set_syscall_breakpoint`, `windbg_list_breakpoints`, `windbg_clear_breakpoint`, `windbg_continue_until_break`, `windbg_read_registers`, `windbg_write_register`, `windbg_read_memory`, `windbg_disassemble`, `windbg_backtrace`, `windbg_breakpoint_snapshot`, `windbg_evaluate_expression`, `windbg_list_modules`, `windbg_search_symbols`, and `windbg_inspect_driver`. Live smoke validation covered breakpoint setup/list/clear, register reads, stack memory reads, disassembly, backtrace, and snapshot collection.

- [x] Make `NtCreateFile` / `NtDeviceIoControlFile` breakpoint workflows stable in headless mode.
  Added `windbg_set_syscall_breakpoint`, which resolves a process through `!process`, prepares `nt` symbols on demand, and sets native WinDbg `bp /p <EPROCESS>` breakpoints for syscalls such as `NtCreateFile` and `NtDeviceIoControlFile`. This avoids unrelated system-wide syscall hits.

- [x] Add process-targeted breakpoint support for live kernel sessions.
  Added `windbg_find_process` and `windbg_set_process_breakpoint`. They parse EPROCESS/PID/image blocks from `!process` output and generate native `bp /p <EPROCESS>` commands so `maze_probe.exe`/`ShadowGateApp.exe` can be traced without unrelated system hits.

- [x] Verify core command execution immediately after ShadowGate load breakpoint hits.
  Verified `break -> .lastevent/lm/lmv/~/r/k/bl -> recover_session -> service RUNNING`, including the `~` fallback path.

- [x] Broaden breakpoint-hit stability testing beyond ShadowGate load events.
  Added `tools/headless_syscall_breakpoint_smoke.py` for repeatable process-scoped `NtCreateFile` / `NtDeviceIoControlFile` setup, optional trigger execution, hit waiting, snapshot collection, cleanup, and close. Live validation confirmed process resolution and scoped syscall breakpoint setup against a KDNET session.

- [x] Add a thread-list fallback for `~` when dbgeng reports transient `0x80040205`.
  The fallback uses `IDebugSystemObjects` to return current/event thread ids instead of failing outright.

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
