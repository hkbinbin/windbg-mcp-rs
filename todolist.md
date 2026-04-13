# Headless KDNET TODO

## P0 Core Reliability

- [x] Add bounded `windbg_close_session` teardown so live KDNET detach cannot hang the MCP server indefinitely.
  The tool now tries to resume a broken target before close, removes the session from the registry first, and reports `resume_error` / `shutdown_error` if dbgeng resume or teardown fails or times out.

- [x] Keep the VM running after `windbg_close_session`.
  Verified with ShadowGate live KDNET regression: guest SSH stayed reachable and the driver could be stopped after MCP session close.

- [x] Eliminate the residual `0x800700D7` / `LoadModule` error from live KDNET detach.
  Fixed by letting the kernel host client own transport teardown instead of calling `EndSession` from the connected command client. Verified with plain KDNET close and ShadowGate load-break close: `shutdown_completed=true`, `shutdown_error=null`, and guest SSH stayed reachable.

- [ ] Make session lifecycle resilient after tool/client interruption.
  If the client script exits mid-debug, the target should still be resumable and the session should be recoverable or self-cleaning.

- [ ] Add a long-running KDNET soak test.
  Minimum target: keep the VM running under MCP control for an extended period, periodically `interrupt -> execute_command -> resume`, and verify SSH remains reachable after each cycle.

- [x] Add an MCP recovery path for "VM paused in debugger" situations.
  `windbg_recover_session` now checks state and resumes a broken target by default, or can intentionally interrupt a running target when requested.

- [x] Add an end-to-end recovery validation that confirms guest SSH is back after `windbg_recover_session`.
  Verified after VM reboot and after ShadowGate load-break regression: `recover_session` resumed the target to `go`, and TCP/22 became reachable again.

## P0 Dynamic Debugging Usability

- [ ] Make `NtCreateFile` / `NtDeviceIoControlFile` breakpoint workflows stable in headless mode.
  Current breakpoints can be set and hit, but global syscall noise plus transient `0x80040205` command errors make targeted tracing unreliable.

- [ ] Add process-targeted breakpoint support for live kernel sessions.
  Preferred outcome: support a clean workflow equivalent to process-scoped breakpoints so `maze_probe.exe`/`ShadowGateApp.exe` can be traced without unrelated system hits.

- [x] Verify core command execution immediately after ShadowGate load breakpoint hits.
  Verified `break -> .lastevent/lm/lmv/~/r/k/bl -> recover_session -> service RUNNING`, including the `~` fallback path.

- [ ] Broaden breakpoint-hit stability testing beyond ShadowGate load events.
  We still need repeatable syscall breakpoint workflows such as `NtCreateFile` / `NtDeviceIoControlFile` without unrelated system noise.

- [x] Add a thread-list fallback for `~` when dbgeng reports transient `0x80040205`.
  The fallback uses `IDebugSystemObjects` to return current/event thread ids instead of failing outright.

## P1 WinDbg Extension Support

- [x] Fix extension DLL discovery/loading in headless sessions.
  Headless mode now discovers WinDbg Preview, copies the runtime into a local cache outside `WindowsApps`, adds the cached `amd64\winxp` / `amd64\winext` paths to `.extpath`, and resolves `.load kdexts` to the cached DLL. Live validation shows `kdexts` loaded in `.chain` and `!process 0 0` reaches the extension.

- [x] Add explicit extension search-path setup during headless session initialization.
  The session host configures `.extpath` from discovered/cache debugger directories instead of relying on ambient PATH state.

- [ ] Add regression coverage for extension-backed commands.
  Minimum smoke target: `.load kdexts`, `!process 0 0`, `!drvobj ShadowGate 7`.

- [ ] Make extension command failures self-diagnosing.
  If `.load kdexts` or `!process` fails, return the effective extension search path and discovered WinDbg extension directories in the tool output.

- [ ] Add a symbol bootstrap workflow for extension-backed commands.
  Live validation now loads `kdexts` from the local WinDbg runtime cache, but `!process 0 0` reports incorrect NT symbols unless the operator configures symbols first, for example through `startup_command`.

## P1 ShadowGate Validation

- [ ] Add a reproducible ShadowGate validation script to the repo.
  It should verify: open session, wait for `break`, resume, `sc start ShadowGate`, run `maze_probe.exe`, interrupt, inspect, resume.

- [ ] Capture a repeatable driver-load breakpoint regression for ShadowGate.
  It should verify `sxe ld:ShadowGateSys.sys`, service start over SSH, load breakpoint hit, `lm m ShadowGate*`, `r rip`, `k`, and clean `recover_session`.

- [ ] Fix or document synthetic module display quirks after driver-load breaks.
  The entrypoint breakpoint currently works, but stack output can show `<Unloaded_ShadowGateSys.sys>+0x8000`; this should either be corrected with better synthetic module registration or documented as cosmetic.

- [ ] Capture and document the ShadowGate protocol observed so far.
  Known facts:
  `IOCTL_MOVE = 0x80012004`
  `IOCTL_RESET = 0x80012008`
  `IOCTL_INFO = 0x8001200C`
  `U/L/D/R -> 0x52/0x53/0xD3/0xD0`
  move packet uses `opIndex` and `0xDEAD1337`
  driver exposes `Global\\MazeMoveOK` and `Global\\MazeMoveWall`

- [ ] Add a regression test plan for `windbg_get_output`.
  Already observed working for `vertarget`; we should verify cursor-based reads across multiple commands and breakpoint hits.

- [ ] Add a ShadowGate-specific command smoke suite.
  Minimum commands: `.lastevent`, `lm m ShadowGate*`, `bl`, `~`, `r rip`, `k`, `!process 0 0`, and `!drvobj ShadowGate 7` when extensions are available.

## P2 Maintainability

- [x] Move the basic stdio/live validation helper into a tracked `tools/` directory.
  `tools/headless_mcp_smoke.py` can validate initialize/tools-list and optionally open/close a live KDNET session without storing secrets in the repo.

- [ ] Promote deeper ShadowGate and breakpoint-hit validation helpers into tracked scripts.
  Current temporary artifacts live outside the repo root and should either be promoted into the project or discarded after capture.

- [ ] Document real-world known limitations in `README.md`.
  Especially:
  initial `no_debuggee` state is expected
  extension commands currently limited
  long-running live sessions need careful cleanup

- [ ] Add an operator guide for stdio MCP usage.
  Include the exact call rhythm:
  `open_session -> wait break -> resume -> guest action -> interrupt -> execute_command/get_output -> resume`
