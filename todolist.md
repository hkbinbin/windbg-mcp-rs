# Headless KDNET TODO

## P0 Core Reliability

- [ ] Fix `windbg_close_session` hanging/failing during live KDNET teardown.
  Repro seen in real runs: `LoadModule`-related errors and `0x800700D7`; session cleanup can leave the VM paused or transport-owned.

- [ ] Make session lifecycle resilient after tool/client interruption.
  If the client script exits mid-debug, the target should still be resumable and the session should be recoverable or self-cleaning.

- [ ] Add a tested recovery path for "VM paused in debugger" situations.
  Goal: one documented command or tool flow to reopen, force `go`, and confirm guest SSH is back.

## P0 Dynamic Debugging Usability

- [ ] Make `NtCreateFile` / `NtDeviceIoControlFile` breakpoint workflows stable in headless mode.
  Current breakpoints can be set and hit, but global syscall noise plus transient `0x80040205` command errors make targeted tracing unreliable.

- [ ] Add process-targeted breakpoint support for live kernel sessions.
  Preferred outcome: support a clean workflow equivalent to process-scoped breakpoints so `maze_probe.exe`/`ShadowGateApp.exe` can be traced without unrelated system hits.

- [ ] Verify command execution remains stable immediately after breakpoint hits.
  We need repeatable `break -> inspect regs/stack -> execute commands -> resume` without transient command-engine failures.

## P1 WinDbg Extension Support

- [ ] Fix extension DLL discovery/loading in headless sessions.
  Current `.chain` only shows `dbghelp`, `.load kdexts` fails, and commands like `!process` / `!drvobj` are unavailable.

- [ ] Add explicit extension search-path setup during headless session initialization.
  Prefer using the installed WinDbg app location rather than relying on ambient PATH state.

- [ ] Add regression coverage for extension-backed commands.
  Minimum smoke target: `.load kdexts`, `!process 0 0`, `!drvobj ShadowGate 7`.

## P1 ShadowGate Validation

- [ ] Add a reproducible ShadowGate validation script to the repo.
  It should verify: open session, wait for `break`, resume, `sc start ShadowGate`, run `maze_probe.exe`, interrupt, inspect, resume.

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

## P2 Maintainability

- [ ] Move ad-hoc external validation helpers into a tracked `tools/` or `scripts/` directory.
  Current temporary artifacts live outside the repo root and should either be promoted into the project or discarded after capture.

- [ ] Document real-world known limitations in `README.md`.
  Especially:
  initial `no_debuggee` state is expected
  extension commands currently limited
  long-running live sessions need careful cleanup

- [ ] Add an operator guide for stdio MCP usage.
  Include the exact call rhythm:
  `open_session -> wait break -> resume -> guest action -> interrupt -> execute_command/get_output -> resume`
