# Headless KDNET Operator Guide

This guide describes the safe rhythm for stdio MCP clients that own a live KDNET session.

## Core Rhythm

1. Start the stdio MCP server.
2. Call `windbg_open_session` with the KDNET connection string.
3. Poll `windbg_get_execution_state` until the session leaves `no_debuggee`.
4. If the state is `break`, run short inspection commands or call `windbg_resume_target`.
5. Perform guest-side work while the target is running.
6. Call `windbg_interrupt_target` only when debugger inspection is needed.
7. Run `windbg_execute_command`, `windbg_get_output`, `windbg_prepare_symbols`, or extension diagnostics while the target is broken.
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

## Driver Load Breakpoints

Use synthetic load-event breakpoints through normal WinDbg syntax:

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
