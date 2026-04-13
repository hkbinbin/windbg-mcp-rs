# `windbg_get_output` Regression Plan

The goal is to prove cursor-based output reads remain stable across ordinary commands and breakpoint-driven workflows.

## Basic Cursor Check

Use `tools/headless_get_output_check.py`:

```powershell
python tools/headless_get_output_check.py `
  --connection "net:port=50000,key=<your-kdnet-key>" `
  --session-id get-output-check `
  --command vertarget `
  --expect "Kernel Version"
```

Expected result:

- The first `windbg_get_output` returns a `next_cursor`.
- `windbg_execute_command` runs the command.
- The second `windbg_get_output` with the saved cursor returns only newer entries.
- The returned entries contain the expected marker.
- `windbg_close_session` resumes and detaches cleanly.

## Breakpoint Cursor Check

Use a short driver-load break:

1. Open a session.
2. Run `sxe ld:ShadowGateSys.sys`.
3. Save the current `windbg_get_output.next_cursor`.
4. Resume the target.
5. Start the driver from the guest.
6. Wait until the load breakpoint breaks.
7. Run `.lastevent`, `r rip`, and `k`.
8. Read output from the saved cursor.

Expected result:

- Cursor deltas include the breakpoint event and command outputs.
- Re-reading with the newest cursor returns no duplicate entries.
- The target can be resumed after inspection.

## Soak Variant

Run `tools/headless_kdnet_soak.py` with a small command such as `vertarget` and a TCP probe against the guest. This catches cursor history regressions that appear only after repeated `interrupt -> execute -> resume` cycles.
