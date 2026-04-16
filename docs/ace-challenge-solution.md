# ACE Challenge Dynamic Solution Notes

This note records the dynamic reverse-engineering result for the 2025 Tencent
PC client security preliminary challenge. It intentionally omits KDNET keys,
VM credentials, and host-specific secrets.

## Verified Result

The intended printable program input is:

```text
ACE_We1C0me!T0Z0Z5GamESecur1t9*CTf
```

Live validation in the VM, with the KDNET debugger attached before launching
the challenge process, produced:

```text
Please input flag:Flag is correct!
Press any key to continue...
```

The challenge submission form expects the standard wrapper, so submit:

```text
flag{ACE_We1C0me!T0Z0Z5GamESecur1t9*CTf}
```

Important correction: an earlier partial inversion only used the first 32 DWORDs
from the driver table and produced a shorter binary stdin sequence:

```text
4143455f2ba842ef820431d32d26fadd862ccb9c76fbceaa435466
```

That sequence also makes the user-mode program print `Flag is correct!` because
the driver accepts the prefix checked by the submitted transformed length. It is
not the intended contest flag. The intended printable flag comes from inverting
the complete 42-DWORD driver table.

## Driver-Side Dynamic Findings

`ACEFirstRound.exe` sends the transformed candidate to `ACEDriver.sys` through a
Filter Manager communication port. At the minifilter message callback:

- `rdx` is the input buffer.
- `r8` is the input buffer length.
- The first DWORD is message id `0x00154004`.
- The second DWORD is the transformed payload length.

The driver compares 16 encrypted pairs against the static table at
`ACEDriver+0x4060`. Each input pair is two bytes widened to DWORDs and encrypted
with key DWORDs:

```text
0x41, 0x43, 0x45, 0x36
```

The helper begins at `ACEDriver+0x1000`, but live single-stepping showed the
second half of each round is patched/trampolined at runtime. The effective
32-round function is:

```python
MASK = 0xffffffff
K = [0x41, 0x43, 0x45, 0x36]

def ace_mix(v0, v1):
    s = 0
    for _ in range(32):
        s = (s + 0x9e3779b9) & MASK
        v0 = (
            v0
            + (((v1 >> 5) + K[1]) ^ (((v1 << 4) & MASK) + K[0]) ^ (v1 + s))
        ) & MASK
        v1 = (
            v1
            + (((((v0 << 4) & MASK) ^ (v0 >> 5)) + v0) ^ (s + K[(s >> 11) & 3]))
        ) & MASK
    return v0, v1
```

This was dynamically validated with the known test payload pair `(0x33, 0x1b)`:

```text
ace_mix(0x33, 0x1b) == (0x50a1c8d3, 0x55e2345b)
```

Brute-inverting the full 42-DWORD driver table over all byte pairs gives the
expected transformed payload:

```text
332813002d164041132a124f454b1f1439493b343a263b19242b22054c0e004c3b042b1d053916223d0b
```

## EXE-Side Transform

The user-mode client requires the input to start with `ACE_`, then transforms
the suffix with a custom base58 alphabet:

```text
abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ1234567890!@+/
```

The transform appends `@`, reverses the resulting encoded string, then XORs it
with the repeating key:

```text
sxx
```

For the driver-expected payload above, undoing the XOR gives the encoded string:

```text
@PksUn39kYj763ggA1HLBUCaWSZv4vs4CwSevAnQEs
```

Reversing and base58-decoding that string gives the printable 30-byte suffix:

```text
We1C0me!T0Z0Z5GamESecur1t9*CTf
```

## MCP Behaviors Observed During Solving

Confirmed working:

- `open_session`, `resume_target`, `interrupt_target`, `execute_command`, and
  `close_session` were sufficient to keep the VM usable while debugging.
- Driver load breakpoints worked for repeatedly reloading `ACEDriver.sys`.
- Register reads, memory reads, disassembly, backtrace, and raw WinDbg command
  execution worked at driver stops.
- `windbg_minifilter_message_snapshot` worked for the Filter Manager callback.
- `gu` can be used as a raw command if the client polls execution state after
  issuing it, then reads registers after the target breaks again.

Defects or gaps exposed:

- `continue_until_break` can observe very short breakpoint stops as unstable and
  return a final `go` state. This was reproducible with some `ACEDriver+0x9c51`
  and callback-entry breakpoint combinations.
- Raw `gu` does not block until the return breakpoint in headless mode. The
  client must poll `windbg_get_execution_state` until the next stable break.
- Breakpoint command strings containing `.echo ...; g` or `.echo ...; gc` did
  not produce reliable asynchronous output in `windbg_get_output` and did not
  behave like an interactive WinDbg log-and-continue breakpoint.
- `r rip rax ...` style register-subset commands can trip the command host into
  an `0x80040205` unsettled state. Full `r` was reliable in the same context.
- Clearing all breakpoints while stopped at the current software breakpoint can
  make the next command fragile. Avoid that workflow until the MCP has a safe
  step/clear abstraction.

Recommended MCP follow-up:

- Add `windbg_step`, `windbg_step_over`, and `windbg_go_up` tools that issue the
  command and wait for a stable break before returning.
- Add a breakpoint command/logging regression for asynchronous output capture.
- Add a safe breakpoint-cleanup helper that handles the "currently stopped at
  this software breakpoint" case without unsettling dbgeng.
