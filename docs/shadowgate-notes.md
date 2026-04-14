# ShadowGate Notes

These notes capture the ShadowGate facts observed while validating the headless KDNET MCP workflow.

## Driver Objects

When the driver is loaded, `!drvobj ShadowGate 7` can resolve the driver object and dispatch table even when `lm m ShadowGate*` is empty after a normal service start. Treat the empty `lm` result as a current module-display limitation rather than proof that the driver is absent.

Useful inspection commands:

```text
!drvobj ShadowGate 7
!object \Driver\ShadowGate
lm m ShadowGate*
bl
r rip
k
```

## IOCTLs

Known IOCTL values:

```text
IOCTL_MOVE  = 0x80012004
IOCTL_RESET = 0x80012008
IOCTL_INFO  = 0x8001200C
```

## Movement Encoding

Known user-facing direction mapping:

```text
W / U -> 0x52
A / L -> 0x53
S / D -> 0xD3
D / R -> 0xD0
```

The move packet uses a per-move seed/index value and the marker `0xDEAD1337`:

```text
encoded = rol8(raw_direction ^ 0x5a, 3)
checksum = encoded ^ seed ^ 0xDEAD1337
```

The driver decodes with:

```text
raw_direction = ror8(encoded, 3) ^ 0x5a
```

## User-Mode Signals

The driver exposes these global events:

```text
Global\MazeMoveOK
Global\MazeMoveWall
```

## Validation Scripts

Use `tools/shadowgate_smoke.py` for repeatable command inspection. With guest SSH available, it can start the service, optionally set `sxe ld:ShadowGateSys.sys`, and run the ShadowGate command smoke suite.

## Dynamic Reversing Result

The maze and final transform are documented in `docs/shadowgate-crypto-reversing.md`.

Validated winning user-facing path:

```text
DDDDDDSSDDDDWWDDSSSSSSSSAASSSSDD
```

Driver-internal canonical path:

```text
RRRRRRDDRRRRUURRDDDDDDDDLLDDDDRR
```

Exit output:

```text
WIN!
flag{SHAD0WNT_HYPERVMX}
```
