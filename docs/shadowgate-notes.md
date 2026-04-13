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

Known direction mapping:

```text
U -> 0x52
L -> 0x53
D -> 0xD3
R -> 0xD0
```

The move packet uses an `opIndex` value and the marker `0xDEAD1337`.

## User-Mode Signals

The driver exposes these global events:

```text
Global\MazeMoveOK
Global\MazeMoveWall
```

## Validation Scripts

Use `tools/shadowgate_smoke.py` for repeatable command inspection. With guest SSH available, it can start the service, optionally set `sxe ld:ShadowGateSys.sys`, and run the ShadowGate command smoke suite.
