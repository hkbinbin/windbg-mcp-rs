# ShadowGateSys.sys Dynamic Reversing Notes

This document records the ShadowGate driver protocol and final secret transform as observed through the headless KDNET MCP workflow. Connection secrets and VM credentials are intentionally omitted.

## Sample

- Driver image used for the main analysis: `ShadowGateSys.raw.sys`
- SHA-256: `17FAF3F248E8B73AF5916C06DEF7321180AEB2353B9F2B9C1DE5652E863533F2`
- Guest service path during validation: `\??\C:\ShadowGate\ShadowGateSys.raw.sys`

## Reliable Live Address Model

Live addresses are session-dependent. In the validated session the driver object reported:

- `DriverEntry = base + 0x8000`
- `IRP_MJ_CREATE = base + 0x14b0`
- `IRP_MJ_CLOSE = base + 0x1410`
- `IRP_MJ_DEVICE_CONTROL = base + 0x1540`
- `DriverUnload = base + 0x1840`

`IRP_MJ_DEVICE_CONTROL` is a trampoline:

```text
0x1540: jmp base+0x3172ab
```

The real IOCTL logic starts at `base+0x3172ab`. Do not use stale `<Unloaded_...>+offset` output as the runtime base. Use `!drvobj ShadowGate 7` and `DriverEntry - 0x8000` to derive the current base.

The global state pointer is stored at:

```text
base+0x50b8 -> SHADOWGATE_STATE*
```

## IOCTL Interface

The driver exposes `\Device\ShadowGate` / `\\.\ShadowGate` and uses buffered IOCTLs:

```text
IOCTL_MOVE  = 0x80012004
IOCTL_RESET = 0x80012008
IOCTL_INFO  = 0x8001200C
```

`IOCTL_INFO` returns 24 bytes:

```c
struct MazeInfo {
    uint32_t width;    // 13
    uint32_t height;   // 13
    uint32_t entry_x;  // 0
    uint32_t entry_y;  // 0
    uint32_t exit_x;   // 12
    uint32_t exit_y;   // 12
};
```

`IOCTL_RESET` resets the current position, path length/counters, and path buffer.

## Move Packet Encoding

`IOCTL_MOVE` expects a 12-byte input buffer and an output buffer of at least `0x84` bytes:

```c
struct MovePacket {
    uint8_t encoded_dir;
    uint8_t reserved0[3];
    uint32_t seed;
    uint32_t checksum;
};
```

The checksum is:

```c
checksum = encoded_dir ^ seed ^ 0xDEAD1337;
```

The user-facing move command is converted to a raw direction byte:

```text
W / I -> 0x10
S / K -> 0x20
A / J -> 0x30
D / L -> 0x40
```

The encoded byte is equivalent to:

```c
encoded_dir = rol8(raw_dir ^ 0x5a, 3);
```

The driver decodes it with the inverse:

```c
raw_dir = ror8(encoded_dir, 3) ^ 0x5a;
```

Observed encoded bytes:

```text
W/U -> 0x52
A/L -> 0x53
S/D -> 0xD3
D/R -> 0xD0
```

Dynamic confirmation at the MOVE branch showed the first `W` packet as:

```text
52 00 00 00 00 00 00 00 65 13 AD DE
```

This is `encoded_dir=0x52`, `seed=0`, `checksum=0xDEAD1365`.

## MCP Dynamic Debugging Validation

The MCP was revalidated with a live KDNET session using a fresh temporary
PowerShell P/Invoke trigger on the guest. The trigger only opened
`\\.\ShadowGate` and called `DeviceIoControl`; it did not reuse the previous
ShadowGate helper scripts or perform static replay. All interesting state was
captured from the debugger side through MCP tools.

Validated breakpoint:

```text
base = DriverEntry - 0x8000
MOVE branch = base + 0x317463
```

The MCP flow was:

```text
windbg_open_session
windbg_execute_command ".sympath C:\Symbols;C:\ProgramData\dbg\sym"
windbg_execute_command ".reload /f nt"
windbg_execute_command ".load kdexts"
windbg_interrupt_target
windbg_execute_command "!drvobj ShadowGate 7"
windbg_set_breakpoint {"location":"base+0x317463","one_shot":true}
windbg_resume_target
guest DeviceIoControl trigger
windbg_read_registers
windbg_disassemble
windbg_backtrace
windbg_read_memory
windbg_ioctl_snapshot {"buffer_count":132}
windbg_resume_target
windbg_close_session
```

Observed live breakpoint registers:

```text
rip = base+0x317463
r14 = SystemBuffer
r15 = IRP
rdx = 0x80012004
```

`windbg_ioctl_snapshot` decoded the live IRP as:

```text
IRP_MJ_DEVICE_CONTROL
Args: 00000084 0000000c 0x80012004 00000000
```

The captured `SystemBuffer` began with the expected buffered MOVE packet:

```text
52 00 00 00 00 00 00 00 65 13 ad de
```

The temporary guest trigger completed after `windbg_resume_target` with:

```text
ok=True, bytes=132, payload=52000000000000006513ADDE
```

This validates that the MCP can perform the core live reverse-engineering loop:
set an internal driver breakpoint, break on a real IOCTL path, read registers,
dump memory, inspect IRP/IO stack data, get a backtrace, and resume the VM.
Current `windbg_ioctl_snapshot` builds can auto-detect the ShadowGate deep-branch
IRP in `@r15` and parse the SystemBuffer pointer from `!irp`; older builds
needed explicit `irp="@r15"` and `system_buffer="@r14"` arguments.

## Maze State

The first `13*13` bytes of `SHADOWGATE_STATE` are the maze grid. `0` is open and `1` is wall.

```text
.......#.....
######.###.#.
.....#.....#.
.###.#######.
.#.........#.
.#.#.#####.#.
.#.#.#...#.#
.#.###.#.###
.#.....#.#...
.#######.#.##
...#...#.#.#.
##.#.#.#.#.#.
.....#.#.....
```

The shortest path from `(0,0)` to `(12,12)` using user-facing `W/A/S/D` commands is:

```text
DDDDDDSSDDDDWWDDSSSSSSSSAASSSSDD
```

Internally the driver stores canonical direction letters at `state+0xc0`. For the winning path the stored path is:

```text
RRRRRRDDRRRRUURRDDDDDDDDLLDDDDRR
```

Observed state fields near the final transform:

```text
state+0xac = 12        // current x
state+0xb0 = 12        // current y
state+0xb4 = 0x20      // stored path length
state+0xbc = 0x20      // move counter / seed index
state+0xc0 = path bytes
```

## MOVE Output Behavior

For invalid packets, walls, and normal movement, the driver overwrites the output buffer with diagnostic-looking bytes. The helper at `base+0x2038` seeds a local LCG from `KUSER_SHARED_DATA` time XOR `0xBAADF00D`:

```c
seed = *(uint32_t *)0xfffff78000000320 ^ 0xBAADF00D;
*(uint32_t *)out = seed;
for (i = 0; i < 0x38; i++) {
    seed = seed * 0x41C64E6D + 0x3039;
    out[4 + i] = seed >> 16;
}
```

Additional status/event helper code updates `MazeMoveOK`, `MazeMoveWall`, and related semaphores. The useful movement outcome signal is the named event/semaphore side channel, not the pseudo-random bytes.

For exit success, `base+0x317629` writes:

```text
SystemBuffer+0x3c = "WIN!"
```

Then the driver copies the stored path from `state+0xc0` to a stack buffer and calls the final transform:

```c
transform(
    src     = stack_path,
    len     = 0x20,
    dst     = SystemBuffer + 0x40,
    out_len = &local_out_len
);
SystemBuffer[0x80..0x83] = local_out_len;
```

## Final Transform

The transform entry is called at `base+0x3f7c6d` from `base+0x3176ef`. The code is heavily obfuscated/virtualized, so the behavior was confirmed dynamically with call-argument snapshots and data breakpoints.

Call arguments for the winning path:

```text
RCX = src path buffer
RDX = 0x20
R8  = output buffer = SystemBuffer+0x40
R9  = out_len pointer
```

Pre-call source buffer:

```text
RRRRRRDDRRRRUURRDDDDDDDDLLDDDDRR
```

Post-call output buffer:

```text
flag{SHAD0WNT_HYPERVMX}
```

Post-call length:

```text
out_len = 0x17
```

## Dynamic XOR String Capture

The final string was re-captured dynamically through MCP breakpoints inside the obfuscated transform, not by replaying the old static helper scripts. A temporary guest P/Invoke trigger only generated real `DeviceIoControl` traffic; all string evidence below came from the kernel debugger session.

Useful breakpoints for the validated build:

```text
final transform call = base+0x3176ef
transform entry      = base+0x3f7c6d
xmm source load      = base+0x2d69b2
xmm output store     = base+0x2d6b53
after xmm store      = base+0x2d6b5c
tail pointer setup   = base+0x2d6c1f
tail dword store     = base+0x2d6c49
```

At `base+0x3176ef`, the transform call received the canonical path as `RCX`:

```text
RRRRRRDDRRRRUURRDDDDDDDDLLDDDDRR
```

At `base+0x2d69b2`, the transform executed:

```text
movups xmm0, xmmword ptr ss:[r9+rdi]
```

The source memory at `[r9+rdi]` was:

```text
66 6c 61 67 7b 53 48 41 44 30 57 4e 54 5f 48 59
50 45 52 56 4d 58 7d 09 09 09 09 09 09 09 09 09
```

ASCII interpretation:

```text
flag{SHAD0WNT_HYPERVMX}\x09\x09\x09\x09\x09\x09\x09\x09\x09
```

So the concrete runtime XOR/decrypted string value is:

```text
flag{SHAD0WNT_HYPERVMX}
```

At `base+0x2d6b53`, the first 16 bytes were stored into the output buffer with:

```text
movups xmmword ptr [r9+rcx-6004CC23h], xmm0
```

Immediately after the store, the output buffer contained:

```text
66 6c 61 67 7b 53 48 41 44 30 57 4e 54 5f 48 59
flag{SHAD0WNT_HY
```

The tail was then assembled through an obfuscated pointer/data pair. At `base+0x2d6c1f`, stack scratch data contained a pointer to `output+0x10` followed by the little-endian dword bytes for `PERV`. At `base+0x2d6c49`, `EDX=0x56524550` was written through `R10`, producing:

```text
50 45 52 56
PERV
```

The remaining `MX}` tail and `out_len=0x17` were confirmed from the final `DeviceIoControl` output buffer. This matches the 23-byte flag string above.

Hardware write breakpoints on predicted stack addresses were attempted as an upstream XOR trace, but they hit kernel stack reuse paths such as `nt!HalPerformEndOfInterrupt`, `nt!KiBeginThreadAccountingPeriod`, and `nt!KiDispatchInterrupt`. For this driver, code breakpoints at the transform materialization instructions are much cleaner and more reliable than broad stack data watchpoints.

A mutation test changed the first source byte from `R` to `A` at the transform breakpoint. The transform returned `out_len=0` and left `SystemBuffer+0x40` zeroed. This confirms the final transform is path-gated: the 32-byte canonical path is the key material/validator for releasing the secret.

Behavior-equivalent pseudocode:

```c
bool shadowgate_transform(const uint8_t *src, uint32_t len, uint8_t *dst, uint32_t *out_len) {
    static const uint8_t expected_path[0x20] =
        "RRRRRRDDRRRRUURRDDDDDDDDLLDDDDRR";

    if (len != sizeof(expected_path) ||
        memcmp(src, expected_path, sizeof(expected_path)) != 0) {
        *out_len = 0;
        return false;
    }

    memcpy(dst, "flag{SHAD0WNT_HYPERVMX}", 0x17);
    *out_len = 0x17;
    return true;
}
```

Internally this is not stored as plain strings in the PE image. Static byte search for the expected path and flag returns no hits; the obfuscated transform materializes the output at runtime. A hardware write breakpoint on `dst` hit at runtime code that writes the first 16 output bytes with an XMM store, followed by a separate write of `out_len=0x17`.

## MCP Validation

The dynamic captures used the headless MCP flow:

```text
open_session
interrupt / break
set breakpoint at base+0x317463 for MOVE packet capture
resume target
run guest probe over SSH
continue_until_break
windbg_ioctl_snapshot { buffer_count=132 }
resume target
```

After adding `windbg_ioctl_snapshot`, live validation on the MOVE branch returned:

```text
tool_count = 36
!irp @r15 -> IRP_MJ_DEVICE_CONTROL, SystemBuffer=<buffer>, Args: 0x84 0x0c 0x80012004
db @r14 L132 -> 52 00 00 00 00 00 00 00 65 13 AD DE ...
```

This confirms the MCP can now collect the standard reverse-engineering data needed for kernel-driver IOCTL work without manual command stitching.
