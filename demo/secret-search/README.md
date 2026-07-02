# secret-search demo

Proves that `windbg_cli do search` can find a secret a DLL hides in **private
memory** (VirtualAlloc), which is *not* part of any module image — the classic
"injected payload / decrypted buffer" case.

## What it contains

- **`src/lib.rs`** → builds `secret_dll.dll` (a cdylib). On `DLL_PROCESS_ATTACH`
  it `VirtualAlloc`s a private RW page and writes two secrets into it:
  - offset `0x100`: ASCII `SUPER_SECRET_TOKEN_9f3a1c`
  - offset `0x200`: Chinese `顶级机密令牌` as UTF-16LE
  It records the region base/size to `%TEMP%\secret_search_demo_region.txt`.
- **`src/bin/secret_host.rs`** → builds `secret_host.exe`. `LoadLibraryA`s the
  DLL (triggering the plant), prints the region info, then idles.
- **`run_demo.py`** → the harness: launches the host under a `windbg_cli`
  daemon, lets it plant the secret, then searches for it.

## Run it

```bash
# 1. Build the debugger tool (repo root)
cargo build --release

# 2. Build the demo DLL + host
cd demo/secret-search && cargo build --release && cd ../..

# 3. Run the end-to-end demo
python demo/secret-search/run_demo.py
```

## What it demonstrates

1. A **module-only** scan does *not* see the private-memory copy (it only finds
   the string literal baked into the DLL image, at a different address).
2. A **`--all`** whole-address-space scan finds the secret at its real
   private-memory address **without knowing the address in advance** — for both
   the ASCII and the Chinese (UTF-16LE) secret.
3. An explicit `--start/--len` scan pinpoints the exact offset.

Expected tail:

```
DEMO RESULT: SUCCESS — a whole-address-space `--all` scan finds
the DLL's private-memory secret (ASCII + Chinese/UTF-16LE)
without knowing its address.
```

This demo is standalone (`publish = false`) and is **not** part of the main
crate's build.
