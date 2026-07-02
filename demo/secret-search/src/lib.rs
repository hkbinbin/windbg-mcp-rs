//! secret_dll — a demo DLL that, on load, allocates a PRIVATE memory region
//! (VirtualAlloc, not backed by any module image) and hides a secret in it.
//!
//! This models the real reverse-engineering case: a payload stashes data in
//! freshly-committed private memory rather than in a module's image, so a
//! search that only scans loaded-module ranges (`lm`) would miss it. The demo
//! writes the secret in multiple encodings and records the region base so the
//! test harness knows where it landed.

use std::ffi::c_void;
use std::fs;
use std::io::Write;

use windows_sys::Win32::Foundation::{BOOL, HMODULE, TRUE};
use windows_sys::Win32::System::Memory::{
    VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
};

// The secret we hide. Two payloads:
//   - an ASCII marker
//   - a Chinese phrase (we lay it down as UTF-16LE, the Windows-native wide
//     form, so a UTF-16LE search must find it)
const SECRET_ASCII: &[u8] = b"SUPER_SECRET_TOKEN_9f3a1c";
const SECRET_CN: &str = "顶级机密令牌"; // "top-secret token"

/// Where we record the allocated region base + length so the harness can read
/// it without needing symbols. Written next to the debuggee under %TEMP%.
fn marker_path() -> std::path::PathBuf {
    let base = std::env::var_os("TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    base.join("secret_search_demo_region.txt")
}

unsafe fn plant_secret() {
    // 1) Commit a private, read/write page. This memory is NOT part of any
    //    module image — exactly the case a module-only search would miss.
    let size: usize = 0x1000; // one page
    let region = VirtualAlloc(std::ptr::null(), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if region.is_null() {
        return;
    }
    let base = region as *mut u8;

    // 2) Zero it, then lay down the secrets at known offsets.
    std::ptr::write_bytes(base, 0, size);

    // Offset 0x100: ASCII secret.
    let ascii_off = 0x100usize;
    std::ptr::copy_nonoverlapping(SECRET_ASCII.as_ptr(), base.add(ascii_off), SECRET_ASCII.len());

    // Offset 0x200: Chinese secret as UTF-16LE code units.
    let cn_off = 0x200usize;
    let utf16: Vec<u16> = SECRET_CN.encode_utf16().collect();
    let cn_bytes: Vec<u8> = utf16.iter().flat_map(|u| u.to_le_bytes()).collect();
    std::ptr::copy_nonoverlapping(cn_bytes.as_ptr(), base.add(cn_off), cn_bytes.len());

    // 3) Record base + size + offsets so the test harness can target the
    //    region precisely and also verify a whole-process scan.
    if let Ok(mut f) = fs::File::create(marker_path()) {
        let _ = writeln!(
            f,
            "region_base=0x{:x}\nregion_size=0x{:x}\nascii_off=0x{:x}\nascii=\"{}\"\ncn_off=0x{:x}\ncn=\"{}\"",
            base as usize,
            size,
            ascii_off,
            String::from_utf8_lossy(SECRET_ASCII),
            cn_off,
            SECRET_CN,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_hinst: HMODULE, reason: u32, _reserved: *mut c_void) -> BOOL {
    const DLL_PROCESS_ATTACH: u32 = 1;
    if reason == DLL_PROCESS_ATTACH {
        unsafe { plant_secret() };
    }
    TRUE
}
