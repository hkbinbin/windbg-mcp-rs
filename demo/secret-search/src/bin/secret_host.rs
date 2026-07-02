//! secret_host — loads secret_dll.dll (which hides a secret in private memory
//! on attach), then idles so a debugger can attach and search for the secret.
//!
//! Usage: place secret_dll.dll next to this exe (cargo puts both in the same
//! target dir) and run `secret_host.exe`. It prints the planted region info
//! and then loops forever until Ctrl+C.

use std::ffi::CString;
use std::thread;
use std::time::Duration;

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

fn main() {
    // Resolve secret_dll.dll relative to this executable so it works no matter
    // the current directory.
    let exe = std::env::current_exe().expect("current_exe");
    let dir = exe.parent().expect("exe dir");
    let dll_path = dir.join("secret_dll.dll");
    let dll_str = dll_path.to_string_lossy().to_string();

    println!("[host] pid = {}", std::process::id());
    println!("[host] loading {dll_str}");

    let c = CString::new(dll_str.clone()).expect("cstring");
    let handle = unsafe { LoadLibraryA(c.as_ptr() as *const u8) };
    if handle.is_null() {
        let err = unsafe { GetLastError() };
        eprintln!("[host] LoadLibrary failed, GetLastError = {err}");
        std::process::exit(1);
    }
    println!("[host] secret_dll loaded at module handle {:p}", handle);
    println!("[host] secret planted in PRIVATE memory (see %TEMP%\\secret_search_demo_region.txt)");
    println!("[host] idling — attach the debugger now. Ctrl+C to exit.");

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
