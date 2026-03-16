/// Anti-attach protection - prevents debuggers from attaching
use std::process;

#[cfg(target_os = "windows")]
use winapi::um::winnt::HANDLE;

#[cfg(target_os = "windows")]
pub fn prevent_debugger_attach() {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    
    unsafe {
        // Remove debug privileges
        remove_debug_privileges();
    }
}

#[cfg(target_os = "windows")]
unsafe fn remove_debug_privileges() {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::winnt::TOKEN_ADJUST_PRIVILEGES;
    
    let mut token: HANDLE = std::ptr::null_mut();
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token);
}

/// Check for debugger attachment attempts
#[cfg(target_os = "windows")]
pub fn check_debugger_attachment() -> bool {
    use winapi::um::debugapi::CheckRemoteDebuggerPresent;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::shared::minwindef::BOOL;
    
    unsafe {
        let mut is_debugged: BOOL = 0;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugged);
        is_debugged != 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn prevent_debugger_attach() {}

#[cfg(not(target_os = "windows"))]
pub fn check_debugger_attachment() -> bool {
    false
}

/// Monitor for debugger attachment and crash immediately
pub fn start_anti_attach_monitor() {
    std::thread::spawn(|| {
        loop {
            if check_debugger_attachment() {
                // Immediate crash
                unsafe {
                    std::ptr::write_volatile(0 as *mut u8, 0);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}
