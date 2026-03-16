use std::process;

#[cfg(target_os = "windows")]
use winapi::um::debugapi::IsDebuggerPresent;

/// Check if a debugger is attached using Windows API
#[cfg(target_os = "windows")]
pub fn is_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(not(target_os = "windows"))]
pub fn is_debugger_present() -> bool {
    false
}

/// Check for remote debugger using NtQueryInformationProcess
#[cfg(target_os = "windows")]
pub fn check_remote_debugger() -> bool {
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::winnt::HANDLE;
    
    unsafe {
        let mut is_debugged: u32 = 0;
        let process_handle: HANDLE = GetCurrentProcess();
        
        // ProcessDebugPort = 7
        let status = ntdll::NtQueryInformationProcess(
            process_handle,
            7,
            &mut is_debugged as *mut _ as *mut _,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
        );
        
        status == 0 && is_debugged != 0
    }
}

#[cfg(not(target_os = "windows"))]
pub fn check_remote_debugger() -> bool {
    false
}

/// Check for hardware breakpoints
#[cfg(target_os = "windows")]
pub fn check_hardware_breakpoints() -> bool {
    use winapi::um::processthreadsapi::GetCurrentThread;
    use winapi::um::winnt::CONTEXT;
    use winapi::um::winnt::CONTEXT_DEBUG_REGISTERS;
    use winapi::um::processthreadsapi::GetThreadContext;
    
    unsafe {
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if GetThreadContext(GetCurrentThread(), &mut context) != 0 {
            return context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0;
        }
    }
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_hardware_breakpoints() -> bool {
    false
}

/// Check for debugger using timing attacks
pub fn check_timing_attack() -> bool {
    // DISABLED - too many false positives on slow systems
    false
}

/// Check for debugger using exception-based detection
#[cfg(target_os = "windows")]
pub fn check_exception_based() -> bool {
    use winapi::um::errhandlingapi::SetUnhandledExceptionFilter;
    
    unsafe {
        let original_filter = SetUnhandledExceptionFilter(Some(exception_handler));
        
        // Trigger an exception
        std::ptr::write_volatile(0 as *mut u8, 0);
        
        // Restore original filter
        SetUnhandledExceptionFilter(original_filter);
    }
    
    false
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn exception_handler(_exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32 {
    // EXCEPTION_CONTINUE_EXECUTION
    -1
}

#[cfg(not(target_os = "windows"))]
pub fn check_exception_based() -> bool {
    false
}

/// Check for parent process (debuggers often spawn the target)
#[cfg(target_os = "windows")]
pub fn check_parent_process() -> bool {
    // Disabled - too many false positives
    false
}

#[cfg(target_os = "windows")]
fn is_explorer_parent(parent_pid: u32) -> bool {
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use winapi::um::handleapi::CloseHandle;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return false;
        }
        
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == parent_pid {
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                    let name = OsString::from_wide(&entry.szExeFile[..len])
                        .to_string_lossy()
                        .to_lowercase();
                    
                    CloseHandle(snapshot);
                    // Allow explorer, cmd, powershell, and other common shells
                    return name.contains("explorer.exe") 
                        || name.contains("cmd.exe") 
                        || name.contains("powershell.exe")
                        || name.contains("pwsh.exe")
                        || name.contains("conhost.exe")
                        || name.contains("windowsterminal.exe");
                }
                
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        
        CloseHandle(snapshot);
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_parent_process() -> bool {
    false
}

/// Check for debugger using PEB flags
#[cfg(target_os = "windows")]
pub fn check_peb_flags() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        unsafe {
            let peb: *const u8;
            std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
            
            if !peb.is_null() {
                // BeingDebugged flag at offset 0x02
                let being_debugged = *peb.offset(0x02);
                if being_debugged != 0 {
                    return true;
                }
                
                // NtGlobalFlag at offset 0xBC (x64)
                let nt_global_flag = *(peb.offset(0xBC) as *const u32);
                // Check for heap flags: FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
                if (nt_global_flag & 0x70) != 0 {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_peb_flags() -> bool {
    false
}

/// Check for debugger using OutputDebugString
#[cfg(target_os = "windows")]
pub fn check_output_debug_string() -> bool {
    // DISABLED - can cause false positives
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_output_debug_string() -> bool {
    false
}

/// Check for debugger using CloseHandle with invalid handle
#[cfg(target_os = "windows")]
pub fn check_close_handle() -> bool {
    // DISABLED - can cause false positives
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_close_handle() -> bool {
    false
}

/// Run all anti-debug checks
pub fn run_all_checks() -> bool {
    let debugger_present = is_debugger_present();
    let remote_debugger = check_remote_debugger();
    let hardware_bp = check_hardware_breakpoints();
    let timing = check_timing_attack();
    let parent = check_parent_process();
    let peb = check_peb_flags();
    let output_debug = check_output_debug_string();
    let close_handle = check_close_handle();
    
    debugger_present || remote_debugger || hardware_bp || timing || parent 
        || peb || output_debug || close_handle
}

/// Continuously monitor for debuggers and CRASH if found
pub fn start_anti_debug_monitor() {
    std::thread::spawn(|| {
        loop {
            if run_all_checks() {
                // Immediate crash - no graceful exit
                trigger_crash();
            }
            std::thread::sleep(std::time::Duration::from_millis(100)); // Check every 100ms
        }
    });
}

/// Trigger immediate application crash
#[inline(never)]
fn trigger_crash() -> ! {
    unsafe {
        // Multiple crash methods to ensure termination
        
        // Method 1: Invalid memory access
        std::ptr::write_volatile(0 as *mut u8, 0);
        
        // Method 2: Stack overflow
        #[inline(always)]
        fn overflow() -> ! {
            overflow()
        }
        overflow();
    }
}

/// Single check - returns true if debugger detected
pub fn is_being_debugged() -> bool {
    run_all_checks()
}

#[cfg(target_os = "windows")]
mod ntdll {
    use winapi::um::winnt::HANDLE;
    
    #[link(name = "ntdll")]
    extern "system" {
        pub fn NtQueryInformationProcess(
            process_handle: HANDLE,
            process_information_class: u32,
            process_information: *mut std::ffi::c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }
}
