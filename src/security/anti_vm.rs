use std::process;

/// Enhanced VM detection with multiple techniques
#[cfg(target_os = "windows")]
pub fn is_virtual_machine() -> bool {
    check_cpuid() || check_vm_registry() || check_vm_files() 
        || check_vm_processes() || check_vm_services() || check_vm_devices()
}

#[cfg(not(target_os = "windows"))]
pub fn is_virtual_machine() -> bool {
    false
}

/// CPUID-based VM detection
#[cfg(target_os = "windows")]
fn check_cpuid() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;
        
        unsafe {
            // Check hypervisor bit (CPUID.1:ECX[31])
            let result = __cpuid(1);
            if (result.ecx & (1 << 31)) != 0 {
                return true;
            }
            
            // Check hypervisor vendor string
            let result = __cpuid(0x40000000);
            if result.eax >= 0x40000000 {
                let vendor = [result.ebx, result.ecx, result.edx];
                let vendor_bytes: &[u8] = std::slice::from_raw_parts(
                    vendor.as_ptr() as *const u8,
                    12
                );
                let vendor_str = String::from_utf8_lossy(vendor_bytes);
                
                if vendor_str.contains("VMware") || vendor_str.contains("VBoxVBox")
                    || vendor_str.contains("KVMKVMKVM") || vendor_str.contains("Microsoft Hv") {
                    return true;
                }
            }
        }
    }
    
    false
}

#[cfg(not(target_os = "windows"))]
fn check_cpuid() -> bool {
    false
}

/// Enhanced registry checks
#[cfg(target_os = "windows")]
fn check_vm_registry() -> bool {
    use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, RegCloseKey, HKEY_LOCAL_MACHINE};
    use winapi::um::winnt::KEY_READ;
    use winapi::shared::minwindef::HKEY;
    
    let vm_keys = [
        ("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier"),
        ("HARDWARE\\Description\\System", "SystemBiosVersion"),
        ("HARDWARE\\Description\\System", "VideoBiosVersion"),
        ("SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0"),
        ("HARDWARE\\Description\\System\\BIOS", "SystemManufacturer"),
    ];
    
    unsafe {
        for (key_path, value_name) in &vm_keys {
            let mut hkey: HKEY = std::ptr::null_mut();
            if RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                format!("{}\0", key_path).as_ptr() as *const i8,
                0,
                KEY_READ,
                &mut hkey,
            ) == 0 {
                let mut buffer = [0u8; 512];
                let mut buffer_size = 512u32;
                
                if RegQueryValueExA(
                    hkey,
                    format!("{}\0", value_name).as_ptr() as *const i8,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    buffer.as_mut_ptr(),
                    &mut buffer_size,
                ) == 0 {
                    let value = String::from_utf8_lossy(&buffer[..buffer_size as usize]).to_lowercase();
                    if value.contains("vbox") || value.contains("vmware") || value.contains("virtual")
                        || value.contains("qemu") || value.contains("xen") || value.contains("hyper-v")
                        || value.contains("parallels") || value.contains("kvm") {
                        RegCloseKey(hkey);
                        return true;
                    }
                }
                RegCloseKey(hkey);
            }
        }
    }
    
    false
}

/// Check VM-specific files
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
        "C:\\windows\\system32\\drivers\\vmci.sys",
        "C:\\windows\\system32\\drivers\\vmusbmouse.sys",
        "C:\\Program Files\\VMware\\VMware Tools\\",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
    ];
    
    vm_files.iter().any(|file| std::path::Path::new(file).exists())
}

/// Check VM-specific processes
#[cfg(target_os = "windows")]
fn check_vm_processes() -> bool {
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use winapi::um::handleapi::CloseHandle;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    
    let vm_processes = [
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
        "vmwareuser.exe", "vmacthlp.exe", "vmsrvc.exe", "vmusrvc.exe",
        "xenservice.exe", "qemu-ga.exe", "prl_cc.exe", "prl_tools.exe",
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
                
                if vm_processes.iter().any(|&vm_proc| name.contains(vm_proc)) {
                    CloseHandle(snapshot);
                    return true;
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

/// Check VM-specific services
#[cfg(target_os = "windows")]
fn check_vm_services() -> bool {
    // Simplified service check - full implementation requires winsvc feature
    // This is a placeholder that checks for service-related registry keys instead
    use winapi::um::winreg::{RegOpenKeyExA, RegCloseKey, HKEY_LOCAL_MACHINE};
    use winapi::um::winnt::KEY_READ;
    use winapi::shared::minwindef::HKEY;
    
    let vm_service_keys = [
        "SYSTEM\\CurrentControlSet\\Services\\VBoxService",
        "SYSTEM\\CurrentControlSet\\Services\\vmtools",
        "SYSTEM\\CurrentControlSet\\Services\\vmware",
    ];
    
    unsafe {
        for key_path in &vm_service_keys {
            let mut hkey: HKEY = std::ptr::null_mut();
            if RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                format!("{}\0", key_path).as_ptr() as *const i8,
                0,
                KEY_READ,
                &mut hkey,
            ) == 0 {
                RegCloseKey(hkey);
                return true;
            }
        }
    }
    
    false
}

/// Check VM-specific devices
#[cfg(target_os = "windows")]
fn check_vm_devices() -> bool {
    use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
    use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
    use winapi::um::winnt::GENERIC_READ;
    
    let vm_devices = [
        "\\\\.\\VBoxMiniRdrDN",
        "\\\\.\\VBoxGuest",
        "\\\\.\\pipe\\VBoxMiniRdDN",
        "\\\\.\\VBoxTrayIPC",
        "\\\\.\\hgfs",
    ];
    
    unsafe {
        for device in &vm_devices {
            let wide: Vec<u16> = device.encode_utf16().chain(std::iter::once(0)).collect();
            let handle = CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                0,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            
            if handle != INVALID_HANDLE_VALUE {
                CloseHandle(handle);
                return true;
            }
        }
    }
    
    false
}

pub fn start_anti_vm_monitor() {
    std::thread::spawn(|| {
        loop {
            if is_virtual_machine() {
                eprintln!("[SECURITY] Virtual machine detected. Exiting...");
                process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_secs(5));
        }
    });
}
