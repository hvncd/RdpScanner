/// Anti-memory dump protection
use std::process;

/// Erase PE headers to prevent dumping
#[cfg(target_os = "windows")]
pub fn erase_pe_headers() {
    use winapi::um::libloaderapi::GetModuleHandleW;
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::{PAGE_READWRITE, PAGE_EXECUTE_READ};
    
    unsafe {
        let base = GetModuleHandleW(std::ptr::null()) as *mut u8;
        if base.is_null() {
            return;
        }
        
        let mut old_protect = 0u32;
        
        // Change protection to writable
        if VirtualProtect(
            base as *mut _,
            0x1000,
            PAGE_READWRITE,
            &mut old_protect,
        ) != 0 {
            // Erase DOS header signature
            std::ptr::write_volatile(base, 0);
            std::ptr::write_volatile(base.offset(1), 0);
            
            // Erase PE signature
            let pe_offset = std::ptr::read_volatile(base.offset(0x3C) as *const u32);
            if pe_offset < 0x1000 {
                let pe_sig = base.offset(pe_offset as isize);
                for i in 0..4 {
                    std::ptr::write_volatile(pe_sig.offset(i), 0);
                }
            }
            
            // Restore protection
            VirtualProtect(
                base as *mut _,
                0x1000,
                old_protect,
                &mut old_protect,
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn erase_pe_headers() {}

/// Detect memory scanning tools
#[cfg(target_os = "windows")]
pub fn detect_memory_scanner() -> bool {
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
    use winapi::um::handleapi::CloseHandle;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    
    let scanner_processes = [
        "cheatengine", "processhacker", "procexp", "procmon",
        "ollydbg", "x64dbg", "x32dbg", "ida", "ida64",
        "windbg", "immunitydebugger", "pestudio",
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
                
                for scanner in &scanner_processes {
                    if name.contains(scanner) {
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

#[cfg(not(target_os = "windows"))]
pub fn detect_memory_scanner() -> bool {
    false
}

/// Hide from debuggers by manipulating PEB
#[cfg(target_os = "windows")]
pub fn hide_from_debugger() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let peb: *mut u8;
        std::arch::asm!("mov {}, gs:[0x60]", out(reg) peb);
        
        if !peb.is_null() {
            // Clear BeingDebugged flag
            std::ptr::write_volatile(peb.offset(0x02), 0);
            
            // Clear NtGlobalFlag
            let nt_global_flag = peb.offset(0xBC) as *mut u32;
            std::ptr::write_volatile(nt_global_flag, 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn hide_from_debugger() {}

/// Encrypt memory regions at runtime
#[cfg(target_os = "windows")]
pub fn encrypt_memory_region(addr: *mut u8, size: usize, key: u8) {
    use winapi::um::memoryapi::VirtualProtect;
    use winapi::um::winnt::PAGE_READWRITE;
    
    unsafe {
        let mut old_protect = 0u32;
        
        if VirtualProtect(addr as *mut _, size, PAGE_READWRITE, &mut old_protect) != 0 {
            for i in 0..size {
                let byte = std::ptr::read_volatile(addr.offset(i as isize));
                std::ptr::write_volatile(addr.offset(i as isize), byte ^ key);
            }
            
            VirtualProtect(addr as *mut _, size, old_protect, &mut old_protect);
        }
    }
}

#[cfg(not(target_os = "windows"))]
pub fn encrypt_memory_region(_addr: *mut u8, _size: usize, _key: u8) {}

/// Monitor for memory dumps and crash if detected
pub fn start_anti_dump_monitor() {
    std::thread::spawn(|| {
        loop {
            if detect_memory_scanner() {
                // Immediate crash
                unsafe {
                    std::ptr::write_volatile(0 as *mut u8, 0);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    });
}

/// Initialize all anti-dump protections
pub fn initialize_anti_dump() {
    erase_pe_headers();
    hide_from_debugger();
    start_anti_dump_monitor();
}
