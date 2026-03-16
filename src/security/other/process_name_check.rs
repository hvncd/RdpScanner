use std::process;

#[cfg(target_os = "windows")]
use std::ffi::OsString;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;

/// List of blacklisted process names (debuggers, analysis tools, monitoring tools)
const BLACKLISTED_PROCESSES: &[&str] = &[
    // Debuggers
    "ida.exe", "ida64.exe", "idag.exe", "idag64.exe", "idaw.exe", "idaw64.exe",
    "ollydbg.exe", "ollyice.exe", "x64dbg.exe", "x32dbg.exe", "x96dbg.exe",
    "windbg.exe", "windbgx.exe", "kd.exe",
    "immunitydebugger.exe", "immunity debugger.exe",
    "radare2.exe", "r2.exe", "cutter.exe",
    "gdb.exe", "gdbserver.exe",
    "edb.exe", "edb-debugger.exe",
    
    // Disassemblers & Decompilers
    "ghidra.exe", "ghidrarun.exe",
    "hopper.exe", "hopperv4.exe",
    "binary ninja.exe", "binaryninja.exe",
    "retdec.exe", "retdec-decompiler.exe",
    
    // System Monitors & Analysis Tools
    "procmon.exe", "procmon64.exe", "procexp.exe", "procexp64.exe",
    "processhacker.exe", "processhacker2.exe",
    "tcpview.exe", "autoruns.exe", "autorunsc.exe",
    "wireshark.exe", "tshark.exe", "dumpcap.exe",
    "fiddler.exe", "charles.exe",
    "regmon.exe", "filemon.exe",
    "apimonitor.exe", "api monitor.exe",
    "rohitab api monitor.exe",
    
    // Memory Editors & Trainers
    "cheatengine.exe", "cheatengine-x86_64.exe",
    "artmoney.exe", "artmoneypro.exe",
    "scanmem.exe", "gameconqueror.exe",
    
    // Sandboxes & Virtual Machines
    "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
    "vmwareuser.exe", "vmacthlp.exe",
    "xenservice.exe", "qemu-ga.exe",
    "sandboxie.exe", "sbiesvc.exe", "sandboxiedcomlaunch.exe",
    
    // Reverse Engineering Tools
    "pe-bear.exe", "pestudio.exe", "pe-sieve.exe",
    "die.exe", "detect it easy.exe",
    "exeinfope.exe", "peid.exe",
    "lordpe.exe", "importrec.exe",
    "scylla.exe", "scylla_x64.exe", "scylla_x86.exe",
    
    // Network Analysis
    "netmon.exe", "microsoft network monitor.exe",
    "networkminer.exe", "ettercap.exe",
    
    // Injection & Hooking Tools
    "frida.exe", "frida-server.exe",
    "xenos.exe", "extreme injector.exe",
    "dll injector.exe", "process hacker.exe",
    
    // Other Analysis Tools
    "dnspy.exe", "ilspy.exe", "dotpeek.exe",
    "reflector.exe", ".net reflector.exe",
    "reshacker.exe", "resource hacker.exe",
    "hxd.exe", "010editor.exe",
    "sysinternals.exe", "autoruns64.exe",
];

/// Check if any blacklisted processes are running
pub fn check_blacklisted_processes() -> bool {
    #[cfg(target_os = "windows")]
    {
        unsafe {
            use winapi::um::tlhelp32::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                PROCESSENTRY32W, TH32CS_SNAPPROCESS,
            };
            use winapi::um::handleapi::CloseHandle;

            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
                return false;
            }

            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

            if Process32FirstW(snapshot, &mut entry) != 0 {
                loop {
                    let process_name = get_process_name(&entry.szExeFile);
                    let process_name_lower = process_name.to_lowercase();

                    for blacklisted in BLACKLISTED_PROCESSES {
                        if process_name_lower == blacklisted.to_lowercase() {
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
    }

    false
}

#[cfg(target_os = "windows")]
fn get_process_name(sz_exe_file: &[u16; 260]) -> String {
    let len = sz_exe_file.iter().position(|&c| c == 0).unwrap_or(260);
    OsString::from_wide(&sz_exe_file[..len])
        .to_string_lossy()
        .to_string()
}

/// Continuously monitor for blacklisted processes and exit if found
pub fn start_process_monitor() {
    std::thread::spawn(|| {
        loop {
            if check_blacklisted_processes() {
                eprintln!("\n[SECURITY] *** ANALYSIS TOOL DETECTED ***");
                eprintln!("[SECURITY] Application will now terminate.");
                process::exit(1);
            }
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    });
}

/// Single check - returns true if blacklisted process found
pub fn is_being_analyzed() -> bool {
    check_blacklisted_processes()
}
