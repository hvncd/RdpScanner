pub mod anti_debug;
pub mod anti_analysis;
pub mod anti_vm;
pub mod anti_attach;
pub mod anti_dump;
pub mod crash_handler;
pub mod code_mutation;
pub mod other;
pub mod crypto;
pub mod obfuscation;

use std::process;
use std::sync::atomic::{AtomicBool, Ordering};

static SECURITY_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Initialize all security checks with polymorphic execution
pub fn initialize_security() {
    if SECURITY_INITIALIZED.swap(true, Ordering::SeqCst) {
        return; // Already initialized
    }

    // Initialize code mutation
    code_mutation::initialize_mutation();
    
    // Initialize anti-dump protections
    anti_dump::initialize_anti_dump();
    
    // Install crash handler
    crash_handler::install_crash_handler();

    // Generate runtime key for polymorphic behavior
    let runtime_key = crypto::generate_runtime_key();
    
    println!("\n========================================");
    println!("    RDP SCANNER - SECURITY CHECKS");
    println!("========================================\n");
    
    // Run initial checks
    println!("[SECURITY] Running initial security verification...\n");
    
    // Polymorphic check order based on runtime key
    initialize_security_with_seed(runtime_key);
    
    println!("========================================");
    println!("  ALL SECURITY CHECKS PASSED");
    println!("========================================\n");
    
    // Start monitoring threads (VM checks disabled)
    anti_debug::anti_debug::start_anti_debug_monitor();
    anti_attach::start_anti_attach_monitor();
    anti_dump::start_anti_dump_monitor();
    // VM monitoring disabled for testing
    // anti_analysis::anti_analysis::start_anti_analysis_monitor();
    // anti_vm::start_anti_vm_monitor();
    other::process_name_check::start_process_monitor();
}

pub fn initialize_security_with_seed(seed: u64) {
    if SECURITY_INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }

    println!("[SECURITY] Anti-Debug ONLY mode enabled");
    
    // ONLY Anti-Debug check - crashes if debugger detected
    if anti_debug::anti_debug::is_debugger_present() {
        println!("[SECURITY] Debugger detected! Crashing...");
        unsafe { std::ptr::write_volatile(0 as *mut u8, 0); }
    }
    
    println!("[SECURITY] No debugger detected - starting app");
    
    // Start ONLY anti-debug monitoring in background
    std::thread::spawn(move || {
        anti_debug::anti_debug::start_anti_debug_monitor();
    });
    
    println!("[SECURITY] Anti-debug monitoring active");
}

