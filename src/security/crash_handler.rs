/// Aggressive crash mechanisms for anti-debugging
use std::sync::atomic::{AtomicBool, Ordering};

static CRASH_TRIGGERED: AtomicBool = AtomicBool::new(false);

/// Trigger immediate crash with multiple methods
#[inline(never)]
pub fn trigger_immediate_crash() -> ! {
    if CRASH_TRIGGERED.swap(true, Ordering::SeqCst) {
        // Already crashing, use alternative method
        unsafe {
            std::ptr::write_volatile(1 as *mut u8, 0);
        }
    }
    
    unsafe {
        // Method 1: Null pointer dereference
        let ptr: *mut u8 = std::ptr::null_mut();
        std::ptr::write_volatile(ptr, 0xFF);
        
        // Method 2: Invalid instruction (if above doesn't work)
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!("ud2"); // Undefined instruction
        
        // Method 3: Stack overflow
        crash_recursive();
    }
}

#[inline(never)]
fn crash_recursive() -> ! {
    let _dummy = Box::new([0u8; 1024 * 1024]); // Allocate 1MB on stack
    crash_recursive()
}

/// Corrupt memory to cause crash
#[inline(never)]
pub fn corrupt_memory() {
    unsafe {
        // Overwrite random memory locations
        for i in 0..1000 {
            let addr = (i * 0x1000) as *mut u8;
            std::ptr::write_volatile(addr, 0xFF);
        }
    }
}

/// Trigger division by zero
#[inline(never)]
pub fn trigger_div_zero() -> ! {
    unsafe {
        let x = std::ptr::read_volatile(&1);
        let y = std::ptr::read_volatile(&0);
        let _z = x / y;
        loop {}
    }
}

/// Multiple crash methods in sequence
pub fn cascade_crash() -> ! {
    // Try multiple crash methods
    std::thread::spawn(|| corrupt_memory());
    std::thread::spawn(|| trigger_div_zero());
    trigger_immediate_crash()
}

/// Install crash handler that triggers on debugger detection
pub fn install_crash_handler() {
    #[cfg(target_os = "windows")]
    unsafe {
        use winapi::um::errhandlingapi::SetUnhandledExceptionFilter;
        
        SetUnhandledExceptionFilter(Some(exception_filter));
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn exception_filter(
    _exception_info: *mut winapi::um::winnt::EXCEPTION_POINTERS
) -> i32 {
    // If exception occurs, trigger additional crash
    std::ptr::write_volatile(0 as *mut u8, 0);
    -1 // EXCEPTION_CONTINUE_EXECUTION (but we crash first)
}
