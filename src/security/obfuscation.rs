/// Code flow obfuscation techniques
use std::sync::atomic::{AtomicU64, Ordering};

static OBFUSCATION_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Opaque predicate - always true but hard to analyze
#[inline(never)]
pub fn opaque_true() -> bool {
    let x = OBFUSCATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    (x * 2 + 1) % 2 == 1
}

/// Opaque predicate - always false but hard to analyze
#[inline(never)]
pub fn opaque_false() -> bool {
    let x = OBFUSCATION_COUNTER.load(Ordering::Relaxed);
    (x * x + x) % 2 == 1
}

/// Add junk code that does nothing but confuses analysis
#[inline(never)]
pub fn junk_code() {
    let mut x = 0u64;
    for i in 0..10 {
        x = x.wrapping_mul(31).wrapping_add(i);
    }
    OBFUSCATION_COUNTER.store(x, Ordering::Relaxed);
}

/// Control flow flattening - makes code harder to follow
pub fn flatten_control_flow<F>(func: F) 
where
    F: Fn() -> bool
{
    let mut state = 0;
    loop {
        match state {
            0 => {
                junk_code();
                state = if opaque_true() { 1 } else { 2 };
            }
            1 => {
                if func() {
                    state = 3;
                } else {
                    state = 2;
                }
            }
            2 => {
                junk_code();
                break;
            }
            3 => {
                break;
            }
            _ => break,
        }
    }
}

/// String encoding at compile time
#[allow(unused_macros)]
macro_rules! encode_str {
    ($s:expr) => {{
        const fn encode(s: &str) -> [u8; $s.len()] {
            let bytes = s.as_bytes();
            let mut result = [0u8; $s.len()];
            let mut i = 0;
            while i < bytes.len() {
                result[i] = bytes[i] ^ 0xAA;
                i += 1;
            }
            result
        }
        
        fn decode(encoded: &[u8]) -> String {
            let decoded: Vec<u8> = encoded.iter().map(|&b| b ^ 0xAA).collect();
            String::from_utf8(decoded).unwrap()
        }
        
        const ENCODED: [u8; $s.len()] = encode($s);
        decode(&ENCODED)
    }};
}

#[allow(unused_imports)]
pub(crate) use encode_str;

/// Dead code insertion - adds fake branches
#[inline(never)]
pub fn dead_code_branch<T>(real_value: T, _fake_value: T) -> T {
    if opaque_true() {
        real_value
    } else {
        _fake_value
    }
}

/// API call obfuscation - indirect calls
pub struct ApiObfuscator {
    seed: u64,
}

impl ApiObfuscator {
    pub fn new() -> Self {
        Self {
            seed: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Obfuscate function pointer
    pub fn obfuscate_ptr<T>(&self, ptr: *const T) -> u64 {
        (ptr as u64) ^ self.seed
    }

    /// Deobfuscate function pointer
    pub fn deobfuscate_ptr<T>(&self, obfuscated: u64) -> *const T {
        (obfuscated ^ self.seed) as *const T
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opaque_predicates() {
        assert!(opaque_true());
        assert!(!opaque_false());
    }

    #[test]
    fn test_api_obfuscator() {
        let obf = ApiObfuscator::new();
        let func = test_opaque_predicates as *const ();
        let obfuscated = obf.obfuscate_ptr(func);
        let deobfuscated = obf.deobfuscate_ptr::<()>(obfuscated);
        assert_eq!(func, deobfuscated);
    }
}
