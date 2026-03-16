use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{KeyIvInit, block_padding::Pkcs7};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit};
use chacha20poly1305::aead::Aead;
use rand::Rng;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

/// Polymorphic encryption - changes algorithm based on runtime seed
pub struct PolymorphicCrypto {
    seed: u64,
    key: Vec<u8>,
}

impl PolymorphicCrypto {
    pub fn new(seed: u64) -> Self {
        let mut key = vec![0u8; 32];
        let mut rng = rand::thread_rng();
        rng.fill(&mut key[..]);
        
        Self { seed, key }
    }

    /// Encrypt data using polymorphic algorithm selection
    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let algo = self.seed % 3;
        
        match algo {
            0 => self.encrypt_aes(data),
            1 => self.encrypt_chacha(data),
            _ => self.encrypt_xor_cascade(data),
        }
    }

    /// Decrypt data using polymorphic algorithm selection
    pub fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        let algo = self.seed % 3;
        
        match algo {
            0 => self.decrypt_aes(data),
            1 => self.decrypt_chacha(data),
            _ => Some(self.decrypt_xor_cascade(data)),
        }
    }

    fn encrypt_aes(&self, data: &[u8]) -> Vec<u8> {
        use cbc::cipher::BlockEncryptMut;
        
        let mut rng = rand::thread_rng();
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);

        let mut buffer = data.to_vec();
        // Add PKCS7 padding
        let padding = 16 - (buffer.len() % 16);
        buffer.extend(vec![padding as u8; padding]);

        let buf_len = buffer.len();
        let cipher = Aes256CbcEnc::new_from_slices(&self.key, &iv).unwrap();
        let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, buf_len).unwrap();

        let mut result = iv.to_vec();
        result.extend_from_slice(ciphertext);
        result
    }

    fn decrypt_aes(&self, data: &[u8]) -> Option<Vec<u8>> {
        use cbc::cipher::BlockDecryptMut;
        
        if data.len() < 16 {
            return None;
        }

        let iv = &data[..16];
        let mut encrypted = data[16..].to_vec();

        let cipher = Aes256CbcDec::new_from_slices(&self.key, iv).ok()?;
        let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut encrypted).ok()?;
        Some(decrypted.to_vec())
    }

    fn encrypt_chacha(&self, data: &[u8]) -> Vec<u8> {
        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);

        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let encrypted = cipher.encrypt(nonce, data).expect("ChaCha20 encryption failed");

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&encrypted);
        result
    }

    fn decrypt_chacha(&self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 12 {
            return None;
        }

        let nonce_bytes = &data[..12];
        let encrypted = &data[12..];

        let key = Key::from_slice(&self.key);
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, encrypted).ok()
    }

    fn encrypt_xor_cascade(&self, data: &[u8]) -> Vec<u8> {
        let mut result = data.to_vec();
        
        // Multi-layer XOR with key derivation
        for layer in 0..3 {
            let derived_key = self.derive_key(layer);
            for (i, byte) in result.iter_mut().enumerate() {
                *byte ^= derived_key[i % derived_key.len()];
            }
        }
        
        result
    }

    fn decrypt_xor_cascade(&self, data: &[u8]) -> Vec<u8> {
        // XOR is symmetric, so decryption is the same as encryption
        self.encrypt_xor_cascade(data)
    }

    fn derive_key(&self, layer: u8) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(&[layer]);
        hasher.update(&self.seed.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

impl Drop for PolymorphicCrypto {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// String obfuscation at runtime
pub fn obfuscate_string(s: &str, seed: u64) -> Vec<u8> {
    let crypto = PolymorphicCrypto::new(seed);
    crypto.encrypt(s.as_bytes())
}

pub fn deobfuscate_string(data: &[u8], seed: u64) -> Option<String> {
    let crypto = PolymorphicCrypto::new(seed);
    crypto.decrypt(data)
        .and_then(|v| String::from_utf8(v).ok())
}

/// Generate runtime key from system entropy
pub fn generate_runtime_key() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    
    // Mix multiple entropy sources
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    
    #[cfg(target_os = "windows")]
    {
        use winapi::um::sysinfoapi::GetTickCount64;
        unsafe {
            GetTickCount64().hash(&mut hasher);
        }
    }
    
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polymorphic_encryption() {
        let crypto = PolymorphicCrypto::new(12345);
        let data = b"test data";
        
        let encrypted = crypto.encrypt(data);
        let decrypted = crypto.decrypt(&encrypted).unwrap();
        
        assert_eq!(data.to_vec(), decrypted);
    }
}
