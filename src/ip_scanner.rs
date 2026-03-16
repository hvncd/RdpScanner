use std::net::Ipv4Addr;
use std::str::FromStr;
use rand::Rng;

#[derive(Debug, Clone)]
pub enum ScanMode {
    Random,
    Range(String),  // CIDR notation like "192.168.1.0/24"
    List(Vec<String>),  // List of IPs
}

pub struct IpGenerator {
    mode: ScanMode,
    current_index: usize,
    ip_list: Vec<String>,
}

impl IpGenerator {
    pub fn new(mode: ScanMode) -> Self {
        let ip_list = match &mode {
            ScanMode::Range(cidr) => Self::generate_from_cidr(cidr),
            ScanMode::List(list) => list.clone(),
            ScanMode::Random => Vec::new(),
        };
        
        IpGenerator {
            mode,
            current_index: 0,
            ip_list,
        }
    }
    
    pub fn next_ip(&mut self) -> Option<String> {
        match &self.mode {
            ScanMode::Random => Some(Self::generate_random_ip()),
            ScanMode::Range(_) | ScanMode::List(_) => {
                if self.current_index < self.ip_list.len() {
                    let ip = self.ip_list[self.current_index].clone();
                    self.current_index += 1;
                    Some(ip)
                } else {
                    None
                }
            }
        }
    }
    
    pub fn total_ips(&self) -> Option<usize> {
        match &self.mode {
            ScanMode::Random => None,
            ScanMode::Range(_) | ScanMode::List(_) => Some(self.ip_list.len()),
        }
    }
    
    pub fn remaining_ips(&self) -> Option<usize> {
        match &self.mode {
            ScanMode::Random => None,
            ScanMode::Range(_) | ScanMode::List(_) => {
                Some(self.ip_list.len().saturating_sub(self.current_index))
            }
        }
    }
    
    fn generate_random_ip() -> String {
        let mut rng = rand::thread_rng();
        loop {
            let ip = Ipv4Addr::new(
                rng.gen_range(1..255),
                rng.gen_range(0..255),
                rng.gen_range(0..255),
                rng.gen_range(1..255),
            );
            
            if !ip.is_private() && !ip.is_loopback() {
                return ip.to_string();
            }
        }
    }
    
    fn generate_from_cidr(cidr: &str) -> Vec<String> {
        let mut ips = Vec::new();
        
        // Parse CIDR notation
        if let Some((base_ip, prefix_len)) = cidr.split_once('/') {
            if let Ok(base) = Ipv4Addr::from_str(base_ip) {
                if let Ok(prefix) = prefix_len.parse::<u8>() {
                    if prefix <= 32 {
                        let base_u32 = u32::from(base);
                        let host_bits = 32 - prefix;
                        let num_hosts = if host_bits >= 31 {
                            // Prevent overflow for /0 and /1
                            1u32 << 30
                        } else {
                            (1u32 << host_bits).saturating_sub(2)
                        };
                        
                        // Limit to reasonable number
                        let max_ips = 100_000;
                        let actual_hosts = num_hosts.min(max_ips);
                        
                        for i in 1..=actual_hosts {
                            let ip_u32 = base_u32.wrapping_add(i);
                            let ip = Ipv4Addr::from(ip_u32);
                            ips.push(ip.to_string());
                        }
                    }
                }
            }
        }
        
        ips
    }
}

pub fn parse_ip_list_file(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                None
            } else {
                // Extract IP from various formats
                if let Some(ip) = extract_ip(line) {
                    Some(ip)
                } else {
                    None
                }
            }
        })
        .collect()
}

fn extract_ip(line: &str) -> Option<String> {
    // Try to parse as plain IP
    if Ipv4Addr::from_str(line).is_ok() {
        return Some(line.to_string());
    }
    
    // Try to extract IP:PORT format
    if let Some((ip, _port)) = line.split_once(':') {
        if Ipv4Addr::from_str(ip).is_ok() {
            return Some(ip.to_string());
        }
    }
    
    // Try to find IP in the line using regex-like pattern
    let parts: Vec<&str> = line.split_whitespace().collect();
    for part in parts {
        if Ipv4Addr::from_str(part).is_ok() {
            return Some(part.to_string());
        }
        if let Some((ip, _)) = part.split_once(':') {
            if Ipv4Addr::from_str(ip).is_ok() {
                return Some(ip.to_string());
            }
        }
    }
    
    None
}

pub fn validate_cidr(cidr: &str) -> bool {
    if let Some((base_ip, prefix_len)) = cidr.split_once('/') {
        if Ipv4Addr::from_str(base_ip).is_ok() {
            if let Ok(prefix) = prefix_len.parse::<u8>() {
                return prefix <= 32;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cidr_validation() {
        assert!(validate_cidr("192.168.1.0/24"));
        assert!(validate_cidr("10.0.0.0/8"));
        assert!(!validate_cidr("192.168.1.0/33"));
        assert!(!validate_cidr("invalid"));
    }
    
    #[test]
    fn test_ip_extraction() {
        assert_eq!(extract_ip("192.168.1.1"), Some("192.168.1.1".to_string()));
        assert_eq!(extract_ip("192.168.1.1:3389"), Some("192.168.1.1".to_string()));
        assert_eq!(extract_ip("Server: 192.168.1.1 Port: 3389"), Some("192.168.1.1".to_string()));
    }
}
