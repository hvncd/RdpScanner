use std::net::{TcpStream, IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::io::{Read, Write};

/// Advanced RDP scanning capabilities
pub struct AdvancedScanner {
    pub custom_port: u16,
    pub timeout_ms: u64,
    pub enable_ipv6: bool,
}

impl AdvancedScanner {
    pub fn new() -> Self {
        AdvancedScanner {
            custom_port: 3389,
            timeout_ms: 500,
            enable_ipv6: false,
        }
    }
    
    /// Scan with custom port
    pub fn scan_custom_port(&self, ip: &str, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)).is_ok()
        } else {
            false
        }
    }
    
    /// Scan IPv6 address
    pub fn scan_ipv6(&self, ipv6: &str, port: u16) -> bool {
        if !self.enable_ipv6 {
            return false;
        }
        
        let addr = format!("[{}]:{}", ipv6, port);
        if let Ok(addr) = addr.parse() {
            TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)).is_ok()
        } else {
            false
        }
    }
    
    /// OS Fingerprinting via RDP banner
    pub fn fingerprint_os(&self, ip: &str, port: u16) -> OsFingerprint {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)) {
                stream.set_read_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                
                // Enhanced RDP negotiation for OS detection
                let rdp_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13,
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
                ];
                
                if stream.write_all(&rdp_request).is_ok() {
                    let mut response = [0u8; 2048];
                    if let Ok(n) = stream.read(&mut response) {
                        return Self::analyze_rdp_response(&response[..n]);
                    }
                }
            }
        }
        OsFingerprint::Unknown
    }
    
    fn analyze_rdp_response(response: &[u8]) -> OsFingerprint {
        if response.len() < 11 {
            return OsFingerprint::Unknown;
        }
        
        // Analyze response patterns
        if response[0] == 0x03 && response[5] == 0xd0 {
            // Check for version indicators
            if response.len() > 19 {
                for i in 11..std::cmp::min(response.len() - 8, 30) {
                    if response[i] == 0x02 { // RDP_NEG_RSP
                        let flags_offset = i + 2;
                        if flags_offset < response.len() {
                            let flags = response[flags_offset];
                            
                            // Pattern matching for different Windows versions
                            return match flags {
                                0x01 | 0x03 | 0x05 => OsFingerprint::Windows10,
                                0x07 | 0x09 => OsFingerprint::Windows11,
                                0x02 | 0x04 => OsFingerprint::WindowsServer2019,
                                0x06 | 0x08 => OsFingerprint::WindowsServer2022,
                                _ => OsFingerprint::WindowsGeneric,
                            };
                        }
                    }
                }
            }
            
            // Fallback to generic Windows
            return OsFingerprint::WindowsGeneric;
        }
        
        OsFingerprint::Unknown
    }
    
    /// Detect RDP service version
    pub fn detect_rdp_version(&self, ip: &str, port: u16) -> RdpVersion {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)) {
                stream.set_read_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                
                let rdp_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13,
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
                ];
                
                if stream.write_all(&rdp_request).is_ok() {
                    let mut response = [0u8; 2048];
                    if let Ok(n) = stream.read(&mut response) {
                        return Self::parse_rdp_version(&response[..n]);
                    }
                }
            }
        }
        RdpVersion::Unknown
    }
    
    fn parse_rdp_version(response: &[u8]) -> RdpVersion {
        if response.len() < 19 {
            return RdpVersion::Rdp50OrOlder;
        }
        
        // Check for protocol version indicators
        for i in 11..std::cmp::min(response.len() - 4, 30) {
            if response[i] == 0x02 { // RDP_NEG_RSP
                let protocol_offset = i + 4;
                if protocol_offset + 4 <= response.len() {
                    let protocol = u32::from_le_bytes([
                        response[protocol_offset],
                        response[protocol_offset + 1],
                        response[protocol_offset + 2],
                        response[protocol_offset + 3],
                    ]);
                    
                    return match protocol {
                        0x00 => RdpVersion::Rdp50OrOlder,
                        0x01 => RdpVersion::Rdp60,
                        0x02 => RdpVersion::Rdp70,
                        0x03 => RdpVersion::Rdp80,
                        0x04 | 0x05 => RdpVersion::Rdp100,
                        _ => RdpVersion::Unknown,
                    };
                }
            }
        }
        
        RdpVersion::Unknown
    }
    
    /// Check for weak cryptography
    pub fn check_weak_crypto(&self, ip: &str, port: u16) -> CryptoStatus {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)) {
                stream.set_read_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(self.timeout_ms))).ok();
                
                // Request with no encryption
                let rdp_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13,
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x08, 0x00,
                    0x00, 0x00, 0x00, 0x00, // Request RDP Security (weak)
                ];
                
                if stream.write_all(&rdp_request).is_ok() {
                    let mut response = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut response) {
                        if n > 11 && response[5] == 0xd0 {
                            // Check if server accepts weak encryption
                            for i in 11..std::cmp::min(n - 4, 25) {
                                if response[i] == 0x02 {
                                    let protocol_offset = i + 4;
                                    if protocol_offset + 4 <= n {
                                        let protocol = u32::from_le_bytes([
                                            response[protocol_offset],
                                            response[protocol_offset + 1],
                                            response[protocol_offset + 2],
                                            response[protocol_offset + 3],
                                        ]);
                                        
                                        return match protocol {
                                            0x00 => CryptoStatus::WeakRdpSecurity,
                                            0x01 => CryptoStatus::StandardTls,
                                            0x02 => CryptoStatus::StrongNla,
                                            _ => CryptoStatus::Unknown,
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        CryptoStatus::Unknown
    }
    
    /// Detect RD Gateway
    pub fn detect_rd_gateway(&self, ip: &str) -> bool {
        // Check for RD Gateway on port 443
        let addr = format!("{}:443", ip);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(self.timeout_ms)) {
                stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(500))).ok();
                
                // Send HTTP request to check for RD Gateway
                let http_request = "GET /remoteDesktopGateway/ HTTP/1.1\r\nHost: {}\r\n\r\n";
                let request = http_request.replace("{}", ip);
                
                if stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut response) {
                        let response_str = String::from_utf8_lossy(&response[..n]);
                        return response_str.contains("RDG") || response_str.contains("Gateway");
                    }
                }
            }
        }
        false
    }
}

impl Default for AdvancedScanner {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OsFingerprint {
    Windows10,
    Windows11,
    WindowsServer2016,
    WindowsServer2019,
    WindowsServer2022,
    WindowsGeneric,
    Unknown,
}

impl std::fmt::Display for OsFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsFingerprint::Windows10 => write!(f, "Windows 10"),
            OsFingerprint::Windows11 => write!(f, "Windows 11"),
            OsFingerprint::WindowsServer2016 => write!(f, "Windows Server 2016"),
            OsFingerprint::WindowsServer2019 => write!(f, "Windows Server 2019"),
            OsFingerprint::WindowsServer2022 => write!(f, "Windows Server 2022"),
            OsFingerprint::WindowsGeneric => write!(f, "Windows (Generic)"),
            OsFingerprint::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RdpVersion {
    Rdp50OrOlder,
    Rdp60,
    Rdp70,
    Rdp80,
    Rdp100,
    Unknown,
}

impl std::fmt::Display for RdpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RdpVersion::Rdp50OrOlder => write!(f, "RDP 5.0 or older"),
            RdpVersion::Rdp60 => write!(f, "RDP 6.0"),
            RdpVersion::Rdp70 => write!(f, "RDP 7.0"),
            RdpVersion::Rdp80 => write!(f, "RDP 8.0"),
            RdpVersion::Rdp100 => write!(f, "RDP 10.0+"),
            RdpVersion::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CryptoStatus {
    WeakRdpSecurity,
    StandardTls,
    StrongNla,
    Unknown,
}

impl std::fmt::Display for CryptoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoStatus::WeakRdpSecurity => write!(f, "⚠️ Weak (RDP Security)"),
            CryptoStatus::StandardTls => write!(f, "Standard (TLS)"),
            CryptoStatus::StrongNla => write!(f, "✓ Strong (NLA/CredSSP)"),
            CryptoStatus::Unknown => write!(f, "Unknown"),
        }
    }
}
