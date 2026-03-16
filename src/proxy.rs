use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use std::io::{Read, Write};

pub struct ProxyConfig {
    pub enabled: bool,
    pub proxy_type: ProxyType,
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ProxyType {
    Socks5,
    Http,
}

impl ProxyConfig {
    pub fn new() -> Self {
        ProxyConfig {
            enabled: false,
            proxy_type: ProxyType::Socks5,
            address: String::new(),
            port: 1080,
            username: None,
            password: None,
        }
    }
    
    pub fn connect_through_proxy(
        &self,
        target_ip: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        if !self.enabled {
            // Direct connection
            let addr = format!("{}:{}", target_ip, target_port);
            return TcpStream::connect_timeout(&addr.parse().unwrap(), timeout);
        }
        
        match self.proxy_type {
            ProxyType::Socks5 => self.connect_socks5(target_ip, target_port, timeout),
            ProxyType::Http => self.connect_http(target_ip, target_port, timeout),
        }
    }
    
    fn connect_socks5(
        &self,
        target_ip: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        let proxy_addr = format!("{}:{}", self.address, self.port);
        let mut stream = TcpStream::connect_timeout(&proxy_addr.parse().unwrap(), timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        
        // SOCKS5 handshake
        // Version 5, 1 auth method
        let auth_methods = if self.username.is_some() {
            vec![5, 1, 2] // Version 5, 1 method, username/password auth
        } else {
            vec![5, 1, 0] // Version 5, 1 method, no auth
        };
        
        stream.write_all(&auth_methods)?;
        
        let mut response = [0u8; 2];
        stream.read_exact(&mut response)?;
        
        if response[0] != 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid SOCKS5 version",
            ));
        }
        
        // Handle authentication if needed
        if response[1] == 2 {
            if let (Some(username), Some(password)) = (&self.username, &self.password) {
                // Username/password auth
                let mut auth_request = vec![1]; // Version 1
                auth_request.push(username.len() as u8);
                auth_request.extend_from_slice(username.as_bytes());
                auth_request.push(password.len() as u8);
                auth_request.extend_from_slice(password.as_bytes());
                
                stream.write_all(&auth_request)?;
                
                let mut auth_response = [0u8; 2];
                stream.read_exact(&mut auth_response)?;
                
                if auth_response[1] != 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "SOCKS5 authentication failed",
                    ));
                }
            }
        }
        
        // Connect request
        let target_ip_bytes: Vec<u8> = target_ip
            .split('.')
            .filter_map(|s| s.parse::<u8>().ok())
            .collect();
        
        if target_ip_bytes.len() != 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Invalid IP address",
            ));
        }
        
        let mut connect_request = vec![
            5,  // Version
            1,  // Connect command
            0,  // Reserved
            1,  // IPv4 address type
        ];
        connect_request.extend_from_slice(&target_ip_bytes);
        connect_request.extend_from_slice(&target_port.to_be_bytes());
        
        stream.write_all(&connect_request)?;
        
        let mut connect_response = [0u8; 10];
        stream.read_exact(&mut connect_response)?;
        
        if connect_response[1] != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "SOCKS5 connection failed",
            ));
        }
        
        Ok(stream)
    }
    
    fn connect_http(
        &self,
        target_ip: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, std::io::Error> {
        let proxy_addr = format!("{}:{}", self.address, self.port);
        let mut stream = TcpStream::connect_timeout(&proxy_addr.parse().unwrap(), timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        
        // HTTP CONNECT method
        let connect_request = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
            target_ip, target_port, target_ip, target_port
        );
        
        stream.write_all(connect_request.as_bytes())?;
        
        let mut response = String::new();
        let mut buffer = [0u8; 1];
        
        // Read until we get \r\n\r\n
        loop {
            stream.read_exact(&mut buffer)?;
            response.push(buffer[0] as char);
            
            if response.ends_with("\r\n\r\n") {
                break;
            }
            
            if response.len() > 4096 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "HTTP proxy response too large",
                ));
            }
        }
        
        // Check for 200 OK
        if !response.contains("200") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "HTTP proxy connection failed",
            ));
        }
        
        Ok(stream)
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self::new()
    }
}
