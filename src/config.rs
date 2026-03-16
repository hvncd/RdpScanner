use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    // Scan settings
    pub default_threads: usize,
    pub default_timeout: f64,
    pub default_target_count: u32,
    
    // UI settings
    pub dark_mode: bool,
    pub auto_save_results: bool,
    pub show_notifications: bool,
    pub play_sounds: bool,
    
    // Advanced settings
    pub use_proxy: bool,
    pub proxy_address: String,
    pub max_retries: u32,
    pub scan_delay_ms: u64,
    
    // Export settings
    pub auto_export: bool,
    pub export_format: String,  // "csv", "json", "txt"
    pub export_path: String,
    
    // Scan profiles
    pub active_profile: String,
    pub profiles: Vec<ScanProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProfile {
    pub name: String,
    pub threads: usize,
    pub timeout: f64,
    pub description: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            default_threads: 500,
            default_timeout: 0.3,
            default_target_count: 100,
            dark_mode: true,
            auto_save_results: true,
            show_notifications: true,
            play_sounds: true,
            use_proxy: false,
            proxy_address: String::new(),
            max_retries: 3,
            scan_delay_ms: 0,
            auto_export: false,
            export_format: "csv".to_string(),
            export_path: String::new(),
            active_profile: "Balanced".to_string(),
            profiles: vec![
                ScanProfile {
                    name: "Quick Scan".to_string(),
                    threads: 1000,
                    timeout: 0.2,
                    description: "Fast scan with high thread count".to_string(),
                },
                ScanProfile {
                    name: "Balanced".to_string(),
                    threads: 500,
                    timeout: 0.3,
                    description: "Balanced speed and accuracy".to_string(),
                },
                ScanProfile {
                    name: "Deep Scan".to_string(),
                    threads: 200,
                    timeout: 1.0,
                    description: "Thorough scan with longer timeout".to_string(),
                },
                ScanProfile {
                    name: "Stealth".to_string(),
                    threads: 50,
                    timeout: 2.0,
                    description: "Slow and stealthy scan".to_string(),
                },
            ],
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let config_path = Self::get_config_path();
        
        if config_path.exists() {
            if let Ok(content) = fs::read_to_string(&config_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }
        
        Self::default()
    }
    
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let config_path = Self::get_config_path();
        
        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let content = toml::to_string_pretty(self)?;
        fs::write(config_path, content)?;
        
        Ok(())
    }
    
    fn get_config_path() -> PathBuf {
        let mut path = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push("SentinelRDP");
        fs::create_dir_all(&path).ok();
        path.push("config.toml");
        path
    }
    
    pub fn get_profile(&self, name: &str) -> Option<&ScanProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }
    
    pub fn apply_profile(&mut self, profile_name: &str) {
        if let Some(profile) = self.profiles.iter().find(|p| p.name == profile_name) {
            let threads = profile.threads;
            let timeout = profile.timeout;
            self.default_threads = threads;
            self.default_timeout = timeout;
            self.active_profile = profile_name.to_string();
        }
    }
}
