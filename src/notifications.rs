use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Clone, Debug)]
pub enum NotificationType {
    RdpFound,
    NlaDisabled,
    CredentialCracked,
    ScanComplete,
    CriticalVulnerability,
}

pub struct NotificationManager {
    enabled: Arc<Mutex<bool>>,
    sound_enabled: Arc<Mutex<bool>>,
    desktop_enabled: Arc<Mutex<bool>>,
}

impl NotificationManager {
    pub fn new() -> Self {
        NotificationManager {
            enabled: Arc::new(Mutex::new(true)),
            sound_enabled: Arc::new(Mutex::new(true)),
            desktop_enabled: Arc::new(Mutex::new(true)),
        }
    }
    
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock() = enabled;
    }
    
    pub fn set_sound_enabled(&self, enabled: bool) {
        *self.sound_enabled.lock() = enabled;
    }
    
    pub fn set_desktop_enabled(&self, enabled: bool) {
        *self.desktop_enabled.lock() = enabled;
    }
    
    pub fn notify(&self, notification_type: NotificationType, message: &str) {
        if !*self.enabled.lock() {
            return;
        }
        
        // Desktop notification
        if *self.desktop_enabled.lock() {
            self.show_desktop_notification(&notification_type, message);
        }
        
        // Sound notification
        if *self.sound_enabled.lock() {
            self.play_sound(&notification_type);
        }
    }
    
    fn show_desktop_notification(&self, notification_type: &NotificationType, message: &str) {
        #[cfg(target_os = "windows")]
        {
            use notify_rust::Notification;
            
            let (title, icon) = match notification_type {
                NotificationType::RdpFound => ("RDP Found!", "dialog-information"),
                NotificationType::NlaDisabled => ("NLA Disabled!", "dialog-warning"),
                NotificationType::CredentialCracked => ("Credentials Cracked!", "dialog-password"),
                NotificationType::ScanComplete => ("Scan Complete", "dialog-information"),
                NotificationType::CriticalVulnerability => ("Critical Vulnerability!", "dialog-error"),
            };
            
            let _ = Notification::new()
                .summary(title)
                .body(message)
                .icon(icon)
                .timeout(5000)
                .show();
        }
    }
    
    fn play_sound(&self, _notification_type: &NotificationType) {
        // Play system beep for now
        // In a full implementation, you could use rodio to play custom sounds
        #[cfg(target_os = "windows")]
        {
            use std::io::Write;
            print!("\x07"); // Bell character
            std::io::stdout().flush().ok();
        }
    }
}

impl Default for NotificationManager {
    fn default() -> Self {
        Self::new()
    }
}
