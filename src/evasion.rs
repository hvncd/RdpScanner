use std::time::Duration;
use rand::Rng;

/// Evasion and stealth techniques
pub struct EvasionConfig {
    pub enabled: bool,
    pub scan_delay_ms: u64,
    pub randomize_delay: bool,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub jitter_percent: u8,
}

impl EvasionConfig {
    pub fn new() -> Self {
        EvasionConfig {
            enabled: false,
            scan_delay_ms: 0,
            randomize_delay: false,
            min_delay_ms: 100,
            max_delay_ms: 5000,
            jitter_percent: 20,
        }
    }
    
    /// Stealth mode - slow and careful
    pub fn stealth() -> Self {
        EvasionConfig {
            enabled: true,
            scan_delay_ms: 2000,
            randomize_delay: true,
            min_delay_ms: 1000,
            max_delay_ms: 5000,
            jitter_percent: 50,
        }
    }
    
    /// Balanced mode - moderate delays
    pub fn balanced() -> Self {
        EvasionConfig {
            enabled: true,
            scan_delay_ms: 500,
            randomize_delay: true,
            min_delay_ms: 200,
            max_delay_ms: 1000,
            jitter_percent: 30,
        }
    }
    
    /// Fast mode - minimal delays
    pub fn fast() -> Self {
        EvasionConfig {
            enabled: true,
            scan_delay_ms: 100,
            randomize_delay: false,
            min_delay_ms: 50,
            max_delay_ms: 200,
            jitter_percent: 10,
        }
    }
    
    /// Get the next delay duration
    pub fn get_delay(&self) -> Duration {
        if !self.enabled {
            return Duration::from_millis(0);
        }
        
        let mut rng = rand::thread_rng();
        
        let base_delay = if self.randomize_delay {
            rng.gen_range(self.min_delay_ms..=self.max_delay_ms)
        } else {
            self.scan_delay_ms
        };
        
        // Add jitter
        let jitter_range = (base_delay as f64 * self.jitter_percent as f64 / 100.0) as u64;
        let jitter = if jitter_range > 0 {
            rng.gen_range(0..=jitter_range)
        } else {
            0
        };
        
        let final_delay = if rng.gen_bool(0.5) {
            base_delay + jitter
        } else {
            base_delay.saturating_sub(jitter)
        };
        
        Duration::from_millis(final_delay)
    }
    
    /// Apply delay
    pub fn apply_delay(&self) {
        if self.enabled {
            std::thread::sleep(self.get_delay());
        }
    }
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Rate limiter for scan operations
pub struct RateLimiter {
    pub max_requests_per_second: u32,
    pub burst_size: u32,
    last_request_time: std::time::Instant,
    tokens: f64,
}

impl RateLimiter {
    pub fn new(max_requests_per_second: u32) -> Self {
        RateLimiter {
            max_requests_per_second,
            burst_size: max_requests_per_second * 2,
            last_request_time: std::time::Instant::now(),
            tokens: max_requests_per_second as f64,
        }
    }
    
    /// Wait until a request can be made
    pub fn acquire(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_request_time).as_secs_f64();
        
        // Refill tokens based on time elapsed
        self.tokens += elapsed * self.max_requests_per_second as f64;
        self.tokens = self.tokens.min(self.burst_size as f64);
        
        // If no tokens available, wait
        if self.tokens < 1.0 {
            let wait_time = (1.0 - self.tokens) / self.max_requests_per_second as f64;
            std::thread::sleep(Duration::from_secs_f64(wait_time));
            self.tokens = 1.0;
        }
        
        // Consume a token
        self.tokens -= 1.0;
        self.last_request_time = std::time::Instant::now();
    }
}

/// User-Agent randomization for HTTP requests
pub struct UserAgentRandomizer {
    user_agents: Vec<String>,
}

impl UserAgentRandomizer {
    pub fn new() -> Self {
        UserAgentRandomizer {
            user_agents: vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0".to_string(),
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36".to_string(),
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36".to_string(),
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/115.0.0.0".to_string(),
            ],
        }
    }
    
    pub fn get_random(&self) -> &str {
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..self.user_agents.len());
        &self.user_agents[index]
    }
}

impl Default for UserAgentRandomizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Scan pattern randomization
pub struct ScanPatternRandomizer {
    pub randomize_order: bool,
}

impl ScanPatternRandomizer {
    pub fn new() -> Self {
        ScanPatternRandomizer {
            randomize_order: false,
        }
    }
    
    /// Randomize IP list order
    pub fn randomize_ips(&self, ips: &mut Vec<String>) {
        if self.randomize_order {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            ips.shuffle(&mut rng);
        }
    }
    
    /// Randomize port list order
    pub fn randomize_ports(&self, ports: &mut Vec<u16>) {
        if self.randomize_order {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            ports.shuffle(&mut rng);
        }
    }
}

impl Default for ScanPatternRandomizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_evasion_config() {
        let config = EvasionConfig::stealth();
        assert!(config.enabled);
        assert!(config.randomize_delay);
        
        let delay = config.get_delay();
        assert!(delay.as_millis() >= config.min_delay_ms as u128);
    }
    
    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(10);
        let start = std::time::Instant::now();
        
        for _ in 0..5 {
            limiter.acquire();
        }
        
        let elapsed = start.elapsed();
        // Should take at least 400ms for 5 requests at 10 req/s
        assert!(elapsed.as_millis() >= 400);
    }
}
