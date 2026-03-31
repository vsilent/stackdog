//! Feature extraction for ML
//!
//! Extracts features from security events for anomaly detection

/// Security features for ML model
pub struct SecurityFeatures {
    pub syscall_rate: f64,
    pub network_rate: f64,
    pub unique_processes: u32,
    pub privileged_calls: u32,
}

impl SecurityFeatures {
    pub fn new() -> Self {
        Self {
            syscall_rate: 0.0,
            network_rate: 0.0,
            unique_processes: 0,
            privileged_calls: 0,
        }
    }
}

impl Default for SecurityFeatures {
    fn default() -> Self {
        Self::new()
    }
}
