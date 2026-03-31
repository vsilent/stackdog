//! API response types

use serde::{Deserialize, Serialize};

/// Security status response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStatusResponse {
    pub overall_score: u32,
    pub active_threats: u32,
    pub quarantined_containers: u32,
    pub alerts_new: u32,
    pub alerts_acknowledged: u32,
    pub last_updated: String,
}

impl SecurityStatusResponse {
    pub fn new() -> Self {
        Self {
            overall_score: 75,
            active_threats: 0,
            quarantined_containers: 0,
            alerts_new: 0,
            alerts_acknowledged: 0,
            last_updated: chrono::Utc::now().to_rfc3339(),
        }
    }
}

impl Default for SecurityStatusResponse {
    fn default() -> Self {
        Self::new()
    }
}
