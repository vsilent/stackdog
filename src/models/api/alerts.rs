//! Alert API response types

use serde::{Deserialize, Serialize};

/// Alert response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertResponse {
    pub id: String,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub status: String,
    pub timestamp: String,
    pub metadata: Option<serde_json::Value>,
}

/// Alert statistics response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertStatsResponse {
    pub total_count: u32,
    pub new_count: u32,
    pub acknowledged_count: u32,
    pub resolved_count: u32,
    pub false_positive_count: u32,
}

impl AlertStatsResponse {
    pub fn new() -> Self {
        Self {
            total_count: 0,
            new_count: 0,
            acknowledged_count: 0,
            resolved_count: 0,
            false_positive_count: 0,
        }
    }
}

impl Default for AlertStatsResponse {
    fn default() -> Self {
        Self::new()
    }
}
