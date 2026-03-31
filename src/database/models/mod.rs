//! Database models

use serde::{Deserialize, Serialize};

/// Alert model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: String,
    pub severity: String,
    pub message: String,
    pub status: String,
    pub timestamp: String,
    pub metadata: Option<String>,
}

/// Threat model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub id: String,
    pub threat_type: String,
    pub severity: String,
    pub score: i32,
    pub source: String,
    pub timestamp: String,
    pub status: String,
    pub metadata: Option<String>,
}

/// Container cache model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerCache {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub risk_score: i32,
    pub security_state: String,
    pub threats_count: i32,
}
