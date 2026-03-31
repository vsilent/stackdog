//! Container API response types

use serde::{Deserialize, Serialize};

/// Container response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResponse {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub security_status: ContainerSecurityStatus,
    pub risk_score: u32,
    pub network_activity: NetworkActivity,
    pub created_at: String,
}

/// Container security status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSecurityStatus {
    pub state: String,
    pub threats: u32,
    pub vulnerabilities: u32,
    pub last_scan: String,
}

/// Network activity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkActivity {
    pub inbound_connections: u32,
    pub outbound_connections: u32,
    pub blocked_connections: u32,
    pub suspicious_activity: bool,
}

/// Quarantine request
#[derive(Debug, Clone, Deserialize)]
pub struct QuarantineRequest {
    pub reason: String,
}
