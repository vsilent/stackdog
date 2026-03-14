//! Anomaly detection
//!
//! Detects anomalies in security events

use anyhow::Result;

/// Anomaly detector
pub struct AnomalyDetector {
    // TODO: Implement in TASK-014
}

impl AnomalyDetector {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
