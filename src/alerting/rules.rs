//! Alert rules

use anyhow::Result;

/// Alert rule
pub struct AlertRule {
    // TODO: Implement in TASK-018
}

impl AlertRule {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for AlertRule {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
