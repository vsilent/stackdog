//! Threat scoring
//!
//! Calculates threat scores from ML output

use anyhow::Result;

/// Threat score levels
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatScore {
    Normal,
    Low,
    Medium,
    High,
    Critical,
}

/// Threat scorer
pub struct Scorer {
    // TODO: Implement in TASK-016
}

impl Scorer {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for Scorer {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
