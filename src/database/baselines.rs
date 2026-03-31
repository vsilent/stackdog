//! Baselines database operations

use anyhow::Result;

/// Baselines database manager
pub struct BaselinesDb {
    // TODO: Implement
}

impl BaselinesDb {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for BaselinesDb {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
