//! Response action pipeline

use anyhow::Result;

/// Action pipeline
pub struct ActionPipeline {
    // TODO: Implement in TASK-011
}

impl ActionPipeline {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for ActionPipeline {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
