//! Baseline learning

use anyhow::Result;

/// Baseline learner
pub struct BaselineLearner {
    // TODO: Implement in TASK-015
}

impl BaselineLearner {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for BaselineLearner {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
