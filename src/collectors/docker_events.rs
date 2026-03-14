//! Docker events collector
//!
//! Streams events from Docker daemon using Bollard

use anyhow::Result;

/// Docker events collector
pub struct DockerEventsCollector {
    // TODO: Implement in TASK-007
}

impl DockerEventsCollector {
    pub fn new() -> Result<Self> {
        // TODO: Implement
        Ok(Self {})
    }
}

impl Default for DockerEventsCollector {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
