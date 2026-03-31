//! Security events database operations

use anyhow::Result;

/// Events database manager
pub struct EventsDb {
    // TODO: Implement
}

impl EventsDb {
    pub fn new() -> Result<Self> {
        Ok(Self {})
    }
}

impl Default for EventsDb {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
