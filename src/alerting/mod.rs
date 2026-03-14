//! Alerting module
//!
//! Alert generation, management, and notifications

pub mod alert;
pub mod manager;
pub mod dedup;
pub mod notifications;

/// Marker struct for module tests
pub struct AlertingMarker;

// Re-export commonly used types
pub use alert::{Alert, AlertSeverity, AlertStatus, AlertType};
pub use manager::{AlertManager, AlertStats};
pub use dedup::{AlertDeduplicator, DedupConfig, Fingerprint, DedupResult};
pub use notifications::{NotificationChannel, NotificationConfig, NotificationResult};
