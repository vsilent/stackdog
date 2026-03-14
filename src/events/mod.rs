//! Events module
//!
//! Contains all security event types, conversions, validation, and streaming

pub mod syscall;
pub mod security;
pub mod validation;
pub mod stream;

/// Marker struct for module tests
pub struct EventsMarker;
