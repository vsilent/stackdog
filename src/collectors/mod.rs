//! Collectors module
//!
//! This module contains all event collectors:
//! - eBPF-based syscall monitoring
//! - Docker events streaming
//! - Network traffic capture

pub mod ebpf;
pub mod docker_events;
pub mod network;

/// Marker struct for module tests
pub struct CollectorsMarker;

// Re-export commonly used types
pub use ebpf::{EbpfLoader, SyscallMonitor};
