//! eBPF collectors module
//!
//! Provides eBPF-based syscall monitoring using aya-rs
//! 
//! Note: This module is only available on Linux with the ebpf feature enabled

pub mod loader;
pub mod kernel;
pub mod syscall_monitor;
pub mod programs;
pub mod ring_buffer;
pub mod enrichment;
pub mod container;
pub mod types;

// Re-export main types
pub use loader::EbpfLoader;
pub use syscall_monitor::SyscallMonitor;
pub use enrichment::EventEnricher;
pub use container::ContainerDetector;
pub use types::{EbpfSyscallEvent, EbpfEventData, to_syscall_event};
