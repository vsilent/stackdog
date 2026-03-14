//! Syscall monitor
//!
//! Monitors syscalls using eBPF tracepoints

use anyhow::{Result, Context};
use crate::events::syscall::{SyscallEvent, SyscallType};
use crate::collectors::ebpf::ring_buffer::EventRingBuffer;
use crate::collectors::ebpf::enrichment::EventEnricher;
use crate::collectors::ebpf::container::ContainerDetector;

/// Syscall monitor using eBPF
pub struct SyscallMonitor {
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    loader: Option<super::loader::EbpfLoader>,
    
    running: bool,
    event_buffer: EventRingBuffer,
    enricher: EventEnricher,
    container_detector: Option<ContainerDetector>,
}

impl SyscallMonitor {
    /// Create a new syscall monitor
    pub fn new() -> Result<Self> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let loader = super::loader::EbpfLoader::new()
                .context("Failed to create eBPF loader")?;
            
            let enricher = EventEnricher::new()
                .context("Failed to create event enricher")?;
            
            let container_detector = ContainerDetector::new().ok();
            
            Ok(Self {
                loader: Some(loader),
                running: false,
                event_buffer: EventRingBuffer::with_capacity(8192),
                enricher,
                container_detector,
            })
        }
        
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            anyhow::bail!("SyscallMonitor is only available on Linux with eBPF feature");
        }
    }
    
    /// Start monitoring syscalls
    pub fn start(&mut self) -> Result<()> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            if self.running {
                anyhow::bail!("Monitor is already running");
            }
            
            // TODO: Actually start eBPF programs in TASK-004
            // For now, just mark as running
            self.running = true;
            
            log::info!("Syscall monitor started");
            Ok(())
        }
        
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            anyhow::bail!("SyscallMonitor is only available on Linux");
        }
    }
    
    /// Stop monitoring syscalls
    pub fn stop(&mut self) -> Result<()> {
        self.running = false;
        self.event_buffer.clear();
        
        log::info!("Syscall monitor stopped");
        Ok(())
    }
    
    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        self.running
    }
    
    /// Poll for new events
    pub fn poll_events(&mut self) -> Vec<SyscallEvent> {
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            if !self.running {
                return Vec::new();
            }
            
            // TODO: Actually poll eBPF ring buffer in TASK-004
            // For now, drain from internal buffer
            let mut events = self.event_buffer.drain();
            
            // Enrich events
            for event in &mut events {
                let _ = self.enricher.enrich(event);
            }
            
            events
        }
        
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        {
            Vec::new()
        }
    }
    
    /// Get events without consuming them
    pub fn peek_events(&self) -> &[SyscallEvent] {
        self.event_buffer.events()
    }
    
    /// Get the eBPF loader
    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    pub fn loader(&self) -> Option<&super::loader::EbpfLoader> {
        self.loader.as_ref()
    }
    
    /// Get container ID for current process
    pub fn current_container_id(&mut self) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if let Some(detector) = &mut self.container_detector {
                return detector.current_container();
            }
        }
        None
    }
    
    /// Detect container for a specific PID
    pub fn detect_container_for_pid(&mut self, pid: u32) -> Option<String> {
        #[cfg(target_os = "linux")]
        {
            if let Some(detector) = &mut self.container_detector {
                return detector.detect_container(pid);
            }
        }
        None
    }
    
    /// Get event count
    pub fn event_count(&self) -> usize {
        self.event_buffer.len()
    }
    
    /// Clear event buffer
    pub fn clear_events(&mut self) {
        self.event_buffer.clear();
    }
}

impl Default for SyscallMonitor {
    fn default() -> Self {
        Self::new().expect("Failed to create SyscallMonitor")
    }
}

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
impl SyscallMonitor {
    /// Stub implementation for non-Linux
    pub fn new_stub() -> Result<Self> {
        anyhow::bail!("SyscallMonitor is only available on Linux")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_syscall_monitor_creation() {
        let result = SyscallMonitor::new();
        
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        assert!(result.is_ok());
        
        #[cfg(not(all(target_os = "linux", feature = "ebpf")))]
        assert!(result.is_err());
    }
    
    #[test]
    fn test_syscall_monitor_not_running_initially() {
        let monitor = SyscallMonitor::new();
        
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let monitor = monitor.unwrap();
            assert!(!monitor.is_running());
        }
    }
    
    #[test]
    fn test_poll_events_empty_when_not_running() {
        let mut monitor = SyscallMonitor::new();
        
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let mut monitor = monitor.unwrap();
            let events = monitor.poll_events();
            assert!(events.is_empty());
        }
    }
    
    #[test]
    fn test_event_count() {
        let mut monitor = SyscallMonitor::new();
        
        #[cfg(all(target_os = "linux", feature = "ebpf"))]
        {
            let mut monitor = monitor.unwrap();
            assert_eq!(monitor.event_count(), 0);
        }
    }
}
