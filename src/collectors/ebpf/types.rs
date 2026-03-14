//! eBPF types
//!
//! Shared type definitions for eBPF programs and userspace

/// eBPF syscall event structure
/// 
/// This structure is shared between eBPF programs and userspace
/// It must be C-compatible for efficient transfer via ring buffer
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct EbpfSyscallEvent {
    /// Process ID
    pub pid: u32,
    /// User ID
    pub uid: u32,
    /// Syscall ID
    pub syscall_id: u32,
    /// Padding for alignment
    pub _pad: u32,
    /// Timestamp (nanoseconds since epoch)
    pub timestamp: u64,
    /// Command name (comm)
    pub comm: [u8; 16],
    /// Union data - syscall specific
    pub data: EbpfEventData,
}

/// Event data union
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub union EbpfEventData {
    /// execve data
    pub execve: ExecveData,
    /// connect data
    pub connect: ConnectData,
    /// openat data
    pub openat: OpenatData,
    /// ptrace data
    pub ptrace: PtraceData,
    /// Raw bytes
    pub raw: [u8; 128],
}

impl Default for EbpfEventData {
    fn default() -> Self {
        Self {
            raw: [0u8; 128],
        }
    }
}

/// execve-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecveData {
    /// Filename length
    pub filename_len: u32,
    /// Filename (first 128 bytes)
    pub filename: [u8; 128],
    /// Argument count
    pub argc: u32,
}

/// connect-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnectData {
    /// Destination IP (v4 or v6)
    pub dst_ip: [u8; 16],
    /// Destination port
    pub dst_port: u16,
    /// Address family (AF_INET or AF_INET6)
    pub family: u16,
}

/// openat-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenatData {
    /// File path length
    pub path_len: u32,
    /// File path (first 256 bytes)
    pub path: [u8; 256],
    /// Open flags
    pub flags: u32,
}

/// ptrace-specific data
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PtraceData {
    /// Target PID being traced
    pub target_pid: u32,
    /// Ptrace request type
    pub request: u32,
    /// Address
    pub addr: u64,
    /// Data
    pub data: u64,
}

impl EbpfSyscallEvent {
    /// Create a new event
    pub fn new(pid: u32, uid: u32, syscall_id: u32) -> Self {
        Self {
            pid,
            uid,
            syscall_id,
            _pad: 0,
            timestamp: 0,
            comm: [0u8; 16],
            data: EbpfEventData::default(),
        }
    }
    
    /// Get command name as string
    pub fn comm_str(&self) -> String {
        let len = self.comm.iter().position(|&b| b == 0).unwrap_or(16);
        String::from_utf8_lossy(&self.comm[..len]).to_string()
    }
    
    /// Set command name
    pub fn set_comm(&mut self, comm: &[u8]) {
        let len = comm.len().min(15);
        self.comm[..len].copy_from_slice(&comm[..len]);
        self.comm[len] = 0;
    }
}

/// Convert eBPF event to userspace SyscallEvent
pub fn to_syscall_event(ebpf_event: &EbpfSyscallEvent) -> crate::events::syscall::SyscallEvent {
    use crate::events::syscall::{SyscallEvent, SyscallType};
    use chrono::Utc;
    
    // Convert syscall_id to SyscallType
    let syscall_type = match ebpf_event.syscall_id {
        59 => SyscallType::Execve,    // sys_execve
        42 => SyscallType::Connect,   // sys_connect
        257 => SyscallType::Openat,   // sys_openat
        101 => SyscallType::Ptrace,   // sys_ptrace
        _ => SyscallType::Unknown,
    };
    
    let mut event = SyscallEvent::new(
        ebpf_event.pid,
        ebpf_event.uid,
        syscall_type,
        Utc::now(),  // Use current time (timestamp from eBPF may need conversion)
    );
    
    event.comm = Some(ebpf_event.comm_str());
    
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_event_creation() {
        let event = EbpfSyscallEvent::new(1234, 1000, 59);
        assert_eq!(event.pid, 1234);
        assert_eq!(event.uid, 1000);
        assert_eq!(event.syscall_id, 59);
    }
    
    #[test]
    fn test_comm_str_empty() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.comm = [0u8; 16];
        assert_eq!(event.comm_str(), "");
    }
    
    #[test]
    fn test_comm_str_short() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"bash");
        assert_eq!(event.comm_str(), "bash");
    }
    
    #[test]
    fn test_comm_str_exact_15() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"longprocessname");
        assert_eq!(event.comm_str(), "longprocessname");
    }
    
    #[test]
    fn test_set_comm_truncates() {
        let mut event = EbpfSyscallEvent::new(1234, 1000, 59);
        event.set_comm(b"this_is_a_very_long_command_name_that_exceeds_limit");
        // Should be truncated to 15 chars + null
        assert_eq!(event.comm_str().len(), 15);
    }
}
