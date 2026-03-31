# Task Specification: TASK-004

## Implement Syscall Event Capture

**Phase:** 1 - Foundation & eBPF Collectors  
**Priority:** High  
**Estimated Effort:** 3-4 days  
**Status:** 🟢 In Progress  

---

## Objective

Implement actual eBPF programs for syscall monitoring and connect them to the userspace event capture system. This task transforms the stub implementation from TASK-003 into a working syscall monitoring system.

---

## Requirements

### 1. eBPF Programs (ebpf/src/)

Implement eBPF tracepoint programs for:

#### sys_enter_execve
- Capture process execution
- Extract: pid, uid, filename, arguments
- Send event to userspace via ring buffer

#### sys_enter_connect
- Capture network connections
- Extract: pid, uid, destination IP, destination port
- Send event to userspace

#### sys_enter_openat
- Capture file access
- Extract: pid, uid, file path, flags
- Send event to userspace

#### sys_enter_ptrace
- Capture debugging attempts
- Extract: pid, uid, target pid, request type
- Send event to userspace

### 2. Event Structure (Shared)

Define C-compatible event structures for eBPF ↔ userspace communication:

```c
struct SyscallEvent {
    u32 pid;
    u32 uid;
    u64 timestamp;
    u32 syscall_id;
    char comm[16];
    // Union for syscall-specific data
};
```

### 3. Ring Buffer Integration

- Connect eBPF perf buffer to userspace
- Implement event polling loop
- Handle event deserialization
- Manage event loss

### 4. Event Enrichment

- Add container ID detection
- Add process tree information
- Add timestamp normalization

---

## TDD Tests to Create

### Test File: `tests/collectors/execve_capture_test.rs`

```rust
#[test]
#[ignore = "requires root"]
fn test_execve_event_captured_on_process_spawn()
#[test]
#[ignore = "requires root"]
fn test_execve_event_contains_filename()
#[test]
#[ignore = "requires root"]
fn test_execve_event_contains_pid()
#[test]
#[ignore = "requires root"]
fn test_execve_event_contains_uid()
```

### Test File: `tests/collectors/connect_capture_test.rs`

```rust
#[test]
#[ignore = "requires root"]
fn test_connect_event_captured_on_tcp_connection()
#[test]
#[ignore = "requires root"]
fn test_connect_event_contains_destination_ip()
#[test]
#[ignore = "requires root"]
fn test_connect_event_contains_destination_port()
```

### Test File: `tests/collectors/openat_capture_test.rs`

```rust
#[test]
#[ignore = "requires root"]
fn test_openat_event_captured_on_file_open()
#[test]
#[ignore = "requires root"]
fn test_openat_event_contains_file_path()
```

### Test File: `tests/collectors/ptrace_capture_test.rs`

```rust
#[test]
#[ignore = "requires root"]
fn test_ptrace_event_captured_on_trace_attempt()
```

### Test File: `tests/collectors/event_enrichment_test.rs`

```rust
#[test]
fn test_container_id_detection()
#[test]
fn test_timestamp_normalization()
#[test]
fn test_process_tree_enrichment()
```

---

## Implementation Files

### eBPF Programs (`ebpf/src/`)

```
ebpf/
├── src/
│   ├── lib.rs
│   ├── syscalls/
│   │   ├── mod.rs
│   │   ├── execve.rs
│   │   ├── connect.rs
│   │   ├── openat.rs
│   │   └── ptrace.rs
│   ├── maps.rs
│   └── types.rs
```

### Userspace (`src/collectors/ebpf/`)

```
src/collectors/ebpf/
├── mod.rs
├── loader.rs              (from TASK-003)
├── event_reader.rs        (NEW - event polling)
├── enrichment.rs          (NEW - event enrichment)
└── container.rs           (NEW - container detection)
```

---

## Acceptance Criteria

- [ ] eBPF programs compile successfully
- [ ] Programs load and attach to kernel
- [ ] execve events captured on process spawn
- [ ] connect events captured on network connections
- [ ] openat events captured on file access
- [ ] ptrace events captured on debugging attempts
- [ ] Events enriched with container ID
- [ ] All tests passing (target: 20+ tests)
- [ ] Documentation complete

---

## Dependencies

- `aya = "0.12"` - eBPF framework
- `libc` - System calls
- `bollard` - Docker API (for container detection)

---

## Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| eBPF program rejection | High | Medium | Test on multiple kernels |
| Performance overhead | Medium | Low | Benchmark early |
| Container detection fails | Medium | Medium | Fallback to cgroup parsing |
| Event loss under load | High | Medium | Tune ring buffer size |

---

*Created: 2026-03-13*
