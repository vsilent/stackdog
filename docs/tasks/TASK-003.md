# Task Specification: TASK-003

## Setup aya-rs eBPF Integration

**Phase:** 1 - Foundation & eBPF Collectors  
**Priority:** High  
**Estimated Effort:** 2-3 days  
**Status:** 🟢 In Progress  

---

## Objective

Implement the eBPF infrastructure using aya-rs framework. This includes the eBPF program loader, syscall tracepoint programs, and event ring buffer for sending events to userspace.

---

## Requirements

### 1. eBPF Program Loader

- Load eBPF programs from ELF files
- Attach programs to kernel tracepoints
- Manage program lifecycle (load/unload)
- Error handling for unsupported kernels

### 2. Syscall Tracepoint Programs

Implement eBPF programs for:
- `sys_enter_execve` - Process execution
- `sys_enter_connect` - Network connections
- `sys_enter_openat` - File access
- `sys_enter_ptrace` - Debugging attempts

### 3. Event Ring Buffer

- Send events from eBPF to userspace
- Efficient event buffering
- Handle event loss gracefully

### 4. Kernel Compatibility

- Check kernel version (4.19+ required)
- Check BTF support
- Fallback mechanisms for older kernels

---

## TDD Tests to Create

### Test File: `tests/collectors/ebpf_loader_test.rs`

```rust
#[test]
fn test_ebpf_loader_creation()
#[test]
fn test_ebpf_program_load_success()
#[test]
fn test_ebpf_program_load_not_found()
#[test]
fn test_ebpf_program_attach()
#[test]
fn test_ebpf_program_detach()
#[test]
fn test_ebpf_kernel_version_check()
```

### Test File: `tests/collectors/ebpf_syscall_test.rs`

```rust
#[test]
fn test_execve_event_capture()
#[test]
fn test_connect_event_capture()
#[test]
fn test_openat_event_capture()
#[test]
fn test_ptrace_event_capture()
#[test]
fn test_event_ring_buffer_poll()
```

### Test File: `tests/collectors/ebpf_integration_test.rs`

```rust
#[test]
#[ignore = "requires root"]
fn test_full_ebpf_pipeline()
#[test]
#[ignore = "requires root"]
fn test_ebpf_event_to_userspace()
```

---

## Implementation Files

### eBPF Programs (`ebpf/src/`)

```
ebpf/
├── src/
│   ├── lib.rs
│   ├── syscalls.rs          # Syscall tracepoint programs
│   ├── maps.rs              # eBPF maps (ring buffer, hash maps)
│   └── types.h              # Shared C types for events
```

### Userspace Loader (`src/collectors/ebpf/`)

```
src/collectors/ebpf/
├── mod.rs
├── loader.rs                # Program loader
├── programs.rs              # Program definitions
├── ring_buffer.rs           # Event ring buffer
└── kernel.rs                # Kernel compatibility
```

---

## Acceptance Criteria

- [ ] eBPF loader compiles without errors
- [ ] Programs load successfully on Linux 4.19+
- [ ] Syscall events captured and sent to userspace
- [ ] Ring buffer polling works correctly
- [ ] All tests passing (target: 15+ tests)
- [ ] Documentation complete
- [ ] Error handling for non-Linux platforms

---

## Dependencies

- `aya = "0.12"` - eBPF framework
- `aya-obj = "0.1"` - eBPF object loading
- `libc` - System calls
- `thiserror` - Error handling

---

## Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| Kernel < 4.19 | High | Version check, graceful fallback |
| No BTF support | Medium | Use non-BTF mode |
| Permission denied | High | Document root requirement |
| macOS development | High | Linux VM for testing |

---

*Created: 2026-03-13*
