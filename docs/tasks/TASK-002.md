# Task Specification: TASK-002

## Define Security Event Types

**Phase:** 1 - Foundation & eBPF Collectors  
**Priority:** High  
**Estimated Effort:** 1-2 days  
**Status:** 🟢 In Progress  

---

## Objective

Complete the security event types implementation with proper conversions, serialization, validation, and event stream support. This task builds on TASK-001's foundation.

---

## Requirements

### 1. Implement From/Into Traits

Create conversions between:
- `SyscallEvent` ↔ `SecurityEvent`
- `NetworkEvent` ↔ `SecurityEvent`
- `ContainerEvent` ↔ `SecurityEvent`
- `AlertEvent` ↔ `SecurityEvent`
- Raw eBPF data → `SyscallEvent`

### 2. Event Serialization

- JSON serialization/deserialization
- Binary serialization for efficient storage
- Event ID generation (UUID)
- Timestamp handling

### 3. Event Validation

- Validate required fields
- Validate IP addresses
- Validate syscall types
- Validate severity levels

### 4. Event Stream Types

- Event batch for bulk operations
- Event filter for querying
- Event iterator for streaming

---

## TDD Tests to Create

### Test File: `tests/events/event_conversion_test.rs`

```rust
#[test]
fn test_syscall_event_to_security_event()
#[test]
fn test_network_event_to_security_event()
#[test]
fn test_container_event_to_security_event()
#[test]
fn test_alert_event_to_security_event()
#[test]
fn test_security_event_into_syscall()
```

### Test File: `tests/events/event_serialization_test.rs`

```rust
#[test]
fn test_syscall_event_json_serialize()
#[test]
fn test_syscall_event_json_deserialize()
#[test]
fn test_security_event_json_roundtrip()
#[test]
fn test_event_with_uuid()
```

### Test File: `tests/events/event_validation_test.rs`

```rust
#[test]
fn test_valid_syscall_event()
#[test]
fn test_invalid_ip_address()
#[test]
fn test_invalid_severity()
#[test]
fn test_event_validation_result()
```

### Test File: `tests/events/event_stream_test.rs`

```rust
#[test]
fn test_event_batch_creation()
#[test]
fn test_event_filter_matching()
#[test]
fn test_event_iterator()
```

---

## Acceptance Criteria

- [ ] All From/Into traits implemented
- [ ] JSON serialization working
- [ ] Event validation implemented
- [ ] Event stream types implemented
- [ ] All tests passing (target: 25+ tests)
- [ ] 100% test coverage for event types
- [ ] Documentation complete

---

*Created: 2026-03-13*
