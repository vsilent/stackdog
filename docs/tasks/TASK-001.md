# Task Specification: TASK-001

## Create Project Structure for Security Modules

**Phase:** 1 - Foundation & eBPF Collectors  
**Priority:** High  
**Estimated Effort:** 2-3 days  
**Status:** 🟢 Ready for Development  

---

## Objective

Create the new project directory structure for security-focused modules, update dependencies, and establish the eBPF build pipeline. This is the foundational task that enables all subsequent security feature development.

---

## Requirements

### 1. Directory Structure

Create the following directory structure under `src/`:

```
src/
├── collectors/
│   ├── ebpf/
│   │   ├── mod.rs
│   │   ├── loader.rs          # eBPF program loader
│   │   └── programs/          # eBPF program definitions
│   │       └── mod.rs
│   ├── docker_events.rs
│   ├── network.rs
│   └── mod.rs
├── events/
│   ├── mod.rs
│   ├── syscall.rs             # SyscallEvent types
│   └── security.rs            # SecurityEvent enum
├── rules/
│   ├── mod.rs
│   ├── engine.rs              # Rule evaluation engine
│   ├── rule.rs                # Rule trait
│   └── signatures.rs          # Known threat signatures
├── ml/
│   ├── mod.rs
│   ├── candle_backend.rs
│   ├── features.rs
│   ├── anomaly.rs
│   ├── scorer.rs
│   └── models/
│       ├── mod.rs
│       └── isolation_forest.rs
├── firewall/
│   ├── mod.rs
│   ├── nftables.rs
│   ├── iptables.rs
│   └── quarantine.rs
├── response/
│   ├── mod.rs
│   ├── actions.rs
│   └── pipeline.rs
├── correlator/
│   ├── mod.rs
│   └── engine.rs
├── alerting/
│   ├── mod.rs
│   ├── rules.rs
│   ├── notifications.rs
│   └── dedup.rs
├── baselines/
│   ├── mod.rs
│   └── learning.rs
├── database/
│   ├── mod.rs
│   ├── events.rs
│   └── baselines.rs
├── api/                       # Existing - keep and update
├── config/                    # Existing - keep
├── middleware/                # Existing - keep
├── models/                    # Existing - keep
├── services/                  # Existing - keep
├── utils/                     # Existing - keep
├── constants.rs               # Existing - keep
├── error.rs                   # Existing - update
├── main.rs                    # Existing - update
└── schema.rs                  # Existing - keep
```

### 2. Create `ebpf/` Crate

Create a separate Cargo workspace member for eBPF programs:

```
ebpf/
├── Cargo.toml
├── .cargo/
│   └── config
└── src/
    ├── lib.rs
    ├── syscalls.rs
    └── maps.rs
```

### 3. Update `Cargo.toml`

Add new dependencies for security features:

```toml
[dependencies]
# eBPF
aya = "0.12"
aya-obj = "0.1"

# ML
candle-core = "0.3"
candle-nn = "0.3"

# Firewall
netlink-packet-route = "0.17"
netlink-sys = "0.8"

# Existing dependencies (keep)
actix-web = "4"
# ... rest of existing deps
```

### 4. Create Module Files

Each new module should have:
- `mod.rs` with module declaration
- Basic struct/enum definitions
- `#[cfg(test)]` test module stub

---

## TDD Approach

### Step 1: Write Tests First

Create test files before implementation:

#### Test 1: Module Structure Tests

**File:** `tests/structure/mod_test.rs`

```rust
/// Test that all security modules can be imported
#[test]
fn test_collectors_module_imports() {
    // Verify collectors module exists and can be imported
    use stackdog::collectors;
    // Test passes if module compiles
}

#[test]
fn test_events_module_imports() {
    use stackdog::events;
}

#[test]
fn test_rules_module_imports() {
    use stackdog::rules;
}

#[test]
fn test_ml_module_imports() {
    use stackdog::ml;
}

#[test]
fn test_firewall_module_imports() {
    use stackdog::firewall;
}
```

#### Test 2: Event Type Tests

**File:** `tests/events/syscall_event_test.rs`

```rust
use stackdog::events::syscall::{SyscallEvent, SyscallType};
use chrono::Utc;

#[test]
fn test_syscall_event_creation() {
    let event = SyscallEvent::new(
        1234,  // pid
        1000,  // uid
        SyscallType::Execve,
        Utc::now(),
    );
    
    assert_eq!(event.pid, 1234);
    assert_eq!(event.uid, 1000);
    assert_eq!(event.syscall_type, SyscallType::Execve);
}

#[test]
fn test_syscall_event_builder() {
    let event = SyscallEvent::builder()
        .pid(1234)
        .uid(1000)
        .syscall_type(SyscallType::Execve)
        .container_id(Some("abc123".to_string()))
        .build();
    
    assert_eq!(event.pid, 1234);
    assert_eq!(event.container_id, Some("abc123".to_string()));
}
```

#### Test 3: eBPF Loader Tests

**File:** `tests/collectors/ebpf_loader_test.rs`

```rust
use stackdog::collectors::ebpf::loader::EbpfLoader;

#[test]
fn test_ebpf_loader_creation() {
    let loader = EbpfLoader::new();
    assert!(loader.is_ok());
}

#[test]
#[ignore] // Requires root and eBPF support
fn test_ebpf_program_load() {
    let mut loader = EbpfLoader::new().unwrap();
    let result = loader.load_program("syscall_monitor");
    assert!(result.is_ok());
}
```

### Step 2: Run Tests (Verify Failure)

```bash
# Run tests - they should fail initially
cargo test --test structure::mod_test
cargo test --test events::syscall_event_test
cargo test --test collectors::ebpf_loader_test
```

### Step 3: Implement Minimal Code

Implement just enough code to make tests pass:

1. Create module files with basic structs
2. Implement `new()` and builder methods
3. Add `#[derive(Debug, Clone, PartialEq)]` where appropriate

### Step 4: Verify Tests Pass

```bash
# All tests should pass now
cargo test --test structure::mod_test
cargo test --test events::syscall_event_test
```

### Step 5: Refactor

- Extract common code
- Apply DRY principle
- Add documentation comments
- Run `cargo fmt` and `cargo clippy`

---

## Implementation Details

### 1. Event Types (`src/events/syscall.rs`)

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SyscallType {
    Execve,
    Execveat,
    Connect,
    Accept,
    Bind,
    Open,
    Openat,
    Ptrace,
    Setuid,
    Setgid,
    Mount,
    Umount,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub pid: u32,
    pub uid: u32,
    pub syscall_type: SyscallType,
    pub timestamp: DateTime<Utc>,
    pub container_id: Option<String>,
    pub comm: Option<String>,
}

impl SyscallEvent {
    pub fn new(
        pid: u32,
        uid: u32,
        syscall_type: SyscallType,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            pid,
            uid,
            syscall_type,
            timestamp,
            container_id: None,
            comm: None,
        }
    }
    
    pub fn builder() -> SyscallEventBuilder {
        SyscallEventBuilder::new()
    }
}

// Builder pattern
pub struct SyscallEventBuilder {
    pid: u32,
    uid: u32,
    syscall_type: SyscallType,
    timestamp: Option<DateTime<Utc>>,
    container_id: Option<String>,
    comm: Option<String>,
}

impl SyscallEventBuilder {
    pub fn new() -> Self {
        Self {
            pid: 0,
            uid: 0,
            syscall_type: SyscallType::Unknown,
            timestamp: None,
            container_id: None,
            comm: None,
        }
    }
    
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }
    
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }
    
    pub fn syscall_type(mut self, syscall_type: SyscallType) -> Self {
        self.syscall_type = syscall_type;
        self
    }
    
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = Some(timestamp);
        self
    }
    
    pub fn container_id(mut self, container_id: Option<String>) -> Self {
        self.container_id = container_id;
        self
    }
    
    pub fn comm(mut self, comm: Option<String>) -> Self {
        self.comm = comm;
        self
    }
    
    pub fn build(self) -> SyscallEvent {
        SyscallEvent {
            pid: self.pid,
            uid: self.uid,
            syscall_type: self.syscall_type,
            timestamp: self.timestamp.unwrap_or_else(Utc::now),
            container_id: self.container_id,
            comm: self.comm,
        }
    }
}

impl Default for SyscallEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}
```

### 2. Security Event Enum (`src/events/security.rs`)

```rust
use crate::events::syscall::SyscallEvent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityEvent {
    Syscall(SyscallEvent),
    Network(NetworkEvent),
    Container(ContainerEvent),
    Alert(AlertEvent),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub timestamp: DateTime<Utc>,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainerEvent {
    pub container_id: String,
    pub event_type: ContainerEventType,
    pub timestamp: DateTime<Utc>,
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContainerEventType {
    Start,
    Stop,
    Create,
    Destroy,
    Pause,
    Unpause,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub source_event_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertType {
    ThreatDetected,
    AnomalyDetected,
    RuleViolation,
    QuarantineApplied,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
```

### 3. eBPF Loader (`src/collectors/ebpf/loader.rs`)

```rust
use anyhow::Result;
use aya::{Bpf, BpfLoader};

pub struct EbpfLoader {
    bpf: Option<Bpf>,
}

impl EbpfLoader {
    pub fn new() -> Result<Self> {
        Ok(Self { bpf: None })
    }
    
    pub fn load_program(&mut self, program_name: &str) -> Result<()> {
        // Implementation will be added in TASK-003
        Ok(())
    }
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new().unwrap()
    }
}
```

---

## Acceptance Criteria

- [ ] All new directories created
- [ ] All module files compile without errors
- [ ] All TDD tests pass
- [ ] `cargo fmt --all` produces no changes
- [ ] `cargo clippy --all` produces no warnings
- [ ] Module structure tests verify imports work
- [ ] Event types have unit tests with 100% coverage
- [ ] Documentation comments for public APIs
- [ ] Changelog updated

---

## Test Commands

```bash
# Run structure tests
cargo test --test structure::mod_test

# Run event tests
cargo test --test events::syscall_event_test
cargo test --test events::security_event_test

# Run eBPF loader tests
cargo test --test collectors::ebpf_loader_test

# Run all tests
cargo test --all

# Check formatting
cargo fmt --all -- --check

# Check for clippy warnings
cargo clippy --all
```

---

## Dependencies

### Required Crates

Add to `Cargo.toml`:

```toml
[dependencies]
# eBPF
aya = "0.12"
aya-obj = "0.1"

# ML (prepare for future tasks)
candle-core = "0.3"
candle-nn = "0.3"

# Firewall (prepare for future tasks)
netlink-packet-route = "0.17"
netlink-sys = "0.8"

# Utilities
anyhow = "1"
thiserror = "1"
```

### Development Dependencies

```toml
[dev-dependencies]
tokio-test = "0.4"
mockall = "0.11"
```

---

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| eBPF kernel compatibility | Medium | Test on target kernel version, provide fallback |
| Directory structure complexity | Low | Keep structure flat, avoid over-nesting |
| Dependency conflicts | Low | Use compatible versions, test early |

---

## Related Tasks

- **TASK-002**: Define security event types (builds on this task)
- **TASK-003**: Setup aya-rs eBPF integration (builds on this task)
- **TASK-004**: Implement syscall event capture (builds on TASK-003)

---

## Resources

- [Rust Module System](https://doc.rust-lang.org/book/ch07-00-managing-growing-projects-with-packages-crates-and-modules.html)
- [Builder Pattern in Rust](https://rust-unofficial.github.io/patterns/patterns/creational/builder.html)
- [aya-rs Documentation](https://aya-rs.dev/)
- [Candle Documentation](https://docs.rs/candle-core)

---

## Notes

- Start with minimal implementation to pass tests
- Refactor after tests pass
- Keep functions small and focused
- Use `#[derive]` macros for common traits
- Document public APIs with `///` comments

---

*Created: 2026-03-13*  
*Last Updated: 2026-03-13*
