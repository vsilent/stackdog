# Stackdog Security

![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Rust](https://img.shields.io/badge/rust-1.75+-orange.svg)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)


<p align="center">
<img width="280" height="280" alt="STACKDOG" src="https://github.com/user-attachments/assets/0c8a9216-8315-4ef7-9b73-d96c40521ed1" />
</p>


## 🛡️ Security platform for Docker Containers & Linux Servers

**Stackdog Security** is a Rust-based security platform that provides real-time threat detection, AI-powered anomaly detection, and automated response for containerized applications.

### 🔥 Key Features

- **📊 Real-time Monitoring** — eBPF-based syscall monitoring with minimal overhead (<5% CPU)
- **🤖 AI/ML Detection** — Candle-powered anomaly detection (native Rust, no Python)
- **🚨 Alert System** — Multi-channel notifications (Slack, email, webhook)
- **🔒 Automated Response** — nftables/iptables firewall, container quarantine
- **📈 Threat Scoring** — Configurable scoring with time-decay
- **🎯 Signature Detection** — 10+ built-in threat signatures

---

## 📖 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Features](#-features)
- [Installation](#-installation)
- [Usage Examples](#-usage-examples)
- [Documentation](#-documentation)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🚀 Quick Start

### Run as Binary

```bash
# Clone repository
git clone https://github.com/vsilent/stackdog
cd stackdog

# Build and run
cargo run
```

### Use as Library

Add to your `Cargo.toml`:

```toml
[dependencies]
stackdog = "0.2"
```

Basic usage:

```rust
use stackdog::{RuleEngine, AlertManager, ThreatScorer};

let mut engine = RuleEngine::new();
let mut alerts = AlertManager::new()?;
let scorer = ThreatScorer::new();

// Process security events
for event in events {
    let score = scorer.calculate_score(&event);
    if score.is_high_or_higher() {
        alerts.generate_alert(...)?;
    }
}
```

### Docker Development

```bash
# Start development environment
docker-compose up -d

# View logs
docker-compose logs -f stackdog
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Stackdog Security Core                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │  Collectors │  │   ML/AI     │  │   Response Engine       │  │
│  │             │  │   Engine    │  │                         │  │
│  │ • eBPF      │  │             │  │ • nftables/iptables     │  │
│  │ • Auditd    │  │ • Anomaly   │  │ • Container quarantine  │  │
│  │ • Docker    │  │   Detection │  │ • Auto-response         │  │
│  │   Events    │  │ • Scoring   │  │ • Alerting              │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Components

| Component | Description | Status |
|-----------|-------------|--------|
| **Events** | Security event types & validation | ✅ Complete |
| **Rules** | Rule engine & signature detection | ✅ Complete |
| **Alerting** | Alert management & notifications | ✅ Complete |
| **Firewall** | nftables/iptables integration | ✅ Complete |
| **Collectors** | eBPF syscall monitoring | ✅ Infrastructure |
| **ML** | Candle-based anomaly detection | 🚧 In progress |

---

## 🎯 Features

### 1. Event Collection

```rust
use stackdog::{SyscallEvent, SyscallType};

let event = SyscallEvent::builder()
    .pid(1234)
    .uid(1000)
    .syscall_type(SyscallType::Execve)
    .container_id(Some("abc123".to_string()))
    .build();
```

**Supported Events:**
- Syscall events (execve, connect, openat, ptrace, etc.)
- Network events
- Container lifecycle events
- Alert events

### 2. Rule Engine

```rust
use stackdog::RuleEngine;
use stackdog::rules::builtin::{SyscallBlocklistRule, ProcessExecutionRule};

let mut engine = RuleEngine::new();
engine.register_rule(Box::new(SyscallBlocklistRule::new(
    vec![SyscallType::Ptrace, SyscallType::Setuid]
)));

let results = engine.evaluate(&event);
```

**Built-in Rules:**
- Syscall allowlist/blocklist
- Process execution monitoring
- Network connection tracking
- File access monitoring

### 3. Signature Detection

```rust
use stackdog::SignatureDatabase;

let db = SignatureDatabase::new();
println!("Loaded {} signatures", db.signature_count());

let matches = db.detect(&event);
for sig in matches {
    println!("Threat: {} (Severity: {})", sig.name(), sig.severity());
}
```

**Built-in Signatures (10+):**
- 🪙 Crypto miner detection
- 🏃 Container escape attempts
- 🌐 Network scanners
- 🔐 Privilege escalation
- 📤 Data exfiltration

### 4. Threat Scoring

```rust
use stackdog::ThreatScorer;

let scorer = ThreatScorer::new();
let score = scorer.calculate_score(&event);

if score.is_critical() {
    println!("Critical threat detected! Score: {}", score.value());
}
```

**Severity Levels:**
- Info (0-19)
- Low (20-39)
- Medium (40-69)
- High (70-89)
- Critical (90-100)

### 5. Alert System

```rust
use stackdog::AlertManager;

let mut manager = AlertManager::new()?;

let alert = manager.generate_alert(
    AlertType::ThreatDetected,
    AlertSeverity::High,
    "Suspicious activity detected".to_string(),
    Some(event),
)?;

manager.acknowledge_alert(&alert.id())?;
```

**Notification Channels:**
- Console (logging)
- Slack webhooks
- Email (SMTP)
- Generic webhooks

### 6. Firewall & Response

```rust
use stackdog::{QuarantineManager, ResponseAction, ResponseType};

// Quarantine container
let mut quarantine = QuarantineManager::new()?;
quarantine.quarantine("container_abc123")?;

// Automated response
let action = ResponseAction::new(
    ResponseType::BlockIP("192.168.1.100".to_string()),
    "Block malicious IP".to_string(),
);
```

**Response Actions:**
- Block IP addresses
- Block ports
- Quarantine containers
- Kill processes
- Send alerts
- Custom commands

---

## 📦 Installation

### Prerequisites

- **Rust** 1.75+ ([install](https://rustup.rs/))
- **SQLite3** + libsqlite3-dev
- **Linux** kernel 4.19+ (for eBPF features)
- **Clang/LLVM** (for eBPF compilation)

### Install Dependencies

**Ubuntu/Debian:**
```bash
apt-get install libsqlite3-dev libssl-dev clang llvm pkg-config
```

**macOS:**
```bash
brew install sqlite openssl llvm
```

**Fedora/RHEL:**
```bash
dnf install sqlite-devel openssl-devel clang llvm
```

### Build from Source

```bash
git clone https://github.com/vsilent/stackdog
cd stackdog
cargo build --release
```

### Run Tests

```bash
# Run all tests
cargo test --lib

# Run specific module tests
cargo test --lib -- events::
cargo test --lib -- rules::
cargo test --lib -- alerting::
```

---

## 💡 Usage Examples

### Example 1: Detect Suspicious Syscalls

```rust
use stackdog::{RuleEngine, SyscallEvent, SyscallType};
use stackdog::rules::builtin::SyscallBlocklistRule;

let mut engine = RuleEngine::new();
engine.register_rule(Box::new(SyscallBlocklistRule::new(
    vec![SyscallType::Ptrace, SyscallType::Setuid]
)));

let event = SyscallEvent::new(
    1234, 1000, SyscallType::Ptrace, Utc::now()
);

let results = engine.evaluate(&event);
if results.iter().any(|r| r.is_match()) {
    println!("⚠️ Suspicious syscall detected!");
}
```

### Example 2: Container Quarantine

```rust
use stackdog::QuarantineManager;

let mut quarantine = QuarantineManager::new()?;

// Quarantine compromised container
quarantine.quarantine("container_abc123")?;

// Check quarantine status
let state = quarantine.get_state("container_abc123");
println!("Container state: {:?}", state);

// Release after investigation
quarantine.release("container_abc123")?;
```

### Example 3: Multi-Event Pattern Detection

```rust
use stackdog::{SignatureMatcher, PatternMatch, SyscallType};

let mut matcher = SignatureMatcher::new();

// Detect: execve followed by ptrace (suspicious)
matcher.add_pattern(
    PatternMatch::new()
        .with_syscall(SyscallType::Execve)
        .then_syscall(SyscallType::Ptrace)
        .within_seconds(60)
);

let result = matcher.match_sequence(&events);
if result.is_match() {
    println!("⚠️ Suspicious pattern detected!");
}
```

### More Examples

See [`examples/usage_examples.rs`](examples/usage_examples.rs) for complete working examples.

Run examples:
```bash
cargo run --example usage_examples
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [DEVELOPMENT.md](DEVELOPMENT.md) | Complete development plan (18 weeks) |
| [TESTING.md](TESTING.md) | Testing guide and infrastructure |
| [TODO.md](TODO.md) | Task tracking and roadmap |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |
| [STATUS.md](STATUS.md) | Current implementation status |

### API Documentation

```bash
# Generate docs
cargo doc --open

# View online (after release)
# https://docs.rs/stackdog
```

---

## 🛠️ Development

### Project Structure

```
stackdog/
├── src/
│   ├── events/          # Event types & validation
│   ├── rules/           # Rule engine & signatures
│   ├── alerting/        # Alerts & notifications
│   ├── firewall/        # nftables/iptables
│   ├── collectors/      # eBPF collectors
│   ├── ml/              # ML infrastructure
│   └── config/          # Configuration
├── examples/            # Usage examples
├── tests/               # Integration tests
├── benches/             # Performance benchmarks
├── ebpf/                # eBPF programs
└── docs/                # Documentation
```

### Development Workflow

```bash
# 1. Clone and setup
git clone https://github.com/vsilent/stackdog
cd stackdog
cp .env.sample .env

# 2. Build
cargo build

# 3. Run tests
cargo test --lib

# 4. Run example
cargo run --example usage_examples

# 5. Check code quality
cargo fmt --all -- --check
cargo clippy --all
```

### Running on Linux

For full eBPF and firewall functionality:

```bash
# Requires root for eBPF
sudo cargo test --lib -- firewall::

# Check eBPF support
bpftool version
uname -r  # Should be 4.19+
```

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Quick Start for Contributors

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/stackdog
cd stackdog

# Create branch
git checkout -b feature/my-feature

# Make changes, run tests
cargo test --lib

# Commit and push
git commit -m "Add my feature"
git push origin feature/my-feature
```

### Good First Issues

Look for issues labeled:
- 🟢 `good first issue` - Easy tasks for newcomers
- 🟡 `help wanted` - Need community help
- 🔵 `documentation` - Improve docs

---

## 📊 Project Status

### Current Phase: Phase 2 - Detection & Response

| Phase | Status | Progress |
|-------|--------|----------|
| **Phase 1: Foundation** | ✅ Complete | 100% |
| **Phase 2: Detection & Response** | 🚧 In Progress | 60% |
| **Phase 3: ML & Automation** | ⏳ Pending | 0% |
| **Phase 4: Web Dashboard** | ⏳ Pending | 0% |

### Completed Tasks

- ✅ Project structure (TASK-001)
- ✅ Event types (TASK-002)
- ✅ eBPF infrastructure (TASK-003)
- ✅ Event enrichment (TASK-004)
- ✅ Rule engine (TASK-005)
- ✅ Signature detection (TASK-006)
- ✅ Alert system (TASK-007)
- ✅ Firewall integration (TASK-008)

### Upcoming Tasks

- ⏳ Web dashboard (TASK-009)
- ⏳ ML anomaly detection (TASK-010)
- ⏳ Kubernetes support (BACKLOG)

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

```
Copyright (c) 2026 Vasili Pascal

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 🙏 Acknowledgments

### Inspired By

- [Portainer](https://github.com/portainer/portainer) - Docker management UI
- [Falco](https://github.com/falcosecurity/falco) - Cloud-native runtime security
- [Sysdig](https://github.com/draios/sysdig) - System visibility

### Technologies

- [aya-rs](https://aya-rs.dev/) - Rust eBPF framework
- [Candle](https://github.com/huggingface/candle) - HuggingFace ML framework
- [Actix-web](https://actix.rs/) - Rust web framework
- [Diesel](http://diesel.rs/) - Rust ORM

---

## 📬 Contact

- **Project Lead:** Vasili Pascal
- **Email:** info@try.direct
- **Twitter:** [@VasiliiPascal](https://twitter.com/VasiliiPascal)
- **Gitter:** [stackdog/community](https://gitter.im/stackdog/community)
- **GitHub:** [vsilent/stackdog](https://github.com/vsilent/stackdog)

---

<p align="center">
<strong>🐕 Built with ❤️ using Rust</strong>
</p>
