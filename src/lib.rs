//! Stackdog Security Library
//!
//! Security platform for Docker containers and Linux servers
//! 
//! ## Features
//! 
//! - **eBPF-based syscall monitoring** - Real-time event collection
//! - **Event enrichment** - Container detection, process info
//! - **Rule engine** - Signature-based detection
//! - **Threat scoring** - ML-ready scoring system
//! - **Alert system** - Multi-channel notifications
//! - **Firewall integration** - nftables/iptables, container quarantine
//! - **Automated response** - Threat response automation

#![allow(unused_must_use)]

// External crates
#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;

// Docker (Linux only)
#[cfg(target_os = "linux")]
extern crate bollard;

// Optional eBPF (Linux only)
#[cfg(all(target_os = "linux", feature = "ebpf"))]
extern crate aya;

// Optional ML
#[cfg(feature = "ml")]
extern crate candle_core;
#[cfg(feature = "ml")]
extern crate candle_nn;

// Security modules - Core
pub mod events;
pub mod rules;
pub mod alerting;
pub mod models;

// Security modules - Linux-specific
#[cfg(target_os = "linux")]
pub mod firewall;

// Security modules - Collectors
#[cfg(target_os = "linux")]
pub mod collectors;

// Optional modules
pub mod ml;
pub mod response;
pub mod correlator;
pub mod baselines;
pub mod database;

// Configuration
pub mod config;

// Re-export commonly used types
pub use events::syscall::{SyscallEvent, SyscallType};
pub use events::security::{SecurityEvent, NetworkEvent, ContainerEvent, AlertEvent};

// Alerting
pub use alerting::{Alert, AlertSeverity, AlertStatus, AlertType};
pub use alerting::{AlertManager, AlertStats};
pub use alerting::{NotificationChannel, NotificationConfig};

// Linux-specific
#[cfg(target_os = "linux")]
pub use firewall::{QuarantineManager, QuarantineState};
#[cfg(target_os = "linux")]
pub use firewall::{ResponseAction, ResponseChain, ResponseExecutor, ResponseType};
#[cfg(target_os = "linux")]
pub use collectors::{EbpfLoader, SyscallMonitor};

// Rules
pub use rules::{RuleEngine, Rule, RuleResult};
pub use rules::{Signature, SignatureDatabase, ThreatCategory};
pub use rules::{SignatureMatcher, PatternMatch, MatchResult};
pub use rules::{ThreatScorer, ThreatScore, ScoringConfig};
pub use rules::{DetectionStats, StatsTracker};
