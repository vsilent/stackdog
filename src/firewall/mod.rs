//! Firewall module
//!
//! Manages firewall rules (nftables/iptables) and container quarantine

pub mod backend;
pub mod nftables;
pub mod iptables;
pub mod quarantine;
pub mod response;

/// Marker struct for module tests
pub struct FirewallMarker;

// Re-export commonly used types
pub use nftables::{NfTablesBackend, NfTable, NfChain, NfRule};
pub use iptables::{IptablesBackend, IptChain, IptRule};
pub use quarantine::{QuarantineManager, QuarantineState, QuarantineInfo};
pub use response::{ResponseAction, ResponseChain, ResponseExecutor, ResponseType};
pub use backend::{FirewallBackend, FirewallRule, FirewallTable, FirewallChain};
