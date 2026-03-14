//! Rules module
//!
//! Contains the rule engine for security rule evaluation

pub mod engine;
pub mod rule;
pub mod signatures;
pub mod builtin;
pub mod result;
pub mod signature_matcher;
pub mod threat_scorer;
pub mod stats;

/// Marker struct for module tests
pub struct RulesMarker;

// Re-export commonly used types
pub use engine::RuleEngine;
pub use rule::{Rule, RuleResult};
pub use signatures::{Signature, SignatureDatabase, ThreatCategory};
pub use result::{RuleEvaluationResult, Severity};
pub use signature_matcher::{SignatureMatcher, PatternMatch, MatchResult};
pub use threat_scorer::{ThreatScorer, ThreatScore, ScoringConfig};
pub use stats::{DetectionStats, StatsTracker};
