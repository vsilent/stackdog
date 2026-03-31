//! Threat scorer
//!
//! Calculates threat scores from events and signatures

use crate::events::security::SecurityEvent;
use crate::rules::result::Severity;
use crate::rules::signature_matcher::SignatureMatcher;
use chrono::Utc;

/// Threat score (0-100)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreatScore {
    value: u8,
}

impl ThreatScore {
    /// Create a new threat score
    pub fn new(value: u8) -> Self {
        Self {
            value: value.min(100),
        }
    }
    
    /// Get the score value
    pub fn value(&self) -> u8 {
        self.value
    }
    
    /// Get severity from score
    pub fn severity(&self) -> Severity {
        Severity::from_score(self.value)
    }
    
    /// Check if score exceeds threshold
    pub fn exceeds_threshold(&self, threshold: u8) -> bool {
        self.value >= threshold
    }
    
    /// Check if score is high or higher (>= 70)
    pub fn is_high_or_higher(&self) -> bool {
        self.value >= 70
    }
    
    /// Check if score is critical (>= 90)
    pub fn is_critical(&self) -> bool {
        self.value >= 90
    }
    
    /// Add to score (capped at 100)
    pub fn add(&mut self, value: u8) {
        self.value = (self.value + value).min(100);
    }
}

impl std::fmt::Display for ThreatScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

/// Scoring configuration
#[derive(Debug, Clone)]
pub struct ScoringConfig {
    base_score: u8,
    multiplier: f64,
    time_decay_enabled: bool,
    decay_half_life_seconds: u64,
}

impl ScoringConfig {
    /// Create default config
    pub fn default() -> Self {
        Self {
            base_score: 50,
            multiplier: 1.0,
            time_decay_enabled: false,
            decay_half_life_seconds: 3600,  // 1 hour
        }
    }
    
    /// Set base score
    pub fn with_base_score(mut self, score: u8) -> Self {
        self.base_score = score;
        self
    }
    
    /// Set multiplier
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }
    
    /// Enable time decay
    pub fn with_time_decay(mut self, enabled: bool) -> Self {
        self.time_decay_enabled = enabled;
        self
    }
    
    /// Set decay half-life
    pub fn with_decay_half_life(mut self, seconds: u64) -> Self {
        self.decay_half_life_seconds = seconds;
        self
    }
    
    /// Check if time decay is enabled
    pub fn time_decay_enabled(&self) -> bool {
        self.time_decay_enabled
    }
    
    /// Get base score
    pub fn base_score(&self) -> u8 {
        self.base_score
    }
    
    /// Get multiplier
    pub fn multiplier(&self) -> f64 {
        self.multiplier
    }
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self::default()
    }
}

/// Threat scorer
pub struct ThreatScorer {
    config: ScoringConfig,
    matcher: SignatureMatcher,
}

impl ThreatScorer {
    /// Create a new threat scorer with default config
    pub fn new() -> Self {
        Self {
            config: ScoringConfig::default(),
            matcher: SignatureMatcher::new(),
        }
    }
    
    /// Create scorer with custom config
    pub fn with_config(config: ScoringConfig) -> Self {
        Self {
            config,
            matcher: SignatureMatcher::new(),
        }
    }
    
    /// Create scorer with custom matcher
    pub fn with_matcher(matcher: SignatureMatcher) -> Self {
        Self {
            config: ScoringConfig::default(),
            matcher,
        }
    }
    
    /// Calculate threat score for an event
    pub fn calculate_score(&self, event: &SecurityEvent) -> ThreatScore {
        // Get signature matches
        let match_result = self.matcher.match_single(event);
        
        if !match_result.is_match() {
            return ThreatScore::new(0);
        }
        
        // Start with base score
        let mut score = self.config.base_score() as f64;
        
        // Apply multiplier based on confidence
        score *= match_result.confidence();
        score *= self.config.multiplier();
        
        // Apply time decay if enabled
        if self.config.time_decay_enabled {
            // Time decay would be applied based on event age
            // For now, use full score (event is "recent")
        }
        
        ThreatScore::new(score as u8)
    }
    
    /// Calculate cumulative score for multiple events
    pub fn calculate_cumulative_score(&self, events: &[SecurityEvent]) -> ThreatScore {
        let mut total_score = 0u16;
        
        for event in events {
            let score = self.calculate_score(event);
            total_score += score.value() as u16;
        }
        
        // Average score with bonus for multiple events
        if events.is_empty() {
            return ThreatScore::new(0);
        }
        
        let avg_score = total_score / events.len() as u16;
        let bonus = (events.len() as u16).min(20);  // Up to 20% bonus
        
        ThreatScore::new(((avg_score as f64) * (1.0 + bonus as f64 / 100.0)) as u8)
    }
    
    /// Get the signature matcher
    pub fn matcher(&self) -> &SignatureMatcher {
        &self.matcher
    }
    
    /// Get the scoring config
    pub fn config(&self) -> &ScoringConfig {
        &self.config
    }
}

impl Default for ThreatScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate severities to highest
pub fn aggregate_severities(severities: &[Severity]) -> Severity {
    severities.iter().copied().max().unwrap_or(Severity::Info)
}

/// Calculate severity from scores
pub fn calculate_severity_from_scores(scores: &[ThreatScore]) -> Severity {
    if scores.is_empty() {
        return Severity::Info;
    }
    
    let max_score = scores.iter().map(|s| s.value()).max().unwrap_or(0);
    Severity::from_score(max_score)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_threat_score_creation() {
        let score = ThreatScore::new(75);
        assert_eq!(score.value(), 75);
    }
    
    #[test]
    fn test_threat_score_cap() {
        let score = ThreatScore::new(150);
        assert_eq!(score.value(), 100);
    }
    
    #[test]
    fn test_threat_score_add() {
        let mut score = ThreatScore::new(50);
        score.add(30);
        assert_eq!(score.value(), 80);
    }
    
    #[test]
    fn test_threat_score_add_cap() {
        let mut score = ThreatScore::new(90);
        score.add(50);
        assert_eq!(score.value(), 100);
    }
    
    #[test]
    fn test_scoring_config_builder() {
        let config = ScoringConfig::default()
            .with_base_score(60)
            .with_multiplier(1.5)
            .with_time_decay(true);
        
        assert_eq!(config.base_score(), 60);
        assert_eq!(config.multiplier(), 1.5);
        assert!(config.time_decay_enabled());
    }
}
