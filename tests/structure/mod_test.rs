//! Module structure tests
//!
//! These tests verify that all security modules can be imported
//! and basic module structure is correct.

#[test]
fn test_collectors_module_imports() {
    // Verify collectors module exists and can be imported
    // This test will compile only if the module structure is correct
    use crate::collectors;
    
    // Suppress unused import warning
    let _ = std::marker::PhantomData::<collectors::CollectorsMarker>;
}

#[test]
fn test_events_module_imports() {
    use crate::events;
    let _ = std::marker::PhantomData::<events::EventsMarker>;
}

#[test]
fn test_rules_module_imports() {
    use crate::rules;
    let _ = std::marker::PhantomData::<rules::RulesMarker>;
}

#[test]
fn test_ml_module_imports() {
    use crate::ml;
    let _ = std::marker::PhantomData::<ml::MlMarker>;
}

#[test]
fn test_firewall_module_imports() {
    use crate::firewall;
    let _ = std::marker::PhantomData::<firewall::FirewallMarker>;
}

#[test]
fn test_response_module_imports() {
    use crate::response;
    let _ = std::marker::PhantomData::<response::ResponseMarker>;
}

#[test]
fn test_correlator_module_imports() {
    use crate::correlator;
    let _ = std::marker::PhantomData::<correlator::CorrelatorMarker>;
}

#[test]
fn test_alerting_module_imports() {
    use crate::alerting;
    let _ = std::marker::PhantomData::<alerting::AlertingMarker>;
}

#[test]
fn test_baselines_module_imports() {
    use crate::baselines;
    let _ = std::marker::PhantomData::<baselines::BaselinesMarker>;
}

#[test]
fn test_database_module_imports() {
    use crate::database;
    let _ = std::marker::PhantomData::<database::DatabaseMarker>;
}
