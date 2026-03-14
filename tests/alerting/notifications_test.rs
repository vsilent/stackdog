//! Notification tests
//!
//! Tests for notification channel functionality

use stackdog::alerting::notifications::{NotificationChannel, NotificationConfig};
use stackdog::alerting::alert::{Alert, AlertSeverity, AlertType};

#[test]
fn test_console_notification() {
    let channel = NotificationChannel::Console;
    
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test alert".to_string(),
    );
    
    // Console notification should succeed (just prints to stdout)
    let result = channel.send(&alert, &NotificationConfig::default());
    
    // Should succeed (may just log)
    assert!(result.is_ok());
}

#[test]
fn test_notification_config_builder() {
    let config = NotificationConfig::default()
        .with_slack_webhook("https://hooks.slack.com/test".to_string())
        .with_smtp_host("smtp.example.com".to_string())
        .with_smtp_port(587)
        .with_webhook_url("https://example.com/webhook".to_string());
    
    assert_eq!(config.slack_webhook(), Some("https://hooks.slack.com/test"));
    assert_eq!(config.smtp_host(), Some("smtp.example.com"));
    assert_eq!(config.smtp_port(), Some(587));
}

#[test]
fn test_slack_notification_format() {
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Critical,
        "Critical threat detected".to_string(),
    );
    
    // Build Slack payload
    let payload = build_slack_payload(&alert);
    
    assert!(payload.contains("Critical"));
    assert!(payload.contains("ThreatDetected"));
    assert!(payload.contains("Critical threat detected"));
}

#[test]
fn test_webhook_notification_format() {
    let alert = Alert::new(
        AlertType::RuleViolation,
        AlertSeverity::Medium,
        "Rule violation".to_string(),
    );
    
    // Build webhook payload
    let payload = build_webhook_payload(&alert);
    
    assert!(payload.contains("RuleViolation"));
    assert!(payload.contains("Medium"));
}

#[test]
fn test_notification_routing_by_severity() {
    use stackdog::alerting::notifications::route_by_severity;
    
    // Critical should route to all channels
    let channels = route_by_severity(AlertSeverity::Critical);
    assert!(channels.len() >= 1);
    
    // Info should route to fewer channels
    let info_channels = route_by_severity(AlertSeverity::Info);
    assert!(info_channels.len() <= channels.len());
}

#[test]
fn test_alert_severity_to_slack_color() {
    use stackdog::alerting::notifications::severity_to_slack_color;
    
    assert_eq!(severity_to_slack_color(AlertSeverity::Critical), "#FF0000");
    assert_eq!(severity_to_slack_color(AlertSeverity::High), "#FF8C00");
    assert_eq!(severity_to_slack_color(AlertSeverity::Medium), "#FFD700");
    assert_eq!(severity_to_slack_color(AlertSeverity::Low), "#008000");
    assert_eq!(severity_to_slack_color(AlertSeverity::Info), "#0000FF");
}

#[test]
fn test_notification_result_display() {
    use stackdog::alerting::notifications::NotificationResult;
    
    let success = NotificationResult::Success("sent".to_string());
    assert!(format!("{}", success).contains("Success") || format!("{}", success).contains("sent"));
    
    let failure = NotificationResult::Failure("error".to_string());
    assert!(format!("{}", failure).contains("Failure") || format!("{}", failure).contains("error"));
}

// Helper functions for testing
fn build_slack_payload(alert: &Alert) -> String {
    format!(
        r#"{{
            "text": "{}",
            "attachments": [{{
                "color": "{}",
                "fields": [
                    {{"title": "Type", "value": "{:?}"}},
                    {{"title": "Message", "value": "{}"}}
                ]
            }}]
        }}"#,
        alert.message(),
        severity_to_slack_color(alert.severity()),
        alert.alert_type(),
        alert.message()
    )
}

fn build_webhook_payload(alert: &Alert) -> String {
    format!(
        r#"{{
            "alert_type": "{:?} ",
            "severity": "{:?} ",
            "message": "{}",
            "timestamp": "{}"
        }}"#,
        alert.alert_type(),
        alert.severity(),
        alert.message(),
        alert.timestamp()
    )
}

fn severity_to_slack_color(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Critical => "#FF0000",
        AlertSeverity::High => "#FF8C00",
        AlertSeverity::Medium => "#FFD700",
        AlertSeverity::Low => "#008000",
        AlertSeverity::Info => "#0000FF",
    }
}
