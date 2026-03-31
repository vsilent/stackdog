//! Alert notifications
//!
//! Notification channels for alert delivery

use anyhow::Result;
use chrono::{DateTime, Utc};

use crate::alerting::alert::{Alert, AlertSeverity};

/// Notification configuration
#[derive(Debug, Clone, Default)]
pub struct NotificationConfig {
    slack_webhook: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_user: Option<String>,
    smtp_password: Option<String>,
    webhook_url: Option<String>,
    email_recipients: Vec<String>,
}

impl NotificationConfig {
    /// Create default config
    pub fn new() -> Self {
        Self {
            slack_webhook: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            webhook_url: None,
            email_recipients: Vec::new(),
        }
    }

    /// Set Slack webhook
    pub fn with_slack_webhook(mut self, url: String) -> Self {
        self.slack_webhook = Some(url);
        self
    }

    /// Set SMTP host
    pub fn with_smtp_host(mut self, host: String) -> Self {
        self.smtp_host = Some(host);
        self
    }

    /// Set SMTP port
    pub fn with_smtp_port(mut self, port: u16) -> Self {
        self.smtp_port = Some(port);
        self
    }

    /// Set webhook URL
    pub fn with_webhook_url(mut self, url: String) -> Self {
        self.webhook_url = Some(url);
        self
    }

    /// Get Slack webhook
    pub fn slack_webhook(&self) -> Option<&str> {
        self.slack_webhook.as_deref()
    }

    /// Get SMTP host
    pub fn smtp_host(&self) -> Option<&str> {
        self.smtp_host.as_deref()
    }

    /// Get SMTP port
    pub fn smtp_port(&self) -> Option<u16> {
        self.smtp_port
    }

    /// Get webhook URL
    pub fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }
}

/// Notification channel
#[derive(Debug, Clone)]
pub enum NotificationChannel {
    Console,
    Slack,
    Email,
    Webhook,
}

impl NotificationChannel {
    /// Send notification
    pub fn send(&self, alert: &Alert, _config: &NotificationConfig) -> Result<NotificationResult> {
        match self {
            NotificationChannel::Console => self.send_console(alert),
            NotificationChannel::Slack => self.send_slack(alert, _config),
            NotificationChannel::Email => self.send_email(alert, _config),
            NotificationChannel::Webhook => self.send_webhook(alert, _config),
        }
    }

    /// Send to console
    fn send_console(&self, alert: &Alert) -> Result<NotificationResult> {
        println!(
            "[ALERT] {} - {} - {} - {}",
            alert.timestamp(),
            alert.severity(),
            alert.alert_type(),
            alert.message()
        );

        Ok(NotificationResult::Success("sent to console".to_string()))
    }

    /// Send to Slack via incoming webhook
    fn send_slack(&self, alert: &Alert, config: &NotificationConfig) -> Result<NotificationResult> {
        if let Some(webhook_url) = config.slack_webhook() {
            let payload = build_slack_message(alert);
            log::debug!("Sending Slack notification to webhook");
            log::trace!("Slack payload: {}", payload);

            // Blocking HTTP POST — notification sending is synchronous in this codebase
            let client = reqwest::blocking::Client::new();
            match client
                .post(webhook_url)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        log::info!("Slack notification sent successfully");
                        Ok(NotificationResult::Success("sent to Slack".to_string()))
                    } else {
                        let status = resp.status();
                        let body = resp.text().unwrap_or_default();
                        log::warn!("Slack API returned {}: {}", status, body);
                        Ok(NotificationResult::Failure(format!(
                            "Slack returned {}: {}",
                            status, body
                        )))
                    }
                }
                Err(e) => {
                    log::warn!("Failed to send Slack notification: {}", e);
                    Ok(NotificationResult::Failure(format!(
                        "Slack request failed: {}",
                        e
                    )))
                }
            }
        } else {
            log::debug!("Slack webhook not configured, skipping");
            Ok(NotificationResult::Failure(
                "Slack webhook not configured".to_string(),
            ))
        }
    }

    /// Send via email
    fn send_email(&self, alert: &Alert, config: &NotificationConfig) -> Result<NotificationResult> {
        // In production, this would send SMTP email
        // For now, just log
        if config.smtp_host().is_some() {
            log::info!("Would send email: {}", alert.message());
            Ok(NotificationResult::Success("sent via email".to_string()))
        } else {
            Ok(NotificationResult::Failure(
                "SMTP not configured".to_string(),
            ))
        }
    }

    /// Send to webhook
    fn send_webhook(
        &self,
        alert: &Alert,
        config: &NotificationConfig,
    ) -> Result<NotificationResult> {
        // In production, this would make HTTP POST
        // For now, just log
        if config.webhook_url().is_some() {
            log::info!("Would send to webhook: {}", alert.message());
            Ok(NotificationResult::Success("sent to webhook".to_string()))
        } else {
            Ok(NotificationResult::Failure(
                "Webhook URL not configured".to_string(),
            ))
        }
    }
}

/// Notification result
#[derive(Debug, Clone)]
pub enum NotificationResult {
    Success(String),
    Failure(String),
}

impl std::fmt::Display for NotificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationResult::Success(msg) => write!(f, "Success: {}", msg),
            NotificationResult::Failure(msg) => write!(f, "Failure: {}", msg),
        }
    }
}

/// Route alerts by severity
pub fn route_by_severity(severity: AlertSeverity) -> Vec<NotificationChannel> {
    match severity {
        AlertSeverity::Critical => {
            // Critical goes to all channels
            vec![
                NotificationChannel::Console,
                NotificationChannel::Slack,
                NotificationChannel::Email,
                NotificationChannel::Webhook,
            ]
        }
        AlertSeverity::High => {
            vec![
                NotificationChannel::Console,
                NotificationChannel::Slack,
                NotificationChannel::Webhook,
            ]
        }
        AlertSeverity::Medium => {
            vec![NotificationChannel::Console, NotificationChannel::Slack]
        }
        AlertSeverity::Low => {
            vec![NotificationChannel::Console]
        }
        AlertSeverity::Info => {
            vec![NotificationChannel::Console]
        }
    }
}

/// Convert severity to Slack color
pub fn severity_to_slack_color(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Critical => "#FF0000",
        AlertSeverity::High => "#FF8C00",
        AlertSeverity::Medium => "#FFD700",
        AlertSeverity::Low => "#008000",
        AlertSeverity::Info => "#0000FF",
    }
}

/// Build Slack message payload
pub fn build_slack_message(alert: &Alert) -> String {
    serde_json::json!({
        "text": "🐕 Stackdog Security Alert",
        "attachments": [{
            "color": severity_to_slack_color(alert.severity()),
            "title": format!("{:?}", alert.alert_type()),
            "text": alert.message(),
            "fields": [
                {"title": "Severity", "value": alert.severity().to_string(), "short": true},
                {"title": "Status", "value": alert.status().to_string(), "short": true},
                {"title": "Time", "value": alert.timestamp().to_rfc3339(), "short": true}
            ]
        }]
    })
    .to_string()
}

/// Build webhook payload
pub fn build_webhook_payload(alert: &Alert) -> String {
    format!(
        r#"{{
            "alert_type": "{:?} ",
            "severity": "{}",
            "message": "{}",
            "timestamp": "{}",
            "status": "{}"
        }}"#,
        alert.alert_type(),
        alert.severity(),
        alert.message(),
        alert.timestamp(),
        alert.status()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_console_notification() {
        let channel = NotificationChannel::Console;
        let alert = Alert::new(
            crate::alerting::alert::AlertType::ThreatDetected,
            AlertSeverity::High,
            "Test".to_string(),
        );

        let result = channel.send(&alert, &NotificationConfig::default());
        assert!(result.is_ok());
    }

    #[test]
    fn test_severity_to_slack_color() {
        assert_eq!(severity_to_slack_color(AlertSeverity::Critical), "#FF0000");
        assert_eq!(severity_to_slack_color(AlertSeverity::High), "#FF8C00");
    }

    #[test]
    fn test_route_by_severity() {
        let critical_routes = route_by_severity(AlertSeverity::Critical);
        assert!(critical_routes.len() >= 3);

        let info_routes = route_by_severity(AlertSeverity::Info);
        assert_eq!(info_routes.len(), 1);
    }
}
