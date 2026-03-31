//! Log analysis reporter
//!
//! Converts log summaries and anomalies into alerts, then dispatches
//! them via the existing notification channels.

use crate::alerting::alert::{Alert, AlertSeverity, AlertType};
use crate::alerting::notifications::{route_by_severity, NotificationChannel, NotificationConfig};
use crate::database::connection::DbPool;
use crate::database::repositories::log_sources;
use crate::sniff::analyzer::{AnomalySeverity, LogAnomaly, LogSummary};
use anyhow::Result;

/// Reports log analysis results to alert channels and persists summaries
pub struct Reporter {
    notification_config: NotificationConfig,
}

impl Reporter {
    pub fn new(notification_config: NotificationConfig) -> Self {
        Self {
            notification_config,
        }
    }

    /// Map anomaly severity to alert severity
    fn map_severity(anomaly_severity: &AnomalySeverity) -> AlertSeverity {
        match anomaly_severity {
            AnomalySeverity::Low => AlertSeverity::Low,
            AnomalySeverity::Medium => AlertSeverity::Medium,
            AnomalySeverity::High => AlertSeverity::High,
            AnomalySeverity::Critical => AlertSeverity::Critical,
        }
    }

    /// Report a log summary: persist to DB and send anomaly alerts
    pub fn report(&self, summary: &LogSummary, pool: Option<&DbPool>) -> Result<ReportResult> {
        let mut alerts_sent = 0;

        // Persist summary to database
        if let Some(pool) = pool {
            log::debug!(
                "Persisting summary for source {} to database",
                summary.source_id
            );
            let _ = log_sources::create_log_summary(
                pool,
                &summary.source_id,
                &summary.summary_text,
                &summary.period_start.to_rfc3339(),
                &summary.period_end.to_rfc3339(),
                summary.total_entries as i64,
                summary.error_count as i64,
                summary.warning_count as i64,
            );
        }

        // Generate alerts for anomalies
        for anomaly in &summary.anomalies {
            let alert_severity = Self::map_severity(&anomaly.severity);

            log::debug!(
                "Generating alert: severity={}, description={}",
                anomaly.severity,
                anomaly.description
            );

            let alert = Alert::new(
                AlertType::AnomalyDetected,
                alert_severity,
                format!(
                    "[Log Sniff] {} — Source: {} | Sample: {}",
                    anomaly.description, summary.source_id, anomaly.sample_line
                ),
            );

            // Route to appropriate notification channels
            let channels = route_by_severity(alert_severity);
            log::debug!("Routing alert to {} notification channels", channels.len());
            for channel in &channels {
                match channel.send(&alert, &self.notification_config) {
                    Ok(_) => alerts_sent += 1,
                    Err(e) => log::warn!("Failed to send notification: {}", e),
                }
            }
        }

        // Log summary to console
        log::info!(
            "📊 Log Summary [{}]: {} entries, {} errors, {} warnings, {} anomalies",
            summary.source_id,
            summary.total_entries,
            summary.error_count,
            summary.warning_count,
            summary.anomalies.len(),
        );

        Ok(ReportResult {
            anomalies_reported: summary.anomalies.len(),
            notifications_sent: alerts_sent,
            summary_persisted: pool.is_some(),
        })
    }
}

/// Result of a report operation
#[derive(Debug, Clone, Default)]
pub struct ReportResult {
    pub anomalies_reported: usize,
    pub notifications_sent: usize,
    pub summary_persisted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::connection::{create_pool, init_database};
    use chrono::Utc;

    fn make_summary(anomalies: Vec<LogAnomaly>) -> LogSummary {
        LogSummary {
            source_id: "test-source".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            total_entries: 100,
            summary_text: "Test summary".into(),
            error_count: 5,
            warning_count: 3,
            key_events: vec!["Service restarted".into()],
            anomalies,
        }
    }

    #[test]
    fn test_map_severity() {
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::Low),
            AlertSeverity::Low
        );
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::Medium),
            AlertSeverity::Medium
        );
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::High),
            AlertSeverity::High
        );
        assert_eq!(
            Reporter::map_severity(&AnomalySeverity::Critical),
            AlertSeverity::Critical
        );
    }

    #[test]
    fn test_report_no_anomalies() {
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![]);
        let result = reporter.report(&summary, None).unwrap();
        assert_eq!(result.anomalies_reported, 0);
        assert_eq!(result.notifications_sent, 0);
        assert!(!result.summary_persisted);
    }

    #[test]
    fn test_report_with_anomalies_sends_alerts() {
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![LogAnomaly {
            description: "High error rate".into(),
            severity: AnomalySeverity::High,
            sample_line: "ERROR: connection failed".into(),
        }]);

        let result = reporter.report(&summary, None).unwrap();
        assert_eq!(result.anomalies_reported, 1);
        // Console channel is always available, so at least 1 notification sent
        assert!(result.notifications_sent >= 1);
    }

    #[test]
    fn test_report_persists_to_database() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![]);

        let result = reporter.report(&summary, Some(&pool)).unwrap();
        assert!(result.summary_persisted);

        // Verify summary was stored
        let summaries = log_sources::list_summaries_for_source(&pool, "test-source").unwrap();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_entries, 100);
    }

    #[test]
    fn test_report_multiple_anomalies() {
        let reporter = Reporter::new(NotificationConfig::default());
        let summary = make_summary(vec![
            LogAnomaly {
                description: "Error spike".into(),
                severity: AnomalySeverity::Critical,
                sample_line: "FATAL: OOM".into(),
            },
            LogAnomaly {
                description: "Unusual pattern".into(),
                severity: AnomalySeverity::Low,
                sample_line: "DEBUG: retry".into(),
            },
        ]);

        let result = reporter.report(&summary, None).unwrap();
        assert_eq!(result.anomalies_reported, 2);
        assert!(result.notifications_sent >= 2);
    }

    #[test]
    fn test_reporter_new() {
        let config = NotificationConfig::default();
        let reporter = Reporter::new(config);
        // Just ensure it constructs without error
        let summary = make_summary(vec![]);
        let result = reporter.report(&summary, None);
        assert!(result.is_ok());
    }
}
