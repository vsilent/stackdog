//! Log sniffing module
//!
//! Discovers, reads, analyzes, and optionally consumes logs from
//! Docker containers, system log files, and custom sources.

pub mod config;
pub mod discovery;
pub mod reader;
pub mod analyzer;
pub mod consumer;
pub mod reporter;

use anyhow::Result;
use crate::database::connection::{create_pool, init_database, DbPool};
use crate::alerting::notifications::NotificationConfig;
use crate::sniff::config::SniffConfig;
use crate::sniff::discovery::LogSourceType;
use crate::sniff::reader::{LogReader, FileLogReader, DockerLogReader};
use crate::sniff::analyzer::{LogAnalyzer, PatternAnalyzer};
use crate::sniff::consumer::LogConsumer;
use crate::sniff::reporter::Reporter;
use crate::database::repositories::log_sources as log_sources_repo;

/// Main orchestrator for the sniff command
pub struct SniffOrchestrator {
    config: SniffConfig,
    pool: DbPool,
    reporter: Reporter,
}

impl SniffOrchestrator {
    pub fn new(config: SniffConfig) -> Result<Self> {
        let pool = create_pool(&config.database_url)?;
        init_database(&pool)?;

        let notification_config = NotificationConfig::default();
        let reporter = Reporter::new(notification_config);

        Ok(Self { config, pool, reporter })
    }

    /// Create the appropriate AI analyzer based on config
    fn create_analyzer(&self) -> Box<dyn LogAnalyzer> {
        match self.config.ai_provider {
            config::AiProvider::OpenAi => {
                Box::new(analyzer::OpenAiAnalyzer::new(
                    self.config.ai_api_url.clone(),
                    self.config.ai_api_key.clone(),
                    self.config.ai_model.clone(),
                ))
            }
            config::AiProvider::Candle => {
                log::info!("Using pattern analyzer (Candle backend not yet implemented)");
                Box::new(PatternAnalyzer::new())
            }
        }
    }

    /// Build readers for discovered sources, restoring saved positions from DB
    fn build_readers(&self, sources: &[discovery::LogSource]) -> Vec<Box<dyn LogReader>> {
        sources.iter().filter_map(|source| {
            let saved = log_sources_repo::get_log_source_by_path(&self.pool, &source.path_or_id)
                .ok()
                .flatten();
            let offset = saved.map(|s| s.last_read_position).unwrap_or(0);

            match source.source_type {
                LogSourceType::SystemLog | LogSourceType::CustomFile => {
                    Some(Box::new(FileLogReader::new(
                        source.id.clone(),
                        source.path_or_id.clone(),
                        offset,
                    )) as Box<dyn LogReader>)
                }
                LogSourceType::DockerContainer => {
                    Some(Box::new(DockerLogReader::new(
                        source.id.clone(),
                        source.path_or_id.clone(),
                    )) as Box<dyn LogReader>)
                }
            }
        }).collect()
    }

    /// Run a single sniff pass: discover → read → analyze → report → consume
    pub async fn run_once(&self) -> Result<SniffPassResult> {
        let mut result = SniffPassResult::default();

        // 1. Discover sources
        let sources = discovery::discover_all(&self.config.extra_sources).await?;
        result.sources_found = sources.len();

        // Register sources in DB
        for source in &sources {
            let _ = log_sources_repo::upsert_log_source(&self.pool, source);
        }

        // 2. Build readers and analyzer
        let mut readers = self.build_readers(&sources);
        let analyzer = self.create_analyzer();
        let mut consumer = if self.config.consume {
            Some(LogConsumer::new(self.config.output_dir.clone())?)
        } else {
            None
        };

        // 3. Process each source
        for (i, reader) in readers.iter_mut().enumerate() {
            let entries = reader.read_new_entries().await?;
            if entries.is_empty() {
                continue;
            }

            result.total_entries += entries.len();

            // 4. Analyze
            let summary = analyzer.summarize(&entries).await?;

            // 5. Report
            let report = self.reporter.report(&summary, Some(&self.pool))?;
            result.anomalies_found += report.anomalies_reported;

            // 6. Consume (if enabled)
            if let Some(ref mut cons) = consumer {
                if i < sources.len() {
                    let source = &sources[i];
                    let consume_result = cons.consume(
                        &entries,
                        &source.name,
                        &source.source_type,
                        &source.path_or_id,
                    ).await?;
                    result.bytes_freed += consume_result.bytes_freed;
                    result.entries_archived += consume_result.entries_archived;
                }
            }

            // 7. Update read position
            let _ = log_sources_repo::update_read_position(
                &self.pool,
                reader.source_id(),
                reader.position(),
            );
        }

        Ok(result)
    }

    /// Run the sniff loop (continuous or one-shot)
    pub async fn run(&self) -> Result<()> {
        log::info!("🔍 Sniff orchestrator started");

        loop {
            match self.run_once().await {
                Ok(result) => {
                    log::info!(
                        "Sniff pass: {} sources, {} entries, {} anomalies, {} bytes freed",
                        result.sources_found,
                        result.total_entries,
                        result.anomalies_found,
                        result.bytes_freed,
                    );
                }
                Err(e) => {
                    log::error!("Sniff pass failed: {}", e);
                }
            }

            if self.config.once {
                log::info!("🏁 One-shot mode: exiting after single pass");
                break;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(self.config.interval_secs)).await;
        }

        Ok(())
    }
}

/// Result of a single sniff pass
#[derive(Debug, Clone, Default)]
pub struct SniffPassResult {
    pub sources_found: usize,
    pub total_entries: usize,
    pub anomalies_found: usize,
    pub bytes_freed: u64,
    pub entries_archived: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sniff_pass_result_default() {
        let result = SniffPassResult::default();
        assert_eq!(result.sources_found, 0);
        assert_eq!(result.total_entries, 0);
        assert_eq!(result.anomalies_found, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_orchestrator_creates_with_memory_db() {
        let mut config = SniffConfig::from_env_and_args(
            true, false, "./stackdog-logs/", None, 30, None,
        );
        config.database_url = ":memory:".into();

        let orchestrator = SniffOrchestrator::new(config);
        assert!(orchestrator.is_ok());
    }

    #[tokio::test]
    async fn test_orchestrator_run_once_with_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            writeln!(f, "INFO: service started").unwrap();
            writeln!(f, "ERROR: connection failed").unwrap();
            writeln!(f, "WARN: retry in 5s").unwrap();
        }

        let mut config = SniffConfig::from_env_and_args(
            true, false, "./stackdog-logs/",
            Some(&log_path.to_string_lossy()),
            30, Some("candle"),
        );
        config.database_url = ":memory:".into();

        let orchestrator = SniffOrchestrator::new(config).unwrap();
        let result = orchestrator.run_once().await.unwrap();

        assert!(result.sources_found >= 1);
        assert!(result.total_entries >= 3);
    }
}
