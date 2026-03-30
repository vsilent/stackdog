//! Log source discovery
//!
//! Scans for log sources across Docker containers, system log files,
//! and user-configured custom paths.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Type of log source
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogSourceType {
    DockerContainer,
    SystemLog,
    CustomFile,
}

impl std::fmt::Display for LogSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSourceType::DockerContainer => write!(f, "DockerContainer"),
            LogSourceType::SystemLog => write!(f, "SystemLog"),
            LogSourceType::CustomFile => write!(f, "CustomFile"),
        }
    }
}

impl LogSourceType {
    pub fn from_str(s: &str) -> Self {
        match s {
            "DockerContainer" => LogSourceType::DockerContainer,
            "SystemLog" => LogSourceType::SystemLog,
            _ => LogSourceType::CustomFile,
        }
    }
}

/// A discovered log source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    pub id: String,
    pub source_type: LogSourceType,
    /// File path (for system/custom) or container ID (for Docker)
    pub path_or_id: String,
    pub name: String,
    pub discovered_at: DateTime<Utc>,
    /// Byte offset for incremental reads (files only)
    pub last_read_position: u64,
}

impl LogSource {
    pub fn new(source_type: LogSourceType, path_or_id: String, name: String) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            source_type,
            path_or_id,
            name,
            discovered_at: Utc::now(),
            last_read_position: 0,
        }
    }
}

/// Well-known system log paths to probe
const SYSTEM_LOG_PATHS: &[&str] = &[
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/auth.log",
    "/var/log/kern.log",
    "/var/log/daemon.log",
    "/var/log/secure",
];

/// Discover system log files that exist and are readable
pub fn discover_system_logs() -> Vec<LogSource> {
    SYSTEM_LOG_PATHS
        .iter()
        .filter(|path| Path::new(path).exists())
        .map(|path| {
            let name = Path::new(path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            LogSource::new(LogSourceType::SystemLog, path.to_string(), name)
        })
        .collect()
}

/// Register user-configured custom log file paths
pub fn discover_custom_sources(paths: &[String]) -> Vec<LogSource> {
    paths
        .iter()
        .filter(|path| Path::new(path.as_str()).exists())
        .map(|path| {
            let name = Path::new(path.as_str())
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("custom")
                .to_string();
            LogSource::new(LogSourceType::CustomFile, path.clone(), name)
        })
        .collect()
}

/// Discover Docker container log sources
pub async fn discover_docker_sources() -> Result<Vec<LogSource>> {
    use crate::docker::DockerClient;

    let client = match DockerClient::new().await {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Docker not available for log discovery: {}", e);
            return Ok(Vec::new());
        }
    };

    let containers = client.list_containers(false).await?;
    let sources = containers
        .into_iter()
        .map(|c| {
            let name = format!("docker:{}", c.name);
            LogSource::new(LogSourceType::DockerContainer, c.id, name)
        })
        .collect();

    Ok(sources)
}

/// Run full discovery across all source types
pub async fn discover_all(extra_paths: &[String]) -> Result<Vec<LogSource>> {
    let mut sources = Vec::new();

    // System logs
    sources.extend(discover_system_logs());

    // Custom paths
    sources.extend(discover_custom_sources(extra_paths));

    // Docker containers
    match discover_docker_sources().await {
        Ok(docker_sources) => sources.extend(docker_sources),
        Err(e) => log::warn!("Docker discovery failed: {}", e),
    }

    Ok(sources)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_log_source_type_display() {
        assert_eq!(LogSourceType::DockerContainer.to_string(), "DockerContainer");
        assert_eq!(LogSourceType::SystemLog.to_string(), "SystemLog");
        assert_eq!(LogSourceType::CustomFile.to_string(), "CustomFile");
    }

    #[test]
    fn test_log_source_type_from_str() {
        assert_eq!(LogSourceType::from_str("DockerContainer"), LogSourceType::DockerContainer);
        assert_eq!(LogSourceType::from_str("SystemLog"), LogSourceType::SystemLog);
        assert_eq!(LogSourceType::from_str("CustomFile"), LogSourceType::CustomFile);
        assert_eq!(LogSourceType::from_str("anything"), LogSourceType::CustomFile);
    }

    #[test]
    fn test_log_source_new() {
        let source = LogSource::new(
            LogSourceType::SystemLog,
            "/var/log/syslog".into(),
            "syslog".into(),
        );
        assert_eq!(source.source_type, LogSourceType::SystemLog);
        assert_eq!(source.path_or_id, "/var/log/syslog");
        assert_eq!(source.name, "syslog");
        assert_eq!(source.last_read_position, 0);
        assert!(!source.id.is_empty());
    }

    #[test]
    fn test_discover_custom_sources_existing_file() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "test log line").unwrap();
        let path = tmp.path().to_string_lossy().to_string();

        let sources = discover_custom_sources(&[path.clone()]);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].source_type, LogSourceType::CustomFile);
        assert_eq!(sources[0].path_or_id, path);
    }

    #[test]
    fn test_discover_custom_sources_nonexistent_file() {
        let sources = discover_custom_sources(&["/nonexistent/path/log.txt".into()]);
        assert!(sources.is_empty());
    }

    #[test]
    fn test_discover_custom_sources_mixed() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "log").unwrap();
        let existing = tmp.path().to_string_lossy().to_string();

        let sources = discover_custom_sources(&[
            existing.clone(),
            "/does/not/exist.log".into(),
        ]);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].path_or_id, existing);
    }

    #[test]
    fn test_discover_system_logs_returns_only_existing() {
        let sources = discover_system_logs();
        for source in &sources {
            assert_eq!(source.source_type, LogSourceType::SystemLog);
            assert!(Path::new(&source.path_or_id).exists());
        }
    }

    #[test]
    fn test_log_source_serialization() {
        let source = LogSource::new(
            LogSourceType::DockerContainer,
            "abc123def456".into(),
            "docker:myapp".into(),
        );
        let json = serde_json::to_string(&source).unwrap();
        let deserialized: LogSource = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_type, LogSourceType::DockerContainer);
        assert_eq!(deserialized.path_or_id, "abc123def456");
        assert_eq!(deserialized.name, "docker:myapp");
    }
}
