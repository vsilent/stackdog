//! Log readers for different source types
//!
//! Implements the `LogReader` trait for file-based logs, Docker container logs,
//! and systemd journal (Linux only).

use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;

/// A single log entry from any source
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub source_id: String,
    pub timestamp: DateTime<Utc>,
    pub line: String,
    pub metadata: HashMap<String, String>,
}

/// Trait for reading log entries from a source
#[async_trait]
pub trait LogReader: Send + Sync {
    /// Read new entries since the last read position
    async fn read_new_entries(&mut self) -> Result<Vec<LogEntry>>;
    /// Return the source identifier
    fn source_id(&self) -> &str;
    /// Return current read position (bytes for files, opaque for others)
    fn position(&self) -> u64;
}

/// Reads log entries from a regular file, tracking byte offset
pub struct FileLogReader {
    source_id: String,
    path: String,
    offset: u64,
}

impl FileLogReader {
    pub fn new(source_id: String, path: String, start_offset: u64) -> Self {
        Self {
            source_id,
            path,
            offset: start_offset,
        }
    }

    fn read_lines_from_offset(&mut self) -> Result<Vec<LogEntry>> {
        let path = Path::new(&self.path);
        if !path.exists() {
            log::debug!("Log file does not exist: {}", self.path);
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let file_len = file.metadata()?.len();
        log::debug!(
            "Reading {} (size: {} bytes, offset: {})",
            self.path,
            file_len,
            self.offset
        );

        // Handle file truncation (log rotation)
        if self.offset > file_len {
            log::debug!(
                "File truncated (rotation?), resetting offset from {} to 0",
                self.offset
            );
            self.offset = 0;
        }

        let mut reader = BufReader::new(file);
        reader.seek(SeekFrom::Start(self.offset))?;

        let mut entries = Vec::new();
        let mut line = Vec::new();

        while reader.read_until(b'\n', &mut line)? > 0 {
            let decoded = String::from_utf8_lossy(&line);
            let trimmed = decoded.trim_end().to_string();
            if !trimmed.is_empty() {
                entries.push(LogEntry {
                    source_id: self.source_id.clone(),
                    timestamp: Utc::now(),
                    line: trimmed,
                    metadata: HashMap::from([("source_path".into(), self.path.clone())]),
                });
            }
            line.clear();
        }

        self.offset = reader.stream_position()?;
        log::debug!(
            "Read {} entries from {}, new offset: {}",
            entries.len(),
            self.path,
            self.offset
        );
        Ok(entries)
    }
}

#[async_trait]
impl LogReader for FileLogReader {
    async fn read_new_entries(&mut self) -> Result<Vec<LogEntry>> {
        self.read_lines_from_offset()
    }

    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn position(&self) -> u64 {
        self.offset
    }
}

/// Reads logs from a Docker container via the bollard API
pub struct DockerLogReader {
    source_id: String,
    container_id: String,
    last_timestamp: Option<i64>,
}

impl DockerLogReader {
    pub fn new(source_id: String, container_id: String) -> Self {
        Self {
            source_id,
            container_id,
            last_timestamp: None,
        }
    }
}

#[async_trait]
impl LogReader for DockerLogReader {
    async fn read_new_entries(&mut self) -> Result<Vec<LogEntry>> {
        use bollard::container::LogsOptions;
        use bollard::Docker;
        use futures_util::stream::StreamExt;

        let docker = match Docker::connect_with_local_defaults() {
            Ok(d) => d,
            Err(e) => {
                log::warn!("Docker not available: {}", e);
                return Ok(Vec::new());
            }
        };

        let options = LogsOptions::<String> {
            stdout: true,
            stderr: true,
            since: self.last_timestamp.unwrap_or(0),
            timestamps: true,
            tail: if self.last_timestamp.is_none() {
                "100".to_string()
            } else {
                "all".to_string()
            },
            ..Default::default()
        };

        let mut stream = docker.logs(&self.container_id, Some(options));
        let mut entries = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(output) => {
                    let line = output.to_string();
                    let trimmed = line.trim().to_string();
                    if !trimmed.is_empty() {
                        entries.push(LogEntry {
                            source_id: self.source_id.clone(),
                            timestamp: Utc::now(),
                            line: trimmed,
                            metadata: HashMap::from([(
                                "container_id".into(),
                                self.container_id.clone(),
                            )]),
                        });
                    }
                }
                Err(e) => {
                    log::warn!("Error reading Docker logs for {}: {}", self.container_id, e);
                    break;
                }
            }
        }

        self.last_timestamp = Some(Utc::now().timestamp());
        Ok(entries)
    }

    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn position(&self) -> u64 {
        self.last_timestamp.unwrap_or(0) as u64
    }
}

/// Reads logs from systemd journal (Linux only)
#[cfg(target_os = "linux")]
pub struct JournaldReader {
    source_id: String,
    cursor: Option<String>,
}

#[cfg(target_os = "linux")]
impl JournaldReader {
    pub fn new(source_id: String) -> Self {
        Self {
            source_id,
            cursor: None,
        }
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl LogReader for JournaldReader {
    async fn read_new_entries(&mut self) -> Result<Vec<LogEntry>> {
        use tokio::process::Command;

        let mut cmd = Command::new("journalctl");
        cmd.arg("--no-pager")
            .arg("-o")
            .arg("short-iso")
            .arg("-n")
            .arg("200");

        if let Some(ref cursor) = self.cursor {
            cmd.arg("--after-cursor").arg(cursor);
        }

        cmd.arg("--show-cursor");

        let output = cmd.output().await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut entries = Vec::new();

        for line in stdout.lines() {
            if line.starts_with("-- cursor:") {
                self.cursor = line.strip_prefix("-- cursor: ").map(|s| s.to_string());
                continue;
            }
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                entries.push(LogEntry {
                    source_id: self.source_id.clone(),
                    timestamp: Utc::now(),
                    line: trimmed,
                    metadata: HashMap::from([("source".into(), "journald".into())]),
                });
            }
        }

        Ok(entries)
    }

    fn source_id(&self) -> &str {
        &self.source_id
    }

    fn position(&self) -> u64 {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry {
            source_id: "test-source".into(),
            timestamp: Utc::now(),
            line: "Error: something went wrong".into(),
            metadata: HashMap::from([("key".into(), "value".into())]),
        };
        assert_eq!(entry.source_id, "test-source");
        assert!(entry.line.contains("Error"));
        assert_eq!(entry.metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_file_log_reader_new() {
        let reader = FileLogReader::new("src-1".into(), "/tmp/test.log".into(), 0);
        assert_eq!(reader.source_id(), "src-1");
        assert_eq!(reader.position(), 0);
    }

    #[tokio::test]
    async fn test_file_log_reader_reads_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.log");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "line 1").unwrap();
            writeln!(f, "line 2").unwrap();
            writeln!(f, "line 3").unwrap();
        }

        let mut reader = FileLogReader::new("test".into(), path.to_string_lossy().to_string(), 0);
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].line, "line 1");
        assert_eq!(entries[1].line, "line 2");
        assert_eq!(entries[2].line, "line 3");
    }

    #[tokio::test]
    async fn test_file_log_reader_incremental_reads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("incremental.log");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "line A").unwrap();
            writeln!(f, "line B").unwrap();
        }

        let path_str = path.to_string_lossy().to_string();
        let mut reader = FileLogReader::new("inc".into(), path_str, 0);

        // First read
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries.len(), 2);

        // No new lines → empty
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries.len(), 0);

        // Append new lines
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "line C").unwrap();
        }

        // Should only get the new line
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line, "line C");
    }

    #[tokio::test]
    async fn test_file_log_reader_handles_invalid_utf8() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid-utf8.log");
        std::fs::write(&path, b"ok line\nbad byte \xff\n").unwrap();

        let mut reader = FileLogReader::new("utf8".into(), path.to_string_lossy().to_string(), 0);
        let entries = reader.read_new_entries().await.unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line, "ok line");
        assert!(entries[1].line.contains("bad byte"));
        assert!(entries[1].line.contains('\u{fffd}'));
    }

    #[tokio::test]
    async fn test_file_log_reader_handles_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rotating.log");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "original long line with lots of content here").unwrap();
        }

        let path_str = path.to_string_lossy().to_string();
        let mut reader = FileLogReader::new("rot".into(), path_str, 0);

        // Read past original content
        reader.read_new_entries().await.unwrap();
        let saved_pos = reader.position();
        assert!(saved_pos > 0);

        // Simulate log rotation: truncate and write shorter content
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "new").unwrap();
        }

        // Should detect truncation and read from beginning
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line, "new");
    }

    #[tokio::test]
    async fn test_file_log_reader_nonexistent_file() {
        let mut reader = FileLogReader::new("missing".into(), "/nonexistent/file.log".into(), 0);
        let entries = reader.read_new_entries().await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_file_log_reader_skips_empty_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty_lines.log");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "line 1").unwrap();
            writeln!(f).unwrap(); // empty line
            writeln!(f, "line 3").unwrap();
        }

        let mut reader = FileLogReader::new("empty".into(), path.to_string_lossy().to_string(), 0);
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].line, "line 1");
        assert_eq!(entries[1].line, "line 3");
    }

    #[tokio::test]
    async fn test_file_log_reader_metadata_contains_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta.log");
        {
            let mut f = File::create(&path).unwrap();
            writeln!(f, "test").unwrap();
        }

        let path_str = path.to_string_lossy().to_string();
        let mut reader = FileLogReader::new("meta".into(), path_str.clone(), 0);
        let entries = reader.read_new_entries().await.unwrap();
        assert_eq!(entries[0].metadata.get("source_path"), Some(&path_str));
    }

    #[test]
    fn test_docker_log_reader_new() {
        let reader = DockerLogReader::new("d-1".into(), "abc123".into());
        assert_eq!(reader.source_id(), "d-1");
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn test_file_log_reader_with_start_offset() {
        let reader = FileLogReader::new("off".into(), "/tmp/test.log".into(), 1024);
        assert_eq!(reader.position(), 1024);
    }
}
