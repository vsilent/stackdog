//! CLI argument parsing for Stackdog
//!
//! Defines the command-line interface using clap derive macros.
//! Supports `serve` (HTTP server) and `sniff` (log analysis) subcommands.

use clap::{Parser, Subcommand};

/// Stackdog Security — Docker & Linux server security platform
#[derive(Parser, Debug)]
#[command(name = "stackdog", version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Start the HTTP API server (default behavior)
    Serve,

    /// Sniff and analyze logs from Docker containers and system sources
    Sniff {
        /// Run a single scan/analysis pass, then exit
        #[arg(long)]
        once: bool,

        /// Consume logs: archive to zstd, then purge originals to free disk
        #[arg(long)]
        consume: bool,

        /// Output directory for consumed logs
        #[arg(long, default_value = "./stackdog-logs/")]
        output: String,

        /// Additional log file paths to watch (comma-separated)
        #[arg(long)]
        sources: Option<String>,

        /// Poll interval in seconds
        #[arg(long, default_value = "30")]
        interval: u64,

        /// AI provider: "openai" or "candle"
        #[arg(long)]
        ai_provider: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_no_subcommand_defaults_to_none() {
        let cli = Cli::parse_from(["stackdog"]);
        assert!(cli.command.is_none(), "No subcommand should yield None (default to serve)");
    }

    #[test]
    fn test_serve_subcommand() {
        let cli = Cli::parse_from(["stackdog", "serve"]);
        assert!(matches!(cli.command, Some(Command::Serve)));
    }

    #[test]
    fn test_sniff_subcommand_defaults() {
        let cli = Cli::parse_from(["stackdog", "sniff"]);
        match cli.command {
            Some(Command::Sniff { once, consume, output, sources, interval, ai_provider }) => {
                assert!(!once);
                assert!(!consume);
                assert_eq!(output, "./stackdog-logs/");
                assert!(sources.is_none());
                assert_eq!(interval, 30);
                assert!(ai_provider.is_none());
            }
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_once_flag() {
        let cli = Cli::parse_from(["stackdog", "sniff", "--once"]);
        match cli.command {
            Some(Command::Sniff { once, .. }) => assert!(once),
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_consume_flag() {
        let cli = Cli::parse_from(["stackdog", "sniff", "--consume"]);
        match cli.command {
            Some(Command::Sniff { consume, .. }) => assert!(consume),
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_all_options() {
        let cli = Cli::parse_from([
            "stackdog", "sniff",
            "--once",
            "--consume",
            "--output", "/tmp/logs/",
            "--sources", "/var/log/syslog,/var/log/auth.log",
            "--interval", "60",
            "--ai-provider", "openai",
        ]);
        match cli.command {
            Some(Command::Sniff { once, consume, output, sources, interval, ai_provider }) => {
                assert!(once);
                assert!(consume);
                assert_eq!(output, "/tmp/logs/");
                assert_eq!(sources.unwrap(), "/var/log/syslog,/var/log/auth.log");
                assert_eq!(interval, 60);
                assert_eq!(ai_provider.unwrap(), "openai");
            }
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_candle_provider() {
        let cli = Cli::parse_from(["stackdog", "sniff", "--ai-provider", "candle"]);
        match cli.command {
            Some(Command::Sniff { ai_provider, .. }) => {
                assert_eq!(ai_provider.unwrap(), "candle");
            }
            _ => panic!("Expected Sniff command"),
        }
    }
}
