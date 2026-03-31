//! Sniff configuration loaded from environment variables and CLI args

use std::env;
use std::path::PathBuf;

/// AI provider selection
#[derive(Debug, Clone, PartialEq)]
pub enum AiProvider {
    /// OpenAI-compatible API (works with OpenAI, Ollama, vLLM, etc.)
    OpenAi,
    /// Local inference via Candle (requires `ml` feature)
    Candle,
}

impl AiProvider {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "candle" => AiProvider::Candle,
            // "ollama" uses the same OpenAI-compatible API client
            "openai" | "ollama" => AiProvider::OpenAi,
            _ => AiProvider::OpenAi,
        }
    }
}

/// Configuration for the `stackdog sniff` command
#[derive(Debug, Clone)]
pub struct SniffConfig {
    /// Run once then exit (vs continuous daemon mode)
    pub once: bool,
    /// Enable consume mode: archive + purge originals
    pub consume: bool,
    /// Output directory for archived/consumed logs
    pub output_dir: PathBuf,
    /// Additional log source paths (user-configured)
    pub extra_sources: Vec<String>,
    /// Poll interval in seconds
    pub interval_secs: u64,
    /// AI provider to use for summarization
    pub ai_provider: AiProvider,
    /// AI API URL (for OpenAI-compatible providers)
    pub ai_api_url: String,
    /// AI API key (optional for local providers like Ollama)
    pub ai_api_key: Option<String>,
    /// AI model name
    pub ai_model: String,
    /// Database URL
    pub database_url: String,
    /// Slack webhook URL for alert notifications
    pub slack_webhook: Option<String>,
    /// Generic webhook URL for alert notifications
    pub webhook_url: Option<String>,
}

impl SniffConfig {
    /// Build config from environment variables, overridden by CLI args
    pub fn from_env_and_args(
        once: bool,
        consume: bool,
        output: &str,
        sources: Option<&str>,
        interval: u64,
        ai_provider_arg: Option<&str>,
        ai_model_arg: Option<&str>,
        ai_api_url_arg: Option<&str>,
        slack_webhook_arg: Option<&str>,
    ) -> Self {
        let env_sources = env::var("STACKDOG_LOG_SOURCES").unwrap_or_default();
        let mut extra_sources: Vec<String> = env_sources
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if let Some(cli_sources) = sources {
            for s in cli_sources.split(',') {
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty() && !extra_sources.contains(&trimmed) {
                    extra_sources.push(trimmed);
                }
            }
        }

        let ai_provider_str = ai_provider_arg
            .map(|s| s.to_string())
            .unwrap_or_else(|| env::var("STACKDOG_AI_PROVIDER").unwrap_or_else(|_| "openai".into()));

        let output_dir = if output != "./stackdog-logs/" {
            PathBuf::from(output)
        } else {
            PathBuf::from(
                env::var("STACKDOG_SNIFF_OUTPUT_DIR")
                    .unwrap_or_else(|_| output.to_string()),
            )
        };

        let interval_secs = if interval != 30 {
            interval
        } else {
            env::var("STACKDOG_SNIFF_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(interval)
        };

        Self {
            once,
            consume,
            output_dir,
            extra_sources,
            interval_secs,
            ai_provider: AiProvider::from_str(&ai_provider_str),
            ai_api_url: ai_api_url_arg
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_AI_API_URL").ok())
                .unwrap_or_else(|| "http://localhost:11434/v1".into()),
            ai_api_key: env::var("STACKDOG_AI_API_KEY").ok(),
            ai_model: ai_model_arg
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_AI_MODEL").ok())
                .unwrap_or_else(|| "llama3".into()),
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "./stackdog.db".into()),
            slack_webhook: slack_webhook_arg
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_SLACK_WEBHOOK_URL").ok()),
            webhook_url: env::var("STACKDOG_WEBHOOK_URL").ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env-mutating tests to avoid cross-contamination
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn clear_sniff_env() {
        env::remove_var("STACKDOG_LOG_SOURCES");
        env::remove_var("STACKDOG_AI_PROVIDER");
        env::remove_var("STACKDOG_AI_API_URL");
        env::remove_var("STACKDOG_AI_API_KEY");
        env::remove_var("STACKDOG_AI_MODEL");
        env::remove_var("STACKDOG_SNIFF_OUTPUT_DIR");
        env::remove_var("STACKDOG_SNIFF_INTERVAL");
        env::remove_var("STACKDOG_SLACK_WEBHOOK_URL");
        env::remove_var("STACKDOG_WEBHOOK_URL");
    }

    #[test]
    fn test_ai_provider_from_str() {
        assert_eq!(AiProvider::from_str("openai"), AiProvider::OpenAi);
        assert_eq!(AiProvider::from_str("OpenAI"), AiProvider::OpenAi);
        assert_eq!(AiProvider::from_str("candle"), AiProvider::Candle);
        assert_eq!(AiProvider::from_str("Candle"), AiProvider::Candle);
        assert_eq!(AiProvider::from_str("unknown"), AiProvider::OpenAi);
    }

    #[test]
    fn test_sniff_config_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(false, false, "./stackdog-logs/", None, 30, None, None, None, None);
        assert!(!config.once);
        assert!(!config.consume);
        assert_eq!(config.output_dir, PathBuf::from("./stackdog-logs/"));
        assert!(config.extra_sources.is_empty());
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.ai_provider, AiProvider::OpenAi);
        assert_eq!(config.ai_api_url, "http://localhost:11434/v1");
        assert!(config.ai_api_key.is_none());
        assert_eq!(config.ai_model, "llama3");
    }

    #[test]
    fn test_sniff_config_cli_overrides() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(
            true, true, "/tmp/output/", Some("/var/log/app.log"), 60, Some("candle"), None, None, None,
        );

        assert!(config.once);
        assert!(config.consume);
        assert_eq!(config.output_dir, PathBuf::from("/tmp/output/"));
        assert_eq!(config.extra_sources, vec!["/var/log/app.log"]);
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.ai_provider, AiProvider::Candle);
    }

    #[test]
    fn test_sniff_config_env_sources_merged_with_cli() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_LOG_SOURCES", "/var/log/syslog,/var/log/auth.log");

        let config = SniffConfig::from_env_and_args(
            false, false, "./stackdog-logs/", Some("/var/log/app.log,/var/log/syslog"), 30, None, None, None, None,
        );

        assert!(config.extra_sources.contains(&"/var/log/syslog".to_string()));
        assert!(config.extra_sources.contains(&"/var/log/auth.log".to_string()));
        assert!(config.extra_sources.contains(&"/var/log/app.log".to_string()));
        assert_eq!(config.extra_sources.len(), 3);

        clear_sniff_env();
    }

    #[test]
    fn test_sniff_config_env_overrides_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_AI_API_URL", "https://api.openai.com/v1");
        env::set_var("STACKDOG_AI_API_KEY", "sk-test123");
        env::set_var("STACKDOG_AI_MODEL", "gpt-4o-mini");
        env::set_var("STACKDOG_SNIFF_INTERVAL", "45");
        env::set_var("STACKDOG_SNIFF_OUTPUT_DIR", "/data/logs/");

        let config = SniffConfig::from_env_and_args(false, false, "./stackdog-logs/", None, 30, None, None, None, None);
        assert_eq!(config.ai_api_url, "https://api.openai.com/v1");
        assert_eq!(config.ai_api_key, Some("sk-test123".into()));
        assert_eq!(config.ai_model, "gpt-4o-mini");
        assert_eq!(config.interval_secs, 45);
        assert_eq!(config.output_dir, PathBuf::from("/data/logs/"));

        clear_sniff_env();
    }

    #[test]
    fn test_ollama_provider_alias() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(
            false, false, "./stackdog-logs/", None, 30,
            Some("ollama"), Some("qwen2.5-coder:latest"), None, None,
        );
        // "ollama" maps to OpenAi internally (same API protocol)
        assert_eq!(config.ai_provider, AiProvider::OpenAi);
        assert_eq!(config.ai_model, "qwen2.5-coder:latest");
        assert_eq!(config.ai_api_url, "http://localhost:11434/v1");

        clear_sniff_env();
    }

    #[test]
    fn test_cli_args_override_env_vars() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_AI_MODEL", "gpt-4o-mini");
        env::set_var("STACKDOG_AI_API_URL", "https://api.openai.com/v1");

        let config = SniffConfig::from_env_and_args(
            false, false, "./stackdog-logs/", None, 30,
            None, Some("llama3"), Some("http://localhost:11434/v1"), None,
        );
        // CLI args take priority over env vars
        assert_eq!(config.ai_model, "llama3");
        assert_eq!(config.ai_api_url, "http://localhost:11434/v1");

        clear_sniff_env();
    }

    #[test]
    fn test_slack_webhook_from_cli() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(
            false, false, "./stackdog-logs/", None, 30,
            None, None, None, Some("https://hooks.slack.com/services/T/B/xxx"),
        );
        assert_eq!(config.slack_webhook.as_deref(), Some("https://hooks.slack.com/services/T/B/xxx"));

        clear_sniff_env();
    }

    #[test]
    fn test_slack_webhook_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/env");

        let config = SniffConfig::from_env_and_args(
            false, false, "./stackdog-logs/", None, 30,
            None, None, None, None,
        );
        assert_eq!(config.slack_webhook.as_deref(), Some("https://hooks.slack.com/services/T/B/env"));

        clear_sniff_env();
    }

    #[test]
    fn test_slack_webhook_cli_overrides_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/env");

        let config = SniffConfig::from_env_and_args(
            false, false, "./stackdog-logs/", None, 30,
            None, None, None, Some("https://hooks.slack.com/services/T/B/cli"),
        );
        assert_eq!(config.slack_webhook.as_deref(), Some("https://hooks.slack.com/services/T/B/cli"));

        clear_sniff_env();
    }
}
