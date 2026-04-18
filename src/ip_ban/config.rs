use std::env;

#[derive(Debug, Clone)]
pub struct IpBanConfig {
    pub enabled: bool,
    pub max_retries: u32,
    pub find_time_secs: u64,
    pub ban_time_secs: u64,
    pub unban_check_interval_secs: u64,
}

impl IpBanConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: parse_bool_env("STACKDOG_IP_BAN_ENABLED", true),
            max_retries: parse_u32_env("STACKDOG_IP_BAN_MAX_RETRIES", 5),
            find_time_secs: parse_u64_env("STACKDOG_IP_BAN_FIND_TIME_SECS", 300),
            ban_time_secs: parse_u64_env("STACKDOG_IP_BAN_BAN_TIME_SECS", 1800),
            unban_check_interval_secs: parse_u64_env(
                "STACKDOG_IP_BAN_UNBAN_CHECK_INTERVAL_SECS",
                60,
            ),
        }
    }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn parse_u64_env(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn parse_u32_env(name: &str, default: u32) -> u32 {
    env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(default)
}
