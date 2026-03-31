//! iptables backend
//!
//! Manages iptables firewall rules (fallback when nftables unavailable)

use anyhow::{Context, Result};
use std::process::Command;

use crate::firewall::backend::FirewallBackend;

/// iptables chain
#[derive(Debug, Clone)]
pub struct IptChain {
    pub table: String,
    pub name: String,
}

impl IptChain {
    pub fn new(table: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            name: name.into(),
        }
    }
}

/// iptables rule
#[derive(Debug, Clone)]
pub struct IptRule {
    pub chain: IptChain,
    pub rule_spec: String,
}

impl IptRule {
    pub fn new(chain: &IptChain, rule_spec: impl Into<String>) -> Self {
        Self {
            chain: chain.clone(),
            rule_spec: rule_spec.into(),
        }
    }
}

/// iptables backend
pub struct IptablesBackend {
    available: bool,
}

impl IptablesBackend {
    /// Create a new iptables backend
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // Check if iptables command is available
            let available = Command::new("iptables")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if !available {
                anyhow::bail!("iptables command not available");
            }

            Ok(Self { available: true })
        }

        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("iptables only available on Linux");
        }
    }

    /// Create a chain
    pub fn create_chain(&self, chain: &IptChain) -> Result<()> {
        let output = Command::new("iptables")
            .args(["-t", &chain.table, "-N", &chain.name])
            .output()
            .context("Failed to create iptables chain")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to create chain: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Delete a chain
    pub fn delete_chain(&self, chain: &IptChain) -> Result<()> {
        let output = Command::new("iptables")
            .args(["-t", &chain.table, "-X", &chain.name])
            .output()
            .context("Failed to delete iptables chain")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to delete chain: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Add a rule
    pub fn add_rule(&self, rule: &IptRule) -> Result<()> {
        let args: Vec<&str> = vec!["-t", &rule.chain.table, "-A", &rule.chain.name];
        let rule_parts: Vec<&str> = rule.rule_spec.split_whitespace().collect();

        let mut cmd = Command::new("iptables");
        cmd.args(&args);
        cmd.args(&rule_parts);

        let output = cmd.output().context("Failed to add iptables rule")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to add rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Delete a rule
    pub fn delete_rule(&self, rule: &IptRule) -> Result<()> {
        let args: Vec<&str> = vec!["-t", &rule.chain.table, "-D", &rule.chain.name];
        let rule_parts: Vec<&str> = rule.rule_spec.split_whitespace().collect();

        let mut cmd = Command::new("iptables");
        cmd.args(&args);
        cmd.args(&rule_parts);

        let output = cmd.output().context("Failed to delete iptables rule")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to delete rule: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// Flush a chain
    pub fn flush_chain(&self, chain: &IptChain) -> Result<()> {
        let output = Command::new("iptables")
            .args(["-t", &chain.table, "-F", &chain.name])
            .output()
            .context("Failed to flush iptables chain")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to flush chain: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }

    /// List rules in a chain
    pub fn list_rules(&self, chain: &IptChain) -> Result<Vec<String>> {
        let output = Command::new("iptables")
            .args(["-t", &chain.table, "-L", &chain.name, "-n"])
            .output()
            .context("Failed to list iptables rules")?;

        if !output.status.success() {
            anyhow::bail!(
                "Failed to list rules: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();

        Ok(rules)
    }
}

impl FirewallBackend for IptablesBackend {
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn block_ip(&self, ip: &str) -> Result<()> {
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, format!("-s {} -j DROP", ip));
        self.add_rule(&rule)
    }

    fn unblock_ip(&self, ip: &str) -> Result<()> {
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, format!("-s {} -j DROP", ip));
        self.delete_rule(&rule)
    }

    fn block_port(&self, port: u16) -> Result<()> {
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, format!("-p tcp --dport {} -j DROP", port));
        self.add_rule(&rule)
    }

    fn unblock_port(&self, port: u16) -> Result<()> {
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, format!("-p tcp --dport {} -j DROP", port));
        self.delete_rule(&rule)
    }

    fn block_container(&self, container_id: &str) -> Result<()> {
        log::info!("Would block container via iptables: {}", container_id);
        Ok(())
    }

    fn unblock_container(&self, container_id: &str) -> Result<()> {
        log::info!("Would unblock container via iptables: {}", container_id);
        Ok(())
    }

    fn name(&self) -> &str {
        "iptables"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipt_chain_creation() {
        let chain = IptChain::new("filter", "INPUT");
        assert_eq!(chain.table, "filter");
        assert_eq!(chain.name, "INPUT");
    }

    #[test]
    fn test_ipt_rule_creation() {
        let chain = IptChain::new("filter", "INPUT");
        let rule = IptRule::new(&chain, "-p tcp --dport 22 -j DROP");
        assert_eq!(rule.rule_spec, "-p tcp --dport 22 -j DROP");
    }
}
