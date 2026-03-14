//! nftables backend
//!
//! Manages nftables firewall rules

use anyhow::{Result, Context};
use std::process::Command;

use crate::firewall::backend::{FirewallBackend, FirewallRule, FirewallTable, FirewallChain};

/// nftables table
#[derive(Debug, Clone)]
pub struct NfTable {
    pub family: String,
    pub name: String,
}

impl NfTable {
    pub fn new(family: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            name: name.into(),
        }
    }
    
    fn to_string(&self) -> String {
        format!("{} {}", self.family, self.name)
    }
}

/// nftables chain
#[derive(Debug, Clone)]
pub struct NfChain {
    pub table: NfTable,
    pub name: String,
    pub chain_type: String,
}

impl NfChain {
    pub fn new(table: &NfTable, name: impl Into<String>, chain_type: impl Into<String>) -> Self {
        Self {
            table: table.clone(),
            name: name.into(),
            chain_type: chain_type.into(),
        }
    }
}

/// nftables rule
#[derive(Debug, Clone)]
pub struct NfRule {
    pub chain: NfChain,
    pub rule_spec: String,
}

impl NfRule {
    pub fn new(chain: &NfChain, rule_spec: impl Into<String>) -> Self {
        Self {
            chain: chain.clone(),
            rule_spec: rule_spec.into(),
        }
    }
}

/// nftables backend
pub struct NfTablesBackend {
    available: bool,
}

impl NfTablesBackend {
    /// Create a new nftables backend
    pub fn new() -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            // Check if nft command is available
            let available = Command::new("nft")
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            
            if !available {
                anyhow::bail!("nft command not available");
            }
            
            Ok(Self { available: true })
        }
        
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("nftables only available on Linux");
        }
    }
    
    /// Create a table
    pub fn create_table(&self, table: &NfTable) -> Result<()> {
        let output = Command::new("nft")
            .args(&["add", "table", &table.to_string()])
            .output()
            .context("Failed to create nftables table")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to create table: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// Delete a table
    pub fn delete_table(&self, table: &NfTable) -> Result<()> {
        let output = Command::new("nft")
            .args(&["delete", "table", &table.to_string()])
            .output()
            .context("Failed to delete nftables table")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to delete table: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// Create a chain
    pub fn create_chain(&self, chain: &NfChain) -> Result<()> {
        let cmd = format!(
            "add chain {} {} {{ type {} hook input priority 0; }}",
            chain.table.to_string(),
            chain.name,
            chain.chain_type
        );
        
        let output = Command::new("nft")
            .args(&["-c", &cmd])
            .output()
            .context("Failed to create nftables chain")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to create chain: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// Delete a chain
    pub fn delete_chain(&self, chain: &NfChain) -> Result<()> {
        let cmd = format!(
            "delete chain {} {}",
            chain.table.to_string(),
            chain.name
        );
        
        let output = Command::new("nft")
            .args(&["-c", &cmd])
            .output()
            .context("Failed to delete nftables chain")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to delete chain: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// Add a rule
    pub fn add_rule(&self, rule: &NfRule) -> Result<()> {
        let cmd = format!(
            "add rule {} {} {}",
            rule.chain.table.to_string(),
            rule.chain.name,
            rule.rule_spec
        );
        
        let output = Command::new("nft")
            .args(&["-c", &cmd])
            .output()
            .context("Failed to add nftables rule")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to add rule: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// Delete a rule
    pub fn delete_rule(&self, rule: &NfRule) -> Result<()> {
        let cmd = format!(
            "delete rule {} {} {}",
            rule.chain.table.to_string(),
            rule.chain.name,
            rule.rule_spec
        );
        
        let output = Command::new("nft")
            .args(&["-c", &cmd])
            .output()
            .context("Failed to delete nftables rule")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to delete rule: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// Batch add multiple rules
    pub fn batch_add_rules(&self, rules: &[NfRule]) -> Result<()> {
        for rule in rules {
            self.add_rule(rule)?;
        }
        Ok(())
    }
    
    /// Flush a chain
    pub fn flush_chain(&self, chain: &NfChain) -> Result<()> {
        let cmd = format!(
            "flush chain {} {}",
            chain.table.to_string(),
            chain.name
        );
        
        let output = Command::new("nft")
            .args(&["-c", &cmd])
            .output()
            .context("Failed to flush nftables chain")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to flush chain: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        Ok(())
    }
    
    /// List rules in a chain
    pub fn list_rules(&self, chain: &NfChain) -> Result<Vec<String>> {
        let cmd = format!(
            "list chain {} {}",
            chain.table.to_string(),
            chain.name
        );
        
        let output = Command::new("nft")
            .args(&["-c", &cmd])
            .output()
            .context("Failed to list nftables rules")?;
        
        if !output.status.success() {
            anyhow::bail!("Failed to list rules: {}", String::from_utf8_lossy(&output.stderr));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let rules: Vec<String> = stdout.lines().map(|s| s.to_string()).collect();
        
        Ok(rules)
    }
}

impl FirewallBackend for NfTablesBackend {
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }
    
    fn is_available(&self) -> bool {
        self.available
    }
    
    fn block_ip(&self, ip: &str) -> Result<()> {
        // Implementation would add nftables rule to block IP
        log::info!("Would block IP: {}", ip);
        Ok(())
    }
    
    fn unblock_ip(&self, ip: &str) -> Result<()> {
        log::info!("Would unblock IP: {}", ip);
        Ok(())
    }
    
    fn block_port(&self, port: u16) -> Result<()> {
        log::info!("Would block port: {}", port);
        Ok(())
    }
    
    fn unblock_port(&self, port: u16) -> Result<()> {
        log::info!("Would unblock port: {}", port);
        Ok(())
    }
    
    fn block_container(&self, container_id: &str) -> Result<()> {
        log::info!("Would block container: {}", container_id);
        Ok(())
    }
    
    fn unblock_container(&self, container_id: &str) -> Result<()> {
        log::info!("Would unblock container: {}", container_id);
        Ok(())
    }
    
    fn name(&self) -> &str {
        "nftables"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_nf_table_creation() {
        let table = NfTable::new("inet", "stackdog_test");
        assert_eq!(table.family, "inet");
        assert_eq!(table.name, "stackdog_test");
    }
    
    #[test]
    fn test_nf_chain_creation() {
        let table = NfTable::new("inet", "stackdog_test");
        let chain = NfChain::new(&table, "input", "filter");
        assert_eq!(chain.name, "input");
        assert_eq!(chain.chain_type, "filter");
    }
}
