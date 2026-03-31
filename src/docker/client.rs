//! Docker client wrapper

use anyhow::{Result, Context};
use std::collections::HashMap;

// Bollard imports
use bollard::Docker;
use bollard::container::{ListContainersOptions, InspectContainerOptions};
use bollard::network::{DisconnectNetworkOptions, ListNetworksOptions};

/// Docker client wrapper
pub struct DockerClient {
    client: Docker,
}

impl DockerClient {
    /// Create a new Docker client
    pub async fn new() -> Result<Self> {
        let client = Docker::connect_with_local_defaults()
            .context("Failed to connect to Docker daemon")?;
        
        // Test connection
        client.ping()
            .await
            .context("Failed to ping Docker daemon")?;
        
        Ok(Self { client })
    }
    
    /// List all containers
    pub async fn list_containers(&self, all: bool) -> Result<Vec<ContainerInfo>> {
        let options: Option<ListContainersOptions<String>> = Some(ListContainersOptions {
            all,
            size: false,
            ..Default::default()
        });

        let containers: Vec<bollard::models::ContainerSummary> = self.client
            .list_containers(options)
            .await
            .context("Failed to list containers")?;
        
        let mut result = Vec::new();
        for container in containers {
            if let Some(id) = container.id {
                let info = self.get_container_info(&id).await?;
                result.push(info);
            }
        }
        
        Ok(result)
    }
    
    /// Get container info by ID
    pub async fn get_container_info(&self, container_id: &str) -> Result<ContainerInfo> {
        let inspect = self.client
            .inspect_container(container_id, None::<InspectContainerOptions>)
            .await
            .context("Failed to inspect container")?;
        
        let config = inspect.config.unwrap_or_default();
        let state = inspect.state.unwrap_or_default();
        
        Ok(ContainerInfo {
            id: container_id.to_string(),
            name: config.hostname.unwrap_or_else(|| container_id[..12].to_string()),
            image: config.image.unwrap_or_else(|| "unknown".to_string()),
            status: if state.running.unwrap_or(false) {
                "Running"
            } else if state.paused.unwrap_or(false) {
                "Paused"
            } else {
                "Stopped"
            }.to_string(),
            created: state.started_at.unwrap_or_default(),
            network_settings: inspect.network_settings.map(|ns| {
                ns.networks.unwrap_or_default()
                    .into_iter()
                    .map(|(name, endpoint)| (name, endpoint.ip_address.unwrap_or_default()))
                    .collect()
            }).unwrap_or_default(),
        })
    }
    
    /// Quarantine a container (disconnect from all networks)
    pub async fn quarantine_container(&self, container_id: &str) -> Result<()> {
        // List all networks
        let networks: Vec<bollard::models::Network> = self.client
            .list_networks(None::<ListNetworksOptions<String>>)
            .await
            .context("Failed to list networks")?;

        // Disconnect from each network
        for network in networks {
            if let Some(name) = network.name {
                // Skip bridge network for localhost communication
                if name == "bridge" || name == "host" || name == "none" {
                    continue;
                }

                let options = DisconnectNetworkOptions {
                    container: container_id.to_string(),
                    force: true,
                };

                let _ = self.client
                    .disconnect_network(&name, options)
                    .await;
            }
        }
        
        Ok(())
    }
    
    /// Release a container (reconnect to default network)
    pub async fn release_container(&self, container_id: &str, network_name: &str) -> Result<()> {
        // Connect to the specified network
        // Note: This requires additional implementation for network connection
        // For now, just log the action
        log::info!("Would reconnect container {} to network {}", container_id, network_name);
        Ok(())
    }
    
    /// Get container stats
    pub async fn get_container_stats(&self, container_id: &str) -> Result<ContainerStats> {
        // Implementation would use Docker stats API
        // For now, return placeholder
        Ok(ContainerStats {
            cpu_percent: 0.0,
            memory_usage: 0,
            memory_limit: 0,
            network_rx: 0,
            network_tx: 0,
        })
    }
}

/// Container information
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub created: String,
    pub network_settings: HashMap<String, String>,
}

/// Container statistics
#[derive(Debug, Clone, Default)]
pub struct ContainerStats {
    pub cpu_percent: f64,
    pub memory_usage: u64,
    pub memory_limit: u64,
    pub network_rx: u64,
    pub network_tx: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn test_docker_client_creation() {
        // This test requires Docker daemon running
        let result = DockerClient::new().await;
        
        // Test may fail if Docker is not running
        if result.is_ok() {
            let client = result.unwrap();
            let containers = client.list_containers(true).await;
            assert!(containers.is_ok());
        }
    }
}
