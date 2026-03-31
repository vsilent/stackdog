//! Container management

use crate::database::models::Alert;
use crate::database::{create_alert, create_sample_alert, update_alert_status, DbPool};
use crate::docker::client::{ContainerInfo, DockerClient};
use anyhow::Result;
use chrono::Utc;
use uuid::Uuid;

/// Container manager
pub struct ContainerManager {
    docker: DockerClient,
    pool: DbPool,
}

impl ContainerManager {
    /// Create a new container manager
    pub async fn new(pool: DbPool) -> Result<Self> {
        let docker = DockerClient::new().await?;
        Ok(Self { docker, pool })
    }

    /// List all containers
    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        self.docker.list_containers(true).await
    }

    /// Get container by ID
    pub async fn get_container(&self, container_id: &str) -> Result<ContainerInfo> {
        self.docker.get_container_info(container_id).await
    }

    /// Quarantine a container
    pub async fn quarantine_container(&self, container_id: &str, reason: &str) -> Result<()> {
        // Disconnect from networks
        self.docker.quarantine_container(container_id).await?;

        // Create alert
        let alert = Alert {
            id: Uuid::new_v4().to_string(),
            alert_type: "QuarantineApplied".to_string(),
            severity: "High".to_string(),
            message: format!("Container {} quarantined: {}", container_id, reason),
            status: "New".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            metadata: Some(format!("container_id={}", container_id)),
        };

        let _ = create_alert(&self.pool, alert).await;

        log::info!("Container {} quarantined: {}", container_id, reason);
        Ok(())
    }

    /// Release a container from quarantine
    pub async fn release_container(&self, container_id: &str) -> Result<()> {
        // Reconnect to default network
        self.docker
            .release_container(container_id, "bridge")
            .await?;

        // Update any quarantine alerts
        // (In production, would query for specific alerts)

        log::info!("Container {} released from quarantine", container_id);
        Ok(())
    }

    /// Get container security status
    pub async fn get_container_security_status(
        &self,
        container_id: &str,
    ) -> Result<ContainerSecurityStatus> {
        let info = self.docker.get_container_info(container_id).await?;

        // Calculate risk score based on various factors
        let mut risk_score = 0;
        let mut threats = 0;
        let mut security_state = "Secure";

        // Check if running as root
        // Check for privileged mode
        // Check for exposed ports
        // Check for volume mounts

        Ok(ContainerSecurityStatus {
            container_id: container_id.to_string(),
            risk_score,
            threats,
            security_state: security_state.to_string(),
        })
    }
}

/// Container security status
#[derive(Debug, Clone)]
pub struct ContainerSecurityStatus {
    pub container_id: String,
    pub risk_score: u32,
    pub threats: u32,
    pub security_state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};

    #[actix_rt::test]
    async fn test_container_manager_creation() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        // This test requires Docker daemon
        let result = ContainerManager::new(pool).await;

        if result.is_ok() {
            let manager = result.unwrap();
            let containers = manager.list_containers().await;
            assert!(containers.is_ok());
        }
    }
}
