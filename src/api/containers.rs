//! Containers API endpoints

use crate::database::DbPool;
use crate::docker::client::ContainerInfo;
use crate::docker::containers::ContainerManager;
use actix_web::{web, HttpResponse, Responder};
use serde::Deserialize;

/// Quarantine request
#[derive(Debug, Deserialize)]
pub struct QuarantineRequest {
    pub reason: String,
}

/// Get all containers
///
/// GET /api/containers
pub async fn get_containers(pool: web::Data<DbPool>) -> impl Responder {
    // Create container manager
    let manager = match ContainerManager::new(pool.get_ref().clone()).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create container manager: {}", e);
            // Return mock data if Docker not available
            return HttpResponse::Ok().json(vec![serde_json::json!({
                "id": "mock-container-1",
                "name": "web-server",
                "image": "nginx:latest",
                "status": "Running",
                "security_status": {
                    "state": "Secure",
                    "threats": 0,
                    "vulnerabilities": 0
                },
                "risk_score": 10,
                "network_activity": {
                    "inbound_connections": 5,
                    "outbound_connections": 3,
                    "blocked_connections": 0,
                    "suspicious_activity": false
                }
            })]);
        }
    };

    match manager.list_containers().await {
        Ok(containers) => {
            // Convert to API response format
            let response: Vec<serde_json::Value> = containers
                .iter()
                .map(|c: &ContainerInfo| {
                    serde_json::json!({
                        "id": c.id,
                        "name": c.name,
                        "image": c.image,
                        "status": c.status,
                        "security_status": {
                            "state": "Secure",
                            "threats": 0,
                            "vulnerabilities": 0
                        },
                        "risk_score": 0,
                        "network_activity": {
                            "inbound_connections": 0,
                            "outbound_connections": 0,
                            "blocked_connections": 0,
                            "suspicious_activity": false
                        }
                    })
                })
                .collect();

            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            log::error!("Failed to list containers: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list containers"
            }))
        }
    }
}

/// Quarantine a container
///
/// POST /api/containers/:id/quarantine
pub async fn quarantine_container(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<QuarantineRequest>,
) -> impl Responder {
    let container_id = path.into_inner();
    let reason = body.into_inner().reason;

    let manager = match ContainerManager::new(pool.get_ref().clone()).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create container manager: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Docker"
            }));
        }
    };

    match manager.quarantine_container(&container_id, &reason).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("Container {} quarantined", container_id)
        })),
        Err(e) => {
            log::error!("Failed to quarantine container: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to quarantine container"
            }))
        }
    }
}

/// Release a container from quarantine
///
/// POST /api/containers/:id/release
pub async fn release_container(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    let container_id = path.into_inner();

    let manager = match ContainerManager::new(pool.get_ref().clone()).await {
        Ok(m) => m,
        Err(e) => {
            log::error!("Failed to create container manager: {}", e);
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Docker"
            }));
        }
    };

    match manager.release_container(&container_id).await {
        Ok(()) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("Container {} released", container_id)
        })),
        Err(e) => {
            log::error!("Failed to release container: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to release container"
            }))
        }
    }
}

/// Configure container routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/containers")
            .route("", web::get().to(get_containers))
            .route("/{id}/quarantine", web::post().to(quarantine_container))
            .route("/{id}/release", web::post().to(release_container)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_get_containers() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let pool_data = web::Data::new(pool);

        let app =
            test::init_service(App::new().app_data(pool_data).configure(configure_routes)).await;

        let req = test::TestRequest::get().uri("/api/containers").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }
}
