//! Threats API endpoints

use crate::models::api::threats::{ThreatResponse, ThreatStatisticsResponse};
use actix_web::{web, HttpResponse, Responder};
use std::collections::HashMap;

/// Get all threats
///
/// GET /api/threats
pub async fn get_threats() -> impl Responder {
    // TODO: Fetch from database when implemented
    let threats = vec![ThreatResponse {
        id: "threat-1".to_string(),
        r#type: "CryptoMiner".to_string(),
        severity: "High".to_string(),
        score: 85,
        source: "container-1".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        status: "New".to_string(),
    }];

    HttpResponse::Ok().json(threats)
}

/// Get threat statistics
///
/// GET /api/threats/statistics
pub async fn get_threat_statistics() -> impl Responder {
    let mut by_severity = HashMap::new();
    by_severity.insert("Info".to_string(), 1);
    by_severity.insert("Low".to_string(), 2);
    by_severity.insert("Medium".to_string(), 3);
    by_severity.insert("High".to_string(), 3);
    by_severity.insert("Critical".to_string(), 1);

    let mut by_type = HashMap::new();
    by_type.insert("CryptoMiner".to_string(), 3);
    by_type.insert("ContainerEscape".to_string(), 2);
    by_type.insert("NetworkScanner".to_string(), 5);

    let stats = ThreatStatisticsResponse {
        total_threats: 10,
        by_severity,
        by_type,
        trend: "stable".to_string(),
    };

    HttpResponse::Ok().json(stats)
}

/// Configure threat routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/threats")
            .route("", web::get().to(get_threats))
            .route("/statistics", web::get().to(get_threat_statistics)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_get_threats() {
        let app = test::init_service(App::new().configure(configure_routes)).await;

        let req = test::TestRequest::get().uri("/api/threats").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_get_threat_statistics() {
        let app = test::init_service(App::new().configure(configure_routes)).await;

        let req = test::TestRequest::get()
            .uri("/api/threats/statistics")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }
}
