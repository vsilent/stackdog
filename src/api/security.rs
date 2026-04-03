//! Security API endpoints

use crate::database::{get_security_status_snapshot, DbPool, SecurityStatusSnapshot};
use crate::models::api::security::SecurityStatusResponse;
use actix_web::{web, HttpResponse, Responder};

/// Get overall security status
///
/// GET /api/security/status
pub async fn get_security_status(pool: web::Data<DbPool>) -> impl Responder {
    match build_security_status(pool.get_ref()) {
        Ok(status) => HttpResponse::Ok().json(status),
        Err(err) => {
            log::error!("Failed to build security status: {}", err);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to build security status"
            }))
        }
    }
}

/// Configure security routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/security").route("/status", web::get().to(get_security_status)));
}

pub(crate) fn build_security_status(pool: &DbPool) -> anyhow::Result<SecurityStatusResponse> {
    let snapshot = get_security_status_snapshot(pool)?;
    Ok(SecurityStatusResponse::from_state(
        calculate_overall_score(&snapshot),
        snapshot.active_threats,
        snapshot.quarantined_containers,
        snapshot.alerts_new,
        snapshot.alerts_acknowledged,
    ))
}

fn calculate_overall_score(snapshot: &SecurityStatusSnapshot) -> u32 {
    let penalty = snapshot.severity_breakdown.weighted_penalty()
        + snapshot.quarantined_containers.saturating_mul(25)
        + snapshot.alerts_acknowledged.saturating_mul(2);
    100u32.saturating_sub(penalty.min(100))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::alert::{AlertSeverity, AlertStatus, AlertType};
    use crate::database::models::{Alert, AlertMetadata};
    use crate::database::{create_alert, create_pool, init_database};
    use actix_web::{test, App};
    use chrono::Utc;

    #[actix_rt::test]
    async fn test_get_security_status() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        let pool_data = web::Data::new(pool);
        let app =
            test::init_service(App::new().app_data(pool_data).configure(configure_routes)).await;

        let req = test::TestRequest::get()
            .uri("/api/security/status")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }

    #[actix_rt::test]
    async fn test_build_security_status_uses_alert_data() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();
        create_alert(
            &pool,
            Alert {
                id: "a1".to_string(),
                alert_type: AlertType::ThreatDetected,
                severity: AlertSeverity::High,
                message: "test".to_string(),
                status: AlertStatus::New,
                timestamp: Utc::now().to_rfc3339(),
                metadata: None,
            },
        )
        .await
        .unwrap();
        create_alert(
            &pool,
            Alert {
                id: "a2".to_string(),
                alert_type: AlertType::QuarantineApplied,
                severity: AlertSeverity::High,
                message: "container quarantined".to_string(),
                status: AlertStatus::Acknowledged,
                timestamp: Utc::now().to_rfc3339(),
                metadata: Some(AlertMetadata::default().with_container_id("abc123")),
            },
        )
        .await
        .unwrap();

        let status = build_security_status(&pool).unwrap();
        assert_eq!(status.active_threats, 1);
        assert_eq!(status.quarantined_containers, 1);
        assert_eq!(status.alerts_new, 1);
        assert_eq!(status.alerts_acknowledged, 1);
        assert!(status.overall_score < 100);
    }
}
