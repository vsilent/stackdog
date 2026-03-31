//! Alerts API endpoints

use crate::database::{
    create_sample_alert, get_alert_stats as db_get_alert_stats, list_alerts as db_list_alerts,
    update_alert_status, AlertFilter, DbPool,
};
use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

/// Query parameters for alert filtering
#[derive(Debug, Deserialize)]
pub struct AlertQuery {
    severity: Option<String>,
    status: Option<String>,
}

/// Get all alerts
///
/// GET /api/alerts
pub async fn get_alerts(pool: web::Data<DbPool>, query: web::Query<AlertQuery>) -> impl Responder {
    let filter = AlertFilter {
        severity: query.severity.clone(),
        status: query.status.clone(),
    };

    match db_list_alerts(&pool, filter).await {
        Ok(alerts) => HttpResponse::Ok().json(alerts),
        Err(e) => {
            log::error!("Failed to list alerts: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to list alerts"
            }))
        }
    }
}

/// Get alert statistics
///
/// GET /api/alerts/stats
pub async fn get_alert_stats(pool: web::Data<DbPool>) -> impl Responder {
    match db_get_alert_stats(&pool).await {
        Ok(stats) => HttpResponse::Ok().json(serde_json::json!({
            "total_count": stats.total_count,
            "new_count": stats.new_count,
            "acknowledged_count": stats.acknowledged_count,
            "resolved_count": stats.resolved_count
        })),
        Err(e) => {
            log::error!("Failed to get alert stats: {}", e);
            // Return default stats on error
            HttpResponse::Ok().json(serde_json::json!({
                "total_count": 0,
                "new_count": 0,
                "acknowledged_count": 0,
                "resolved_count": 0
            }))
        }
    }
}

/// Acknowledge an alert
///
/// POST /api/alerts/:id/acknowledge
pub async fn acknowledge_alert(pool: web::Data<DbPool>, path: web::Path<String>) -> impl Responder {
    let alert_id = path.into_inner();

    match update_alert_status(&pool, &alert_id, "Acknowledged").await {
        Ok(()) => {
            log::info!("Acknowledged alert: {}", alert_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Alert {} acknowledged", alert_id)
            }))
        }
        Err(e) => {
            log::error!("Failed to acknowledge alert {}: {}", alert_id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to acknowledge alert"
            }))
        }
    }
}

/// Resolve an alert
///
/// POST /api/alerts/:id/resolve
#[derive(Debug, Deserialize)]
pub struct ResolveRequest {
    pub note: Option<String>,
}

pub async fn resolve_alert(
    pool: web::Data<DbPool>,
    path: web::Path<String>,
    body: web::Json<ResolveRequest>,
) -> impl Responder {
    let alert_id = path.into_inner();
    let _note = body.note.clone().unwrap_or_default();

    match update_alert_status(&pool, &alert_id, "Resolved").await {
        Ok(()) => {
            log::info!("Resolved alert {}: {}", alert_id, _note);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": format!("Alert {} resolved", alert_id)
            }))
        }
        Err(e) => {
            log::error!("Failed to resolve alert {}: {}", alert_id, e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to resolve alert"
            }))
        }
    }
}

/// Seed database with sample alerts (for testing)
pub async fn seed_sample_alerts(pool: web::Data<DbPool>) -> impl Responder {
    use crate::database::create_alert;

    let mut created = Vec::new();

    for i in 0..5 {
        let alert = create_sample_alert();
        if create_alert(&pool, alert).await.is_ok() {
            created.push(i);
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "created": created.len(),
        "message": "Sample alerts created"
    }))
}

/// Configure alert routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/alerts")
            .route("", web::get().to(get_alerts))
            .route("/stats", web::get().to(get_alert_stats))
            .route("/{id}/acknowledge", web::post().to(acknowledge_alert))
            .route("/{id}/resolve", web::post().to(resolve_alert))
            .route("/seed", web::post().to(seed_sample_alerts)), // For testing
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::create_pool;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_get_alerts_empty() {
        let pool = create_pool(":memory:").unwrap();
        let pool_data = web::Data::new(pool);

        let app =
            test::init_service(App::new().app_data(pool_data).configure(configure_routes)).await;

        let req = test::TestRequest::get().uri("/api/alerts").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }
}
