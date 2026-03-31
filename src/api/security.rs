//! Security API endpoints

use crate::models::api::security::SecurityStatusResponse;
use actix_web::{web, HttpResponse, Responder};

/// Get overall security status
///
/// GET /api/security/status
pub async fn get_security_status() -> impl Responder {
    let status = SecurityStatusResponse::new();
    HttpResponse::Ok().json(status)
}

/// Configure security routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/security").route("/status", web::get().to(get_security_status)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_rt::test]
    async fn test_get_security_status() {
        let app = test::init_service(App::new().configure(configure_routes)).await;

        let req = test::TestRequest::get()
            .uri("/api/security/status")
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
    }
}
