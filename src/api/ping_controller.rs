use actix_web::HttpResponse;

#[get("/ping")]
pub(crate) fn ping() -> HttpResponse {
    HttpResponse::Ok()
        .body("pong!".to_string())
}

#[cfg(test)]
mod tests {
    use crate::{App, config};
    use actix_cors::Cors;
    use actix_service::Service;
    use actix_web::{test, http, http::StatusCode};
    use futures::FutureExt;

    #[actix_rt::test]
    async fn test_ping_ok() {
        let mut app = test::init_service(
            App::new()
            .wrap(Cors::new()
            .send_wildcard()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600)
            .finish())
            .data(config::db::migrate_and_config_db(":memory:"))
            .wrap(actix_web::middleware::Logger::default())
            .wrap(crate::middleware::authen_middleware::Authentication)
            .wrap_fn(|req, srv| {
                srv.call(req).map(|res| res)
            })
            .configure(crate::config::app::config_services)
        ).await;

        let req = test::TestRequest::get().uri("/api/ping").to_request();
        let resp = test::call_service(&mut app, req).await;

        assert_eq!(resp.status(), StatusCode::OK);
    }
}
