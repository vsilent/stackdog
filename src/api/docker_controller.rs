use crate::{
    constants, models::response::ResponseBody, services::docker_service,
};
use actix_web::{web, HttpResponse, Result};
// use crate::{
//     models::{
//         docker::{DockerTDO},
//     }
// };

pub async fn find_all() -> Result<HttpResponse> {
    match docker_service::find_all().await {
        Ok(message) => Ok(HttpResponse::Ok().json(
            ResponseBody::new(constants::EMPTY, &message))),
        Err(err) => Ok(err.response()),
    }
}

pub async fn find_one(id: String) -> Result<HttpResponse> {
    debug!("Get container by id ... {:?}", id);
    match docker_service::find_one(id).await {
        Ok(message) => Ok(HttpResponse::Ok().json(
            ResponseBody::new(constants::EMPTY, &message))),
        Err(err) => Ok(err.response()),
    }
}

pub async fn get_logs(container_name: String) -> Result<HttpResponse> {
    debug!("Get container logs by id ... {:?}", container_name);
    match docker_service::get_logs(container_name.as_str()).await {
        Ok(message) => Ok(HttpResponse::Ok().json(
            ResponseBody::new(constants::EMPTY, &message))),
        Err(err) => Ok(err.response()),
    }
}


#[cfg(test)]
mod tests {
    use crate::{App, config};
    use actix_cors::Cors;
    use actix_service::Service;
    use actix_web::{test, http, http::StatusCode};
    use futures::FutureExt;
    use http::header;


    #[actix_rt::test]
    async fn test_list_ok() {
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

        let resp = test::TestRequest::post()
            .uri("/api/auth/login")
            .set(header::ContentType::json())
            .set_payload(r#"{"username_or_email":"admin","password":"password"}"#.as_bytes())
            .send_request(&mut app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);

        let resp = test::TestRequest::post()
            .uri("/api/services")
            .set(header::ContentType::json())
            // .set(header::ContentType::json()) // here we need to set bearer token
            .send_request(&mut app)
            .await;
    }
}
