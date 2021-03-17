use crate::{
    config::db::Pool,
    constants,
    models::{
        user::{LoginDTO},
        response::ResponseBody,
    },
    services::account_service,
};
use actix_web::{web, HttpRequest, HttpResponse, Result};

// POST api/auth/login
pub async fn login(login_dto: web::Json<LoginDTO>, pool: web::Data<Pool>) -> Result<HttpResponse> {
    match account_service::login(login_dto.0, &pool) {
        Ok(token_res) => Ok(HttpResponse::Ok().json(ResponseBody::new(constants::MESSAGE_LOGIN_SUCCESS, token_res))),
        Err(err) => Ok(err.response()),
    }
}

// POST api/auth/logout
pub async fn logout(req: HttpRequest, pool: web::Data<Pool>) -> Result<HttpResponse> {
    if let Some(authen_header) = req.headers().get(constants::AUTHORIZATION) {
        account_service::logout(authen_header, &pool);
        Ok(HttpResponse::Ok().json(ResponseBody::new(constants::MESSAGE_LOGOUT_SUCCESS, constants::EMPTY)))
    } else {
        Ok(HttpResponse::BadRequest().json(ResponseBody::new(constants::MESSAGE_TOKEN_MISSING, constants::EMPTY)))
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
    async fn test_login_ok_with_username() {
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
    }

    #[actix_rt::test]
    async fn test_login_ok_with_email() {
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
            .set_payload(r#"{"username_or_email":"admin@gmail.com","password":"password"}"#.as_bytes())
            .send_request(&mut app)
            .await;

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_login_password_incorrect_with_username() {
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

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_login_password_incorrect_with_email() {
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
            .set_payload(r#"{"username_or_email":"admin@gmail.com","password":"password"}"#.as_bytes())
            .send_request(&mut app)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_login_user_not_found_with_username() {
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
            .set_payload(r#"{"username_or_email":"abc","password":"password"}"#.as_bytes())
            .send_request(&mut app)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn test_login_user_not_found_with_email() {
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
            .set_payload(r#"{"username_or_email":"abc@gmail.com","password":"password"}"#.as_bytes())
            .send_request(&mut app)
            .await;

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
