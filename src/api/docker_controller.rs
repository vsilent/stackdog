use crate::{
    config::db::Pool,
    constants,
    models::{
        response::ResponseBody,
    },
    services::docker_service,
};
use actix_web::{web, HttpRequest, HttpResponse, Result};

pub async fn find_all(pool: web::Data<Pool>) -> Result<HttpResponse> {
    match docker_service::find_all(&pool) {
        Ok(message) => Ok(HttpResponse::Ok().json(ResponseBody::new(&message, constants::EMPTY))),
        Err(err) => Ok(err.response()),
    }
}
