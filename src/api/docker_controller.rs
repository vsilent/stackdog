use crate::{
    constants, models::response::ResponseBody, services::docker_service,
};
use actix_web::{HttpResponse, Result};

pub async fn find_all() -> Result<HttpResponse> {
    match docker_service::find_all().await {
        Ok(message) => Ok(HttpResponse::Ok().json(
            ResponseBody::new(constants::EMPTY, &message))),
        Err(err) => Ok(err.response()),
    }
}
