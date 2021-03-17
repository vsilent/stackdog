use crate::{
    error::ServiceError,
    config::db::Pool,
};
use actix_web::{
    // http::{
    //     StatusCode,
    //     header::HeaderValue,
    // },
    web,
};

pub fn find_all(pool: &web::Data<Pool>) -> Result<String, ServiceError> {
    // docker
    // Here we need to discuss how to connect docker api
    // let docker = // docker api client;
    // match docker::find_all(&pool.get().unwrap()) {
    //     Ok(message) => Ok(message),
    //     Err(message) => Err(ServiceError::new(StatusCode::BAD_REQUEST, message))
    // }
    unimplemented!()
}
