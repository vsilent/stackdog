use std::process::Command;
use tracing;

use crate::{config::db::Pool, constants, models::{
    user::{LoginDTO},
    response::ResponseBody,
}};
use actix_web::{web, HttpRequest, HttpResponse, Result};

pub async fn scan_online(req: HttpRequest) -> Result<HttpResponse> {

    debug!("req: {:?}", req);

    let output =
        Command::new("ls")
            .arg("-l")
            .arg("-a")
            .output()
            .expect("ls command failed to start");
    debug!("status: {:?}", output.status);
    debug!("stdout: {:?}", String::from_utf8_lossy(&output.stdout));
    debug!("stderr: {:?}", String::from_utf8_lossy(&output.stderr));

    let response = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(HttpResponse::Ok().json(ResponseBody::new(constants::EMPTY, response)))

}

pub async fn scan_ssl(req: HttpRequest) -> Result<HttpResponse> {

    debug!("req: {:?}", req);

    let output =
        Command::new("ls")
            .arg("-l")
            .arg("-a")
            .output()
            .expect("ls command failed to start");

    debug!("status: {:?}", output.status);
    debug!("stdout: {:?}", String::from_utf8_lossy(&output.stdout));
    debug!("stderr: {:?}", String::from_utf8_lossy(&output.stderr));

    let response = String::from_utf8_lossy(&output.stdout).to_string();
    Ok(HttpResponse::Ok().json(ResponseBody::new(constants::EMPTY, response)))
}
