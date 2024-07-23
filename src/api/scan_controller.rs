use std::process::Command;
use tracing;

use crate::{config::db::Pool, constants, models::{
    scan::{IP, Domain},
    response::ResponseBody,
}};
use actix_web::{web, HttpRequest, HttpResponse, Result};

pub async fn scan_online(ip: web::Json<IP>) -> Result<HttpResponse> {

    // println!("ip: {:?}", ip.ip);
    let ip:&str  = ip.ip.as_ref();

    let output =
        Command::new("/usr/local/bin/rustscan")
            .arg(format!("-a {}", ip))
            .arg("--accessible")
            .arg("--ulimit 5000")
            .arg("--ports 443,80,8080,8000,5000,3000")
            .output()
            .expect("command failed to start");

    debug!("status: {:?}", output.status);
    debug!("stdout: {:?}", String::from_utf8_lossy(&output.stdout));
    debug!("stderr: {:?}", String::from_utf8_lossy(&output.stderr));

    let response = String::from_utf8_lossy(&output.stdout).to_string();
    println!("stderr response: {:?}", &output.stderr);
    println!("stdout response: {:?}", response);
    Ok(HttpResponse::Ok().json(ResponseBody::new(constants::EMPTY, response)))

}

pub async fn scan_ssl(domain: web::Json<Domain>) -> Result<HttpResponse> {

    // debug!("req: {:?}", req);

    let output =
        Command::new("/usr/bin/openssl")
            .arg("s_client")
            .arg("-connect")
            .arg(format!("{}:443", domain.name))
            .output()
            .expect("command failed to start");

    debug!("status: {:?}", output.status);
    debug!("stdout: {:?}", String::from_utf8_lossy(&output.stdout));
    debug!("stderr: {:?}", String::from_utf8_lossy(&output.stderr));

    let response = String::from_utf8_lossy(&output.stdout).to_string();
    println!("stderr response: {:?}", &output.stderr);
    println!("stdout response: {:?}", response);
    Ok(HttpResponse::Ok().json(ResponseBody::new(constants::EMPTY, response)))
}
