use std::collections::HashMap;
use bollard::container::ListContainersOptions;
use bollard::Docker;
use serde_json;

use crate::{
    error::ServiceError
};
use actix_web::{
    http::{
        StatusCode,
    }
};
use actix_web::web::Json;
use bollard::container::LogsOptions;
use std::default::Default;
use crate::futures::StreamExt;


pub async fn find_all() -> Result<String, ServiceError> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let mut filters = HashMap::new();
    filters.insert("status", vec!["running"]);

    let docker_response = &docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters: filters,
            ..Default::default()
        }))
        .await;
    debug!("docker_response {:?}", &docker_response);
    match docker_response {
        Err(_) => Err(ServiceError::new(
            StatusCode::NO_CONTENT,
            "No containers found".to_string())),
        Ok(cs) => Ok(
            serde_json::to_string(cs).unwrap()
        ),
    }
}

pub async fn find_one(id: String) -> Result<String, ServiceError> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let mut filters = HashMap::new();
    debug!("Get container by id {:?}", id);
    filters.insert("id", vec![id.as_str()]);
    let docker_response = docker
        .list_containers(
            Some(ListContainersOptions {
                all: true,
                filters: filters,
                ..Default::default()
            })
        )
        .await;

    debug!("container {:?}", docker_response);

    // Ok("No container found".to_string())
    match docker_response {
        Err(_) => Err(
            ServiceError::new(
                StatusCode::NO_CONTENT,
                "No containers found".to_string()
            )
        ),
        Ok(res) => Ok(
            serde_json::to_string(&res).unwrap()
        ),
    }
}

pub async fn get_logs(container_name: &str) -> Result<String, ServiceError> {
    debug!("Get container logs by name {:?}", container_name);
    let docker = Docker::connect_with_local_defaults().unwrap();
    let mut filters = HashMap::new();
    filters.insert("id", vec![container_name]);
    let options = Some(LogsOptions::<String> {
        stdout: true,
        ..Default::default()
    });
    let mut docker_response = docker.logs(container_name, options);
    while let Some(chunk) = docker_response.next().await {
        debug!("Chunk {:?}", chunk);
    }
    Ok("No container found".to_string())
}
