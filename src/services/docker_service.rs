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

pub async fn find_all() -> Result<String, ServiceError> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let mut list_container_filters = HashMap::new();
    list_container_filters.insert("status", vec!["running"]);

    let containers = &docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            filters: list_container_filters,
            ..Default::default()
        }))
        .await;
    // let c = containers.iter().collect::<String>();
    // let mut names = Vec::new();
    // for container in containers {
    //     names.push(container.);
    // }
    match containers {
        Err(_)=> Err(ServiceError::new(StatusCode::NO_CONTENT,
                                  "No containers found".to_string())),
        Ok(cs) => Ok(serde_json::to_string(cs).unwrap()),
    }
}
