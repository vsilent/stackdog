use crate::api::*;
use actix_web::web;

pub fn config_services(cfg: &mut web::ServiceConfig) {
    info!("Configurating routes...");
    cfg.service(
        web::scope("/api")
            .service(ping_controller::ping)
            .service(
                web::resource("/scan/online")
                .route(web::post().to(scan_controller::scan_online))
            )
            .service(
                web::resource("/scan/ssl")
                    .route(web::post().to(scan_controller::scan_ssl))
            )
            .service(
                web::scope("/auth")
                    .service(
                        web::resource("/login")
                            .route(web::post().to(account_controller::login))
                    )
                    .service(
                        web::resource("/logout")
                            .route(web::post().to(account_controller::logout))
                    )
            )
            .service(
                web::scope("/services")
                    .service(
                        web::resource("/")
                            .route(web::get().to(docker_controller::find_all))
                    )
                    .service(
                        web::resource("/{id}")
                            .route(web::get().to(docker_controller::find_one))
                    )
                    .service(
                        web::resource("/{id}/logs")
                            .route(web::get().to(docker_controller::get_logs))
                    )
                    // .service(
                    //     web::resource("/{id}/restart")
                    //         .route(web::get().to(docker_controller::service_restart))
                    // )
                    // .service(
                    //     web::resource("/{id}/pause")
                    //         .route(web::get().to(docker_controller::service_pause))
                    // )
                    // .service(
                    //     web::resource("/{id}/stop")
                    //         .route(web::get().to(docker_controller::service_stop))
                    // )
            )
    );
}
