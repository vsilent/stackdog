//! Stackdog Security - Main Binary
//!
//! Security platform for Docker containers and Linux servers

#![allow(unused_must_use)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;
extern crate bollard;

extern crate actix_rt;
extern crate actix_cors;
extern crate actix_web;
extern crate env_logger;
extern crate dotenv;
extern crate tracing;
extern crate tracing_subscriber;

mod config;
mod api;
mod database;
mod docker;
mod cli;
mod sniff;

use std::{io, env};
use actix_web::{HttpServer, App, web};
use actix_cors::Cors;
use clap::Parser;
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;
use database::{create_pool, init_database};
use cli::{Cli, Command};

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // Load environment
    dotenv::dotenv().expect("Could not read .env file");

    // Parse CLI arguments
    let cli = Cli::parse();

    // Setup logging
    env::set_var("RUST_LOG", "stackdog=info,actix_web=info");
    env_logger::init();
    
    // Setup tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");

    info!("🐕 Stackdog Security starting...");
    info!("Platform: {}", std::env::consts::OS);
    info!("Architecture: {}", std::env::consts::ARCH);

    match cli.command {
        Some(Command::Sniff { once, consume, output, sources, interval, ai_provider }) => {
            run_sniff(once, consume, output, sources, interval, ai_provider).await
        }
        // Default: serve (backward compatible)
        Some(Command::Serve) | None => run_serve().await,
    }
}

async fn run_serve() -> io::Result<()> {
    let app_host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let app_port = env::var("APP_PORT").unwrap_or_else(|_| "5000".to_string());
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "./stackdog.db".to_string());
    
    info!("Host: {}", app_host);
    info!("Port: {}", app_port);
    info!("Database: {}", database_url);
    
    let app_url = format!("{}:{}", &app_host, &app_port);
    
    // Initialize database
    info!("Initializing database...");
    let pool = create_pool(&database_url).expect("Failed to create database pool");
    init_database(&pool).expect("Failed to initialize database");
    info!("Database initialized successfully");
    
    info!("🎉 Stackdog Security ready!");
    info!("");
    info!("API Endpoints:");
    info!("  GET  /api/security/status     - Security status");
    info!("  GET  /api/alerts              - List alerts");
    info!("  POST /api/alerts/:id/ack      - Acknowledge alert");
    info!("  POST /api/alerts/:id/resolve  - Resolve alert");
    info!("  GET  /api/containers          - List containers");
    info!("  POST /api/containers/:id/quar - Quarantine container");
    info!("  GET  /api/threats             - List threats");
    info!("  GET  /api/threats/statistics  - Threat statistics");
    info!("  WS   /ws                      - WebSocket for real-time updates");
    info!("");
    info!("Web Dashboard: http://{}:{}", app_host, app_port);
    info!("");
    
    // Start HTTP server
    info!("Starting HTTP server on {}...", app_url);
    
    let pool_data = web::Data::new(pool);
    
    HttpServer::new(move || {
        App::new()
            .app_data(pool_data.clone())
            .wrap(Cors::permissive())
            .wrap(actix_web::middleware::Logger::default())
            .configure(api::configure_all_routes)
    })
    .bind(&app_url)?
    .run()
    .await
}

async fn run_sniff(
    once: bool,
    consume: bool,
    output: String,
    sources: Option<String>,
    interval: u64,
    ai_provider: Option<String>,
) -> io::Result<()> {
    let config = sniff::config::SniffConfig::from_env_and_args(
        once,
        consume,
        &output,
        sources.as_deref(),
        interval,
        ai_provider.as_deref(),
    );

    info!("🔍 Stackdog Sniff starting...");
    info!("Mode: {}", if config.once { "one-shot" } else { "continuous" });
    info!("Consume: {}", config.consume);
    info!("Output: {}", config.output_dir.display());
    info!("Interval: {}s", config.interval_secs);
    info!("AI Provider: {:?}", config.ai_provider);

    // TODO: Implement sniff orchestrator (Checkpoint 6)
    info!("⚠️  Sniff orchestrator not yet implemented");
    Ok(())
}

