//! Stackdog Security - Main Binary
//!
//! Security platform for Docker containers and Linux servers

#![allow(unused_must_use)]

extern crate bollard;
extern crate log;
extern crate serde_json;

extern crate actix_cors;
extern crate actix_rt;
extern crate actix_web;
extern crate dotenv;
extern crate env_logger;
extern crate tracing;
extern crate tracing_subscriber;

mod cli;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use clap::Parser;
use cli::{Cli, Command};
use stackdog::database::{create_pool, init_database};
use stackdog::sniff;
use std::{env, io};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // Load environment
    dotenv::dotenv().expect("Could not read .env file");

    // Parse CLI arguments
    let cli = Cli::parse();

    // Setup logging
    // Only set default RUST_LOG if user hasn't configured it
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "stackdog=info,actix_web=info");
    }
    env_logger::init();

    // Setup tracing — respect RUST_LOG for level
    let max_level = if env::var("RUST_LOG")
        .map(|v| v.contains("debug"))
        .unwrap_or(false)
    {
        Level::DEBUG
    } else if env::var("RUST_LOG")
        .map(|v| v.contains("trace"))
        .unwrap_or(false)
    {
        Level::TRACE
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(max_level).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🐕 Stackdog Security starting...");
    info!("Platform: {}", std::env::consts::OS);
    info!("Architecture: {}", std::env::consts::ARCH);

    match cli.command {
        Some(Command::Sniff {
            once,
            consume,
            output,
            sources,
            interval,
            ai_provider,
            ai_model,
            ai_api_url,
            slack_webhook,
        }) => {
            let config = sniff::config::SniffConfig::from_env_and_args(sniff::config::SniffArgs {
                once,
                consume,
                output: &output,
                sources: sources.as_deref(),
                interval,
                ai_provider: ai_provider.as_deref(),
                ai_model: ai_model.as_deref(),
                ai_api_url: ai_api_url.as_deref(),
                slack_webhook: slack_webhook.as_deref(),
            });
            run_sniff(config).await
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
    info!("  GET  /api/logs/sources        - List log sources");
    info!("  POST /api/logs/sources        - Add log source");
    info!("  GET  /api/logs/summaries      - List AI summaries");
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
            .configure(stackdog::api::configure_all_routes)
    })
    .bind(&app_url)?
    .run()
    .await
}

async fn run_sniff(config: sniff::config::SniffConfig) -> io::Result<()> {
    info!("🔍 Stackdog Sniff starting...");
    info!(
        "Mode: {}",
        if config.once {
            "one-shot"
        } else {
            "continuous"
        }
    );
    info!("Consume: {}", config.consume);
    info!("Output: {}", config.output_dir.display());
    info!("Interval: {}s", config.interval_secs);
    info!("AI Provider: {:?}", config.ai_provider);
    info!("AI Model: {}", config.ai_model);
    info!("AI API URL: {}", config.ai_api_url);
    if config.slack_webhook.is_some() {
        info!("Slack: configured ✓");
    }

    let orchestrator = sniff::SniffOrchestrator::new(config).map_err(io::Error::other)?;

    orchestrator.run().await.map_err(io::Error::other)
}
