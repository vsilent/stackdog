//! Stackdog Security - Main Binary
//!
//! Security platform for Docker containers and Linux servers

#![allow(unused_must_use)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;

extern crate actix_rt;
extern crate env_logger;
extern crate dotenv;
extern crate tracing;
extern crate tracing_subscriber;

mod config;

use std::{io, env};
use tracing::{Level, info};
use tracing_subscriber::FmtSubscriber;

#[actix_rt::main]
async fn main() -> io::Result<()> {
    // Load environment
    dotenv::dotenv().expect("Could not read .env file");
    
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
    
    // Display configuration
    let app_host = env::var("APP_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let app_port = env::var("APP_PORT").unwrap_or_else(|_| "5000".to_string());
    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| "./stackdog.db".to_string());
    
    info!("Host: {}", app_host);
    info!("Port: {}", app_port);
    info!("Database: {}", database_url);
    
    // Check Linux-specific features
    #[cfg(target_os = "linux")]
    {
        info!("Linux detected - eBPF and firewall features available");
        
        // Check eBPF support
        match stackdog::collectors::EbpfLoader::new() {
            Ok(loader) => {
                info!("eBPF loader initialized");
                if loader.is_ebpf_supported() {
                    info!("✓ eBPF is supported on this system");
                } else {
                    info!("⚠ eBPF is not supported (kernel may be too old)");
                }
            }
            Err(e) => {
                info!("eBPF loader error: {}", e);
            }
        }
        
        // Check nftables
        match stackdog::firewall::NfTablesBackend::new() {
            Ok(_) => info!("✓ nftables backend available"),
            Err(e) => info!("⚠ nftables not available: {}", e),
        }
        
        // Check iptables
        match stackdog::firewall::IptablesBackend::new() {
            Ok(_) => info!("✓ iptables backend available"),
            Err(e) => info!("⚠ iptables not available: {}", e),
        }
    }
    
    #[cfg(not(target_os = "linux"))]
    {
        info!("Non-Linux platform - some features unavailable");
        info!("For full functionality, run on Linux with kernel 4.19+");
    }
    
    info!("🎉 Stackdog Security ready!");
    info!("");
    info!("Next steps:");
    info!("  1. Configure rules in your application");
    info!("  2. Start event collectors");
    info!("  3. Monitor for threats");
    info!("");
    
    // For now, just exit after displaying info
    // In production, this would start the security monitoring loop
    println!("\n✅ Stackdog Security initialized successfully!");
    println!("   See documentation for usage examples.");
    
    Ok(())
}
