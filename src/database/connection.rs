//! Database connection pool using rusqlite and r2d2

use r2d2::{Pool, ManageConnection};
use rusqlite::{Connection, Result as RusqliteResult};
use anyhow::Result;
use std::fmt;

/// Rusqlite connection manager
#[derive(Debug)]
pub struct SqliteConnectionManager {
    database_url: String,
}

impl SqliteConnectionManager {
    pub fn new(database_url: &str) -> Self {
        Self {
            database_url: database_url.to_string(),
        }
    }
}

impl ManageConnection for SqliteConnectionManager {
    type Connection = Connection;
    type Error = rusqlite::Error;

    fn connect(&self) -> RusqliteResult<Self::Connection> {
        Connection::open(&self.database_url)
    }

    fn is_valid(&self, conn: &mut Self::Connection) -> RusqliteResult<()> {
        conn.execute_batch("").map_err(|e| e.into())
    }

    fn has_broken(&self, _: &mut Self::Connection) -> bool {
        false
    }
}

pub type DbPool = Pool<SqliteConnectionManager>;

/// Create database connection pool
pub fn create_pool(database_url: &str) -> Result<DbPool> {
    let manager = SqliteConnectionManager::new(database_url);
    let pool = Pool::builder()
        .max_size(10)
        .build(manager)?;
    
    Ok(pool)
}

/// Initialize database (create tables if not exist)
pub fn init_database(pool: &DbPool) -> Result<()> {
    let conn = pool.get()?;
    
    // Create alerts table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alerts (
            id TEXT PRIMARY KEY,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            timestamp TEXT NOT NULL,
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    
    // Create threats table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS threats (
            id TEXT PRIMARY KEY,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            score INTEGER NOT NULL,
            source TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New',
            metadata TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    
    // Create containers_cache table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS containers_cache (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            image TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0,
            security_state TEXT DEFAULT 'Unknown',
            threats_count INTEGER DEFAULT 0,
            last_updated TEXT DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    
    // Create indexes for performance
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)", []);
    
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity)", []);
    
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_containers_status ON containers_cache(status)", []);
    let _ = conn.execute("CREATE INDEX IF NOT EXISTS idx_containers_name ON containers_cache(name)", []);
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pool() {
        let pool = create_pool(":memory:");
        assert!(pool.is_ok());
    }
    
    #[test]
    fn test_init_database() {
        let pool = create_pool(":memory:").unwrap();
        let result = init_database(&pool);
        assert!(result.is_ok());
    }
}
