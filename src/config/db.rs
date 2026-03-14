//! Database configuration

#[allow(unused_imports)]
use diesel::{
    SqliteConnection,
    r2d2::{self, ConnectionManager},
};

pub type Connection = SqliteConnection;
pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

/// Get database connection pool
pub fn get_connection(url: &str) -> Pool {
    let manager = ConnectionManager::<SqliteConnection>::new(url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    pool
}

/// Initialize database (creates tables if needed)
pub fn init_db(url: &str) -> Pool {
    log::info!("Initializing database...");
    let pool = get_connection(url);
    
    // For now, just return the pool
    // Tables will be created by individual modules as needed
    log::info!("Database initialized: {}", url);
    
    pool
}

#[cfg(test)]
pub fn migrate_and_config_db(url: &str) -> Pool {
    use diesel::sql_query;
    use diesel::RunQueryDsl;
    
    log::info!("Configure db pool for testing...");
    let manager = ConnectionManager::<SqliteConnection>::new(url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    
    // Create test tables
    sql_query(r#"DROP TABLE IF EXISTS users;"#).execute(&pool.get().unwrap()).ok();
    sql_query(r#"CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY NOT NULL,
        username TEXT NOT NULL,
        email TEXT NOT NULL
    );"#).execute(&pool.get().unwrap()).ok();

    pool
}
