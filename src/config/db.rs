#[allow(unused_imports)]
use diesel::{
    SqliteConnection,
    sql_query,
    r2d2::{self, ConnectionManager},
};

embed_migrations!();

#[cfg(not(test))]
pub type Connection = SqliteConnection;

pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

#[cfg(not(test))]
pub fn migrate_and_config_db(url: &str) -> Pool {
    info!("Migrating and configurating database...");
    // let manager = ConnectionManager::<Connection>::new(url);
    let manager = ConnectionManager::<SqliteConnection>::new(":memory:");
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    embedded_migrations::run(&pool.get().expect("Failed to migrate."));

    pool
}

#[cfg(test)]
pub fn migrate_and_config_db(url: &str) -> Pool {
    use crate::diesel::RunQueryDsl;
    info!("Migrating and configurating database...");
    let manager = ConnectionManager::<Connection>::new(url);
    let pool = r2d2::Pool::builder().build(manager).expect("Failed to create pool.");
    // sql_query(r#""#).execute(&pool.get().unwrap());
    pool
}
