#[allow(unused_imports)]
use diesel::{
    SqliteConnection,
    sql_query,
    r2d2::{self, ConnectionManager},
    dsl
};
use crate::schema::users::columns::updated_at;
use chrono::Utc;
use diesel::connection::SimpleConnection;
use crate::schema::users::dsl::users;
use diesel::RunQueryDsl;

embed_migrations!();

// #[cfg(not(test))]
pub type Connection = SqliteConnection;
pub type Pool = r2d2::Pool<ConnectionManager<Connection>>;

#[cfg(not(test))]
pub fn get_connection(url: &str) -> Pool {
    let manager = ConnectionManager::<SqliteConnection>::new(url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    pool
}

#[cfg(not(test))]
pub fn migrate_and_config_db(url: &str) -> Pool {
    info!("Configure db pool and run migrations...");
    embedded_migrations::run(&get_connection(url).get().expect("Failed to migrate."));
    get_connection(url)

}


#[cfg(test)]
pub fn migrate_and_config_db(url: &str) -> Pool {
    use crate::diesel::RunQueryDsl;
    info!("Configure db pool and run migrations...");
    let manager = ConnectionManager::<SqliteConnection>::new(url);
    let pool = r2d2::Pool::builder()
        .build(manager)
        .expect("Failed to create pool.");
    embedded_migrations::run(&pool.get().expect("Failed to migrate."));
    sql_query(r#"DROP TABLE IF EXISTS users;"#).execute(&pool.get().unwrap());
    sql_query(r#"CREATE TABLE users (
        id INTEGER PRIMARY KEY NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        login_session TEXT NOT NULL DEFAULT ''
    );"#).execute(&pool.get().unwrap());

    use crate::models::user::{User, UserDTO};
    let user = UserDTO {
        created_at: Utc::now().naive_utc(),
        updated_at: Utc::now().naive_utc(),
        username: String::from("admin"),
        email: String::from("admin@gmail.com"),
        password: String::from("password")
    };
    // For testing purpose
    User::make_admin(user, &pool.get().unwrap());
    // let conn  = &pool.get().unwrap();
    // let results = users
    //     .load::<User>(conn)
    //     .expect("Error loading users");
    //
    // println!("Displaying {} users", results.len());
    // for user in results {
    //     println!("{:?}", user.email);
    // }

    pool
}
