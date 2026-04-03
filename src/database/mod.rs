//! Database module

pub mod baselines;
pub mod connection;
pub mod models;
pub mod repositories;

pub use baselines::*;
pub use connection::{create_pool, init_database, DbPool};
pub use models::*;
pub use repositories::alerts::*;

/// Marker struct for module tests
pub struct DatabaseMarker;
