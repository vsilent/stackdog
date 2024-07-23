use crate::{
    config::db::Connection,
    models::{user_token::UserToken},
    schema::users::{self, dsl::*},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::prelude::*;
use uuid::Uuid;

// #[derive(Serialize, Deserialize)]
// pub struct DockerTDO {
//     pub id: String,
// }
