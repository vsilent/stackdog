use crate::{
    constants,
    config::db::Connection,
    models::{user_token::UserToken},
    schema::users::{self, dsl::*},
};
use bcrypt::{hash, verify, DEFAULT_COST};
use diesel::prelude::*;
use uuid::Uuid;

#[derive(Identifiable, Queryable, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
    pub username: String,
    pub email: String,
    pub password: String,
    pub login_session: String,
}

#[derive(Insertable, Serialize, Deserialize)]
#[table_name = "users"]
pub struct UserDTO {
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginDTO {
    pub username_or_email: String,
    pub password: String,
}

#[derive(Insertable)]
#[table_name = "users"]
pub struct LoginInfoDTO {
    pub username: String,
    pub login_session: String,
}

impl User {

    pub fn login(login: LoginDTO, conn: &Connection) -> Option<LoginInfoDTO> {
        if let Ok(user_to_verify) = users
            .filter(username.eq(&login.username_or_email))
            .or_filter(email.eq(&login.username_or_email))
            .get_result::<User>(conn)
        {
            if !user_to_verify.password.is_empty()
                && verify(&login.password, &user_to_verify.password).unwrap()
            {
                let login_session_str = User::generate_login_session();
                if User::update_login_session_to_db(
                    &user_to_verify.username,
                    &login_session_str,
                    conn,
                ) {
                    return Some(LoginInfoDTO {
                        username: user_to_verify.username,
                        login_session: login_session_str,
                    });
                }
            } else {
                return Some(LoginInfoDTO {
                    username: user_to_verify.username,
                    login_session: String::new(),
                });
            }
        }

        None
    }

    pub fn logout(user_id: i32, conn: &Connection) {
        if let Ok(user) = users.find(user_id).get_result::<User>(conn) {
            Self::update_login_session_to_db(&user.username, "", conn);
        }
    }

    pub fn is_valid_login_session(user_token: &UserToken, conn: &Connection) -> bool {
        users
            .filter(username.eq(&user_token.user))
            .filter(login_session.eq(&user_token.login_session))
            .get_result::<User>(conn)
            .is_ok()
    }

    pub fn find_user_by_username(un: &str, conn: &Connection) -> QueryResult<User> {
        users.filter(username.eq(un)).get_result::<User>(conn)
    }

    pub fn generate_login_session() -> String {
        Uuid::new_v4().to_simple().to_string()
    }

    pub fn update_login_session_to_db(
        un: &str,
        login_session_str: &str,
        conn: &Connection,
    ) -> bool {
        if let Ok(user) = User::find_user_by_username(un, conn) {
            diesel::update(users.find(user.id))
                .set(login_session.eq(login_session_str.to_string()))
                .execute(conn)
                .is_ok()
        } else {
            false
        }
    }

    pub fn make_admin(user: UserDTO, conn: &Connection) {
        let hashed_pwd = hash(&user.password, DEFAULT_COST).unwrap();
        let user = UserDTO {
            password: hashed_pwd,
            ..user
        };
        let rs = diesel::insert_into(users).values(&user).execute(conn);
        println!("Creating admin .. {:?}", rs);
    }

}
