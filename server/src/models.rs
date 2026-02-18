use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::Type;

#[derive(Debug, Deserialize, Serialize, Clone, Copy, Type, PartialEq)]
#[sqlx(type_name = "user_group", rename_all = "lowercase")]
pub enum UserGroup {
    Admin,
    User,
}

impl UserGroup {
    pub fn to_str(&self) -> &str {
        match self {
            UserGroup::User => "user",
            UserGroup::Admin => "admin",
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone, Type)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub password: String,
    pub group: UserGroup,
    pub verified: bool,
    pub created: Option<DateTime<Utc>>,
    pub updated: Option<DateTime<Utc>>,
}
