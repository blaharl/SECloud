use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::models::{User, UserGroup};

#[derive(Debug, Clone)]
pub struct DBClient {
    pool: Pool<Postgres>,
}

impl DBClient {
    pub fn new(pool: Pool<Postgres>) -> Self {
        DBClient { pool }
    }
}

#[async_trait]
pub trait UserExt {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        username: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error>;

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error>;

    async fn save_user<T: Into<String> + Send>(
        &self,
        username: T,
        password: T,
    ) -> Result<User, sqlx::Error>;

    async fn get_user_count(&self) -> Result<i64, sqlx::Error>;

    async fn verify_user<T: Into<String> + Send>(&self, username: T) -> Result<User, sqlx::Error>;

    async fn update_username<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        username: T,
    ) -> Result<User, sqlx::Error>;

    async fn update_user_group(&self, user_id: Uuid, group: UserGroup)
    -> Result<User, sqlx::Error>;

    async fn update_user_password(
        &self,
        user_id: Uuid,
        password: String,
    ) -> Result<User, sqlx::Error>;
}

#[async_trait]
impl UserExt for DBClient {
    async fn get_user(
        &self,
        user_id: Option<Uuid>,
        username: Option<&str>,
    ) -> Result<Option<User>, sqlx::Error> {
        let mut user: Option<User> = None;

        if let Some(user_id) = user_id {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, username, password, verified, created, updated, group1 as "group: UserGroup" FROM users WHERE id = $1"#,
                user_id
            ).fetch_optional(&self.pool).await?;
        } else if let Some(username) = username {
            user = sqlx::query_as!(
                User,
                r#"SELECT id, username, password, verified, created, updated, group1 as "group: UserGroup" FROM users WHERE username = $1"#,
                username
            ).fetch_optional(&self.pool).await?;
        }

        Ok(user)
    }

    async fn get_users(&self, page: u32, limit: usize) -> Result<Vec<User>, sqlx::Error> {
        let offset = (page - 1) * limit as u32;

        let users = sqlx::query_as!(
            User,
            r#"SELECT id, username, password, verified, created, updated, group1 as "group: UserGroup" FROM users 
            ORDER BY created DESC LIMIT $1 OFFSET $2"#,
            limit as i64,
            offset as i64,
        ).fetch_all(&self.pool)
        .await?;

        Ok(users)
    }

    async fn save_user<T: Into<String> + Send>(
        &self,
        username: T,
        password: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (username, password) 
            VALUES ($1, $2) 
            RETURNING id, username, password, verified, created, updated, group1 as "group: UserGroup"
            "#,
            username.into(),
            password.into(),
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(user)
    }

    async fn get_user_count(&self) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(r#"SELECT COUNT(*) FROM users"#)
            .fetch_one(&self.pool)
            .await?;

        Ok(count.unwrap_or(0))
    }

    async fn verify_user<T: Into<String> + Send>(&self, username: T) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET verified = TRUE, updated = Now()
            WHERE username = $1
            RETURNING id, username, password, verified, created, updated, group1 as "group: UserGroup"
            "#,
            username.into()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_username<T: Into<String> + Send>(
        &self,
        user_id: Uuid,
        new_username: T,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET username = $1, updated = Now()
            WHERE id = $2
            RETURNING id, username, password, verified, created, updated, group1 as "group: UserGroup"
            "#,
            new_username.into(),
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_group(
        &self,
        user_id: Uuid,
        new_group: UserGroup,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET group1 = $1, updated = Now()
            WHERE id = $2
            RETURNING id, username, password, verified, created, updated, group1 as "group: UserGroup"
            "#,
            new_group as UserGroup,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }

    async fn update_user_password(
        &self,
        user_id: Uuid,
        new_password: String,
    ) -> Result<User, sqlx::Error> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET password = $1, updated = Now()
            WHERE id = $2
            RETURNING id, username, password, verified, created, updated, group1 as "group: UserGroup"
            "#,
            new_password,
            user_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(user)
    }
}
