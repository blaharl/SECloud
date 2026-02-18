use chrono::{DateTime, Utc};
use core::str;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::models::{User, UserGroup};

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct RegisterUserDto {
    #[validate(length(min = 1, message = "Username is required"))]
    pub username: String,

    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,

    #[validate(must_match(other = "password", message = "passwords do not match"))]
    #[serde(rename = "passwordConfirm")]
    pub password_confirm: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct LoginUserDto {
    #[validate(length(min = 1, message = "Password is required"))]
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Validate)]
pub struct RequestQueryDto {
    #[validate(range(min = 1))]
    pub page: Option<usize>,
    #[validate(range(min = 1, max = 50))]
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilterUserDto {
    pub id: String,
    pub username: String,
    pub group: String,
    pub verified: bool,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

impl FilterUserDto {
    pub fn filter_user(user: &User) -> Self {
        FilterUserDto {
            id: user.id.to_string(),
            username: user.username.to_owned(),
            verified: user.verified,
            group: user.group.to_str().to_string(),
            created: user.created.unwrap(),
            updated: user.updated.unwrap(),
        }
    }

    pub fn filter_users(user: &[User]) -> Vec<FilterUserDto> {
        user.iter().map(FilterUserDto::filter_user).collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserData {
    pub user: FilterUserDto,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponseDto {
    pub status: String,
    pub data: UserData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserListResponseDto {
    pub status: String,
    pub users: Vec<FilterUserDto>,
    pub results: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserLoginResponseDto {
    pub status: String,
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct Response {
    pub status: &'static str,
    pub message: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct VerifyUserDto {
    #[validate(length(min = 1, message = "Username is required"))]
    pub username: String,
}

#[derive(Validate, Debug, Default, Clone, Serialize, Deserialize)]
pub struct UsernameUpdateDto {
    #[validate(length(min = 1, message = "Username is required"))]
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct GroupUpdateDto {
    #[validate(custom(function = "validate_user_group"))]
    pub group: UserGroup,
}

fn validate_user_group(group: &UserGroup) -> Result<(), validator::ValidationError> {
    match group {
        UserGroup::Admin | UserGroup::User => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_group")),
    }
}

#[derive(Debug, Validate, Default, Clone, Serialize, Deserialize)]
pub struct UserPasswordUpdateDto {
    #[validate(length(min = 1, message = "Username is required"))]
    pub username: String,

    #[validate(length(min = 1, message = "New password is required."))]
    pub new_password: String,

    #[validate(must_match(other = "new_password", message = "new passwords do not match"))]
    pub new_password_confirm: String,

    #[validate(length(min = 1, message = "Old password is required."))]
    pub old_password: String,
}
