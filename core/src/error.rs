use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}

#[derive(Debug, PartialEq)]
pub enum ErrorMessage {
    EmptyPassword,
    UserNameExist,
    InvalidHashFormat,
    HashingError,
    EncryptionError,
    DecryptionError,
    ExceededMaxPasswordLength(usize),
    ServerError,
    WrongCredentials,
    UserNoLongerExist,
    PermissionDenied,
    UserNotAuthenticated,
    TokenNotProvided,
    InvalidToken,
}

impl fmt::Display for ErrorMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_str().to_owned())
    }
}

impl ErrorMessage {
    fn to_str(&self) -> String {
        match self {
            ErrorMessage::ServerError => "Server Error. Please try again later".to_string(),
            ErrorMessage::WrongCredentials => "User id or password is wrong".to_string(),
            ErrorMessage::TokenNotProvided => "Token not provided".to_string(),
            ErrorMessage::InvalidToken => "Invalid token".to_string(),
            ErrorMessage::UserNoLongerExist => {
                "User belonging to this token no longer exists".to_string()
            }
            ErrorMessage::EmptyPassword => "Password cannot be empty".to_string(),
            ErrorMessage::HashingError => "Error while hashing password".to_string(),
            ErrorMessage::EncryptionError => "Error while encrypting file".to_string(),
            ErrorMessage::DecryptionError => "Error while decrypting file".to_string(),
            ErrorMessage::InvalidHashFormat => "Invalid password hash format".to_string(),
            ErrorMessage::UserNameExist => "Username already exists".to_string(),
            ErrorMessage::ExceededMaxPasswordLength(max_length) => {
                format!("Password must not be more than {} characters", max_length)
            }
            ErrorMessage::PermissionDenied => {
                "You are not allowed to perform this action".to_string()
            }
            ErrorMessage::UserNotAuthenticated => {
                "User not authenticated. Please try again later".to_string()
            }
        }
    }
}
