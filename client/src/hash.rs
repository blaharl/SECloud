use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use sha2::{Digest, Sha256};

use crate::error::ErrorMessage;
use crate::user::LoginInfo;

const MAX_PASSWORD_LENGTH: usize = 255;

pub fn sha256_hash(input: impl Into<String>) -> Result<String, ErrorMessage> {
    let mut hasher = Sha256::new();
    hasher.update(input.into());
    let username_hash = hasher.finalize();
    String::from_utf8(format!("{:x}", username_hash).into()).map_err(|_| ErrorMessage::HashingError)
}

pub fn argon2id_hash(input: &[u8], salt: impl Into<String>) -> Result<String, ErrorMessage> {
    let argon2id = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(19456, 2, 1, None).map_err(|_| ErrorMessage::HashingError)?,
    );

    let salt = SaltString::from_b64(&salt.into()).map_err(|_| ErrorMessage::HashingError)?;

    Ok(argon2id
        .hash_password(input, &salt)
        .map_err(|_| ErrorMessage::HashingError)?
        .to_string())
}

/// hash password with argon2d (default params)
/// username (sha256) used as salt
pub fn password_hash(user: LoginInfo) -> Result<String, ErrorMessage> {
    let password = user.password();

    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    let username_hash = sha256_hash(user.username())?;
    let hashed_password = argon2id_hash(password.as_bytes(), username_hash)
        .map_err(|_| ErrorMessage::HashingError)?;

    if hashed_password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    Ok(hashed_password)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> LoginInfo {
        LoginInfo::new("username", "password", None)
    }

    #[test]
    fn test_sha256() {
        let user = test_user();
        let hash_str = sha256_hash(user.username()).unwrap();
        assert_eq!(
            hash_str,
            "16f78a7d6317f102bbd95fc9a4f3ff2e3249287690b8bdad6b7810f82b34ace3"
        );
    }

    #[test]
    fn test_hash() {
        let user = test_user();
        let hashed_result = password_hash(user).unwrap();
        assert_eq!(
            hashed_result,
            "$argon2id$v=19$m=19456,t=2,p=1$16f78a7d6317f102bbd95fc9a4f3ff2e3249287690b8bdad6b7810f82b34ace3$lzrW+r2NWIW2MRpY5u2aYgg4kPckPBeILt3RsgpSKR8"
        )
    }
}
