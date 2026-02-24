use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use sha2::{Digest, Sha256};

use crate::error::ErrorMessage;

const MAX_PASSWORD_LENGTH: usize = 255;

pub fn hash(
    password: impl Into<String>,
    username: impl Into<String>,
) -> Result<String, ErrorMessage> {
    let password = password.into();

    if password.is_empty() {
        return Err(ErrorMessage::EmptyPassword);
    }

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(19456, 2, 1, None).map_err(|_| ErrorMessage::HashingError)?,
    );

    let mut hasher = Sha256::new();
    hasher.update(username.into());
    let username_hash = hasher.finalize();
    let username_hash = String::from_utf8(format!("{:x}", username_hash).into())
        .map_err(|_| ErrorMessage::HashingError)?;
    eprintln!("{}", username_hash);
    let salt = SaltString::from_b64(&username_hash).map_err(|_| ErrorMessage::HashingError)?;

    let hashed_password = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| ErrorMessage::HashingError)?
        .to_string();

    if hashed_password.len() > MAX_PASSWORD_LENGTH {
        return Err(ErrorMessage::ExceededMaxPasswordLength(MAX_PASSWORD_LENGTH));
    }

    Ok(hashed_password)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let username = "username";

        let mut hasher = Sha256::new();
        hasher.update(username);
        let username_hash = hasher.finalize();
        let hash_str = String::from_utf8(format!("{:x}", username_hash).into()).unwrap();
        assert_eq!(
            hash_str,
            "16f78a7d6317f102bbd95fc9a4f3ff2e3249287690b8bdad6b7810f82b34ace3"
        );
    }

    #[test]
    fn test_hash() {
        let username = "username";
        let password = "password";
        let hashed_result = hash(password, username).unwrap();
        assert_eq!(
            hashed_result,
            "$argon2id$v=19$m=19456,t=2,p=1$16f78a7d6317f102bbd95fc9a4f3ff2e3249287690b8bdad6b7810f82b34ace3$lzrW+r2NWIW2MRpY5u2aYgg4kPckPBeILt3RsgpSKR8"
        )
    }
}
