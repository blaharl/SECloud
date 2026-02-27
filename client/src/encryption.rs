use crate::hash::argon2_params;
use crate::user::LoginInfo;
use crate::{error::ErrorMessage, hash};
use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

#[derive(Clone, Copy)]
pub enum Kdf {
    Argon2id,
}

#[derive(Clone, Copy)]
pub enum Algorithm {
    Aes256,
}

pub fn derive_key(user: LoginInfo, kdf: Kdf) -> Result<[u8; 32], ErrorMessage> {
    let salt = hash::sha256_hash(user.username())?;
    match kdf {
        Kdf::Argon2id => {
            let mut out = [0_u8; 32];
            hash::argon2id_hash_kdf(
                user.password().as_bytes(),
                salt,
                &mut out,
                // WARN: setting t to 2 makes the derived key identical to the stored password
                Some(argon2_params(19456, 3, 1, None)?),
            )?;
            Ok(out)
        }
    }
}

pub fn aes256_encrypt(
    user: LoginInfo,
    plaintext: &[u8],
    kdf: Kdf,
) -> Result<(Vec<u8>, Vec<u8>), ErrorMessage> {
    let key = derive_key(user, kdf)?;
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| ErrorMessage::EncryptionError)?;

    Ok((ciphertext, nonce.to_vec()))
}

pub fn aes256_decrypt(
    user: LoginInfo,
    ciphertext: &[u8],
    nonce: &[u8],
    kdf: Kdf,
) -> Result<Vec<u8>, ErrorMessage> {
    let key = derive_key(user, kdf)?;
    let key = Key::<Aes256Gcm>::from_slice(&key);

    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce.into(), ciphertext.as_ref())
        .map_err(|_| ErrorMessage::DecryptionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> LoginInfo {
        LoginInfo::new("username", "password", None)
    }

    #[test]
    fn test_aes256() {
        let user = test_user();
        let plaintext = b"hello world!";
        let kdf = Kdf::Argon2id;

        let (ciphertext, nonce) = aes256_encrypt(user.clone(), plaintext, kdf).unwrap();
        let decryptedtext = aes256_decrypt(user, &ciphertext, &nonce, kdf).unwrap();

        assert_eq!(plaintext.to_vec(), decryptedtext);
    }
}
