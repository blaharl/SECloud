use crate::hash::argon2_params;
use crate::user::LoginInfo;
use crate::{error::ErrorMessage, hash};
use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum Kdf {
    Argon2id,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
pub enum Algorithm {
    Aes256,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AlgoInfo {
    algorithm: Algorithm,
    derived_key: Vec<u8>,
    nonce: Option<Vec<u8>>,
}

impl AlgoInfo {
    pub fn new(
        user: &LoginInfo,
        algorithm: Option<Algorithm>,
        kdf: Option<Kdf>,
        nonce: Option<Vec<u8>>,
    ) -> Result<Self, ErrorMessage> {
        Ok(Self {
            algorithm: algorithm.unwrap_or(Algorithm::Aes256),
            derived_key: derive_key(user, kdf.unwrap_or(Kdf::Argon2id))?,
            nonce,
        })
    }

    pub fn set_nonce(&mut self, nonce: Vec<u8>) {
        self.nonce = Some(nonce);
    }
}

fn derive_key(user: &LoginInfo, kdf: Kdf) -> Result<Vec<u8>, ErrorMessage> {
    let salt = hash::sha256_hash(user.username())?;
    match kdf {
        Kdf::Argon2id => {
            let mut out = vec![0_u8; 32];
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

/// used for encrypting root folder only
pub fn root_nonce(user: &LoginInfo, algorithm: Algorithm) -> Result<Vec<u8>, ErrorMessage> {
    let salt = hash::sha256_hash(user.username())?;
    match algorithm {
        Algorithm::Aes256 => {
            let mut out = vec![0_u8; 32];
            hash::argon2id_hash_kdf(
                user.password().as_bytes(),
                salt,
                &mut out,
                Some(argon2_params(19456, 4, 1, None)?),
            )?;
            Ok(out[0..12].to_vec())
        }
    }
}

pub fn encrypt(plaintext: &[u8], algo_info: &AlgoInfo) -> Result<(Vec<u8>, Vec<u8>), ErrorMessage> {
    match algo_info.algorithm {
        Algorithm::Aes256 => {
            aes256_encrypt(plaintext, &algo_info.derived_key, algo_info.nonce.clone())
        }
    }
}

pub fn decrypt(ciphertext: &[u8], algo_info: &AlgoInfo) -> Result<Vec<u8>, ErrorMessage> {
    match algo_info.algorithm {
        Algorithm::Aes256 => aes256_decrypt(
            ciphertext,
            &algo_info.derived_key,
            &algo_info
                .nonce
                .clone()
                .ok_or(ErrorMessage::DecryptionError)?,
        ),
    }
}

fn aes256_encrypt(
    plaintext: &[u8],
    derived_key: &[u8],
    nonce: Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), ErrorMessage> {
    let key = Key::<Aes256Gcm>::from_slice(derived_key);

    let cipher = Aes256Gcm::new(key);
    let nonce = nonce.unwrap_or(Aes256Gcm::generate_nonce(&mut OsRng).to_vec());
    let ciphertext = cipher
        .encrypt((&*nonce).into(), plaintext.as_ref())
        .map_err(|_| ErrorMessage::EncryptionError)?;

    Ok((ciphertext, nonce.to_vec()))
}

fn aes256_decrypt(
    ciphertext: &[u8],
    derived_key: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, ErrorMessage> {
    let key = Key::<Aes256Gcm>::from_slice(derived_key);

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

    fn test_algo() -> AlgoInfo {
        AlgoInfo::new(
            &test_user(),
            None,
            None,
            Some(root_nonce(&test_user(), Algorithm::Aes256).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn test_aes256_encrypt() {
        let plaintext = b"hello world!";
        let algo_info = test_algo();
        let ciphertext = [
            162, 44, 7, 18, 202, 235, 54, 107, 59, 106, 167, 94, 157, 184, 182, 80, 177, 93, 222,
            230, 63, 223, 75, 115, 110, 83, 10, 3,
        ];

        let encrypted_text = encrypt(plaintext, &algo_info).unwrap().0;
        assert_eq!(encrypted_text, ciphertext);
    }

    #[test]
    fn test_aes256_decrypt() {
        let plaintext = b"hello world!";
        let algo_info = test_algo();
        let ciphertext = [
            162, 44, 7, 18, 202, 235, 54, 107, 59, 106, 167, 94, 157, 184, 182, 80, 177, 93, 222,
            230, 63, 223, 75, 115, 110, 83, 10, 3,
        ];

        let decrypted_text = decrypt(&ciphertext, &algo_info).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted_text);
    }
}
