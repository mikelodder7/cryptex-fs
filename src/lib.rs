//! A crate for representing a keyring as a file
#![deny(
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    unused_parens,
    unused_lifetimes,
    unconditional_recursion,
    unused_extern_crates,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod protected;
mod uint;

use std::collections::BTreeMap;
use std::{
    fs::create_dir_all,
    path::PathBuf,
};

use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, NewAead};
use cryptex::{error::KeyRingError, KeyRing, KeyRingSecret};
use heed::{
    types::{OwnedSlice, Str},
    Database, Env, EnvOpenOptions,
};
use zeroize::Zeroize;

/// Protected region of memory
pub use protected::*;
/// A wrapper for zig-zag encoding integers efficiently as bytes
pub use uint::*;

pub use argon2;

/// A keyring backed by lmdb. Each entry is wrapped in envelope
/// encryption. The master key is derived from entropy or a password.
/// The master key is stored in protected memory and only exposed when needed.
pub struct KeyRingFile {
    decryption_key: Protected,
    encryption_key: x25519_dalek::PublicKey,
    env: Env,
    db: Database<Str, OwnedSlice<u8>>,
}

unsafe impl Send for KeyRingFile {}
unsafe impl Sync for KeyRingFile {}

impl KeyRing for KeyRingFile {
    fn new<S: AsRef<str>>(_service: S) -> cryptex::Result<Self> {
        unimplemented!();
    }

    fn get_secret<S: AsRef<str>>(&mut self, id: S) -> cryptex::Result<KeyRingSecret> {
        let id = id.as_ref();
        let rtxn = self.env.read_txn().map_err(|e| KeyRingError::GeneralError { msg: format!("{:?}", e) })?;
        let opt_ciphertext_and_enc_key = self.db.get(&rtxn, id).map_err(|e| KeyRingError::GeneralError { msg: format!("{:?}", e) })?;

        if opt_ciphertext_and_enc_key.is_none() {
            return Err(KeyRingError::ItemNotFound);
        }

        let ciphertext_and_enc_key = opt_ciphertext_and_enc_key.unwrap();
        let mut eph_pub_key_bytes = [0u8; 32];
        eph_pub_key_bytes.copy_from_slice(&ciphertext_and_enc_key[..32]);
        let eph_pub_key = x25519_dalek::PublicKey::from(eph_pub_key_bytes);

        match self.decryption_key.unprotect() {
            None => Err(KeyRingError::AccessDenied {msg: String::from("decryption key has been tampered")}),
            Some(secret_bytes) => {
                let scalar_bytes = <[u8; 32]>::try_from(secret_bytes.as_ref()).unwrap();
                let secret_key = x25519_dalek::StaticSecret::from(scalar_bytes);
                let mut output = derive_symm_key(id, &eph_pub_key, &self.encryption_key, secret_key.diffie_hellman(&eph_pub_key));

                let seal_key = chacha20poly1305::Key::from_slice(&output[..32]);
                let nonce = chacha20poly1305::XNonce::from_slice(&output[32..56]);
                let cipher = chacha20poly1305::XChaCha20Poly1305::new(seal_key);
                let plaintext = cipher.decrypt(&nonce, &ciphertext_and_enc_key[32..]).map_err(|e| KeyRingError::GeneralError {msg: format!("{:?}", e)})?;
                output.zeroize();
                Ok(KeyRingSecret(plaintext))
            }
        }
    }

    fn set_secret<S: AsRef<str>, B: AsRef<[u8]>>(
        &mut self,
        id: S,
        secret: B,
    ) -> cryptex::Result<()> {
        let id = id.as_ref();
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("{:?}", e),
            })?;
        let enc_secret = x25519_dalek::EphemeralSecret::new(rand_core::OsRng);
        let enc_public = x25519_dalek::PublicKey::from(&enc_secret);
        let mut output = derive_symm_key(
            id,
            &enc_public,
            &self.encryption_key,
            enc_secret.diffie_hellman(&self.encryption_key),
        );
        let seal_key = chacha20poly1305::Key::from_slice(&output[..32]);
        let nonce = chacha20poly1305::XNonce::from_slice(&output[32..56]);
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(seal_key);

        let mut ciphertext =
            cipher
                .encrypt(nonce, secret.as_ref())
                .map_err(|e| KeyRingError::GeneralError {
                    msg: format!("{:?}", e),
                })?;
        output.zeroize();
        let mut keyring_data = enc_public.to_bytes().to_vec();
        keyring_data.append(&mut ciphertext);
        self.db
            .put(&mut wtxn, id, keyring_data.as_slice())
            .map_err(|e| KeyRingError::GeneralError {
                msg: format!("{:?}", e),
            })?;
        wtxn.commit().map_err(|e| KeyRingError::GeneralError {
            msg: format!("{:?}", e),
        })
    }

    fn delete_secret<S: AsRef<str>>(&mut self, id: S) -> cryptex::Result<()> {
        let mut wtxn = self.env.write_txn().map_err(|e| KeyRingError::AccessDenied {msg: format!("{:?}", e)})?;
        let ret = self.db.delete(&mut wtxn, id.as_ref()).map_err(|e| KeyRingError::GeneralError {msg: format!("{:?}", e)})?;
        if ret {
            Ok(())
        } else {
            Err(KeyRingError::ItemNotFound)
        }
    }

    fn peek_secret<S: AsRef<str>>(_id: S) -> cryptex::Result<Vec<(String, KeyRingSecret)>> {
        unimplemented!()
    }

    fn list_secrets() -> cryptex::Result<Vec<BTreeMap<String, String>>> {
        unimplemented!()
    }
}

/// The config options for opening the keyring file
#[derive(Clone)]
pub struct KeyRingFileOpenOptions<'a> {
    /// If entropy is set, it is used vs hashing a password
    pub entropy: Option<[u8; 32]>,
    /// If a password is used, Argon2id is used to generate the entropy
    pub password: Option<String>,
    /// The password hashing algorithm
    pub password_hash: Option<Argon2<'a>>,
    /// the password salt to use
    pub password_salt: Option<SaltString>,
    /// The location of the keyring file
    pub path: PathBuf,
}

impl<'a> Default for KeyRingFileOpenOptions<'a> {
    fn default() -> Self {
        Self {
            password: None,
            entropy: None,
            password_hash: None,
            password_salt: None,
            path: Self::default_path(),
        }
    }
}

impl<'a> KeyRingFileOpenOptions<'a> {
    /// The default memory cost in KB
    pub const DEFAULT_M_COST: u32 = 32768;
    /// The default number of iterations
    pub const DEFAULT_T_COST: u32 = 48;
    /// The default parallelization
    pub const DEFAULT_P_COST: u32 = 2;
    /// The default output length
    pub const DEFAULT_OUT_LEN: usize = 64;

    /// Create a new config with default settings for password hashing and
    /// generate a random salt
    pub fn with_default_password_hash(password: &str) -> Self {
        let salt = SaltString::generate(&mut rand_core::OsRng);
        let argon2 = Self::default_password_hash();
        Self {
            password: Some(password.to_string()),
            password_salt: Some(salt),
            password_hash: Some(argon2),
            entropy: None,
            path: Self::default_path(),
        }
    }

    /// Get the default password hasher
    pub fn default_password_hash() -> Argon2<'a> {
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                Self::DEFAULT_M_COST,
                Self::DEFAULT_T_COST,
                Self::DEFAULT_P_COST,
                Some(Self::DEFAULT_OUT_LEN),
            )
            .unwrap(),
        )
    }

    /// Get the default keyring path
    pub fn default_path() -> PathBuf {
        let mut path =
            dirs::home_dir().unwrap_or(dirs::data_dir().unwrap_or(dirs::data_local_dir().unwrap()));
        path.push(".keyring");
        path
    }

    /// Open the keyring
    pub fn open_keyring(self) -> Result<KeyRingFile, KeyRingError> {
        let _ = create_dir_all(&self.path);
        if !self.path.as_path().exists() {
            return Err(KeyRingError::AccessDenied {
                msg: String::from("cannot access the keyring path"),
            });
        }

        if let Some(e) = self.entropy {
            let secret_key = x25519_dalek::StaticSecret::from(e);
            let encryption_key = x25519_dalek::PublicKey::from(&secret_key);
            let decryption_key = Protected::new(&e[..]);
            let (env, db) = open_database(&self.path)?;
            Ok(KeyRingFile {
                decryption_key,
                encryption_key,
                env,
                db,
            })
        } else {
            match (self.password, self.password_salt, self.password_hash) {
                (Some(ref mut pass), Some(salt), Some(hasher)) => {
                    let hash = hasher.hash_password(pass.as_bytes(), &salt).map_err(|e| {
                        KeyRingError::GeneralError {
                            msg: format!("{:?}", e),
                        }
                    })?;
                    pass.zeroize();
                    let hash = hash.hash.unwrap();
                    let mut hash_bytes =
                        <[u8; KeyRingFileOpenOptions::DEFAULT_OUT_LEN]>::try_from(hash.as_bytes()).unwrap();
                    let mut scalar =
                        curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&hash_bytes);
                    let secret_key = x25519_dalek::StaticSecret::from(scalar.to_bytes());
                    let encryption_key = x25519_dalek::PublicKey::from(&secret_key);
                    let decryption_key = Protected::new(scalar.as_bytes());
                    hash_bytes.zeroize();
                    scalar.zeroize();
                    let (env, db) = open_database(&self.path)?;
                    Ok(KeyRingFile {
                        decryption_key,
                        encryption_key,
                        env,
                        db,
                    })
                }
                (_, _, _) => Err(KeyRingError::GeneralError {
                    msg: String::from("password and other settings not completely specified"),
                }),
            }
        }
    }
}

fn open_database(path: &PathBuf) -> Result<(Env, Database<Str, OwnedSlice<u8>>), KeyRingError> {
    let env = EnvOpenOptions::new()
        .open(path)
        .map_err(|e| KeyRingError::AccessDenied {
            msg: format!("{:?}", e),
        })?;
    let db = env.create_database(None).map_err(|e| KeyRingError::AccessDenied {
        msg: format!("{:?}", e),
    })?;
    Ok((env, db))
}

fn derive_symm_key(
    id: &str,
    eph_pub_key: &x25519_dalek::PublicKey,
    enc_pub_key: &x25519_dalek::PublicKey,
    ss: x25519_dalek::SharedSecret,
) -> [u8; 64] {
    let mut transcript = merlin::Transcript::new(b"set_secret");
    transcript.append_message(b"identifier", id.as_bytes());
    transcript.append_message(b"ephemeral_public_key", eph_pub_key.as_bytes());
    transcript.append_message(b"encryption_public_key", enc_pub_key.as_bytes());
    transcript.append_message(b"shared_secret", ss.as_bytes());
    let mut output = [0u8; 64];
    transcript.challenge_bytes(b"output_bytes", &mut output);
    output
}
