use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::SystemTime};

/// A "secret" stored inside the database, AKA the actual K/V pair itself.
/// This struct will be contained as a sled value with a unique salt.
///
/// This will be a bincode-serialized struct containing the actual secret data
#[derive(Serialize, Deserialize)]
pub struct Secret {
    /// Encrypted ciphertext version of the secret data
    ciphertext: Vec<u8>,
    /// Initialization vector used for encryption
    iv: [u8; 12],
    /// A unique salt used with the master key to derive the intermediate key
    /// via HKDF. This salt is per-secret and randomly generated.
    salt: Vec<u8>,
    /// A list of additional salt providers used for additional key derivation.
    /// NOTE: This list is a vector of strings representing the sources of the MFA derivations.
    /// It is ***ordered*** and may even contain duplicates.
    /// They're stored as a vector of strings so frontends may be able to implement their own
    /// sources of the MFA derivations.
    ///
    /// TL;DR: if MFA is enabled for this secret, you'll have to figure out the salts for each listed
    /// source to create a properly usable session key for this secret.
    pub mfa_sources: Vec<String>,
    /// Whether multi-factor authentication is enabled for this secret.
    pub mfa: bool,

    /// Additional metadata about the secret.
    pub metadata: SecretMeta,
}

impl Secret {
    /// Creates a new `Secret` with the provided ciphertext, iv, salt, and metadata.
    pub fn new(
        ciphertext: Vec<u8>,
        iv: [u8; 12],
        salt: Vec<u8>,
        mfa_sources: Vec<String>,
        mfa: bool,
        metadata: SecretMeta,
    ) -> Self {
        Self {
            ciphertext,
            iv,
            salt,
            mfa_sources,
            mfa,
            metadata,
        }
    }

    /// Returns a reference to the ciphertext.
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }

    /// Returns the initialization vector.
    pub fn iv(&self) -> &[u8; 12] {
        &self.iv
    }

    /// Returns the unique salt used for key derivation.
    pub fn salt(&self) -> &Vec<u8> {
        &self.salt
    }
}

/// A struct containing metadata about a secret.
///
/// This struct contains information about the secret, such as its metadata and additional encryption details
/// that SecretData provides.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretMeta {
    /// Optional description of the secret.
    pub description: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl SecretMeta {
    /// Creates a new `SecretMeta` with the provided description and attributes.
    pub fn new(description: Option<String>, attributes: BTreeMap<String, String>) -> Self {
        let now = SystemTime::now();
        Self {
            description,
            attributes,
            created_at: now,
            updated_at: now,
        }
    }

    /// Simply update the metadata's updated_at field to the current time.
    /// 
    /// The other fields have to be set explicitly.
    pub fn update(&mut self) {
        self.updated_at = SystemTime::now();
    }
}
