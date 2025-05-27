pub mod crypt;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use secrecy::ExposeSecret;
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::SystemTime};
use tss_esapi::Context as TpmContext;
use zeroize::Zeroize;
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

/// A struct containing the master key,
/// which can then be used to derive other keys from.
///
/// The `MasterKey` is a fundamental security component that serves as the root
/// of a key hierarchy. It is typically generated using a cryptographically secure
/// random number generator and stored securely in memory using `SecretSlice`.
///
/// This key should be protected with the highest level of security, as compromise
/// of the master key would allow an attacker to derive all session keys.
///
/// In TPM terms, this is considered the Storage Root Key (SRK).
pub struct MasterKey {
    key: SecretSlice<u8>,
}

impl MasterKey {
    pub fn generate() -> Self {
        // TODO: implement TpmRng
        let mut ephemeral_key = Aes256Gcm::generate_key(&mut OsRng);
        let key_vec = ephemeral_key.as_slice().to_vec();
        ephemeral_key.as_mut_slice().zeroize();
        Self {
            key: SecretSlice::new(key_vec.into()),
        }
    }

    pub fn key(&self) -> &SecretSlice<u8> {
        &self.key
    }

    pub fn unseal_from_ciphertxt(ciphertxt: &[u8], tpm_context: &TpmContext) -> Self {
        todo!("Implement unsealing logic")
    }

    pub fn seal_to_ciphertext(&self, tpm_context: &TpmContext) -> Vec<u8> {
        todo!("Implement sealing logic")
    }
}

impl Zeroize for MasterKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A session key derived from a MasterKey
///
/// The `SessionKey` struct represents a cryptographic key that is derived
/// from a `MasterKey`. This key can be used for secure communication or
/// encryption tasks within a session. The key is stored securely using
/// the `SecretSlice` type to ensure sensitive data is protected.
pub struct SessionKey {
    key: SecretSlice<u8>,
}

impl SessionKey {
    // The master key here is consumed for security reasons
    // todo: consider if consuming the master key is necessary
    pub fn new(master_key: MasterKey, starting_salt: Option<&[u8]>, salt: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let hkdf = Hkdf::<sha2::Sha256>::new(starting_salt, master_key.key().expose_secret());
        drop(master_key); // Explicit drop just to be extra sure
        hkdf.expand(salt, &mut key).expect("hkdf expansion failed");
        Self {
            key: SecretSlice::new(key.into()),
        }
    }

    /// Further expand the derived key using HKDF
    pub fn expand(self, salt: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let hkdf = Hkdf::<sha2::Sha256>::new(None, self.key.expose_secret());
        hkdf.expand(salt, &mut key).expect("hkdf expansion failed");
        Self {
            key: SecretSlice::new(key.into()),
        }
    }

    pub fn key(&self) -> &SecretSlice<u8> {
        &self.key
    }
}
