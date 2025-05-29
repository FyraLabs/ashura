//! Module for handling key-value store operations.
//!
//! This module manages the actual on-disk kv store using sled.

use crate::crypt::SessionKey;
use crate::secret::{Secret, StatefulSecretError};
use crate::tpm::SealedMasterKey;
use bincode::{self, Decode, Encode};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sled::Db;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors that can occur during stateful secret operations on collections
#[derive(Debug)]
pub enum StatefulDecryptionError {
    /// The secret was not found in the collection
    SecretNotFound(String),
    /// The collection's master key was not found
    MasterKeyNotFound,
    /// TPM operation failed
    TmpError(String),
    /// TPM decryption failed
    TmpDecryptionFailed(String),
    /// Required MFA salt is missing
    MfaSaltMissing(String),
    /// Underlying stateful secret error
    StatefulSecret(StatefulSecretError),
    /// Database storage error
    Storage(sled::Error),
}

impl From<StatefulSecretError> for StatefulDecryptionError {
    fn from(err: StatefulSecretError) -> Self {
        StatefulDecryptionError::StatefulSecret(err)
    }
}

impl From<sled::Error> for StatefulDecryptionError {
    fn from(err: sled::Error) -> Self {
        StatefulDecryptionError::Storage(err)
    }
}

impl std::fmt::Display for StatefulDecryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatefulDecryptionError::SecretNotFound(name) => {
                write!(f, "Secret '{}' not found", name)
            }
            StatefulDecryptionError::MasterKeyNotFound => {
                write!(f, "Master key not found in collection")
            }
            StatefulDecryptionError::TmpError(msg) => write!(f, "TPM error: {}", msg),
            StatefulDecryptionError::TmpDecryptionFailed(msg) => {
                write!(f, "TPM decryption failed: {}", msg)
            }
            StatefulDecryptionError::MfaSaltMissing(source) => {
                write!(f, "MFA salt missing for source: {}", source)
            }
            StatefulDecryptionError::StatefulSecret(err) => {
                write!(f, "Stateful secret error: {:?}", err)
            }
            StatefulDecryptionError::Storage(err) => write!(f, "Storage error: {}", err),
        }
    }
}

impl std::error::Error for StatefulDecryptionError {}

// The kv path is defined in this format, delimited by a slash
// `<collection_name>/secret/<secret_name>`
// Each secret is stored in a collection prefix, then the secret label itself.
// There's also additional data for the collection itself, which will have these paths:
// `<collection_name>/sealed_master_key`
// ... for TPM-sealed master keys

/// A struct representing the main key-value store.
/// A wrapper around sled's `Db` type.
#[derive(Clone)]
pub struct KvStore {
    db: Arc<Mutex<Db>>,
}

impl KvStore {
    /// Creates a new `KvStore` instance with the specified path.
    pub fn new(path: PathBuf) -> Self {
        let display_path = path.clone();
        match sled::open(path) {
            Ok(db) => Self {
                db: Arc::new(Mutex::new(db)),
            },
            Err(e) => {
                error!("Failed to open sled database at {:?}: {}", display_path, e);
                panic!("Failed to open sled database");
            }
        }
    }

    /// Returns a reference to the underlying sled database.
    pub fn db(&self) -> Arc<Mutex<Db>> {
        self.db.clone()
    }
}
#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone, PartialEq, Eq)]
/// A struct representing a serialized blob of data.
pub struct EncryptedBlob(pub Vec<u8>);

impl Zeroize for EncryptedBlob {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for EncryptedBlob {}

impl Drop for EncryptedBlob {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// A collection of secrets stored in the key-value store.
pub struct SecretCollection {
    kv_store: KvStore,
    pub name: String,
}

impl SecretCollection {
    /// Creates a new `SecretCollection` with the specified name and kv_store.
    pub fn new(kv_store: KvStore, name: String) -> Self {
        Self { kv_store, name }
    }

    pub fn new_init(
        kv_store: KvStore,
        collection_name: &str,
        tcti: &tss_esapi::Tcti,
    ) -> Result<Self, sled::Error> {
        // Set the sealed master key for the collection
        let master_key = {
            let context_gen =
                tss_esapi::Context::new(tcti.clone()).expect("Failed to create TSS context");
            let context_encrypt = tss_esapi::Context::new(tcti.clone())
                .expect("Failed to create TSS context for encryption");
            SealedMasterKey::encrypt(
                crate::crypt::MasterKey::generate(context_gen),
                context_encrypt,
                None, // Provide an appropriate third argument, e.g., None or a policy/password as required
            )
            .expect("Failed to seal master key")
        };

        let collection = Self::new(kv_store, collection_name.to_string());
        collection.set_sealed_master_key(&master_key).map_err(|e| {
            error!(
                "Failed to set sealed master key for collection {}: {}",
                collection_name, e
            );
            e
        })?;
        Ok(collection)
    }

    /// Returns the name of the collection.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a reference to the underlying kv store.
    pub fn kv_store(&self) -> &KvStore {
        &self.kv_store
    }

    pub fn prefix(&self) -> String {
        self.name.to_string()
    }

    pub fn secret_collection_path(&self, secret_name: &str) -> String {
        format!(
            "{prefix}/secret/{secret_name}",
            prefix = self.prefix(),
            secret_name = secret_name
        )
    }

    pub fn sealed_master_key_path(&self) -> String {
        format!("{prefix}/sealed_master_key", prefix = self.prefix())
    }

    /// Sets the sealed master key for the collection.
    /// The key is serialized using bincode before storing.
    pub fn set_sealed_master_key(&self, master_key: &SealedMasterKey) -> Result<(), sled::Error> {
        let db = self.kv_store.db.lock().unwrap();
        let encoded_key = bincode::encode_to_vec(master_key, bincode::config::standard())
            .expect("Failed to serialize SealedMasterKey");
        db.insert(self.sealed_master_key_path(), encoded_key)?;
        Ok(())
    }

    /// Gets the sealed master key for the collection.
    pub fn get_sealed_master_key(&self) -> Result<Option<SealedMasterKey>, sled::Error> {
        let db = self.kv_store.db.lock().unwrap();
        match db.get(self.sealed_master_key_path())? {
            Some(value) => {
                let (sealed_master_key, _): (SealedMasterKey, usize) =
                    bincode::decode_from_slice(&value, bincode::config::standard())
                        .expect("Failed to deserialize SealedMasterKey");
                Ok(Some(sealed_master_key))
            }
            None => Ok(None),
        }
    }

    pub fn get_secret(&self, secret_name: &str) -> Result<Option<Secret>, sled::Error> {
        let db = self.kv_store.db.lock().unwrap();
        match db.get(self.secret_collection_path(secret_name))? {
            Some(value) => {
                // just deserialize the secret
                let (secret, _): (Secret, usize) =
                    bincode::decode_from_slice(&value, bincode::config::standard())
                        .expect("Failed to deserialize Secret");
                Ok(Some(secret))
            }
            None => Ok(None),
        }
    }

    pub fn set_secret_raw(&self, secret_name: &str, secret: Secret) -> Result<(), sled::Error> {
        let db = self.kv_store.db.lock().unwrap();
        let encoded_secret = bincode::encode_to_vec(&secret, bincode::config::standard())
            .expect("Failed to serialize Secret");
        db.insert(self.secret_collection_path(secret_name), encoded_secret)?;
        Ok(())
    }

    /// Creates a new secret for the collection with the given plaintext and extra salts.
    /// The plaintext is encrypted using the sealed master key of the collection.
    ///
    /// # Arguments
    /// * `secret_name` - The name to store the secret under
    /// * `plaintext` - The plaintext data to be encrypted and stored as a secret.
    /// * `extra_salts` - Additional salts to be used in the encryption process, a key-value map of the MFA source name and the output of the MFA source to be salted with.
    /// * `tcti` - The TCTI context used to create the TSS context for encryption.
    pub fn new_secret_for_collection(
        &self,
        secret_name: &str,
        plaintext: Vec<u8>,
        extra_salts: BTreeMap<String, Vec<u8>>,
        tcti: &tss_esapi::Tcti,
    ) -> Result<Secret, sled::Error> {
        let sealed_master_key = self
            .get_sealed_master_key()?
            .expect("No sealed master key found for collection");
        let tpm_context =
            tss_esapi::Context::new(tcti.clone()).expect("Failed to create TSS context");

        // Extract MFA source names and their salt values
        let (mfa_labels, mfa_inputs): (Vec<String>, Vec<Vec<u8>>) = extra_salts.into_iter().unzip();

        // Generate a random secondary salt for the session key derivation
        let mut secondary_salt = vec![0u8; 32];
        rand::rng().fill(&mut secondary_salt[..]);

        // Decrypt master key and create base session key
        let master_key = sealed_master_key
            .decrypt(tpm_context)
            .expect("Failed to decrypt sealed master key");
        let mut session_key = SessionKey::new(master_key, Some(&secondary_salt), &secondary_salt);

        // Apply MFA salts to extend the session key if any MFA sources are provided
        for mfa_salt in &mfa_inputs {
            session_key = session_key.expand(mfa_salt);
        }

        // Determine if MFA is enabled based on whether extra salts were provided
        let mfa_enabled = !mfa_labels.is_empty();

        // Create the secret with proper MFA configuration
        let mut secret = if mfa_enabled {
            Secret::from_plaintext_with_options(
                plaintext,
                session_key,
                secondary_salt.clone(),
                mfa_labels,
                true,
                None,
                BTreeMap::new(),
            )
        } else {
            Secret::from_plaintext_blank(plaintext, session_key, secondary_salt.clone())
        };

        secret.metadata.update();
        self.set_secret_raw(secret_name, secret.clone())?;
        Ok(secret)
    }

    /// Decrypt a secret with replay protection and automatically update the stored secret.
    ///
    /// This method provides cryptographic replay protection by:
    /// 1. Retrieving the secret from storage
    /// 2. Performing decryption with the provided nonce
    /// 3. Automatically saving the updated secret back to storage
    ///
    /// # Arguments
    /// * `secret_name` - The name of the secret to decrypt
    /// * `session_key` - The session key for decryption
    /// * `access_nonce` - Must be strictly greater than the last used nonce
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The decrypted data
    /// * `Err(StatefulDecryptionError)` - Various validation, decryption, or storage errors
    pub fn decrypt_secret(
        &self,
        secret_name: &str,
        session_key: &crate::SessionKey,
        access_nonce: u64,
    ) -> Result<Vec<u8>, StatefulDecryptionError> {
        // 1. Retrieve the current secret
        let secret =
            self.get_secret(secret_name)?
                .ok_or(StatefulDecryptionError::SecretNotFound(
                    secret_name.to_string(),
                ))?;

        // 2. Perform decryption
        let (plaintext, updated_secret) = secret.decrypt(session_key, access_nonce)?;

        // 3. Save the updated secret back to storage
        self.set_secret_raw(secret_name, updated_secret)?;

        Ok(plaintext)
    }

    /// Decrypt a secret with MFA and replay protection.
    ///
    /// This combines MFA salt handling with encryption for maximum security.
    ///
    /// # Arguments
    /// * `secret_name` - The name of the secret to decrypt
    /// * `extra_salts` - MFA salts in the same order as stored in the secret
    /// * `access_nonce` - Must be strictly greater than the last used nonce
    /// * `tcti` - TPM context for key operations
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The decrypted data
    /// * `Err(StatefulDecryptionError)` - Various validation, decryption, or storage errors
    pub fn decrypt_secret_with_mfa(
        &self,
        secret_name: &str,
        extra_salts: &BTreeMap<String, Vec<u8>>,
        access_nonce: u64,
        tcti: &tss_esapi::Tcti,
    ) -> Result<Vec<u8>, StatefulDecryptionError> {
        // 1. Retrieve the current secret
        let secret =
            self.get_secret(secret_name)?
                .ok_or(StatefulDecryptionError::SecretNotFound(
                    secret_name.to_string(),
                ))?;

        // 2. Reconstruct the session key with MFA
        let sealed_master_key = self
            .get_sealed_master_key()?
            .ok_or(StatefulDecryptionError::MasterKeyNotFound)?;

        let tmp_context = tss_esapi::Context::new(tcti.clone()).map_err(|e| {
            StatefulDecryptionError::TmpError(format!("Failed to create TPM context: {}", e))
        })?;

        let master_key = sealed_master_key.decrypt(tmp_context).map_err(|e| {
            StatefulDecryptionError::TmpDecryptionFailed(format!(
                "Failed to decrypt master key: {}",
                e
            ))
        })?;

        // Build session key with secondary salt and MFA salts
        let mut session_key = crate::SessionKey::new(
            master_key,
            Some(secret.secondary_salt()),
            secret.secondary_salt(),
        );

        // Extract MFA salts in the same order as stored in the secret
        let mfa_salt_values: Vec<Vec<u8>> = secret
            .mfa_sources
            .iter()
            .map(|source| {
                extra_salts
                    .get(source)
                    .ok_or_else(|| StatefulDecryptionError::MfaSaltMissing(source.clone()))
                    .cloned()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Apply MFA salts to session key
        for mfa_salt in &mfa_salt_values {
            session_key = session_key.expand(mfa_salt);
        }

        // 3. Perform decryption
        let (plaintext, updated_secret) = secret.decrypt(&session_key, access_nonce)?;

        // 4. Save the updated secret back to storage
        self.set_secret_raw(secret_name, updated_secret)?;

        Ok(plaintext)
    }

    /// Decrypt a secret with stateful replay protection using auto-generated nonce.
    ///
    /// This is a convenience method that automatically generates a suitable nonce for
    /// decryption. The secret is automatically updated in storage after decryption.
    ///
    /// # Arguments
    /// * `secret_name` - The name of the secret to decrypt
    /// * `session_key` - The session key for decryption
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The decrypted data
    /// * `Err(StatefulDecryptionError)` - Various validation, decryption, or storage errors
    pub fn decrypt_secret_auto(
        &self,
        secret_name: &str,
        session_key: &crate::SessionKey,
    ) -> Result<Vec<u8>, StatefulDecryptionError> {
        // 1. Retrieve the current secret
        let secret =
            self.get_secret(secret_name)?
                .ok_or(StatefulDecryptionError::SecretNotFound(
                    secret_name.to_string(),
                ))?;

        // 2. Perform decryption with auto-generated nonce
        let (plaintext, updated_secret) = secret.decrypt_auto_nonce(session_key)?;

        // 3. Save the updated secret back to storage
        self.set_secret_raw(secret_name, updated_secret)?;

        Ok(plaintext)
    }

    /// Decrypt a secret with replay protection using next sequential nonce.
    ///
    /// This method uses the next sequential nonce (last_access_nonce + 1) for decryption.
    /// The secret is automatically updated in storage after decryption.
    ///
    /// # Arguments
    /// * `secret_name` - The name of the secret to decrypt
    /// * `session_key` - The session key for decryption
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The decrypted data
    /// * `Err(StatefulDecryptionError)` - Various validation, decryption, or storage errors
    pub fn decrypt_secret_next(
        &self,
        secret_name: &str,
        session_key: &crate::SessionKey,
    ) -> Result<Vec<u8>, StatefulDecryptionError> {
        // 1. Retrieve the current secret
        let secret =
            self.get_secret(secret_name)?
                .ok_or(StatefulDecryptionError::SecretNotFound(
                    secret_name.to_string(),
                ))?;

        // 2. Perform decryption with next sequential nonce
        let (plaintext, updated_secret) = secret.decrypt_next(session_key)?;

        // 3. Save the updated secret back to storage
        self.set_secret_raw(secret_name, updated_secret)?;

        Ok(plaintext)
    }

    /// Decrypt an MFA-protected secret with auto-generated nonce.
    ///
    /// This convenience method combines MFA reconstruction with decryption
    /// using an automatically generated nonce.
    ///
    /// # Arguments
    /// * `secret_name` - The name of the secret to decrypt
    /// * `extra_salts` - Map of MFA source names to their derived salt values
    /// * `tcti` - TPM context interface for accessing the sealed master key
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The decrypted data
    /// * `Err(StatefulDecryptionError)` - Various validation, decryption, or storage errors
    pub fn decrypt_secret_with_mfa_auto(
        &self,
        secret_name: &str,
        extra_salts: &BTreeMap<String, Vec<u8>>,
        tcti: &tss_esapi::Tcti,
    ) -> Result<Vec<u8>, StatefulDecryptionError> {
        // 1. Retrieve the current secret
        let secret =
            self.get_secret(secret_name)?
                .ok_or(StatefulDecryptionError::SecretNotFound(
                    secret_name.to_string(),
                ))?;

        // 2. Reconstruct the session key with MFA
        let sealed_master_key = self
            .get_sealed_master_key()?
            .ok_or(StatefulDecryptionError::MasterKeyNotFound)?;

        let tmp_context = tss_esapi::Context::new(tcti.clone()).map_err(|e| {
            StatefulDecryptionError::TmpError(format!("Failed to create TPM context: {}", e))
        })?;

        let master_key = sealed_master_key.decrypt(tmp_context).map_err(|e| {
            StatefulDecryptionError::TmpDecryptionFailed(format!(
                "Failed to decrypt master key: {}",
                e
            ))
        })?;

        // Build session key with secondary salt and MFA salts
        let mut session_key = crate::SessionKey::new(
            master_key,
            Some(secret.secondary_salt()),
            secret.secondary_salt(),
        );

        // Extract MFA salts in the same order as stored in the secret
        let mfa_salt_values: Vec<Vec<u8>> = secret
            .mfa_sources
            .iter()
            .map(|source| {
                extra_salts
                    .get(source)
                    .ok_or_else(|| StatefulDecryptionError::MfaSaltMissing(source.clone()))
                    .cloned()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Apply MFA salts to session key
        for mfa_salt in &mfa_salt_values {
            session_key = session_key.expand(mfa_salt);
        }

        // 3. Perform decryption with auto-generated nonce
        let (plaintext, updated_secret) = secret.decrypt_auto_nonce(&session_key)?;

        // 4. Save the updated secret back to storage
        self.set_secret_raw(secret_name, updated_secret)?;

        Ok(plaintext)
    }

    /// Decrypt an MFA-protected secret with next sequential nonce.
    ///
    /// This convenience method combines MFA reconstruction with decryption
    /// using the next sequential nonce.
    ///
    /// # Arguments
    /// * `secret_name` - The name of the secret to decrypt
    /// * `extra_salts` - Map of MFA source names to their derived salt values
    /// * `tcti` - TPM context interface for accessing the sealed master key
    ///
    /// # Returns
    /// * `Ok(plaintext)` - The decrypted data
    /// * `Err(StatefulDecryptionError)` - Various validation, decryption, or storage errors
    pub fn decrypt_secret_with_mfa_next(
        &self,
        secret_name: &str,
        extra_salts: &BTreeMap<String, Vec<u8>>,
        tcti: &tss_esapi::Tcti,
    ) -> Result<Vec<u8>, StatefulDecryptionError> {
        // 1. Retrieve the current secret
        let secret =
            self.get_secret(secret_name)?
                .ok_or(StatefulDecryptionError::SecretNotFound(
                    secret_name.to_string(),
                ))?;

        // 2. Reconstruct the session key with MFA
        let sealed_master_key = self
            .get_sealed_master_key()?
            .ok_or(StatefulDecryptionError::MasterKeyNotFound)?;

        let tmp_context = tss_esapi::Context::new(tcti.clone()).map_err(|e| {
            StatefulDecryptionError::TmpError(format!("Failed to create TPM context: {}", e))
        })?;

        let master_key = sealed_master_key.decrypt(tmp_context).map_err(|e| {
            StatefulDecryptionError::TmpDecryptionFailed(format!(
                "Failed to decrypt master key: {}",
                e
            ))
        })?;

        // Build session key with secondary salt and MFA salts
        let mut session_key = crate::SessionKey::new(
            master_key,
            Some(secret.secondary_salt()),
            secret.secondary_salt(),
        );

        // Extract MFA salts in the same order as stored in the secret
        let mfa_salt_values: Vec<Vec<u8>> = secret
            .mfa_sources
            .iter()
            .map(|source| {
                extra_salts
                    .get(source)
                    .ok_or_else(|| StatefulDecryptionError::MfaSaltMissing(source.clone()))
                    .cloned()
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Apply MFA salts to session key
        for mfa_salt in &mfa_salt_values {
            session_key = session_key.expand(mfa_salt);
        }

        // 3. Perform decryption with next sequential nonce
        let (plaintext, updated_secret) = secret.decrypt_next(&session_key)?;

        // 4. Save the updated secret back to storage
        self.set_secret_raw(secret_name, updated_secret)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    #[serial]
    fn test_kv_store() {
        let temp_dir = tempfile::tempdir().unwrap();
        let kv_store = KvStore::new(temp_dir.path().to_path_buf());

        let collection_name = "test_collection".to_string();
        let collection = SecretCollection::new(kv_store.clone(), collection_name.clone());

        let secret_name = "test_secret";
        let ciphertext = vec![1, 2, 3, 4, 5];
        let iv = [0u8; 12];
        let salt = vec![9, 8, 7, 6];
        let secondary_salt = vec![7, 8, 9, 10];
        let mfa_sources = vec![];
        let mfa = false;
        let metadata = crate::secret::SecretMeta::new(None, std::collections::BTreeMap::new());
        let secret_data = Secret::new(
            ciphertext,
            iv,
            salt,
            secondary_salt,
            mfa_sources,
            mfa,
            metadata,
        );

        // Set the secret
        collection
            .set_secret_raw(secret_name, secret_data.clone())
            .unwrap();

        // Get the secret
        let retrieved_secret = collection.get_secret(secret_name).unwrap();
        assert_eq!(retrieved_secret, Some(secret_data));
    }
}
