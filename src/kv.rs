//! Module for handling key-value store operations.
//!
//! This module manages the actual on-disk kv store using sled.

use bincode::{self, Decode, Encode};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::error;

// The kv path is defined in this format, delimited by a slash
// `<collection_name>/secret/<secret_name>`
// Each secret is stored in a collection prefix, then the secret label itself.
// There's also additional data for the collection itself, which will have these paths:
// `<collection_name>/sealed_master_key`
// ... for TPM-sealed master keys

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone, Default)]
pub enum AesSymmetricMode {
    #[default]
    Cbc,
    Ctr,
    Ofb,
    Cfb,
    Ecb,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub enum TpmEncryptionType {
    /// An AES-128 CFB encryption type (default)
    Aes128Cfb {
        iv: Vec<u8>,
        symmetric_mode: AesSymmetricMode,
    },
    /// RSA 2048-bit encryption type
    Rsa2048,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub struct SealedMasterKey {
    pub crypted_type: TpmEncryptionType,
    pub public_key: Vec<u8>,
    pub private_key_blob: Vec<u8>,
}

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
#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
/// A struct representing a serialized blob of data.
pub struct EncryptedBlob(pub Vec<u8>);

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

    pub fn get_secret(&self, secret_name: &str) -> Result<Option<EncryptedBlob>, sled::Error> {
        let db = self.kv_store.db.lock().unwrap();
        match db.get(self.secret_collection_path(secret_name))? {
            Some(value) => {
                let (blob, _): (EncryptedBlob, usize) =
                    bincode::decode_from_slice(&value, bincode::config::standard())
                        .expect("Failed to deserialize SerializedBlob");
                Ok(Some(blob))
            }
            None => Ok(None),
        }
    }
}
