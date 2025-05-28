//! Module for handling key-value store operations.
//!
//! This module manages the actual on-disk kv store using sled.

use sled::Db;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::error;

// The kv path is defined in this format, delimited by a slash
// `<collection_name>/secret/<secret_name>`
// Each secret is stored in a collection prefix, then the secret label itself.

// There's also additional data for the collection itself, which will have these paths:
// `<collection_name>/master_key/rsa_pub`
// `<collection_name>/master_key/rsa_priv`
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

pub struct SerializedBlob {
    pub data: Vec<u8>,
}

/// A collection of secrets stored in the key-value store.
///
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
    
}


