//! # Ashura: TPM-Backed Secret Storage Library
//!
//! Ashura is a Rust secrets management library designed to securely store sensitive data using hardware-backed keys.
//! It leverages the Trusted Platform Module (TPM) for master key generation and sealing,
//! ensuring that secrets are protected against unauthorized access and tampering.
//! Ashura supports multi-factor authentication (MFA) for session keys, providing an additional layer of security.
//!
//! ## Features
//!
//! - **TPM-Backed Security**: Hardware-enforced master key generation and sealing
//! - **Multi-Factor Authentication**: Extensible session keys with MFA support
//! - **Per-Secret Isolation**: Each secret gets its own derived encryption key
//! - **Persistent Storage**: Encrypted data storage using the Sled database
//! - **Modern Cryptography**: AES-GCM encryption with HKDF key derivation
//! - **Zero-Copy Secrets**: Memory-safe secret handling with the `secrecy` crate
//!
//! ## Architecture Overview
//!
//! Ashura implements a layered security architecture with multiple key derivation stages:
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │   TPM Hardware  │───▶│   Master Key     │───▶│  Session Key    │
//! │   (True RNG)    │    │  (TPM-Sealed)    │    │ (Base + Salt)   │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//!                                                          │
//!                        ┌─────────────────────────────────┘
//!                        ▼
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │  Secret-Specific│◀───│ Extended Session │◀───│   MFA Factors   │
//! │      Key        │    │      Key         │    │ (Optional HKDF) │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │   AES-GCM       │
//! │  Encryption     │
//! └─────────────────┘
//! ```
//!
//! ### Key Derivation Flow
//!
//! 1. **TPM Master Key**: Generated using TPM's hardware RNG and sealed to the TPM chip
//! 2. **Session Key**: Derived from master key + secondary salt using HKDF
//! 3. **MFA Extension**: Optional HKDF expansion with multi-factor authentication salts
//! 4. **Secret Key**: Final HKDF derivation with per-secret salt for isolation
//! 5. **AES-GCM**: Authenticated encryption of the actual secret data
//!
//! ## Quick Start
//!
//! ### Basic Secret Storage
//!
//! ```rust,no_run
//! use ashura::{MasterKey, SessionKey, Secret};
//! use ashura::kv::{KvStore, SecretCollection};
//! use tss_esapi::Tcti;
//! use std::collections::BTreeMap;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Set up TPM connection
//! let tcti = Tcti::from_environment_variable()
//!     .unwrap_or_else(|_| Tcti::Device(Default::default()));
//!
//! // Create storage and secret collection
//! let kv_store = KvStore::new("./secrets".into());
//! let collection = SecretCollection::new_init(
//!     kv_store,
//!     "my_secrets",
//!     &tcti
//! )?;
//!
//! // Create and store a secret directly using the collection
//! let plaintext = b"My secret data".to_vec();
//! let empty_salts = std::collections::BTreeMap::new(); // No MFA for basic example
//! let secret = collection.new_secret_for_collection(
//!     "my_secret",
//!     plaintext,
//!     empty_salts,
//!     &tcti
//! )?;
//!
//! // Retrieve the secret from collection
//! let retrieved = collection.get_secret("my_secret")?.unwrap();
//!
//! // For decryption, we need to reconstruct the session key
//! let sealed_master = collection.get_sealed_master_key()?.unwrap();
//! let context = tss_esapi::Context::new(tcti)?;
//! let master_key = sealed_master.decrypt(context)?;
//! let session_key = SessionKey::new(master_key, Some(retrieved.secondary_salt()), retrieved.secondary_salt());
//!
//! // Decrypt the secret using auto-nonce for convenience
//! let (decrypted, _updated_secret) = retrieved.decrypt_auto_nonce(&session_key)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Multi-Factor Authentication
//!
//! ```rust,no_run
//! use ashura::kv::{KvStore, SecretCollection};
//! use ashura::SessionKey;
//! use sha2::{Sha256, Digest};
//! use std::collections::BTreeMap;
//! use tss_esapi::Tcti;
//!
//! # fn mfa_example() -> Result<(), Box<dyn std::error::Error>> {
//! # let tcti = Tcti::Device(Default::default());
//! # let kv_store = KvStore::new("./secrets".into());
//! # let collection = SecretCollection::new_init(kv_store, "my_secrets", &tcti)?;
//! // Collect MFA inputs (in practice, these come from user authentication)
//! let password_hash = Sha256::digest(b"user_password_123").to_vec();
//! let pin_hash = Sha256::digest(b"1234").to_vec();
//! let device_key = Sha256::digest(b"device_identifier").to_vec();
//!
//! // Create MFA salts map
//! let mut mfa_salts = BTreeMap::new();
//! mfa_salts.insert("password".to_string(), password_hash.clone());
//! mfa_salts.insert("pin".to_string(), pin_hash.clone());
//! mfa_salts.insert("device".to_string(), device_key.clone());
//!
//! // Create MFA-protected secret using the collection method
//! let secret = collection.new_secret_for_collection(
//!     "mfa_secret",
//!     b"Highly sensitive data".to_vec(),
//!     mfa_salts.clone(),
//!     &tcti
//! )?;
//!
//! // Retrieve the secret
//! let retrieved = collection.get_secret("mfa_secret")?.unwrap();
//!
//! // Decrypt using the collection's MFA method (handles session key reconstruction automatically)
//! let decrypted = collection.decrypt_secret_with_mfa_auto("mfa_secret", &mfa_salts, &tcti)?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Model
//!
//! Ashura's security model is built around the principles of hardware-backed key management and multi-factor authentication. The master key is generated and sealed by the TPM, ensuring that it cannot be extracted or misused outside of the TPM environment. Session keys are derived from the master key with additional salts, requiring each secret to have its own unique key.
//! The keys are also re-generated every time a secret changes, ensuring that even if a session key is compromised, it only affects that specific secret until the next change.
//!
//! There are multiple layers of encryption to access a single secret, ensuring that even if one layer
//! is compromised, the final data may still remain secure.
//!
//! ### Layers
//! - Master Key: The root key sealed by the TPM, used to derive session keys, can be either in AES-128-CFB or RSA format depending on the TPM capabilities.
//! - Secret-specific Keys: Uses 2 HKDF stages to derive a unique key for each secret, ensuring isolation and security.
//! - Optionally, Multi-Factor Authentication (MFA) can be used to further secure session keys, requiring multiple inputs to derive the final key.
//!
//! Even if an attacker somehow manages to access the master key, they would still need to also find the keys specific to each
//! secret, and if MFA is used, they would also need to provide the correct MFA inputs *in perfect order* to decrypt the secret.
//!
//! If the session key is compromised, the attacker would only be able to access that one specific secret associated with that session key,
//! and not any other secrets in the system.
//!
//! ...Still vulnerable from [xkcd #538](https://xkcd.com/538/) though, but at that point you might as well hire bodyguards.
//!
//! ## Requirements
//! - A TPM 2.0 compliant device, optionally with AES-128-CFB support
//! - Rust 1.85.0 or later
//! - `tpm2-tss` library for TPM operations
//!

pub mod crypt;
pub mod kv;
pub mod secret;
pub mod tpm;

pub use crypt::{MasterKey, SessionKey};
pub use secret::{Secret, SecretMeta};
