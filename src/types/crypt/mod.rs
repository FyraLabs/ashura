//! Cryptography module for ashura
//! 
//! This module provides traits and implementations for cryptographic operations used in ashura.
//! 
//! Includes stuff like backends for keyslots, and how to properly encrypt/decrypt data with them
use serde::{Deserialize, Serialize};
pub mod tpm2;


/// Ciphertext structure to hold encrypted data along with optional IV and nonce
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ciphertext {
    pub data: Vec<u8>,
    pub iv: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

// todo
pub trait CryptBackend {
}
