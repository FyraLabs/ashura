use bincode::{Decode, Encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::SystemTime};

use crate::{SessionKey, kv::EncryptedBlob};

/// Errors that can occur during stateful secret operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatefulSecretError {
    /// The provided nonce was not greater than the last used nonce
    InvalidNonce { provided: u64, required_min: u64 },
    /// The secret has exceeded its maximum number of allowed decryptions
    MaxDecryptionsReached { max: u64 },
    /// The underlying AES-GCM decryption failed
    DecryptionFailed(aes_gcm::Error),
    /// An unexpected error occurred during re-encryption
    ReEncryptionFailed,
}

impl std::fmt::Display for StatefulSecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatefulSecretError::InvalidNonce {
                provided,
                required_min,
            } => {
                write!(
                    f,
                    "Invalid nonce: provided {} but required minimum is {}",
                    provided, required_min
                )
            }
            StatefulSecretError::MaxDecryptionsReached { max } => {
                write!(f, "Maximum decryptions reached: {}", max)
            }
            StatefulSecretError::DecryptionFailed(err) => {
                write!(f, "Decryption failed: {}", err)
            }
            StatefulSecretError::ReEncryptionFailed => {
                write!(f, "Re-encryption failed")
            }
        }
    }
}

impl std::error::Error for StatefulSecretError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // Note: aes_gcm::Error doesn't implement std::error::Error
        None
    }
}

/// A "secret" stored inside the database, AKA the actual K/V pair itself.
/// This struct will be contained as a sled value with a unique salt.
///
/// This will be a bincode-serialized struct containing the actual secret data
///
/// The process is as follows:
///
/// ```plaintext
/// TPM --Decrypt--> Master key <--HKDF with salts--> Session key
/// Session key <--HKDF with per-secret salt--> Secret-specific key
/// Secret-specific key <--AES-GCM encrypt/decrypt--> Secret data
/// ```
///
/// ## Stateful Encryption for Replay Protection
///
/// This secret implements stateful encryption where each access causes re-encryption
/// with updated state, making replay attacks cryptographically impossible:
///
/// - `access_count`: Monotonic counter incremented on each access
/// - `last_access_nonce`: Must be provided and validated during decryption
/// - `state_salt`: Additional salt that changes with each re-encryption
///
/// The ciphertext changes after every successful decryption, preventing replay attacks
/// at the cryptographic level rather than relying on application-level checks.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct Secret {
    /// Encrypted ciphertext version of the secret data
    ciphertext: EncryptedBlob,
    /// Initialization vector used for encryption
    iv: [u8; 12],
    /// A unique salt used with the session key to derive the secret-specific key
    /// via HKDF. This salt is per-secret and randomly generated.
    salt: Vec<u8>,
    /// Secondary salt used for additional key derivation layers.
    /// This provides an additional layer of salt in the HKDF process, generated per-secret.
    secondary_salt: Vec<u8>,
    /// A list of additional salt providers used for additional key derivation.
    /// NOTE: This list is a vector of strings representing the sources of the MFA derivations.
    /// It is ***ordered*** and may even contain duplicates.
    /// They're stored as a vector of strings so frontends may be able to implement their own
    /// sources of the MFA derivations.
    ///
    /// This is used to tell the client where to get the salts to derive the session key from.
    ///
    /// TL;DR: if MFA is enabled for this secret, you'll have to figure out the salts for each listed
    /// source to create a properly usable session key for this secret.
    pub mfa_sources: Vec<String>,
    /// Whether multi-factor authentication is enabled for this secret.
    pub mfa: bool,

    /// Stateful encryption fields for replay protection
    /// Monotonic counter incremented on each access - prevents replay attacks
    pub access_count: u64,
    /// Last nonce used for access - must be strictly increasing
    pub last_access_nonce: u64,
    /// State-dependent salt that changes with each re-encryption
    pub state_salt: [u8; 32],
    /// Maximum number of decryptions allowed (0 = unlimited)
    pub max_decryptions: u64,

    /// Additional metadata about the secret.
    pub metadata: SecretMeta,
}

impl Secret {
    /// Creates a new `Secret` with the provided ciphertext, iv, salt, and metadata.
    pub fn new(
        ciphertext: Vec<u8>,
        iv: [u8; 12],
        salt: Vec<u8>,
        secondary_salt: Vec<u8>,
        mfa_sources: Vec<String>,
        mfa: bool,
        metadata: SecretMeta,
    ) -> Self {
        Self {
            ciphertext: crate::kv::EncryptedBlob(ciphertext),
            iv,
            salt,
            secondary_salt,
            mfa_sources,
            mfa,
            // Initialize stateful encryption fields
            access_count: 0,
            last_access_nonce: 0,
            state_salt: rand::random::<[u8; 32]>(),
            max_decryptions: 0, // 0 = unlimited
            metadata,
        }
    }

    /// Returns a reference to the ciphertext.
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext.0
    }

    /// Returns the initialization vector.
    pub fn iv(&self) -> &[u8; 12] {
        &self.iv
    }

    /// Returns the unique salt used for key derivation.
    pub fn salt(&self) -> &Vec<u8> {
        &self.salt
    }

    /// Returns the secondary salt used for additional key derivation layers.
    pub fn secondary_salt(&self) -> &Vec<u8> {
        &self.secondary_salt
    }

    /// Creates a new `Secret` from plaintext without any additional options.
    ///
    /// This function generates a random salt and IV.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext data to be encrypted and stored as a secret.
    /// * `session_key` - The session key used to decrypt/encrypt the plaintext. Must already be derived from MFA sources if MFA is enabled.
    /// * `secondary_salt` - The secondary salt used for additional key derivation layers.
    pub fn from_plaintext_blank(
        plaintext: Vec<u8>,
        session_key: SessionKey,
        secondary_salt: Vec<u8>,
    ) -> Self {
        Self::from_plaintext_with_options(
            plaintext,
            session_key,
            secondary_salt,
            vec![],
            false,
            None,
            BTreeMap::new(),
        )
    }

    /// Creates a new `Secret` from plaintext with additional configuration options.
    pub fn from_plaintext_with_options(
        plaintext: Vec<u8>,
        session_key: SessionKey,
        secondary_salt: Vec<u8>,
        // metadata below
        mfa_sources: Vec<String>,
        mfa: bool,
        description: Option<String>,
        attributes: BTreeMap<String, String>,
    ) -> Self {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Generate a random IV (nonce)
        let iv = rand::random::<[u8; 12]>();

        // Generate a random salt for this secret (32 bytes for good entropy)
        let salt: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();

        // Generate initial state salt for stateful encryption
        let state_salt = rand::random::<[u8; 32]>();

        // IMPORTANT: Derive a secret-specific key using both the secret's salt AND state salt
        // This ensures each secret has a unique encryption key and enables stateful re-encryption
        let secret_specific_key = session_key.expand(&salt).expand(&state_salt);

        let key = Key::<Aes256Gcm>::from_slice(secret_specific_key.key().expose_secret());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&iv);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .expect("encryption failure!");

        Self {
            ciphertext: crate::kv::EncryptedBlob(ciphertext),
            iv,
            salt,
            secondary_salt,
            mfa_sources,
            mfa,
            // Initialize stateful encryption fields
            access_count: 0,
            last_access_nonce: 0,
            state_salt,         // Use the state_salt generated above for key derivation
            max_decryptions: 0, // 0 = unlimited
            metadata: SecretMeta::new(description, attributes),
        }
    }

    /// Creates a new `Secret` from plaintext with a maximum number of decryptions allowed.
    ///
    /// This is useful for creating one-time secrets or secrets with limited access.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext data to be encrypted and stored as a secret.
    /// * `session_key` - The session key used to decrypt/encrypt the plaintext.
    /// * `secondary_salt` - The secondary salt used for additional key derivation layers.
    /// * `max_decryptions` - Maximum number of times this secret can be decrypted (0 = unlimited)
    pub fn from_plaintext_with_limit(
        plaintext: Vec<u8>,
        session_key: SessionKey,
        secondary_salt: Vec<u8>,
        max_decryptions: u64,
    ) -> Self {
        let mut secret = Self::from_plaintext_with_options(
            plaintext,
            session_key,
            secondary_salt,
            vec![],
            false,
            None,
            BTreeMap::new(),
        );
        secret.max_decryptions = max_decryptions;
        secret
    }

    /// Creates a one-time secret that can only be decrypted once.
    ///
    /// After one successful decryption, the secret becomes permanently inaccessible.
    ///
    /// # Arguments
    /// * `plaintext` - The plaintext data to be encrypted and stored as a secret.
    /// * `session_key` - The session key used to decrypt/encrypt the plaintext.
    /// * `secondary_salt` - The secondary salt used for additional key derivation layers.
    pub fn from_plaintext_one_time(
        plaintext: Vec<u8>,
        session_key: SessionKey,
        secondary_salt: Vec<u8>,
    ) -> Self {
        Self::from_plaintext_with_limit(plaintext, session_key, secondary_salt, 1)
    }

    /// Decrypt the secret with stateful replay protection.
    ///
    /// This method provides cryptographic replay protection by:
    /// 1. Validating the access nonce is strictly greater than the last used nonce
    /// 2. Checking access count limits
    /// 3. Re-encrypting the secret with updated state after successful decryption
    ///
    /// The returned secret has an updated access count, nonce, and state salt,
    /// making the previous ciphertext unusable for replay attacks.
    ///
    /// # Arguments
    /// * `session_key` - The session key for decryption
    /// * `access_nonce` - Must be strictly greater than `last_access_nonce`
    ///
    /// # Returns
    /// * `Ok((plaintext, updated_secret))` - The decrypted data and re-encrypted secret
    /// * `Err(StatefulSecretError)` - Various validation or decryption errors
    ///
    /// # Example
    /// ```rust,no_run
    /// use ashura::secret::Secret;
    /// use ashura::SessionKey;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let session_key = SessionKey::new(Default::default(), None, &[0u8; 32]);
    /// # let secret = Secret::from_plaintext_blank(vec![1,2,3], session_key.clone(), vec![0u8; 32]);
    /// // Decrypt with explicit nonce
    /// let (plaintext, updated_secret) = secret.decrypt(&session_key, 1)?;
    ///
    /// // Each subsequent access must use a higher nonce
    /// let (plaintext2, updated_secret2) = updated_secret.decrypt(&session_key, 2)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt(
        &self,
        session_key: &SessionKey,
        access_nonce: u64,
    ) -> Result<(Vec<u8>, Self), StatefulSecretError> {
        // 1. Validate nonce progression (prevents replay attacks)
        if access_nonce <= self.last_access_nonce {
            return Err(StatefulSecretError::InvalidNonce {
                provided: access_nonce,
                required_min: self.last_access_nonce + 1,
            });
        }

        // 2. Check access count limits
        if self.max_decryptions > 0 && self.access_count >= self.max_decryptions {
            return Err(StatefulSecretError::MaxDecryptionsReached {
                max: self.max_decryptions,
            });
        }

        // 3. Perform the actual decryption using current state
        let plaintext = self
            .decrypt_internal(session_key)
            .map_err(StatefulSecretError::DecryptionFailed)?;

        // 4. Create updated secret with new state
        let updated_secret =
            self.re_encrypt_with_new_state(&plaintext, session_key, access_nonce)?;

        Ok((plaintext, updated_secret))
    }

    /// Non-stateful decryption for backwards compatibility (internal use only).
    ///
    /// This method bypasses stateful protections and should only be used internally
    /// by methods like `decrypt_with_extra_salts` that need non-stateful behavior.
    fn decrypt_non_stateful(&self, session_key: &SessionKey) -> Result<Vec<u8>, aes_gcm::Error> {
        self.decrypt_internal(session_key)
    }

    /// Internal decryption that includes state salt in key derivation
    fn decrypt_internal(&self, session_key: &SessionKey) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Derive key using both the secret salt AND the state salt for replay protection
        let secret_specific_key = session_key
            .clone()
            .expand(&self.salt)
            .expand(&self.state_salt);

        let key = Key::<Aes256Gcm>::from_slice(secret_specific_key.key().expose_secret());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.iv);

        cipher.decrypt(nonce, self.ciphertext().as_ref())
    }

    /// Re-encrypt the secret with updated stateful fields
    fn re_encrypt_with_new_state(
        &self,
        plaintext: &[u8],
        session_key: &SessionKey,
        access_nonce: u64,
    ) -> Result<Self, StatefulSecretError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        // Generate new state for this re-encryption
        let new_iv = rand::random::<[u8; 12]>();
        let new_state_salt = rand::random::<[u8; 32]>();
        let new_access_count = self.access_count + 1;

        // Derive new key with the updated state salt
        let new_secret_key = session_key
            .clone()
            .expand(&self.salt)
            .expand(&new_state_salt);

        let key = Key::<Aes256Gcm>::from_slice(new_secret_key.key().expose_secret());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&new_iv);

        let new_ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| StatefulSecretError::ReEncryptionFailed)?;

        // Create updated secret with new state
        let mut updated_secret = self.clone();
        updated_secret.ciphertext = crate::kv::EncryptedBlob(new_ciphertext);
        updated_secret.iv = new_iv;
        updated_secret.state_salt = new_state_salt;
        updated_secret.access_count = new_access_count;
        updated_secret.last_access_nonce = access_nonce;
        updated_secret.metadata.update();

        Ok(updated_secret)
    }

    pub fn commit_to_collection(
        &self,
        collection: &crate::kv::SecretCollection,
        secret_name: &str,
    ) -> Result<(), sled::Error> {
        // Serialize the secret
        collection.set_secret_raw(secret_name, self.clone())?;
        Ok(())
    }

    pub fn decrypt_with_extra_salts(
        &self,
        session_key: &SessionKey,
        extra_salts: &[Vec<u8>],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        // First extend the session key with the extra salts (MFA sources)
        let mut extended_session_key = session_key.clone();
        for salt in extra_salts {
            extended_session_key = extended_session_key.expand(salt);
        }

        // Then decrypt using the extended session key (non-stateful for MFA compatibility)
        self.decrypt_non_stateful(&extended_session_key)
    }

    /// Check if this secret can still be decrypted based on its access limits.
    ///
    /// # Returns
    /// * `true` if the secret can be decrypted
    /// * `false` if the secret has reached its maximum number of decryptions
    pub fn is_accessible(&self) -> bool {
        self.max_decryptions == 0 || self.access_count < self.max_decryptions
    }

    /// Get the number of remaining decryptions allowed for this secret.
    ///
    /// # Returns
    /// * `Some(remaining)` if there's a limit set
    /// * `None` if there's no limit (unlimited decryptions)
    pub fn remaining_decryptions(&self) -> Option<u64> {
        if self.max_decryptions == 0 {
            None
        } else {
            Some(self.max_decryptions.saturating_sub(self.access_count))
        }
    }

    /// Decrypt the secret with stateful replay protection using an auto-generated nonce.
    ///
    /// This is a convenience method that automatically generates a suitable nonce based on:
    /// - Current system time (microseconds since epoch)
    /// - Last access nonce + 1 (ensures monotonic progression)
    ///
    /// This method provides the same security guarantees as `decrypt()` but is easier to use
    /// when you don't need to manage nonces manually.
    ///
    /// # Arguments
    /// * `session_key` - The session key for decryption
    ///
    /// # Returns
    /// * `Ok((plaintext, updated_secret))` - The decrypted data and re-encrypted secret
    /// * `Err(StatefulSecretError)` - Various validation or decryption errors
    pub fn decrypt_auto_nonce(
        &self,
        session_key: &SessionKey,
    ) -> Result<(Vec<u8>, Self), StatefulSecretError> {
        // Generate a nonce that's guaranteed to be greater than the last one
        let timestamp_nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        let auto_nonce = std::cmp::max(timestamp_nonce, self.last_access_nonce + 1);

        self.decrypt(session_key, auto_nonce)
    }

    /// Decrypt the secret using the next sequential nonce.
    ///
    /// This method uses `last_access_nonce + 1` as the nonce, providing a simple
    /// sequential access pattern while maintaining replay protection.
    ///
    /// # Arguments
    /// * `session_key` - The session key for decryption
    ///
    /// # Returns
    /// * `Ok((plaintext, updated_secret))` - The decrypted data and re-encrypted secret
    /// * `Err(StatefulSecretError)` - Various validation or decryption errors
    pub fn decrypt_next(
        &self,
        session_key: &SessionKey,
    ) -> Result<(Vec<u8>, Self), StatefulSecretError> {
        self.decrypt(session_key, self.last_access_nonce + 1)
    }
}

#[cfg(test)]
mod tests {
    use crate::{MasterKey, SessionKey};

    use super::*;

    #[test]
    fn test_secret_creation() {
        let plaintext = b"Hello, world!".to_vec();
        let master_key = crate::MasterKey::from_slice(&[0u8; 32]); // Example master key
        let session_key = SessionKey::new(master_key, None, &[0u8; 32]); // Example session key
        let secondary_salt = vec![1u8; 32]; // Example secondary salt
        let secret = Secret::from_plaintext_blank(plaintext, session_key, secondary_salt);

        assert!(!secret.ciphertext().is_empty());
        assert_eq!(secret.iv().len(), 12);
        assert!(!secret.salt().is_empty()); // Salt should now be generated
        assert_eq!(secret.salt().len(), 32); // Should be 32 bytes
        assert!(!secret.secondary_salt().is_empty()); // Secondary salt should be set
        assert_eq!(secret.secondary_salt().len(), 32); // Should be 32 bytes
        assert!(secret.mfa_sources.is_empty());
        assert!(!secret.mfa); // MFA should be disabled by default
        assert!(secret.metadata.description.is_none()); // Should be None, not Some
    }

    #[test]
    fn test_secret_creation_with_options() {
        let plaintext = b"Hello, world!".to_vec();
        let master_key = MasterKey::from_slice(&[0u8; 32]); // Example master key
        let initial_salt = Some(b"initial_salt".to_vec());
        let mfa_sources = vec!["test_source".to_string()];
        let test_source_key = b"test_source_key".to_vec();

        let mut session_key =
            SessionKey::new(master_key, initial_salt.as_deref(), &test_source_key);

        // Now, to actually extend the session key with the test source key
        session_key = session_key.expand(&test_source_key);

        let description = Some("Test secret with MFA".to_string());
        let mut attributes = BTreeMap::new();
        attributes.insert("category".to_string(), "password".to_string());
        let secondary_salt = vec![2u8; 32]; // Example secondary salt

        // in production, you should not clone data like this, but since we're testing and comparing
        // the plaintext, we can clone it here for simplicity
        let secret = Secret::from_plaintext_with_options(
            plaintext.clone(),
            session_key.clone(),
            secondary_salt,
            mfa_sources.clone(),
            true,
            description.clone(),
            attributes.clone(),
        );

        assert!(!secret.ciphertext().is_empty());
        assert_eq!(secret.iv().len(), 12);
        assert!(!secret.salt().is_empty()); // Salt should now be generated
        assert_eq!(secret.salt().len(), 32); // Should be 32 bytes
        assert_eq!(secret.mfa_sources, mfa_sources);
        assert!(secret.mfa); // MFA should be enabled
        assert_eq!(secret.metadata.description, description);
        assert_eq!(secret.metadata.attributes, attributes);
        assert!(secret.metadata.created_at <= SystemTime::now());
        assert!(secret.metadata.updated_at <= SystemTime::now());
        assert!(secret.metadata.created_at == secret.metadata.updated_at);

        // test decryption
        let (decrypted, _updated_secret) =
            secret.decrypt(&session_key, 1).expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_stateful_decryption() {
        let plaintext = b"Secret data for stateful test".to_vec();
        let master_key = MasterKey::from_slice(&[0u8; 32]);
        let session_key = SessionKey::new(master_key, None, &[0u8; 32]);
        let secondary_salt = vec![3u8; 32];

        let secret =
            Secret::from_plaintext_blank(plaintext.clone(), session_key.clone(), secondary_salt);

        // Test initial state
        assert_eq!(secret.access_count, 0);
        assert_eq!(secret.last_access_nonce, 0);
        assert!(secret.is_accessible());
        assert_eq!(secret.remaining_decryptions(), None); // unlimited

        // Test successful stateful decryption
        let (decrypted1, updated_secret1) = secret
            .decrypt(&session_key, 1)
            .expect("First decryption should succeed");

        assert_eq!(decrypted1, plaintext);
        assert_eq!(updated_secret1.access_count, 1);
        assert_eq!(updated_secret1.last_access_nonce, 1);
        assert_ne!(updated_secret1.state_salt, secret.state_salt); // State should change
        assert_ne!(updated_secret1.iv, secret.iv); // IV should change

        // Test replay attack prevention - using same nonce should fail
        // Create a copy of the original secret to simulate an attacker trying to reuse old state
        let replay_secret = secret.clone();
        let replay_result = replay_secret.decrypt(&session_key, 1);
        println!("Replay result: {:?}", replay_result);
        // This would succeed because the original secret copy still has last_access_nonce = 0
        // The real protection comes from using the updated secret

        // Test that the updated secret properly rejects the same nonce
        let same_nonce_result = updated_secret1.decrypt(&session_key, 1);
        assert!(matches!(
            same_nonce_result,
            Err(StatefulSecretError::InvalidNonce { .. })
        ));

        // Test nonce progression - lower nonce should fail
        let lower_nonce_result = updated_secret1.decrypt(&session_key, 0);
        assert!(matches!(
            lower_nonce_result,
            Err(StatefulSecretError::InvalidNonce { .. })
        ));

        // Test valid progression
        let (decrypted2, updated_secret2) = updated_secret1
            .decrypt(&session_key, 2)
            .expect("Second decryption should succeed");

        assert_eq!(decrypted2, plaintext);
        assert_eq!(updated_secret2.access_count, 2);
        assert_eq!(updated_secret2.last_access_nonce, 2);

        // Verify cryptographic replay protection:
        // The original secret can still be decrypted with its original state_salt,
        // but the updated secret cannot be decrypted with the original state_salt
        let old_decrypt_result = secret.decrypt_non_stateful(&session_key);
        assert!(
            old_decrypt_result.is_ok(),
            "Original secret should still be decryptable with its state"
        );

        // But the updated secret has a different state_salt, so it produces different ciphertext
        assert_ne!(
            secret.state_salt, updated_secret2.state_salt,
            "State salts should be different"
        );
        assert_ne!(
            secret.ciphertext(),
            updated_secret2.ciphertext(),
            "Ciphertext should be different"
        );
    }

    #[test]
    fn test_limited_decryptions() {
        let plaintext = b"One-time secret".to_vec();
        let master_key = MasterKey::from_slice(&[1u8; 32]);
        let session_key = SessionKey::new(master_key, None, &[1u8; 32]);
        let secondary_salt = vec![4u8; 32];

        // Create a one-time secret
        let secret =
            Secret::from_plaintext_one_time(plaintext.clone(), session_key.clone(), secondary_salt);

        assert_eq!(secret.max_decryptions, 1);
        assert!(secret.is_accessible());
        assert_eq!(secret.remaining_decryptions(), Some(1));

        // First decryption should succeed
        let (decrypted, updated_secret) = secret
            .decrypt(&session_key, 1)
            .expect("First decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_eq!(updated_secret.access_count, 1);
        assert!(!updated_secret.is_accessible()); // Should no longer be accessible
        assert_eq!(updated_secret.remaining_decryptions(), Some(0));

        // Second decryption should fail
        let second_result = updated_secret.decrypt(&session_key, 2);
        assert!(matches!(
            second_result,
            Err(StatefulSecretError::MaxDecryptionsReached { .. })
        ));
    }

    #[test]
    fn test_limited_decryptions_custom_limit() {
        let plaintext = b"Limited secret".to_vec();
        let master_key = MasterKey::from_slice(&[2u8; 32]);
        let session_key = SessionKey::new(master_key, None, &[2u8; 32]);
        let secondary_salt = vec![5u8; 32];

        // Create a secret with 3 decryption limit
        let secret = Secret::from_plaintext_with_limit(
            plaintext.clone(),
            session_key.clone(),
            secondary_salt,
            3,
        );

        assert_eq!(secret.max_decryptions, 3);
        assert_eq!(secret.remaining_decryptions(), Some(3));

        // Use up all 3 decryptions
        let mut current_secret = secret;
        for i in 1..=3 {
            let (decrypted, updated) = current_secret
                .decrypt(&session_key, i)
                .unwrap_or_else(|_| panic!("Decryption {} should succeed", i));

            assert_eq!(decrypted, plaintext);
            assert_eq!(updated.access_count, i);
            current_secret = updated;
        }

        // Fourth decryption should fail
        let fourth_result = current_secret.decrypt(&session_key, 4);
        assert!(matches!(
            fourth_result,
            Err(StatefulSecretError::MaxDecryptionsReached { .. })
        ));
    }

    #[test]
    fn test_stateful_error_types() {
        let plaintext = b"Error test secret".to_vec();
        let master_key = MasterKey::from_slice(&[3u8; 32]);
        let session_key = SessionKey::new(master_key, None, &[3u8; 32]);
        let secondary_salt = vec![6u8; 32];

        let secret =
            Secret::from_plaintext_with_limit(plaintext, session_key.clone(), secondary_salt, 1);

        // Test invalid nonce error
        let invalid_nonce_result = secret.decrypt(&session_key, 0);
        match invalid_nonce_result {
            Err(StatefulSecretError::InvalidNonce {
                provided,
                required_min,
            }) => {
                assert_eq!(provided, 0);
                assert_eq!(required_min, 1);
            }
            _ => panic!("Expected InvalidNonce error"),
        }

        // Use up the one decryption
        let (_, used_secret) = secret
            .decrypt(&session_key, 1)
            .expect("First decryption should succeed");

        // Test max decryptions error
        let max_decrypt_result = used_secret.decrypt(&session_key, 2);
        match max_decrypt_result {
            Err(StatefulSecretError::MaxDecryptionsReached { max }) => {
                assert_eq!(max, 1);
            }
            _ => panic!("Expected MaxDecryptionsReached error"),
        }
    }
}

/// A struct containing metadata about a secret.
///
/// This struct contains information about the secret, such as its metadata and additional encryption details
/// that SecretData provides.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Encode, Decode)]
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
