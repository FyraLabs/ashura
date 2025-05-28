use aes_gcm::{Aes256Gcm, aead::KeyInit};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretSlice};
use tss_esapi::Context as TpmContext;
use zeroize::Zeroize;

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
/// In TPM terms, this is considered the Content Encryption Key (CEK).
pub struct MasterKey {
    key: SecretSlice<u8>,
}

impl MasterKey {
    pub fn generate(tpm_context: TpmContext) -> Self {
        // TODO: implement TpmRng
        let mut tpm2_rng = tpm2_rand::TpmRand::new(tpm_context);
        let mut ephemeral_key = Aes256Gcm::generate_key(&mut tpm2_rng);
        let key_vec = ephemeral_key.as_slice().to_vec();
        ephemeral_key.as_mut_slice().zeroize();
        Self {
            key: SecretSlice::new(key_vec.into()),
        }
    }

    pub fn key(&self) -> &SecretSlice<u8> {
        &self.key
    }

    pub fn unseal_from_ciphertxt(ciphertxt: &[u8], tpm_context: crate::tpm::TpmManagerHandle) -> Self {
        todo!("Implement unsealing logic")
    }

    pub fn seal_to_ciphertext(&self, tpm_context: crate::tpm::TpmManagerHandle) -> Vec<u8> {
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
