// use log::{debug, error, info, warn};
// use std::cell::RefCell; // Unused
use bincode::Decode;
use bincode::Encode;
use secrecy::ExposeSecret;
use serde::Deserialize;
use serde::Serialize;
use std::convert::TryFrom;
use tracing::trace;
use tracing::{debug, error, info, instrument};
use tss_esapi::traits::UnMarshall;
// TryInto is unused
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::AlgorithmIdentifier;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::CapabilityData;
use tss_esapi::structures::RsaDecryptionScheme; // Keep for rsa_encrypt/decrypt
use tss_esapi::structures::{
    CreateKeyResult,
    Digest,
    InitialValue,
    MaxBuffer,
    Private,
    Public,
    PublicBuilder,
    SymmetricCipherParameters,
    SymmetricDefinitionObject, // SensitiveData is unused
};
use tss_esapi::traits::Marshall;
use tss_esapi::{Context, tcti_ldr::TabrmdConfig};

use crate::MasterKey; // Keep Context import

pub fn default_tcti_handle() -> tss_esapi::TctiNameConf {
    tss_esapi::TctiNameConf::from_environment_variable()
        .unwrap_or(tss_esapi::TctiNameConf::Tabrmd(TabrmdConfig::default()))
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub struct SealedMasterKey {
    pub crypted_type: TpmEncryptionMeta,
    pub key_seal: KeySeal,
    pub encrypted_key: Vec<u8>,
}

impl SealedMasterKey {
    /// Creates a new `SealedMasterKey` with the given encryption metadata and key seal.
    pub fn new(crypted_type: TpmEncryptionMeta, key_seal: KeySeal, encrypted_key: Vec<u8>) -> Self {
        Self {
            crypted_type,
            key_seal,
            encrypted_key,
        }
    }

    pub fn decrypt(&self, tpm_context: Context) -> Result<MasterKey, tss_esapi::Error> {
        // Decrypt the sealed master key using the TPM context
        match &self.key_seal {
            KeySeal::Blobs {
                public_key,
                private_key_blob,
            } => {
                let mut manager = TpmManagerHandle::new_with_primary_auto(tpm_context)?;

                // Load the pub and priv keys
                let public = Public::unmarshall(public_key)?;
                let private = Private::try_from(private_key_blob.as_slice()).map_err(|_| {
                    tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
                })?;
                manager.load_key(public, private).and_then(|_key_handle| {
                    // Decrypt the master key using the loaded key
                    let decrypted = manager.decrypt(&self.encrypted_key, &self.crypted_type)?;
                    Ok(MasterKey::from_slice(decrypted.as_slice()))
                })
            }

            KeySeal::TpmAddress { address } => {
                let mut manager = TpmManagerHandle::new_without_primary(tpm_context);
                // Create a TpmObjectHandle from the address
                let _ = manager.load_key_from_persistent_address(*address);
                // Decrypt the master key using the loaded key
                let decrypted = manager.decrypt(&self.encrypted_key, &self.crypted_type)?;
                Ok(MasterKey::from_slice(decrypted.as_slice()))
            }
        }
    }

    pub fn encrypt(
        master_key: MasterKey,
        tpm_context: Context,
        persistent_address: Option<u32>,
    ) -> Result<Self, tss_esapi::Error> {
        // Encrypt the master key using the TPM context
        let mut manager = TpmManagerHandle::new_with_primary_auto(tpm_context)?;

        // Generate a new key pair for sealing
        let (_key_handle, public, private) = manager.generate_keypair_auto()?;

        // Encrypt the master key using the generated key
        let (encrypted_key, crypted_type) = manager.encrypt(master_key.key().expose_secret())?;

        // Determine the key seal type based on whether a persistent address is provided
        let key_seal = if let Some(address) = persistent_address {
            KeySeal::TpmAddress { address }
        } else {
            KeySeal::Blobs {
                public_key: public.marshall()?,
                private_key_blob: private.value().to_vec(),
            }
        };

        Ok(SealedMasterKey::new(crypted_type, key_seal, encrypted_key))
    }
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub enum TpmEncryptionMeta {
    /// An AES-128 CFB encryption type (default)
    Aes128Cfb { iv: Vec<u8> },
    /// RSA 2048-bit encryption type
    Rsa2048,
}

/// Scheme of the key store, either Public/Private blobs
/// or referenced an address directly
#[derive(Serialize, Deserialize, Encode, Decode, Debug, Clone)]
pub enum KeySeal {
    Blobs {
        public_key: Vec<u8>,
        private_key_blob: Vec<u8>,
    },
    TpmAddress {
        address: u32,
    },
}

/// Represents a loaded TPM object (e.g., a key or primary object).
#[derive(Clone, Debug)]
pub struct TpmObjectHandle {
    handle: ObjectHandle,
}

impl TpmObjectHandle {
    /// Creates a new `TpmObjectHandle` with the given handle.
    pub fn new(handle: ObjectHandle /*, ctx: *mut tss_esapi::Context */) -> Self {
        Self { handle, /*, ctx */ }
    }

    /// Returns the underlying TPM object handle.
    pub fn handle(&self) -> ObjectHandle {
        self.handle
    }
}

pub struct TpmManagerHandle {
    ctx: Context, // Assuming Context is directly held
    primary_handle: Option<KeyHandle>,
    current_child_key_handle: Option<KeyHandle>, // Renamed from current_aes_handle
}

// impl Drop for TpmManagerHandle {
//     fn drop(&mut self) {
//         // Flush the primary handle when the TpmManagerHandle is dropped
//         self.ctx
//             .clear(ObjectHandle::from(self.primary_handle.value()).into())
//             .unwrap_or_else(|e| {
//                 error!(error = %e, "Failed to flush primary handle on drop");
//             });
//         if let Some(child_handle) = &self.current_child_key_handle {
//             // Renamed variable
//             // Flush the current child key handle if it exists

//             self.ctx
//                 .execute_with_nullauth_session(|ctx| {
//                     ctx.clear(ObjectHandle::from(child_handle.value()).into())
//                 })
//                 .unwrap_or_else(|e| {
//                     error!(error = %e, "Failed to flush current child key handle on drop");
//                 });
//         }

//         self.ctx.clear_sessions();
//     }
// }

#[inline]
/// Helper to enumerate a [`PublicAlgorithm`] from a [`Public`] key
pub fn get_public_algo(public: Public) -> PublicAlgorithm {
    match public {
        Public::SymCipher { .. } => PublicAlgorithm::SymCipher,
        Public::Rsa { .. } => PublicAlgorithm::Rsa,
        Public::Ecc { .. } => PublicAlgorithm::Ecc,
        Public::KeyedHash { .. } => PublicAlgorithm::KeyedHash,
    }
}

pub fn is_aes_supported(ctx: &mut Context) -> Result<bool, tss_esapi::Error> {
    // Check if our specific AES scheme (AES_128_CFB) is supported
    // Useful for our helper function to negotiate the way to seal the CEK

    let (data, _) = ctx.get_capability(
        tss_esapi::constants::CapabilityType::Algorithms,
        0,  // No specific property
        50, // We only need to check one property
    )?;

    // inspect the enum we get

    if let CapabilityData::Algorithms(algorithms) = data {
        // Check if AES_128_CFB is in the list of supported algorithms
        // AlgorithmPropertyList is a Vec<AlgorithmProperty> of maps
        // Check if AES and CFB are supported algorithms
        let aes_supported = algorithms
            .iter()
            .any(|algo| algo.algorithm_identifier() == AlgorithmIdentifier::Aes);
        let cfb_supported = algorithms
            .iter()
            .any(|algo| algo.algorithm_identifier() == AlgorithmIdentifier::Cfb);

        if aes_supported && cfb_supported {
            Ok(true)
        } else {
            Ok(false)
        }
    } else {
        error!("Unexpected capability data type: {:?}", data);
        Err(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::UnsupportedParam,
        ))
    }
}

impl TpmManagerHandle {
    /// Creates a new `TpmManagerHandle` with the given context and primary handle.
    pub fn new(ctx: Context, primary_handle: KeyHandle) -> Self {
        Self {
            ctx,
            primary_handle: Some(primary_handle),
            current_child_key_handle: None, // Renamed and initialized
        }
    }

    /// Creates a new `TmpManagerHandle` with only context for working with persistent keys
    pub fn new_without_primary(ctx: Context) -> Self {
        Self {
            ctx,
            primary_handle: None,
            current_child_key_handle: None,
        }
    }

    /// Automatically creates a primary key (AES if supported, otherwise RSA) and returns a new TpmManagerHandle.
    pub fn new_with_primary_auto(mut ctx: Context) -> Result<Self, tss_esapi::Error> {
        match is_aes_supported(&mut ctx) {
            Ok(true) => {
                info!("Creating AES primary key in TPM");
                TpmManagerHandle::create_with_aes_primary(ctx)
            }
            _ => {
                info!("Creating RSA primary key in TPM");
                TpmManagerHandle::create_with_rsa_primary(ctx, 2048)
            }
        }
    }

    pub fn generate_keypair_auto(
        &mut self,
    ) -> Result<
        (
            KeyHandle,
            tss_esapi::structures::Public,
            tss_esapi::structures::Private,
        ),
        tss_esapi::Error,
    > {
        // Require a primary key for generating child keys
        let primary = self.primary_handle.ok_or_else(|| {
            error!("No primary key available for child key generation");
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::ParamsMissing)
        })?;

        // Automatically determine the public algorithm based on the primary key
        let public_algorithm = self.get_key_type(primary)?;
        match public_algorithm {
            PublicAlgorithm::Rsa => {
                debug!("Generating RSA key pair under primary handle");
                self.generate_rsa_child_key_pair(2048)
            }
            PublicAlgorithm::SymCipher => {
                debug!("Generating AES key pair under primary handle");
                self.generate_aes_child_key(
                    tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
                    tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
                )
            }
            _ => {
                error!(
                    "Unsupported public algorithm for key generation: {:?}",
                    public_algorithm
                );
                Err(tss_esapi::Error::WrapperError(
                    tss_esapi::WrapperErrorKind::UnsupportedParam,
                ))
            }
        }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, TpmEncryptionMeta), tss_esapi::Error> {
        // Determine which key to use for encryption - prefer child key if available
        let key_handle = match self.current_child_key_handle() {
            Some(child_handle) => *child_handle,
            None => match self.primary_handle {
                Some(primary) => primary,
                None => {
                    error!(
                        "No key available for encryption - neither primary nor child key loaded"
                    );
                    return Err(tss_esapi::Error::WrapperError(
                        tss_esapi::WrapperErrorKind::ParamsMissing,
                    ));
                }
            },
        };

        // Automatically determine the public algorithm based on the key
        let public_algorithm = self.get_key_type(key_handle)?;
        match public_algorithm {
            PublicAlgorithm::Rsa => {
                debug!("Encrypting data using RSA key");
                let ciphertext = self.rsa_encrypt(plaintext)?;
                Ok((ciphertext, TpmEncryptionMeta::Rsa2048))
            }
            PublicAlgorithm::SymCipher => {
                debug!("Encrypting data using AES key");
                let (ciphertext, iv) = self.aes_encrypt(
                    plaintext,
                    tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
                )?;
                Ok((
                    ciphertext,
                    TpmEncryptionMeta::Aes128Cfb {
                        iv: iv.value().to_vec(),
                    },
                ))
            }
            _ => {
                error!(
                    "Unsupported public algorithm for encryption: {:?}",
                    public_algorithm
                );
                Err(tss_esapi::Error::WrapperError(
                    tss_esapi::WrapperErrorKind::UnsupportedParam,
                ))
            }
        }
    }

    pub fn decrypt(
        &mut self,
        ciphertext: &[u8],
        meta: &TpmEncryptionMeta,
    ) -> Result<Vec<u8>, tss_esapi::Error> {
        match meta {
            TpmEncryptionMeta::Rsa2048 => {
                debug!("Decrypting data using RSA key");
                self.rsa_decrypt(ciphertext)
            }
            TpmEncryptionMeta::Aes128Cfb { iv } => {
                debug!("Decrypting data using AES key with IV: {:?}", iv);
                let iv_value = InitialValue::try_from(iv.clone()).map_err(|_| {
                    tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
                })?;
                self.aes_decrypt(
                    ciphertext,
                    iv_value,
                    tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
                )
            }
        }
    }

    /// Returns a reference to the primary TPM object handle if available.
    pub fn primary_handle(&self) -> Option<&KeyHandle> {
        self.primary_handle.as_ref()
    }

    /// Sets the child key handle, replacing any existing one.
    pub fn set_child_key_handle(&mut self, handle: KeyHandle) {
        // Renamed method
        self.current_child_key_handle = Some(handle); // Renamed field
    }

    /// Returns a reference to the currently loaded child key handle, if present.
    pub fn current_child_key_handle(&self) -> Option<&KeyHandle> {
        // Renamed method
        self.current_child_key_handle.as_ref() // Renamed field
    }

    /// Generate RSA key pair in the TPM and store it in the context.
    /// Returns the TPM object handle and the public/private blobs.
    #[instrument(level = "debug", skip(self))]
    pub fn generate_rsa_child_key_pair(
        &mut self,
        key_size: u16,
    ) -> Result<
        (
            KeyHandle,
            tss_esapi::structures::Public,
            tss_esapi::structures::Private,
        ),
        tss_esapi::Error,
    > {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::interface_types::key_bits::RsaKeyBits;

        use tss_esapi::structures::{
            PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
            SensitiveData, SymmetricDefinitionObject,
        };

        // No explicit session needed for basic operations

        // Build the public area for the RSA key
        debug!("Generating RSA key with key size: {} bits", key_size);

        // Create parameters for an unrestricted decryption key using NULL scheme
        // For encryption/decryption keys, we need to use a NULL scheme to allow the TPM
        // to infer the scheme from the encryption/decryption call
        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::Null) // NULL scheme allows any scheme to be used
            .with_key_bits(RsaKeyBits::try_from(key_size)?)
            .with_exponent(RsaExponent::default())
            .with_symmetric(SymmetricDefinitionObject::Null) // No symmetric for unrestricted keys
            .with_is_signing_key(false) // Not for signing
            .with_is_decryption_key(true) // For decryption
            .with_restricted(false); // Unrestricted key is important for this use case

        debug!(?rsa_params, "Building RSA parameters for key generation");

        let rsa_params = rsa_params.build()?;

        debug!(?rsa_params, "Generating RSA key with parameters");

        // Object attributes for the RSA child key.
        // Must match the parameters (decrypt=true, sign=false)
        let object_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true) // Must match is_decryption_key=true in parameters
            // Remove with_sign_encrypt, not needed for RSA decrypt keys
            .build()?;

        debug!(?object_attrs, "Object attributes for RSA key");

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attrs)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .expect("Failed to build RSA public template");

        info!(
            ?public,
            "RSA keypair template generated successfully, proceeding to create in TPM"
        );

        let sensitive = SensitiveData::default();

        // Require a primary key for generating child keys
        let primary = self.primary_handle.ok_or_else(|| {
            error!("No primary key available for RSA child key generation");
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::ParamsMissing)
        })?;

        // Create the key under the primary handle using a null auth session
        let create_result = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.create(
                primary,
                public.clone(),
                None, // authValue for the new key (empty)
                Some(sensitive),
                None, // creationPCRs
                None, // ticket
            )
        })?;

        debug!(
            "Key created in TPM: out_public={:?}, out_private size={}",
            create_result.out_public,
            create_result.out_private.value().len(),
        );

        // Load the key into the TPM using a null auth session
        let key_handle = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.load(
                primary,
                create_result.out_private.clone(),
                create_result.out_public.clone(),
            )
        })?;

        self.set_child_key_handle(key_handle); // Renamed method
        Ok((
            key_handle,
            create_result.out_public,
            create_result.out_private,
        ))
    }

    /// Load an RSA key from TPM2B_PUBLIC and TPM2B_PRIVATE blobs.
    pub fn load_key(
        &mut self,
        public: tss_esapi::structures::Public,
        private: tss_esapi::structures::Private,
    ) -> Result<KeyHandle, tss_esapi::Error> {
        // Require a primary key for loading child keys
        let primary = self.primary_handle.ok_or_else(|| {
            error!("No primary key available for loading child key");
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::ParamsMissing)
        })?;

        let key_handle = self
            .ctx
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))?;

        self.set_child_key_handle(key_handle); // Renamed method
        Ok(key_handle)
    }

    /// Encrypts data using the currently loaded RSA key in the TPM.
    /// Note: RSA can only encrypt small amounts of data - for 2048-bit RSA keys,
    /// the maximum data size is around 190 bytes due to padding requirements.
    pub fn rsa_encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
        use tss_esapi::structures::{Data, PublicKeyRsa};

        // Check if the plaintext is too large for RSA encryption
        // For all RSA key sizes, we'll use a conservative limit of 100 bytes
        // which should work with 2048-bit RSA keys (max ~214 bytes)
        if plaintext.len() > 190 {
            debug!(
                "Plaintext too large for RSA encryption, length: {}",
                plaintext.len()
            );
            return Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ));
        }

        let rsa_handle = self.current_child_key_handle().ok_or_else(|| {
            debug!("No current child key handle found for RSA encryption");
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::WrongParamSize)
        })?;

        let khandle = *rsa_handle;
        debug!("Using RSA key handle: {:?} for encryption", khandle);

        let rsa_key_scheme = RsaDecryptionScheme::RsaEs;
        debug!("Using RSA scheme: {:?}", rsa_key_scheme);

        // Make sure plaintext is properly converted to TPM Data type
        let label_data = Data::default(); // Empty label for RSA encryption
        debug!(
            "Converted plaintext to Data, size: {}",
            label_data.value().len()
        );

        // Empty label for RSA
        let message = PublicKeyRsa::try_from(plaintext.to_vec())?;
        debug!("Using empty label for encryption");

        debug!("Executing RSA encryption with null auth session");

        // Execute the encryption operation with a null auth session
        let encrypted_data = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.rsa_encrypt(khandle, message, rsa_key_scheme, label_data)
        })?;

        debug!(
            "RSA encryption successful, ciphertext size: {}",
            encrypted_data.value().len()
        );
        Ok(encrypted_data.value().to_vec())
    }

    /// Decrypts data using the currently loaded RSA key in the TPM.
    pub fn rsa_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
        use tss_esapi::structures::{Data, PublicKeyRsa};

        let rsa_handle = self
            .current_child_key_handle()
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ))?;

        let khandle = *rsa_handle;

        let rsa_key_scheme = RsaDecryptionScheme::RsaEs;
        // Correctly convert ciphertext to PublicKeyRsa
        let rsa_cipher_text = PublicKeyRsa::try_from(ciphertext.to_vec())?;
        let label_data = Data::default();

        // Execute the decryption operation with a null auth session
        let decrypted_data = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.rsa_decrypt(
                khandle,
                rsa_cipher_text, // Use PublicKeyRsa typed variable
                rsa_key_scheme,
                label_data,
            )
        })?;

        Ok(decrypted_data.value().to_vec())
    }

    /// Generates a new AES key in the TPM under the primary key.
    pub fn generate_aes_child_key(
        &mut self,
        key_bits: tss_esapi::interface_types::key_bits::AesKeyBits,
        mode: tss_esapi::interface_types::algorithm::SymmetricMode,
    ) -> Result<(KeyHandle, Public, Private), tss_esapi::Error> {
        // AES key attributes: must be restricted if parent is restricted.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(true) // Changed to true to match example_aes_encryptdecrypt.rs for child key
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true) // Allows use with null auth if authValue is empty
            .with_sign_encrypt(true) // For symmetric keys, enables encryption/decryption
            .with_decrypt(true)
            .with_restricted(false)
            .build()?;

        let sym_def_obj = SymmetricDefinitionObject::Aes { key_bits, mode };

        let aes_params = SymmetricCipherParameters::new(sym_def_obj);

        let key_public_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(aes_params)
            .with_symmetric_cipher_unique_identifier(Digest::default()) // For symmetric keys
            .build()?;

        // Require a primary key for generating child keys
        let primary = self.primary_handle.ok_or_else(|| {
            error!("No primary key available for AES child key generation");
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::ParamsMissing)
        })?;

        let (created_private, created_public) = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.create(
                primary,
                key_public_template.clone(),
                None, // authValue for the new key (empty)
                None, // initialData
                None, // creationPCRs
                None, // ticket
            )
            .map(|key: CreateKeyResult| (key.out_private, key.out_public))
        })?;

        let loaded_key_handle = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.load(primary, created_private.clone(), created_public.clone())
        })?;

        self.set_child_key_handle(loaded_key_handle);

        Ok((loaded_key_handle, created_public, created_private))
    }

    // /// Loads an existing AES key into the TPM under the current primary key.
    // pub fn load_aes_key(
    //     &mut self,
    //     public: Public,
    //     private: Private,
    // ) -> Result<KeyHandle, tss_esapi::Error> {
    //     // Require a primary key for loading child keys
    //     let primary = self.primary_handle.ok_or_else(|| {
    //         error!("No primary key available for loading AES child key");
    //         tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::ParamsMissing)
    //     })?;

    //     let key_handle = self
    //         .ctx
    //         .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))?;
    //     self.set_child_key_handle(key_handle);
    //     Ok(key_handle)
    // }

    pub fn get_key_type(
        &mut self,
        key_handle: KeyHandle,
    ) -> Result<PublicAlgorithm, tss_esapi::Error> {
        // Get the public area of the key to determine its type
        let (public, _name1, _name2) = self
            .ctx
            .execute_with_nullauth_session(|ctx| ctx.read_public(key_handle))?;

        Ok(get_public_algo(public))
    }

    /// Encrypts data using the currently loaded AES key in the TPM.
    /// Generates a new IV for each encryption operation.
    pub fn aes_encrypt(
        &mut self,
        plaintext: &[u8],
        mode: tss_esapi::interface_types::algorithm::SymmetricMode, // Mode must match the key's mode
    ) -> Result<(Vec<u8>, InitialValue), tss_esapi::Error> {
        let aes_key_handle = *self
            .current_child_key_handle() // Renamed method
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ))?;

        let iv = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.get_random(InitialValue::MAX_SIZE)
                .and_then(|random_bytes| {
                    InitialValue::try_from(random_bytes.to_vec()).map_err(|_| {
                        // e is unused
                        tss_esapi::Error::WrapperError(
                            tss_esapi::WrapperErrorKind::InvalidParam, // Or a more specific error
                        )
                    })
                })
        })?;

        let padded_plaintext = pkcs7_pad(plaintext);
        let data_to_encrypt = MaxBuffer::try_from(padded_plaintext).map_err(|_| {
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
        })?;

        let (encrypted_data, _returned_iv) = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.encrypt_decrypt_2(
                aes_key_handle,
                false, // false for encrypt
                mode,  // e.g., SymmetricMode::Cbc
                data_to_encrypt.clone(),
                iv.clone(),
            )
        })?;

        Ok((encrypted_data.to_vec(), iv)) // Return the original IV used for encryption
    }

    /// Decrypts data using the currently loaded AES key in the TPM.
    #[instrument(level = "debug", skip(self))]
    pub fn aes_decrypt(
        &mut self,
        ciphertext: &[u8],
        iv: InitialValue, // IV used for encryption must be provided
        mode: tss_esapi::interface_types::algorithm::SymmetricMode, // Mode must match the key's mode
    ) -> Result<Vec<u8>, tss_esapi::Error> {
        let aes_key_handle = *self
            .current_child_key_handle() // Renamed method
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ))?; // Clone the KeyHandle

        trace!(
            "Decrypting with AES key handle: {:?}, mode: {:?}, iv: {:?}",
            aes_key_handle, mode, iv
        );
        let data_to_decrypt = MaxBuffer::try_from(ciphertext.to_vec()).map_err(|_| {
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
        })?;

        trace!(
            "Data to decrypt size: {}, IV size: {}",
            data_to_decrypt.value().len(),
            iv.value().len()
        );

        let (decrypted_padded_data, _returned_iv) =
            self.ctx.execute_with_nullauth_session(|ctx| {
                ctx.encrypt_decrypt_2(
                    aes_key_handle,
                    true, // true for decrypt
                    mode, // e.g., SymmetricMode::Cbc
                    data_to_decrypt.clone(),
                    iv,
                )
            })?;

        pkcs7_unpad(&decrypted_padded_data.to_vec())
    }

    /// Create a new AES128CFB primary key in the TPM and return a new TpmManagerHandle.
    /// This will generate a symmetric primary key suitable for use as a parent for child AES keys.
    #[instrument(level = "debug", skip(ctx))]
    pub fn create_with_aes_primary(mut ctx: Context) -> Result<Self, tss_esapi::Error> {
        // Primary key attributes: restricted, decrypt, suitable for parenting symmetric keys.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_st_clear(true) // Changed to true to match example_aes_encryptdecrypt.rs
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true) // Allows use with null auth if authValue is empty
            .with_decrypt(true) // Allows key to be used for decryption
            // .with_sign_encrypt(true) // REMOVED: sign must be CLEAR for primary SymCipher keys
            .with_restricted(true) // CHANGED: Primary key is restricted as per user finding
            .build()?;

        // Primary key symmetric parameters (e.g., AES_128_CFB as in example)
        // This defines the "type" of symmetric key the primary key is.
        let primary_symmetric_params =
            SymmetricCipherParameters::new(SymmetricDefinitionObject::AES_128_CFB);
        let public_for_primary = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher) // Primary key is a symmetric cipher
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(primary_symmetric_params)
            .with_symmetric_cipher_unique_identifier(Digest::default()) // For symmetric keys
            .build()?;

        trace!(
            ?public_for_primary,
            "Creating symmetric primary key with public template"
        );

        // Create primary key using null auth session, assuming empty auth value for Owner hierarchy.
        let create_primary_result = ctx.execute_with_nullauth_session(|ctx_session| {
            ctx_session.create_primary(
                Hierarchy::Owner, // Example uses Owner, suitable for general user keys
                public_for_primary,
                None, // authValue (empty)
                None, // initialData
                None, // creationPCRs
                None, // ticket
            )
        })?;

        Ok(TpmManagerHandle::new(ctx, create_primary_result.key_handle))
    }

    pub fn create_with_rsa_primary(
        mut ctx: Context,
        key_size: u16,
    ) -> Result<Self, tss_esapi::Error> {
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::structures::{
            PublicKeyRsa, // Added PublicKeyRsa
            PublicRsaParametersBuilder,
            RsaExponent,
        };

        debug!("Creating RSA primary key with key size: {} bits", key_size);
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_restricted(true) // Primary key is restricted
            .with_decrypt(true); // Must be set to true for restricted decryption key

        trace!(
            ?object_attributes,
            "Building object attributes for RSA primary key template"
        );
        let object_attributes = object_attributes.build()?;

        trace!(
            ?object_attributes,
            "Object attributes for RSA primary key template"
        );

        let rsa_params = PublicRsaParametersBuilder::new_restricted_decryption_key(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::try_from(key_size)?,
            RsaExponent::default(), // Default exponent (0 for 65537)
        )
        .build()?;
        trace!(?rsa_params, "RSA parameters for primary key template");

        let public_for_primary = PublicBuilder::new()
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(rsa_params)
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()?;

        trace!(
            ?public_for_primary,
            "Creating RSA primary key with public template"
        );

        let create_primary_result = ctx.execute_with_nullauth_session(|ctx_session| {
            ctx_session.create_primary(
                Hierarchy::Owner,
                public_for_primary,
                None, // authValue (empty)
                None, // initialData
                None, // creationPCRs
                None, // ticket
            )
        })?;

        Ok(TpmManagerHandle::new(ctx, create_primary_result.key_handle))
    }

    /// Stores the currently loaded child key at a persistent address in the TPM
    pub fn store_key_at_persistent_address(
        &mut self,
        persistent_handle_value: u32,
    ) -> Result<ObjectHandle, tss_esapi::Error> {
        use tss_esapi::handles::PersistentTpmHandle;

        // Get the current transient key handle
        let transient_handle = match self.current_child_key_handle() {
            Some(handle) => *handle,
            None => {
                return Err(tss_esapi::Error::WrapperError(
                    tss_esapi::WrapperErrorKind::ParamsMissing,
                ));
            }
        };

        // Convert the u32 to a PersistentTpmHandle
        // Valid persistent handle values are in the range 0x81000000 to 0x81FFFFFF
        let persistent_handle = PersistentTpmHandle::new(persistent_handle_value)?;

        // Store the key at the persistent handle
        use tss_esapi::interface_types::resource_handles::Provision;
        let result = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                Provision::Owner,
                ObjectHandle::from(transient_handle.value()),
                tss_esapi::interface_types::dynamic_handles::Persistent::from(persistent_handle),
            )
        })?;
        // Now the session is dropped, return the persistent handle as ObjectHandle
        Ok(result)
    }

    /// Loads a key from a persistent address in the TPM
    pub fn load_key_from_persistent_address(
        &mut self,
        persistent_handle_value: u32,
    ) -> Result<KeyHandle, tss_esapi::Error> {
        // Convert to KeyHandle type and set as current child key
        let key_handle = KeyHandle::from(persistent_handle_value);
        self.set_child_key_handle(key_handle);

        Ok(key_handle)
    }

    /// Removes a key from persistent storage in the TPM
    pub fn remove_persistent_key(
        &mut self,
        persistent_handle_value: u32,
    ) -> Result<(), tss_esapi::Error> {
        use tss_esapi::handles::PersistentTpmHandle;

        // Convert the u32 to a PersistentTpmHandle
        let persistent_handle = PersistentTpmHandle::new(persistent_handle_value)?;

        // Remove the key from persistent storage
        self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.evict_control(
                tss_esapi::interface_types::resource_handles::Provision::Owner,
                ObjectHandle::from(persistent_handle_value),
                tss_esapi::interface_types::dynamic_handles::Persistent::from(persistent_handle),
            )
        })?;

        Ok(())
    }
}

/// Export the key material into marshalled blobs (Vec<u8>).
pub fn export_key_material_blobs(
    public: &Public,
    private: &Private,
) -> Result<(Vec<u8>, Vec<u8>), tss_esapi::Error> {
    let pub_blob = public.marshall()?;
    let priv_blob = private.to_vec();
    Ok((pub_blob, priv_blob))
}

// WARNING: Manually implemented pkcs7 follows. This has not been audited. Don't use this
// in production.
const AES_BLOCK_SIZE: usize = 16; // AES block size is 128 bits (16 bytes)

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let data_len = data.len();
    // PKCS7 always pads, even if the data is already a multiple of the block size.
    let padding_value = AES_BLOCK_SIZE - (data_len % AES_BLOCK_SIZE);
    let mut padded_data = data.to_vec();
    padded_data.resize(data_len + padding_value, padding_value as u8);
    padded_data
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
    if data.is_empty() {
        return Err(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::InvalidParam,
        ));
    }
    let last_byte_val = data[data.len() - 1];
    if last_byte_val == 0 || last_byte_val as usize > AES_BLOCK_SIZE {
        return Err(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::InvalidParam,
        ));
    }
    let pad_len = last_byte_val as usize;
    if data.len() < pad_len {
        return Err(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::InvalidParam,
        ));
    }
    for i in 0..pad_len {
        if data[data.len() - 1 - i] != last_byte_val {
            return Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::InvalidParam,
            ));
        }
    }
    Ok(data[..data.len() - pad_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use serial_test::serial;
    use tracing_test::traced_test;
    use tss_esapi::{
        Tcti, // For Tcti::Swtpm
        interface_types::{algorithm::SymmetricMode, key_bits::AesKeyBits},
        tcti_ldr::NetworkTPMConfig,
        traits::UnMarshall,
    };
    // use zeroize::Zeroizing; // Unused

    // Assuming default_tcti_handle() is defined elsewhere or replace if not.
    // For consistency, let's use Swtpm for all tests if default_tcti_handle is problematic
    fn get_test_tcti() -> Tcti {
        Tcti::from_environment_variable().unwrap_or(Tcti::Swtpm(NetworkTPMConfig::default()))
    }

    #[test]
    fn test_tpm_object_handle() {
        let ctx = Context::new(get_test_tcti()).unwrap(); // mut removed
        let primary_handle = TpmObjectHandle::new(ObjectHandle::from(0x81010001));
        let tmp_handle =
            TpmManagerHandle::new(ctx, KeyHandle::from(primary_handle.handle().value()));

        assert_eq!(tmp_handle.primary_handle().unwrap().value(), 0x81010001);
    }

    #[test]
    #[serial]
    fn test_aes_primary_child_encryptdecrypt2() {
        let ctx = Context::new(get_test_tcti()).expect("Failed to create TPM context");
        let mut tpm_handle = TpmManagerHandle::create_with_aes_primary(ctx).unwrap();

        // Generate an AES-128-CFB key
        let (_aes_handle_generated, public, private) = tpm_handle
            .generate_aes_child_key(AesKeyBits::Aes128, SymmetricMode::Cfb)
            .expect("AES key generation failed");

        // Load the key using the *same* TpmManagerHandle.
        let _loaded_handle = tpm_handle
            .load_key(public, private)
            .expect("AES key loading failed");

        // Test encryption and decryption using the loaded key via tpm_handle
        let plaintext = b"hello AES TPM!";
        let (ciphertext, iv) = tpm_handle
            .aes_encrypt(plaintext, SymmetricMode::Cfb)
            .expect("AES Encryption failed");

        let decrypted_plaintext = tpm_handle
            .aes_decrypt(&ciphertext, iv, SymmetricMode::Cfb)
            .expect("AES Decryption failed");

        assert_eq!(decrypted_plaintext, plaintext);
    }

    #[test]
    #[serial]
    #[traced_test]
    fn test_rsa_primary_child_rsacrypt() {
        // let's make an RSA primary first
        let ctx = Context::new(get_test_tcti()).expect("Failed to create TPM context");
        let mut tpm_handle = TpmManagerHandle::create_with_rsa_primary(ctx, 2048)
            .expect("Failed to create RSA primary key");

        // Generate an RSA key under the RSA primary
        let (_rsa_key_handle, _rsa_public, _rsa_private) = tpm_handle
            .generate_rsa_child_key_pair(2048)
            .expect("Failed to generate RSA key pair");

        // Test encryption and decryption
        let plaintext = b"Short test string"; // Keep it small for RSA encryption
        let ciphertext = tpm_handle
            .rsa_encrypt(plaintext)
            .expect("RSA encryption failed");
        let decrypted = tpm_handle
            .rsa_decrypt(&ciphertext)
            .expect("RSA decryption failed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted text should match original plaintext"
        );

        // Create a new Context for MasterKey::generate since the original ctx was moved
        let ctx_for_master_key =
            Context::new(get_test_tcti()).expect("Failed to create TPM context for MasterKey");
        let master_key = crate::MasterKey::generate(ctx_for_master_key);
        // test long string (i.e the actual CEK)
        let long = master_key.key().expose_secret();
        debug!("Data length: {}", long.len());
        let long_ciphertext = tpm_handle
            .rsa_encrypt(long)
            .expect("RSA encryption of long data failed");
        let long_decrypted = tpm_handle
            .rsa_decrypt(&long_ciphertext)
            .expect("RSA decryption of long data failed");
        assert_eq!(
            long_decrypted, long,
            "Decrypted long data should match original long data"
        );
    }

    #[test]
    #[serial]
    #[traced_test]
    fn test_export_key_material_blobs() {
        let ctx_orig = Context::new(get_test_tcti()).unwrap();
        let mut tpm_handle_orig = TpmManagerHandle::create_with_aes_primary(ctx_orig).unwrap();
        let (_aes_handle, public_orig, private_orig) = tpm_handle_orig
            .generate_aes_child_key(AesKeyBits::Aes128, SymmetricMode::Cbc)
            .unwrap();
        let (pub_blob, priv_blob) = export_key_material_blobs(&public_orig, &private_orig).unwrap();
        assert!(!pub_blob.is_empty());
        assert!(!priv_blob.is_empty());

        // Unmarshall and verify
        let unmarshalled_public =
            Public::unmarshall(&pub_blob).expect("Failed to unmarshal public key blob");
        let unmarshalled_private =
            Private::try_from(priv_blob.clone()).expect("Failed to create Private from blob"); // Use .clone() if priv_blob is used later, though not strictly necessary here.
        assert_eq!(
            public_orig, unmarshalled_public,
            "Unmarshalled public key does not match original"
        );
        assert_eq!(
            private_orig, unmarshalled_private,
            "Unmarshalled private key does not match original"
        );

        drop(tpm_handle_orig); // Ensure the original handle and its context are dropped

        // Create a new TpmManagerHandle with a new context to simulate loading in a new session/application instance
        let ctx_new = Context::new(get_test_tcti()).unwrap();
        let mut tpm_handle_loaded_key = TpmManagerHandle::create_with_aes_primary(ctx_new).unwrap();

        // Load the unmarshalled key into the new handle
        let _loaded_key_object_handle = tpm_handle_loaded_key
            .load_key(unmarshalled_public, unmarshalled_private) // Pass the unmarshalled Public and Private structs
            .expect("Failed to load exported/unmarshalled AES key into new handle");

        // Encrypt-decrypt test using the new handle with the loaded key
        let plaintext = b"test export key material with loaded key";
        let (ciphertext, iv) = tpm_handle_loaded_key
            .aes_encrypt(plaintext, SymmetricMode::Cbc)
            .expect("AES Encryption failed using the loaded key");
        assert_ne!(
            ciphertext, plaintext,
            "Ciphertext should not be same as plaintext"
        );

        let decrypted_text = tpm_handle_loaded_key
            .aes_decrypt(&ciphertext, iv, SymmetricMode::Cbc)
            .expect("AES Decryption failed using the loaded key");
        assert_eq!(
            decrypted_text, plaintext,
            "Decrypted text does not match original plaintext after loading key"
        );
    }

    #[test]
    #[serial]
    #[traced_test]
    fn test_generate_rsa_key_under_symmetric_primary() {
        let ctx = Context::new(get_test_tcti())
            .expect("Failed to create TPM context for RSA under AES primary test");
        let mut tpm_handle = TpmManagerHandle::create_with_aes_primary(ctx)
            .expect("Failed to create AES primary key for RSA child test");

        // Generate an RSA 2048 key pair under the AES primary key
        let (rsa_key_handle, rsa_public, _rsa_private) = tpm_handle
            .generate_rsa_child_key_pair(2048)
            .expect("RSA key generation under AES primary failed");

        assert!(
            tpm_handle.current_child_key_handle().is_some(),
            "Child key handle should be set after RSA key generation"
        );
        assert_eq!(
            tpm_handle.current_child_key_handle().unwrap().value(),
            rsa_key_handle.value(),
            "Current child key handle should be the generated RSA key"
        );

        // Debug the public structure
        debug!("RSA public key: {:?}", rsa_public);

        // Use extremely short plaintext for testing
        let plaintext = b"test"; // Just 4 bytes
        debug!("Encrypting plaintext: {:?}", plaintext);
        let ciphertext = tpm_handle
            .rsa_encrypt(plaintext)
            .expect("RSA encryption failed");

        debug!(
            "Successfully encrypted data, ciphertext length: {}",
            ciphertext.len()
        );

        let decrypted_plaintext = tpm_handle
            .rsa_decrypt(&ciphertext)
            .expect("RSA decryption failed");

        assert_eq!(
            decrypted_plaintext, plaintext,
            "RSA decrypted text should match original plaintext"
        );
    }
}
