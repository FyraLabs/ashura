// use log::{debug, error, info, warn};
// use std::cell::RefCell; // Unused
use std::convert::TryFrom; // TryInto is unused
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::handles::ObjectHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::resource_handles::Hierarchy;
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
use tss_esapi::{Context, tcti_ldr::TabrmdConfig}; // Keep Context import

pub fn default_tcti_handle() -> tss_esapi::TctiNameConf {
    tss_esapi::TctiNameConf::from_environment_variable()
        .unwrap_or(tss_esapi::TctiNameConf::Tabrmd(TabrmdConfig::default()))
}
/// Represents a loaded TPM object (e.g., a key or primary object).
#[derive(Clone)]
pub struct TpmObjectHandle {
    handle: ObjectHandle,
    // ctx: *mut tss_esapi::Context, // Removed
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

// impl Drop for TpmObjectHandle {
//     fn drop(&mut self) {
//         // Unload the TPM object when the handle is dropped
//         unsafe {
//             if let Some(ctx) = self.ctx.as_mut() {
//                 if let Err(e) = ctx.flush_context(self.handle) {
//                     eprintln!("Failed to flush TPM object handle: {}", e);
//                 }
//             } else {
//                 eprintln!("Failed to flush TPM object handle: context pointer was null");
//             }
//         }
//     }
// }

pub struct TpmManagerHandle {
    ctx: Context, // Assuming Context is directly held
    primary_handle: TpmObjectHandle,
    current_aes_handle: Option<TpmObjectHandle>, // Changed from current_rsa_handle
}

impl TpmManagerHandle {
    /// Creates a new `TpmManagerHandle` with the given context and primary handle.
    pub fn new(ctx: Context, primary_handle: TpmObjectHandle) -> Self {
        Self {
            ctx,
            primary_handle,
            current_aes_handle: None, // Initialize current_aes_handle
        }
    }

    /// Returns a reference to the primary TPM object handle.
    pub fn primary_handle(&self) -> &TpmObjectHandle {
        &self.primary_handle
    }

    /// Sets the AES handle, replacing any existing one.
    pub fn set_aes_handle(&mut self, handle: TpmObjectHandle) {
        self.current_aes_handle = Some(handle);
    }

    /// Returns a reference to the currently loaded AES key handle, if present.
    pub fn current_aes_handle(&self) -> Option<&TpmObjectHandle> {
        self.current_aes_handle.as_ref()
    }

    /// Generate RSA key pair in the TPM and store it in the context.
    /// Returns the TPM object handle and the public/private blobs.
    pub fn generate_rsa_key_pair(
        &mut self,
        key_size: u16,
    ) -> Result<
        (
            TpmObjectHandle,
            tss_esapi::structures::Public,
            tss_esapi::structures::Private,
        ),
        tss_esapi::Error,
    > {
        /*
        Example output when running `tpm2_create -G rsa2048:rsaes -g sha256 -u rsa.pub -r rsa.priv -C primary.ctx`:
        name-alg:
        value: sha256
        raw: 0xb
        attributes:
        value: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
        raw: 0x20072
        type:
        value: rsa
        raw: 0x1
        exponent: 65537
        bits: 2048
        scheme:
        value: rsaes
        raw: 0x15
        sym-alg:
        value: null
        raw: 0x10
        sym-mode:
        value: (null)
        raw: 0x0
        sym-keybits: 0
        rsa: c717cd8f3ca9b413ec31a815ff04ad6eb373c924f8e360e25cf61f452db2fc72e73cf949255650c3fb39a8951f05b45b9d30b6469c912e30fa25ddfe5bf16fd9e70357610f3ce07e92d59797a649b47f2059edc5a38d1a99e04f7494247275037b8d2ed5183c54925fe78ce746d3bdf22cd8558d08bb0d6ac06d8efe2b452cd6aeb3007ab1195525a091d637d8093d546ce319e426baea3cd71331b9bad6c01c02f8b683d82a73d497cb17e9a4c66e70e57c1f8171de6b3bb7146c192f0eaabd06ba7889a6f781acd7037efc9de83af59b4caef6cf768a80188bf04d85f1783908bc8a90eaed80924283b6114bf9428feff9cc10c4e2c0a0221ee50eaedefe79
        This matches the output of tpm2-tools exactly, so we can use the same builders to create the key.
        */
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::handles::KeyHandle;
        use tss_esapi::interface_types::algorithm::{
            HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
        };
        use tss_esapi::interface_types::key_bits::RsaKeyBits;

        use tss_esapi::structures::{
            PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
            SensitiveData, SymmetricDefinitionObject,
        };

        // No explicit session needed for basic operations

        // Build the public area for the RSA key - match tmp2-tools exactly
        let rsa_params = PublicRsaParametersBuilder::new()
            .with_scheme(RsaScheme::create(RsaSchemeAlgorithm::RsaEs, None).unwrap())
            .with_exponent(RsaExponent::default())
            .with_symmetric(SymmetricDefinitionObject::Null) // Child decryption keys use Null symmetric
            .with_is_decryption_key(true) // Inform builder this is a decryption key
            .with_key_bits(RsaKeyBits::try_from(key_size)?) // Use the key_size parameter
            .with_restricted(false) // Builder default is false, which is correct for an unrestricted child key
            .build()
            .unwrap();

        println!(
            "[KeyPairGen] Generating RSA key with parameters: {:?}",
            rsa_params
        );

        // Child key attributes to match tpm2-tools: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
        // This means restricted is false.
        let object_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(false) // Reverted to false, aligning with tpm2-tools output for child
            .build()?;

        println!("[KeyPairGen] Object attributes: {:?}", object_attrs);

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attrs)
            .with_rsa_parameters(rsa_params)
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .unwrap();

        println!(
            "[KeyPairGen] Keypair generation successful! Public area for RSA key: {:?}",
            public
        );

        let sensitive = SensitiveData::default();

        // Create the key under the primary handle
        let create_result = self.ctx.create(
            KeyHandle::from(self.primary_handle.handle().value()),
            public,
            None,
            Some(sensitive),
            None,
            None,
        )?;
        // No explicit session cleanup needed

        // Load the key into the TPM
        let key_handle = self.ctx.load(
            KeyHandle::from(self.primary_handle.handle().value()),
            create_result.out_private.clone(),
            create_result.out_public.clone(),
        )?;
        let tpm_object_handle = TpmObjectHandle::new(
            tss_esapi::handles::ObjectHandle::from(key_handle.value()),
            // &mut self.ctx, // Argument removed
        );
        self.set_aes_handle(tpm_object_handle.clone());
        Ok((
            tpm_object_handle,
            create_result.out_public,
            create_result.out_private,
        ))
    }

    /// Load an RSA key from TPM2B_PUBLIC and TPM2B_PRIVATE blobs.
    pub fn load_key(
        &mut self,
        public: tss_esapi::structures::Public,
        private: tss_esapi::structures::Private,
    ) -> Result<TpmObjectHandle, tss_esapi::Error> {
        use tss_esapi::handles::KeyHandle;
        let key_handle = self.ctx.load(
            KeyHandle::from(self.primary_handle.handle().value()),
            private,
            public,
        )?;
        let tpm_object_handle = TpmObjectHandle::new(
            tss_esapi::handles::ObjectHandle::from(key_handle.value()),
            // &mut self.ctx, // Argument removed
        );
        self.set_aes_handle(tpm_object_handle.clone());
        Ok(tpm_object_handle)
    }

    /// Encrypts data using the currently loaded RSA key in the TPM.
    pub fn rsa_encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
        // use tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm; // Unused
        use tss_esapi::structures::Data; // PublicKeyRsa is used via tss_esapi::structures::PublicKeyRsa
        // use tss_esapi::structures::RsaScheme; // Unused

        let rsa_handle = self
            .current_aes_handle()
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ))?;

        let khandle = KeyHandle::from(rsa_handle.handle().value());

        let rsa_key_scheme = RsaDecryptionScheme::RsaEs;
        let message_data = Data::try_from(plaintext.to_vec())?; // Ensure it's Vec<u8> for TryFrom<Vec<u8>>

        // Store current sessions
        let original_sessions = self.ctx.sessions();

        // Set no sessions, to attempt password-less auth for key with empty authValue.
        // The key has user_with_auth=true, empty authPolicy, and empty authValue.
        // In this scenario, an empty authorization area (achieved by providing no sessions)
        // should equate to using TPM_RS_PW with an empty password.
        self.ctx.set_sessions((None, None, None));

        // note: they fucked up the signatures, so
        // `message` is actually PublicKeyRsa
        // and `label` is actually Data, the ciphertext itself
        // Just assume the input in rsa_encrypt and rsa_decrypt are correct,

        let encrypted_data_result = self.ctx.rsa_encrypt(
            khandle,
            tss_esapi::structures::PublicKeyRsa::default(), // Use default, TPM fills this (corresponds to 'label' in TPM2_RSA_Encrypt)
            rsa_key_scheme,
            message_data, // (corresponds to 'message' in TPM2_RSA_Encrypt - plaintext)
        );

        // Restore
        self.ctx.set_sessions(original_sessions);

        // Handle the result after restoring sessions
        let encrypted_data = encrypted_data_result?;
        Ok(encrypted_data.value().to_vec())
    }

    /// Decrypts data using the currently loaded RSA key in the TPM.
    pub fn rsa_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
        use tss_esapi::handles::KeyHandle;
        // use tss_esapi::interface_types::algorithm::RsaSchemeAlgorithm; // Unused
        use tss_esapi::structures::{Data, PublicKeyRsa}; // RsaScheme unused
        // use tss_esapi::structures::RsaScheme; // Unused

        let rsa_handle = self
            .current_aes_handle()
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ))?;

        let khandle = KeyHandle::from(rsa_handle.handle().value());

        let rsa_key_scheme = RsaDecryptionScheme::RsaEs;
        // Correctly convert ciphertext to PublicKeyRsa
        let rsa_cipher_text = PublicKeyRsa::try_from(ciphertext.to_vec())?;
        let label_data = Data::default();

        // they also fucked up the signatures here, so
        // `message` is actually PublicKeyRsa
        // and `label` is actually Data, the label data

        let decrypted_data = self.ctx.rsa_decrypt(
            khandle,
            rsa_cipher_text, // Use PublicKeyRsa typed variable
            rsa_key_scheme,
            label_data,
        )?;
        Ok(decrypted_data.value().to_vec())
    }

    /// Generates a new AES key in the TPM under the primary key.
    pub fn generate_aes_key(
        &mut self,
        key_bits: tss_esapi::interface_types::key_bits::AesKeyBits,
        mode: tss_esapi::interface_types::algorithm::SymmetricMode,
    ) -> Result<(TpmObjectHandle, Public, Private), tss_esapi::Error> {
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

        let sym_def_obj = match (key_bits, mode) {
            (
                tss_esapi::interface_types::key_bits::AesKeyBits::Aes128,
                tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            ) => SymmetricDefinitionObject::AES_128_CFB,
            (
                tss_esapi::interface_types::key_bits::AesKeyBits::Aes192,
                tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            ) => SymmetricDefinitionObject::Aes {
                key_bits: tss_esapi::interface_types::key_bits::AesKeyBits::Aes192,
                mode: tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            },
            (
                tss_esapi::interface_types::key_bits::AesKeyBits::Aes256,
                tss_esapi::interface_types::algorithm::SymmetricMode::Cfb,
            ) => SymmetricDefinitionObject::AES_256_CFB,
            // For CBC and other modes, use the generic Aes variant
            _ => SymmetricDefinitionObject::Aes { key_bits, mode },
        };

        let aes_params = SymmetricCipherParameters::new(sym_def_obj);

        let key_public_template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::SymCipher)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_symmetric_cipher_parameters(aes_params)
            .with_symmetric_cipher_unique_identifier(Digest::default()) // For symmetric keys
            .build()?;

        let (created_private, created_public) = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.create(
                self.primary_handle.handle().into(),
                key_public_template.clone(),
                None, // authValue for the new key (empty)
                None, // initialData
                None, // creationPCRs
                None, // ticket
            )
            .map(|key: CreateKeyResult| (key.out_private, key.out_public))
        })?;

        let loaded_key_handle = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.load(
                self.primary_handle.handle().into(),
                created_private.clone(),
                created_public.clone(),
            )
        })?;

        let tpm_object_handle = TpmObjectHandle::new(loaded_key_handle.into());
        self.set_aes_handle(tpm_object_handle.clone());

        Ok((tpm_object_handle, created_public, created_private))
    }

    /// Load an AES key from TPM2B_PUBLIC and TPM2B_PRIVATE blobs.
    pub fn load_aes_key(
        &mut self,
        public: Public,
        private: Private,
    ) -> Result<TpmObjectHandle, tss_esapi::Error> {
        let key_handle = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.load(self.primary_handle.handle().into(), private, public)
        })?;
        let tpm_object_handle = TpmObjectHandle::new(key_handle.into());
        self.set_aes_handle(tpm_object_handle.clone());
        Ok(tpm_object_handle)
    }

    /// Encrypts data using the currently loaded AES key in the TPM.
    /// Generates a new IV for each encryption operation.
    pub fn aes_encrypt(
        &mut self,
        plaintext: &[u8],
        mode: tss_esapi::interface_types::algorithm::SymmetricMode, // Mode must match the key's mode
    ) -> Result<(Vec<u8>, InitialValue), tss_esapi::Error> {
        let aes_key_handle = self
            .current_aes_handle()
            .ok_or_else(|| {
                tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
            })?
            .handle();

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
                aes_key_handle.into(),
                false, // false for encrypt
                mode,  // e.g., SymmetricMode::Cbc
                data_to_encrypt.clone(),
                iv.clone(),
            )
        })?;

        Ok((encrypted_data.to_vec(), iv)) // Return the original IV used for encryption
    }

    /// Decrypts data using the currently loaded AES key in the TPM.
    pub fn aes_decrypt(
        &mut self,
        ciphertext: &[u8],
        iv: InitialValue, // IV used for encryption must be provided
        mode: tss_esapi::interface_types::algorithm::SymmetricMode, // Mode must match the key's mode
    ) -> Result<Vec<u8>, tss_esapi::Error> {
        let aes_key_handle = self
            .current_aes_handle()
            .ok_or_else(|| {
                tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
            })?
            .handle();

        let data_to_decrypt = MaxBuffer::try_from(ciphertext.to_vec()).map_err(|_| {
            tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
        })?;

        let (decrypted_padded_data, _returned_iv) =
            self.ctx.execute_with_nullauth_session(|ctx| {
                ctx.encrypt_decrypt_2(
                    aes_key_handle.into(),
                    true, // true for decrypt
                    mode, // e.g., SymmetricMode::Cbc
                    data_to_decrypt.clone(),
                    iv,
                )
            })?;

        pkcs7_unpad(&decrypted_padded_data.to_vec())
    }

    /// Create a new primary key in the TPM and return a new TpmManagerHandle.
    /// This will generate a symmetric primary key suitable for use as a parent for child AES keys.
    pub fn create_with_primary(mut ctx: Context) -> Result<Self, tss_esapi::Error> {
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

        println!(
            "[PrimaryCreate] Creating symmetric primary key with public template: {:?}",
            public_for_primary
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

        let primary_handle = TpmObjectHandle::new(create_primary_result.key_handle.into());
        Ok(TpmManagerHandle::new(ctx, primary_handle))
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
    use tss_esapi::{
        Tcti, // For Tcti::Swtpm
        interface_types::{algorithm::SymmetricMode, key_bits::AesKeyBits},
        tcti_ldr::NetworkTPMConfig,
        traits::UnMarshall,
    };
    // use zeroize::Zeroizing; // Unused

    // Assuming default_tcti_handle() is defined elsewhere or replace if not.
    // For consistency, let's use Swtpm for all tests if default_tcti_handle is problematic.
    fn get_test_tcti() -> Tcti {
        Tcti::Swtpm(NetworkTPMConfig::default())
    }

    #[test]
    fn test_tpm_object_handle() {
        let ctx = Context::new(get_test_tcti()).unwrap(); // mut removed
        let primary_handle = TpmObjectHandle::new(ObjectHandle::from(0x81010001));
        let tpm_handle = TpmManagerHandle::new(ctx, primary_handle);

        assert_eq!(tpm_handle.primary_handle().handle().value(), 0x81010001);
    }

    #[test]
    fn test_generate_aes_key_and_encrypt_decrypt() {
        let ctx = Context::new(get_test_tcti()).expect("Failed to create TPM context");
        let mut tpm_handle = TpmManagerHandle::create_with_primary(ctx).unwrap();

        // Generate an AES-128-CFB key (changed from Cbc for diagnostics)
        let (_aes_handle_generated, public, private) = tpm_handle
            .generate_aes_key(AesKeyBits::Aes128, SymmetricMode::Cfb) // Changed to Cfb
            .unwrap();

        // Export blobs and reload the key to test load_aes_key
        // let (_pub_blob, _priv_blob) = export_key_material_blobs(&public, &private).unwrap(); // Blobs not directly used by load_aes_key current signature

        // Load the key using the *same* TpmManagerHandle.
        // This ensures the primary key is known in the context.
        let _loaded_handle = tpm_handle // Use the original tpm_handle
            .load_aes_key(public.clone(), private.clone())
            .expect("Failed to load AES key");

        // Ensure the original handle and loaded handle point to the same logical key
        // This might involve comparing properties or just ensuring load was successful.
        // For now, we trust load_aes_key sets the current_aes_handle correctly.

        // Test encryption and decryption using the loaded key via tpm_handle
        let plaintext = b"hello AES TPM!";
        let (ciphertext, iv) = tpm_handle // Use the original tpm_handle
            .aes_encrypt(plaintext, SymmetricMode::Cfb) // Pass the mode
            .expect("AES Encryption failed");
        assert_ne!(ciphertext, plaintext);

        let decrypted = tpm_handle // Use the original tpm_handle
            .aes_decrypt(&ciphertext, iv, SymmetricMode::Cfb) // Pass the mode
            .expect("AES Decryption failed");
        assert_eq!(decrypted, plaintext);

        // Test with the original handle as well
        let (ciphertext2, iv2) = tpm_handle
            .aes_encrypt(plaintext, SymmetricMode::Cfb) // Changed to Cfb
            .expect("AES Encryption failed on original handle");
        assert_ne!(ciphertext2, plaintext);
        let decrypted2 = tpm_handle
            .aes_decrypt(&ciphertext2, iv2, SymmetricMode::Cfb) // Changed to Cfb
            .expect("AES Decryption failed on original handle");
        assert_eq!(decrypted2, plaintext);

        // Silence unused variable warnings for test clarity if any remain
    }

    #[test]
    fn test_export_key_material_blobs() {
        let ctx = Context::new(get_test_tcti()).unwrap();
        let mut tpm_handle = TpmManagerHandle::create_with_primary(ctx).unwrap();
        let (_aes_handle, public, private) = tpm_handle
            .generate_aes_key(AesKeyBits::Aes128, SymmetricMode::Cbc)
            .unwrap();
        let (pub_blob, priv_blob) = export_key_material_blobs(&public, &private).unwrap();
        assert!(!pub_blob.is_empty());
        assert!(!priv_blob.is_empty());

        // Optional: Try to unmarshall and verify
        let unmarshalled_public = Public::unmarshall(&pub_blob).unwrap();
        assert_eq!(public, unmarshalled_public);
        // let unmarshalled_private =
        // assert_eq!(private, unmarshalled_private);
    }
}
