use std::cell::RefCell;
use tss_esapi::handles::KeyHandle;
use tss_esapi::structures::{Digest, RsaDecryptionScheme};
use tss_esapi::traits::Marshall;
use tss_esapi::{handles::ObjectHandle, tcti_ldr::TabrmdConfig};

pub fn default_tcti_handle() -> tss_esapi::TctiNameConf {
    tss_esapi::TctiNameConf::from_environment_variable()
        .unwrap_or(tss_esapi::TctiNameConf::Tabrmd(TabrmdConfig::default()))
}
/// Represents a loaded TPM object (e.g., a key or primary object).
#[derive(Clone)]
pub struct TpmObjectHandle {
    handle: ObjectHandle,
    ctx: *mut tss_esapi::Context,
}

impl TpmObjectHandle {
    /// Creates a new `TpmObjectHandle` with the given handle and context.
    pub fn new(handle: ObjectHandle, ctx: *mut tss_esapi::Context) -> Self {
        Self { handle, ctx }
    }

    /// Returns the underlying TPM object handle.
    pub fn handle(&self) -> ObjectHandle {
        self.handle
    }
}

impl Drop for TpmObjectHandle {
    fn drop(&mut self) {
        // Unload the TPM object when the handle is dropped
        unsafe {
            if let Some(ctx) = self.ctx.as_mut() {
                if let Err(e) = ctx.flush_context(self.handle) {
                    eprintln!("Failed to flush TPM object handle: {}", e);
                }
            } else {
                eprintln!("Failed to flush TPM object handle: context pointer was null");
            }
        }
    }
}

pub struct TpmManagerHandle {
    ctx: tss_esapi::Context,
    primary_handle: TpmObjectHandle,
    rsa_handle: RefCell<Option<TpmObjectHandle>>,
}

impl TpmManagerHandle {
    /// Creates a new `TpmManagerHandle` with the given context and primary handle.
    pub fn new(ctx: tss_esapi::Context, primary_handle: TpmObjectHandle) -> Self {
        Self {
            ctx,
            primary_handle,
            rsa_handle: RefCell::new(None),
        }
    }

    /// Returns a reference to the primary TPM object handle.
    pub fn primary_handle(&self) -> &TpmObjectHandle {
        &self.primary_handle
    }

    /// Sets the RSA handle, replacing any existing one.
    pub fn set_rsa_handle(&self, rsa_handle: TpmObjectHandle) {
        *self.rsa_handle.borrow_mut() = Some(rsa_handle);
    }

    /// Returns a clone of the currently loaded RSA key handle, if present.
    pub fn current_rsa_handle(&self) -> Option<TpmObjectHandle> {
        self.rsa_handle.borrow().clone()
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
        let rsa_params = PublicRsaParametersBuilder::new_restricted_decryption_key(
            SymmetricDefinitionObject::AES_128_CFB, // Use AES_128_CFB for symmetric encryption
            RsaKeyBits::Rsa2048, // Convert key size to RsaKeyBits
            RsaExponent::default(), // Default exponent (65537)
        )
        .build()
        .unwrap();

        println!("[KeyPairGen] Generating RSA key with parameters: {:?}", rsa_params);

        // Child key attributes exactly like tpm2-tools: fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt
        let object_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(false) // No restricted for child
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

        println!("[KeyPairGen] Public area for RSA key: {:?}", public);

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
            &mut self.ctx,
        );
        self.set_rsa_handle(tpm_object_handle.clone());
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
            &mut self.ctx,
        );
        self.set_rsa_handle(tpm_object_handle.clone());
        Ok(tpm_object_handle)
    }

    /// Encrypts data using the currently loaded RSA key in the TPM.
    pub fn rsa_encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
        use tss_esapi::interface_types::algorithm::RsaDecryptAlgorithm;
        use tss_esapi::structures::Data;
        let rsa_handle = self
            .current_rsa_handle()
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ))?;
        let scheme = RsaDecryptionScheme::create(RsaDecryptAlgorithm::RsaEs, None)?;
        let data = Data::try_from(plaintext)?;
        let khandle = KeyHandle::from(rsa_handle.handle().value());
        let (pubkey, name1, name2) = self.ctx.read_public(khandle)?;
        let pubkey_rsa = if let tss_esapi::structures::Public::Rsa { unique, .. } = pubkey {
            unique
        } else {
            return Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ));
        };
        let encrypted = self.ctx.rsa_encrypt(
            khandle, // message is a misnomer, this is the public key lol
            pubkey_rsa, scheme, data,
        )?;
        Ok(encrypted.value().to_vec())
    }

    /// Decrypts data using the currently loaded RSA key in the TPM.
    pub fn rsa_decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, tss_esapi::Error> {
        use tss_esapi::handles::KeyHandle;
        use tss_esapi::structures::{Data, RsaDecryptionScheme};
        let rsa_handle = self
            .current_rsa_handle()
            .ok_or(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ))?;
        let scheme = RsaDecryptionScheme::create(
            tss_esapi::interface_types::algorithm::RsaDecryptAlgorithm::RsaEs,
            None,
        )?;
        let khandle = KeyHandle::from(rsa_handle.handle().value());
        let (pubkey, name1, name2) = self.ctx.read_public(khandle)?;
        let pubkey_rsa = if let tss_esapi::structures::Public::Rsa { unique, .. } = pubkey {
            unique
        } else {
            return Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::WrongParamSize,
            ));
        };
        let data = Data::try_from(ciphertext)?;
        let decrypted = self.ctx.rsa_decrypt(khandle, pubkey_rsa, scheme, data)?;
        Ok(decrypted.value().to_vec())
    }

    /// Create a new primary key in the TPM and return a new TpmManagerHandle.
    /// This will generate a storage primary key suitable for use as a parent for child keys.
    pub fn create_with_primary(ctx: tss_esapi::Context) -> Result<Self, tss_esapi::Error> {
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::{
            HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
        };
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::{
            PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent, RsaScheme,
            SymmetricDefinitionObject,
        };

        // Use working unrestricted parent configuration
        let object_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true) // Matches tpm2-tools
            .build()
            .unwrap();

        let rsa_params = PublicRsaParametersBuilder::new_restricted_decryption_key(
            SymmetricDefinitionObject::AES_128_CFB,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .build()
        .unwrap();

        println!("Creating primary key with RSA parameters: {:?}", rsa_params);
        println!("Object attributes: {:?}", object_attrs);

        let public = PublicBuilder::new()
            .with_object_attributes(object_attrs)
            .with_rsa_parameters(rsa_params)
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_rsa_unique_identifier(PublicKeyRsa::default()) // Use default for empty unique field
            .build()
            .unwrap();

        println!("Public area for primary key: {:?}", public);

        // Start an HMAC session for authorization
        let mut ctx = ctx;
        let session = ctx.start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            SymmetricDefinitionObject::AES_128_CFB.into(), // Use AES_128_CFB symmetric for session
            HashingAlgorithm::Sha256,
        )?;
        ctx.set_sessions((session, None, None));

        let create_primary_result =
            ctx.create_primary(Hierarchy::Endorsement, public, None, None, None, None)?;
        // Keep session active for child key operations

        let primary_handle =
            TpmObjectHandle::new(create_primary_result.key_handle.into(), &mut ctx);
        Ok(TpmManagerHandle::new(ctx, primary_handle))
    }
}

/// Export the RSA keypair into marshalled blobs (Vec<u8>).
pub fn export_rsa_keypair_blobs(
    public: &tss_esapi::structures::Public,
    private: &tss_esapi::structures::Private,
) -> Result<(Vec<u8>, Vec<u8>), tss_esapi::Error> {
    let pub_blob = public.marshall()?;
    let priv_blob = private;
    Ok((pub_blob, priv_blob.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tss_esapi::{Context, tcti_ldr::NetworkTPMConfig};

    #[test]
    fn test_tpm_object_handle() {
        let mut ctx = Context::new(default_tcti_handle()).unwrap();
        let primary_handle = TpmObjectHandle::new(ObjectHandle::from(0x81010001), &mut ctx);
        let tpm_handle = TpmManagerHandle::new(ctx, primary_handle);

        assert_eq!(tpm_handle.primary_handle().handle().value(), 0x81010001);
    }

    #[test]
    fn test_generate_rsa_key_pair_and_encrypt_decrypt() {
        let ctx = Context::new(tss_esapi::Tcti::Swtpm(NetworkTPMConfig::default()))
            .expect("Failed to create TPM context");
        let mut tpm_handle = TpmManagerHandle::create_with_primary(ctx).unwrap();

        // Generate a 2048-bit RSA key pair
        let (rsa_handle, public, private) = tpm_handle.generate_rsa_key_pair(2048).unwrap();

        // Export blobs and reload the key to test load_key
        let (pub_blob, priv_blob) = export_rsa_keypair_blobs(&public, &private).unwrap();
        let loaded_handle = tpm_handle
            .load_key(public.clone(), private.clone())
            .expect("Failed to load key");

        // Silence unused variable warnings for test clarity
        let _ = rsa_handle;
        let _ = pub_blob;
        let _ = priv_blob;
        let _ = loaded_handle;

        // Test encryption and decryption
        let plaintext = b"hello TPM!";
        let ciphertext = tpm_handle
            .rsa_encrypt(plaintext)
            .expect("Encryption failed");
        assert_ne!(ciphertext, plaintext);

        let decrypted = tpm_handle
            .rsa_decrypt(&ciphertext)
            .expect("Decryption failed");
        assert_eq!(&decrypted[..plaintext.len()], plaintext);
    }

    #[test]
    fn test_export_rsa_keypair_blobs() {
        let ctx = Context::new(default_tcti_handle()).unwrap();
        let mut tpm_handle = TpmManagerHandle::create_with_primary(ctx).unwrap();
        let (_rsa_handle, public, private) = tpm_handle.generate_rsa_key_pair(2048).unwrap();
        let (pub_blob, priv_blob) = export_rsa_keypair_blobs(&public, &private).unwrap();
        assert!(!pub_blob.is_empty());
        assert!(!priv_blob.is_empty());
    }
}
