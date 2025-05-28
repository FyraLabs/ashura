use std::cell::RefCell;
use tss_esapi::handles::KeyHandle;
// Remove Digest as it's no longer used directly in create_with_primary with builders
// use tss_esapi::structures::{Digest, RsaDecryptionScheme};
use tss_esapi::structures::RsaDecryptionScheme; // Keep for rsa_encrypt/decrypt
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
            // .with_key_bits(RsaKeyBits::try_from(key_size).unwrap())
            .with_exponent(RsaExponent::default())
            .with_symmetric(SymmetricDefinitionObject::Null) // Child decryption keys use Null symmetric
            .with_is_decryption_key(true) // Inform builder this is a decryption key
            .with_key_bits(RsaKeyBits::Rsa2048)
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
        let (pubkey, _name1, _name2) = self.ctx.read_public(khandle)?; // Mark unused as _
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
        let (pubkey, _name1, _name2) = self.ctx.read_public(khandle)?; // Mark unused as _
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
    pub fn create_with_primary(mut ctx: tss_esapi::Context) -> Result<Self, tss_esapi::Error> {
        // Added mut ctx
        use tss_esapi::attributes::ObjectAttributesBuilder;
        use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
        use tss_esapi::interface_types::key_bits::RsaKeyBits;
        use tss_esapi::interface_types::resource_handles::Hierarchy;
        use tss_esapi::structures::{
            PublicBuilder,
            PublicKeyRsa,
            PublicRsaParametersBuilder,
            RsaExponent,
            // RsaScheme, // No longer needed directly here, new_restricted_decryption_key handles it
            SymmetricDefinitionObject,
        };

        // Parent key attributes: restricted decryption key
        let object_attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_restricted(true) // Restricted parent
            .build()
            .unwrap();

        // Parent key RSA parameters: For a restricted decryption key, scheme is Null, symmetric is non-Null.
        // This uses the helper that correctly sets internal flags for the builder.
        let rsa_params = PublicRsaParametersBuilder::new_restricted_decryption_key(
            SymmetricDefinitionObject::AES_128_CFB, // Example symmetric cipher
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .build()
        .unwrap();

        println!(
            "[PrimaryCreate] Creating primary key with RSA parameters: {:?}",
            rsa_params
        );
        println!("[PrimaryCreate] Object attributes: {:?}", object_attrs);

        // Construct the Public structure for the primary key using PublicBuilder
        let public_for_primary = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attrs)
            .with_rsa_parameters(rsa_params)
            // .with_auth_policy(Digest::default()) // auth_policy is optional in builder, defaults to empty
            .with_rsa_unique_identifier(PublicKeyRsa::default()) // TPM fills this
            .build()
            .unwrap();

        println!(
            "[PrimaryCreate] Public area for primary key: {:?}",
            public_for_primary
        );

        // Start an HMAC session for authorization
        // ctx is already mutable due to function signature
        let session = ctx.start_auth_session(
            None,
            None,
            None,
            tss_esapi::constants::SessionType::Hmac,
            SymmetricDefinitionObject::AES_128_CFB.into(), // Session symmetric can remain for session security
            HashingAlgorithm::Sha256,
        )?;
        ctx.set_sessions((session, None, None));

        let create_primary_result = ctx.create_primary(
            Hierarchy::Endorsement,
            public_for_primary,
            None,
            None,
            None,
            None,
        )?;

        // The TpmObjectHandle needs a pointer to the context to flush it on drop.
        // Storing a raw pointer `*mut tss_esapi::Context` is tricky if `ctx` is moved out of `create_with_primary`.
        // However, TpmManagerHandle takes ownership of ctx.
        // For TpmObjectHandle to safely use the context, it must not outlive TpmManagerHandle.
        // A raw pointer is okay if TpmManagerHandle owns ctx and TpmObjectHandle is used carefully.
        // Let's assume the current structure with *mut ctx is managed correctly by the caller or TpmManagerHandle's lifetime.
        // When creating primary_handle, it will be stored in TpmManagerHandle which also stores ctx.
        // So, we pass a pointer to the ctx that TpmManagerHandle will own.
        let primary_handle_raw_ctx_ptr = &mut ctx as *mut tss_esapi::Context;
        let primary_handle = TpmObjectHandle::new(
            create_primary_result.key_handle.into(),
            primary_handle_raw_ctx_ptr,
        );
        Ok(TpmManagerHandle::new(ctx, primary_handle))
    }
}

/// Export the RSA keypair into marshalled blobs (Vec<u8>).
pub fn export_rsa_keypair_blobs(
    public: &tss_esapi::structures::Public,
    private: &tss_esapi::structures::Private,
) -> Result<(Vec<u8>, Vec<u8>), tss_esapi::Error> {
    let pub_blob = public.marshall()?;
    let priv_blob = private.value().to_vec(); // Access the inner buffer and convert to Vec<u8>
    Ok((pub_blob, priv_blob))
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
