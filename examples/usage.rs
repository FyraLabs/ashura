use ashura::crypt::{MasterKey, SessionKey};
use ashura::kv::{KvStore, SecretCollection};
use ashura::secret::Secret;
use tss_esapi::Tcti;
use tss_esapi::tcti_ldr::TabrmdConfig;

/// # Ashura Usage Example: Basic and MFA-Protected Secrets
///
/// This example demonstrates:
/// 1. Basic secret encryption/decryption (no MFA)
/// 2. MFA-protected secret encryption/decryption
/// 3. How to properly implement multi-factor authentication with HKDF
///
/// ## MFA Implementation Guide:
///
/// ### Encryption (Creating MFA-protected secrets):
/// 1. Start with base session key (Master Key + Secondary Salt)
/// 2. Collect MFA inputs from user (TOTP, hardware tokens, biometrics, etc.)
/// 3. Derive salts from each MFA input
/// 4. Extend session key sequentially: key = HKDF(key, mfa_salt) for each MFA factor
/// 5. Use extended session key to encrypt the secret
/// 6. Store MFA source names in secret metadata for decryption reference
///
/// ### Decryption (Accessing MFA-protected secrets):
/// 1. Retrieve secret and check mfa_sources field
/// 2. For each required MFA source, prompt user for fresh input
/// 3. Derive salts from MFA inputs (same derivation as during encryption)
/// 4. Recreate extended session key by applying MFA salts IN THE SAME ORDER
/// 5. Use recreated extended session key to decrypt the secret
///
/// ### Security Notes:
/// - MFA salts should be derived from actual authentication events, not stored
/// - Order of MFA application matters - must be consistent between encrypt/decrypt
/// - Each MFA factor should provide sufficient entropy (avoid weak sources)
/// - Consider using PBKDF2/Argon2 for password-based MFA factors
/// - Hardware tokens (YubiKey) provide excellent entropy and tamper resistance
fn default_tcti() -> Tcti {
    // Default TCTI configuration for our session,
    // We'll be using tabrmd as an example here because desktop applications,
    // some may want to just use /dev/tpmrm0 directly, but we're not
    // here to judge.
    Tcti::from_environment_variable().unwrap_or(Tcti::Tabrmd(TabrmdConfig::default()))
}

pub fn new_masterkey(tcti: &Tcti) -> MasterKey {
    let context = tss_esapi::Context::new(tcti.clone()).expect("Failed to create TSS context");
    MasterKey::generate(context)
}

pub fn main() {
    // You need to feed the TCTI to create TPM contexts
    let tcti = default_tcti();
    // setup before we actually do anything
    // Create a temporary directory for the kv store
    let kv_store_path = "tmp/kvstore";

    if std::path::Path::new(kv_store_path).exists() {
        std::fs::remove_dir_all(kv_store_path).expect("Failed to remove existing kvstore path");
    }
    std::fs::create_dir_all(kv_store_path).expect("Failed to create kvstore path");

    // let's actually create the kv store
    let kv_store = KvStore::new("tmp/kvstore".into());

    // Now, let's make a secret collection
    // this is just a Sled database, so we can use it like a normal key-value store,
    // but since this is a secret store, we will encrypt them first

    // new_init will create a new collection with a sealed master key
    let collection = SecretCollection::new_init(kv_store, "my_secret_collection", &tcti)
        .expect("Failed to create secret collection");

    // get the new master key for the collection
    let sealed_master_key = collection
        .get_sealed_master_key()
        .expect("Failed to get sealed master key")
        .expect("No sealed master key found");

    // Now we can create a session key from the master key
    let tpm_context = tss_esapi::Context::new(tcti.clone()).expect("Failed to create TSS context");
    let master_key = sealed_master_key
        .decrypt(tpm_context)
        .expect("Failed to decrypt sealed master key");

    // Generate a secondary salt for the session key
    let secondary_salt = vec![0u8; 32]; // In production, this should be properly generated and stored
    let session_key = SessionKey::new(master_key, None, &secondary_salt);

    // === BASIC ENCRYPTION/DECRYPTION (No MFA) ===
    // Basic encryption/decryption example

    let basic_plaintext = b"Hello, world! This is my basic secret.".to_vec();
    println!(
        "Basic plaintext: {:?}",
        String::from_utf8_lossy(&basic_plaintext)
    );

    let basic_secret = Secret::from_plaintext_blank(
        basic_plaintext.clone(),
        session_key.clone(),
        secondary_salt.clone(),
    );

    basic_secret
        .commit_to_collection(&collection, "basic_secret")
        .expect("Failed to commit basic secret");

    let retrieved_basic = collection
        .get_secret("basic_secret")
        .expect("Failed to get basic secret")
        .expect("Basic secret not found");

    let (decrypted_basic, _updated_secret) = retrieved_basic
        .decrypt_auto_nonce(&session_key)
        .expect("Failed to decrypt basic secret");

    assert_eq!(decrypted_basic, basic_plaintext);
    println!("✅ Basic secret encrypted/decrypted successfully!");

    // === MFA-PROTECTED ENCRYPTION/DECRYPTION ===
    // MFA-protected encryption/decryption example

    // In a real application, these MFA salts would come from:
    // - Password hashes (PBKDF2/Argon2 of user passwords)
    // - PIN hashes (numeric codes that don't change)
    // - Hardware token static keys (device-specific keys)
    // - Biometric template hashes (consistent fingerprint/face templates)
    // - Smart card certificates (consistent cryptographic material)
    // Simulating consistent MFA sources:
    //   - password_hash: PBKDF2 hash of user password
    //   - pin_hash: Argon2 hash of numeric PIN
    //   - device_key: Hardware-bound device identifier

    let mfa_sources = vec![
        "password_hash".to_string(),
        "pin_hash".to_string(),
        "device_key".to_string(),
    ];

    // Simulate consistent MFA salts derived from stable inputs
    // These would be the SAME every time the user provides the same credentials
    use sha2::{Digest, Sha256};

    // Password hash - would be PBKDF2/Argon2 in production
    let user_password = "my_secure_password123";
    let password_salt = Sha256::digest(format!("password:{}", user_password).as_bytes()).to_vec();

    // PIN hash - would be Argon2 in production for rate limiting
    let user_pin = "1234";
    let pin_salt = Sha256::digest(format!("pin:{}", user_pin).as_bytes()).to_vec();

    // Device key - could be TPM-bound, MAC address hash, etc.
    let device_id = "device_12345_mac_aa:bb:cc:dd:ee:ff";
    let device_salt = Sha256::digest(format!("device:{}", device_id).as_bytes()).to_vec();

    let mfa_salts = [&password_salt, &pin_salt, &device_salt];

    // Extending session key with MFA salts...

    // Create an extended session key by applying all MFA salts in sequence
    let mut extended_session_key = session_key.clone();
    for mfa_salt in mfa_salts.iter() {
        // Applying MFA salt to extend session key
        extended_session_key = extended_session_key.expand(mfa_salt);
    }

    // Session key extended successfully with MFA factors

    // === ENCRYPTION PHASE ===
    // MFA encryption phase

    let original_plaintext = b"Hello, world! This is my MFA-protected secret data.".to_vec();
    println!(
        "MFA-protected plaintext: {:?}",
        String::from_utf8_lossy(&original_plaintext)
    );

    // Create a secret with MFA protection using the extended session key
    let secret = Secret::from_plaintext_with_options(
        original_plaintext.clone(),
        extended_session_key.clone(),
        secondary_salt.clone(),
        mfa_sources.clone(), // Store which MFA sources are required
        true,                // MFA is enabled
        Some("My MFA-protected secret description".to_string()),
        std::collections::BTreeMap::new(),
    );

    // Secret created successfully
    println!("Secret Metadata: {:?}", secret.metadata);
    println!("Secret Ciphertext (encrypted): {:?}", secret.ciphertext());
    println!("Ciphertext length: {} bytes", secret.ciphertext().len());

    // Store the MFA-protected secret in the collection
    secret
        .commit_to_collection(&collection, "mfa_secret")
        .expect("Failed to commit secret to collection");

    // Secret stored in collection successfully

    // === MFA RETRIEVAL PHASE ===
    // MFA retrieval phase

    // Retrieve the MFA-protected secret from the collection
    let retrieved_secret = collection
        .get_secret("mfa_secret")
        .expect("Failed to get secret")
        .expect("Secret not found");

    // MFA-protected secret retrieved from collection successfully
    println!("Retrieved secret metadata: {:?}", retrieved_secret.metadata);
    println!("MFA enabled: {}", retrieved_secret.mfa);
    println!("Required MFA sources: {:?}", retrieved_secret.mfa_sources);

    // === MFA DECRYPTION PHASE ===
    // MFA decryption phase

    // IMPORTANT: To decrypt an MFA-protected secret, we must:
    // 1. Re-create the same extended session key using the SAME MFA salts
    // 2. Apply them in the SAME ORDER as during encryption

    // Re-creating extended session key for decryption...
    // Re-authenticating with MFA sources

    // In a real application, you would prompt the user for the same credentials:
    // - Ask for the same password (hash it the same way)
    // - Request the same PIN (hash it the same way)
    // - Read the same device identifier

    // For this demo, we're using the same derived salts because the user provided
    // the same credentials (password, PIN, device) - this is how it works in practice
    let mut decryption_session_key = session_key.clone();
    for (_source, mfa_salt) in retrieved_secret.mfa_sources.iter().zip(mfa_salts.iter()) {
        // Authenticated with MFA source and applying derived salt from user credential
        decryption_session_key = decryption_session_key.expand(mfa_salt);
    }

    // Extended session key recreated with MFA factors

    // Decrypt the secret back to plaintext using the extended session key
    let (decrypted_plaintext, _updated_secret) = retrieved_secret
        .decrypt_auto_nonce(&decryption_session_key)
        .expect("Failed to decrypt secret");

    // MFA-protected secret decrypted successfully
    println!(
        "Decrypted plaintext: {:?}",
        String::from_utf8_lossy(&decrypted_plaintext)
    );

    // Verify that the decrypted data matches the original
    assert_eq!(
        decrypted_plaintext, original_plaintext,
        "Decrypted data must match original plaintext!"
    );
    println!("✅ SUCCESS: Decrypted data matches original plaintext!");

    // === MFA SECURITY SUMMARY ===
    // MFA Protection Analysis:
    //   - Basic secret: No MFA required
    //   - MFA secret: Multiple factors required
    //   - Required MFA sources: Listed in secret metadata
    //   - Decryption requires ALL MFA factors in correct order
    //   - Each MFA factor extends the session key via HKDF

    // HKDF Key Derivation Flow:
    //   1. Master Key (TPM-sealed)
    //   2. + Secondary Salt → Base Session Key
    //   3. + Password Hash → Extended Session Key (Level 1)
    //   4. + PIN Hash → Extended Session Key (Level 2)
    //   5. + Device Key → Extended Session Key (Level 3)
    //   6. + Secret Salt → Secret-Specific Key
    //   7. → AES-GCM Encryption/Decryption

    // === FINAL SUMMARY ===
    println!(
        "Original plaintext length: {} bytes",
        original_plaintext.len()
    );
    println!(
        "Ciphertext length: {} bytes",
        retrieved_secret.ciphertext().len()
    );
    println!(
        "Decrypted plaintext length: {} bytes",
        decrypted_plaintext.len()
    );
    println!("Secret IV (nonce): {:?}", retrieved_secret.iv());
    println!(
        "Secret salt length: {} bytes",
        retrieved_secret.salt().len()
    );
    println!(
        "Secondary salt length: {} bytes",
        retrieved_secret.secondary_salt().len()
    );
}
