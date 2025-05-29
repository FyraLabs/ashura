//! # Easy Stateful Encryption Example
use ashura::crypt::SessionKey;
use ashura::kv::{KvStore, SecretCollection};
use ashura::secret::Secret;
use tss_esapi::Tcti;
use tss_esapi::tcti_ldr::TabrmdConfig;

fn default_tcti() -> Tcti {
    Tcti::from_environment_variable().unwrap_or(Tcti::Tabrmd(TabrmdConfig::default()))
}

pub fn main() {
    let tcti = default_tcti();

    // Setup storage
    let kv_store_path = "tmp/easy_demo";
    if std::path::Path::new(kv_store_path).exists() {
        std::fs::remove_dir_all(kv_store_path).expect("Failed to remove existing demo path");
    }
    std::fs::create_dir_all(kv_store_path).expect("Failed to create demo path");

    let kv_store = KvStore::new(kv_store_path.into());
    let collection = SecretCollection::new_init(kv_store, "easy_demo", &tcti)
        .expect("Failed to create collection");

    // Get session key
    let sealed_master_key = collection
        .get_sealed_master_key()
        .expect("Failed to get sealed master key")
        .expect("No sealed master key found");

    let tmp_context = tss_esapi::Context::new(tcti.clone()).expect("Failed to create TSS context");
    let master_key = sealed_master_key
        .decrypt(tmp_context)
        .expect("Failed to decrypt sealed master key");

    let secondary_salt = vec![0u8; 32];
    let session_key = SessionKey::new(master_key, None, &secondary_salt);

    println!("=== Easy Stateful Encryption Demo ===\n");

    // === METHOD 1: Collection API (Recommended) ===
    println!("Method 1: Using Collection API (Easiest)");

    // Create and store secret
    let basic_secret = Secret::from_plaintext_blank(
        b"Hello, stateful world!".to_vec(),
        session_key.clone(),
        secondary_salt.clone(),
    );

    basic_secret
        .commit_to_collection(&collection, "easy_secret")
        .expect("Failed to commit secret");

    println!("✓ Secret stored");

    // Decrypt using collection API - handles everything automatically
    let plaintext = collection
        .decrypt_secret_auto("easy_secret", &session_key)
        .expect("Failed to decrypt secret");

    println!("✓ Decrypted: {}", String::from_utf8_lossy(&plaintext));
    println!("✓ State automatically updated in storage\n");

    // === METHOD 2: Direct Secret API with Auto-Nonce ===
    println!("Method 2: Direct Secret API with Auto-Nonce");

    let secret2 = Secret::from_plaintext_blank(
        b"Another secret message".to_vec(),
        session_key.clone(),
        secondary_salt.clone(),
    );

    secret2
        .commit_to_collection(&collection, "direct_secret")
        .expect("Failed to commit secret");

    // Retrieve and decrypt with auto-nonce
    let retrieved = collection
        .get_secret("direct_secret")
        .expect("Failed to get secret")
        .expect("Secret not found");

    let (plaintext, updated_secret) = retrieved
        .decrypt_auto_nonce(&session_key)
        .expect("Failed to decrypt");

    println!("✓ Decrypted: {}", String::from_utf8_lossy(&plaintext));

    // Store the updated secret
    collection
        .set_secret_raw("direct_secret", updated_secret)
        .expect("Failed to update secret");

    println!("✓ State manually updated in storage\n");

    // === METHOD 3: One-Time Secret ===
    println!("Method 3: One-Time Secret (Built-in Access Control)");

    let one_time = Secret::from_plaintext_one_time(
        b"This can only be read once!".to_vec(),
        session_key.clone(),
        secondary_salt.clone(),
    );

    one_time
        .commit_to_collection(&collection, "one_time")
        .expect("Failed to commit one-time secret");

    // First access - should work
    match collection.decrypt_secret_auto("one_time", &session_key) {
        Ok(plaintext) => {
            println!("✓ First access: {}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => println!("✗ First access failed: {}", e),
    }

    // Second access - should fail
    match collection.decrypt_secret_auto("one_time", &session_key) {
        Ok(_) => println!("✗ Second access should have failed!"),
        Err(e) => println!("✓ Second access blocked: {}", e),
    }
}
