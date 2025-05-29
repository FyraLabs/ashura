//! # Ashura Stateful Encryption Example
//!
//! This example demonstrates the stateful encryption features that provide
//! cryptographic replay protection without requiring application-level tracking.
//!
//! ## Key Features Demonstrated:
//! 1. **One-time secrets** - Can only be decrypted once, then become permanently inaccessible
//! 2. **Limited-use secrets** - Can be decrypted a specific number of times
//! 3. **Nonce-based replay protection** - Each decryption requires a monotonically increasing nonce
//! 4. **Automatic re-encryption** - After each decryption, the secret is re-encrypted with new state
//! 5. **Collection-level stateful operations** - Automatic storage management with state updates
//! 6. **MFA + Stateful encryption** - Combining multi-factor authentication with stateful features
//!
//! ## Security Properties:
//! - **Cryptographic replay protection**: Old ciphertext becomes invalid after state updates
//! - **Forward secrecy**: Previous states cannot be used to decrypt newer versions
//! - **Access counting**: Built-in tracking of how many times a secret has been accessed
//! - **Nonce progression**: Prevents reuse of old access tokens/nonces

use ashura::crypt::SessionKey;
use ashura::kv::{KvStore, SecretCollection};
use ashura::secret::{Secret, StatefulSecretError};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tss_esapi::Tcti;
use tss_esapi::tcti_ldr::TabrmdConfig;

fn default_tcti() -> Tcti {
    // Default TCTI configuration for our session,
    // We'll be using tabrmd as an example here because desktop applications,
    // some may want to just use /dev/tpmrm0 directly, but we're not
    // here to judge.
    Tcti::from_environment_variable().unwrap_or(Tcti::Tabrmd(TabrmdConfig::default()))
}

pub fn main() {
    // You need to feed the TCTI to create TPM contexts
    let tcti = default_tcti();

    // Setup before we actually do anything
    // Create a temporary directory for the kv store
    let kv_store_path = "tmp/stateful_demo";

    if std::path::Path::new(kv_store_path).exists() {
        std::fs::remove_dir_all(kv_store_path)
            .expect("Failed to remove existing stateful demo path");
    }
    std::fs::create_dir_all(kv_store_path).expect("Failed to create stateful demo path");

    // Let's actually create the kv store
    let kv_store = KvStore::new(kv_store_path.into());

    // Now, let's make a secret collection
    // this is just a Sled database, so we can use it like a normal key-value store,
    // but since this is a secret store, we will encrypt them first

    // new_init will create a new collection with a sealed master key
    let collection = SecretCollection::new_init(kv_store, "stateful_demo_collection", &tcti)
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

    println!("=== Ashura Stateful Encryption Demo ===\n");

    // === 1. ONE-TIME SECRETS ===
    println!("1. Creating One-Time Secret (Maximum 1 decryption)");

    let one_time_secret = Secret::from_plaintext_one_time(
        b"This secret can only be read once!".to_vec(),
        session_key.clone(),
        secondary_salt.clone(),
    );

    one_time_secret
        .commit_to_collection(&collection, "one_time_secret")
        .expect("Failed to commit one-time secret");

    println!("   ✓ One-time secret created and stored");
    println!("   Access count: {}", one_time_secret.access_count);
    println!("   Max decryptions: {}", one_time_secret.max_decryptions);
    println!(
        "   Remaining: {:?}",
        one_time_secret.remaining_decryptions()
    );
    println!("   Is accessible: {}\n", one_time_secret.is_accessible());

    // Test the one-time secret
    println!("   Testing one-time access:");
    let retrieved_secret = collection
        .get_secret("one_time_secret")
        .expect("Failed to get one-time secret")
        .expect("One-time secret not found");

    match retrieved_secret.decrypt(&session_key, 1) {
        Ok((plaintext, updated_secret)) => {
            println!(
                "     ✓ First access successful: {}",
                String::from_utf8_lossy(&plaintext)
            );
            println!("     Updated access count: {}", updated_secret.access_count);

            // Store the updated secret
            collection
                .set_secret_raw("one_time_secret", updated_secret.clone())
                .expect("Failed to update one-time secret");

            // Try to access again - should fail
            match updated_secret.decrypt(&session_key, 2) {
                Err(StatefulSecretError::MaxDecryptionsReached { max }) => {
                    println!(
                        "     ✓ Second access blocked - max decryptions ({}) reached",
                        max
                    );
                }
                _ => println!("     ✗ Second access should have been blocked!"),
            }
        }
        Err(e) => println!("     ✗ First access failed: {:?}", e),
    }
    println!();

    // === 2. LIMITED-USE SECRETS ===
    println!("2. Creating Limited-Use Secret (Maximum 3 decryptions)");

    let limited_secret = Secret::from_plaintext_with_limit(
        b"This secret can be read 3 times maximum".to_vec(),
        session_key.clone(),
        secondary_salt.clone(),
        3,
    );

    limited_secret
        .commit_to_collection(&collection, "limited_secret")
        .expect("Failed to commit limited secret");

    println!("   ✓ Limited-use secret created and stored");
    println!("   Max decryptions: {}", limited_secret.max_decryptions);
    println!(
        "   Remaining: {:?}\n",
        limited_secret.remaining_decryptions()
    );

    // Test the limited secret multiple times
    println!("   Testing limited access (3 times max):");
    for attempt in 1..=4 {
        println!(
            "     Attempt {}: Trying to decrypt limited secret...",
            attempt
        );

        let current_secret = collection
            .get_secret("limited_secret")
            .expect("Failed to get limited secret")
            .expect("Limited secret not found");

        println!(
            "       Current access count: {}",
            current_secret.access_count
        );
        println!("       Last nonce: {}", current_secret.last_access_nonce);
        println!(
            "       Remaining: {:?}",
            current_secret.remaining_decryptions()
        );

        match current_secret.decrypt(&session_key, attempt) {
            Ok((plaintext, updated_secret)) => {
                println!("       ✓ Decryption successful!");
                println!("       Plaintext: {}", String::from_utf8_lossy(&plaintext));
                println!(
                    "       Updated access count: {}",
                    updated_secret.access_count
                );
                println!(
                    "       Updated last nonce: {}",
                    updated_secret.last_access_nonce
                );

                // Store the updated secret back to collection
                collection
                    .set_secret_raw("limited_secret", updated_secret)
                    .expect("Failed to update limited secret");

                // Verify old ciphertext is now invalid (replay protection)
                let old_decrypt_result = current_secret.decrypt(&session_key, attempt);
                if old_decrypt_result.is_err() {
                    println!("       ✓ Old ciphertext is now invalid (replay protection works!)");
                }
            }
            Err(StatefulSecretError::MaxDecryptionsReached { max }) => {
                println!("       ✗ Maximum decryptions ({}) reached", max);
            }
            Err(e) => {
                println!("       ✗ Decryption failed: {:?}", e);
            }
        }
        println!();
    }

    // === 3. NONCE-BASED REPLAY PROTECTION ===
    println!("3. Demonstrating Nonce-Based Replay Protection");

    // Create a fresh secret for nonce testing
    let nonce_test_secret = Secret::from_plaintext_blank(
        b"Testing nonce-based replay protection".to_vec(),
        session_key.clone(),
        secondary_salt.clone(),
    );

    nonce_test_secret
        .commit_to_collection(&collection, "nonce_test")
        .expect("Failed to commit nonce test secret");

    println!("   First decryption with nonce 5:");
    let secret = collection
        .get_secret("nonce_test")
        .expect("Failed to get nonce test secret")
        .expect("Nonce test secret not found");

    let (plaintext, updated_secret) = secret
        .decrypt(&session_key, 5)
        .expect("First nonce decryption should succeed");

    println!("     ✓ Success: {}", String::from_utf8_lossy(&plaintext));
    println!("     Access count: {}", updated_secret.access_count);
    println!("     Last nonce: {}", updated_secret.last_access_nonce);

    collection
        .set_secret_raw("nonce_test", updated_secret)
        .expect("Failed to update nonce test secret");

    println!("   Trying to replay with same nonce (5):");
    let secret = collection
        .get_secret("nonce_test")
        .expect("Failed to get nonce test secret")
        .expect("Nonce test secret not found");

    match secret.decrypt(&session_key, 5) {
        Err(StatefulSecretError::InvalidNonce {
            provided,
            required_min,
        }) => {
            println!(
                "     ✓ Replay blocked! Provided: {}, Required min: {}",
                provided, required_min
            );
        }
        _ => println!("     ✗ Replay protection failed!"),
    }

    println!("   Trying with lower nonce (3):");
    let secret = collection
        .get_secret("nonce_test")
        .expect("Failed to get nonce test secret")
        .expect("Nonce test secret not found");

    match secret.decrypt(&session_key, 3) {
        Err(StatefulSecretError::InvalidNonce {
            provided,
            required_min,
        }) => {
            println!(
                "     ✓ Lower nonce blocked! Provided: {}, Required min: {}",
                provided, required_min
            );
        }
        _ => println!("     ✗ Nonce validation failed!"),
    }

    println!("   Valid progression with nonce 10:");
    let secret = collection
        .get_secret("nonce_test")
        .expect("Failed to get nonce test secret")
        .expect("Nonce test secret not found");

    let (plaintext, updated_secret) = secret
        .decrypt(&session_key, 10)
        .expect("Valid nonce progression should succeed");

    println!("     ✓ Success: {}", String::from_utf8_lossy(&plaintext));
    println!("     Access count: {}", updated_secret.access_count);
    println!("     Last nonce: {}", updated_secret.last_access_nonce);

    collection
        .set_secret_raw("nonce_test", updated_secret)
        .expect("Failed to update nonce test secret");

    // === 4. COLLECTION-LEVEL STATEFUL API ===
    println!("\n4. Demonstrating Collection-Level Stateful API");

    // Use the collection's built-in decryption method
    println!("   Using collection.decrypt_secret():");
    match collection.decrypt_secret("nonce_test", &session_key, 15) {
        Ok(plaintext) => {
            println!("     ✓ Collection-level decryption successful!");
            println!("     Plaintext: {}", String::from_utf8_lossy(&plaintext));
            println!("     Secret automatically updated in storage");
        }
        Err(e) => {
            println!("     ✗ Collection-level decryption failed: {}", e);
        }
    }

    // === 5. MFA + STATEFUL ENCRYPTION ===
    println!("\n5. Demonstrating MFA + Stateful Encryption");

    // Create MFA-protected secret with stateful encryption
    let password_hash = Sha256::digest(b"user_password_123").to_vec();
    let pin_hash = Sha256::digest(b"1234").to_vec();

    let mut mfa_salts = BTreeMap::new();
    mfa_salts.insert("password".to_string(), password_hash);
    mfa_salts.insert("pin".to_string(), pin_hash);

    let _mfa_secret = collection
        .new_secret_for_collection(
            "mfa_stateful_secret",
            b"MFA + Stateful protected data".to_vec(),
            mfa_salts.clone(),
            &tcti,
        )
        .expect("Failed to create MFA + stateful secret");

    println!("   ✓ MFA + Stateful secret created");

    // Decrypt using collection's MFA method
    match collection.decrypt_secret_with_mfa("mfa_stateful_secret", &mfa_salts, 1, &tcti) {
        Ok(plaintext) => {
            println!("   ✓ MFA + Stateful decryption successful!");
            println!("   Plaintext: {}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => {
            println!("   ✗ MFA + Stateful decryption failed: {}", e);
        }
    }

    // Try second access with higher nonce
    match collection.decrypt_secret_with_mfa("mfa_stateful_secret", &mfa_salts, 2, &tcti) {
        Ok(plaintext) => {
            println!("   ✓ Second MFA + Stateful decryption successful!");
            println!("   Plaintext: {}", String::from_utf8_lossy(&plaintext));
        }
        Err(e) => {
            println!("   ✗ Second MFA + Stateful decryption failed: {}", e);
        }
    }
}
