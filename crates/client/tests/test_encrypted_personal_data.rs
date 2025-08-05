use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use tempfile::TempDir;
use tracing::info;
use zoe_wire_protocol::{Ed25519EncryptedContent, MnemonicPhrase, generate_ed25519_from_mnemonic};

/// Test data structure matching the main example
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct PersonalData {
    name: String,
    email: String,
    notes: String,
    created_at: u64,
}

/// Test the complete encryption/decryption cycle without relay dependency
async fn test_encryption_cycle() -> Result<()> {
    info!("🧪 Testing encryption/decryption cycle...");

    // Create test data
    let test_data = PersonalData {
        name: "Test User".to_string(),
        email: "test@example.com".to_string(),
        notes: "This is a test of encrypted personal data storage".to_string(),
        created_at: 1640995200,
    };

    // Generate a mnemonic phrase
    let mnemonic = MnemonicPhrase::generate()?;
    info!("📝 Generated test mnemonic: {}", mnemonic.phrase());

    // Generate ed25519 signing key from mnemonic (much simpler - only one key needed!)
    let signing_key = generate_ed25519_from_mnemonic(
        &mnemonic,
        "", // no passphrase
        "test-encrypted-personal-data",
    )?;

    // Test 1: Serialize and encrypt the data directly with ed25519 key (using postcard)
    let plaintext = postcard::to_stdvec(&test_data)?;
    info!("📦 Serialized test data: {} bytes", plaintext.len());

    let encrypted_content = Ed25519EncryptedContent::encrypt(&plaintext, &signing_key)?;
    info!(
        "🔒 Encrypted data with nonce: {:02x?}",
        encrypted_content.nonce
    );

    // Test 2: Decrypt and deserialize the data using the same ed25519 key (using postcard)
    let decrypted_plaintext = encrypted_content.decrypt(&signing_key)?;
    let decrypted_data: PersonalData = postcard::from_bytes(&decrypted_plaintext)?;

    // Test 3: Verify data integrity
    assert_eq!(test_data, decrypted_data);
    info!("✅ Data integrity verified!");

    // Test 4: Verify key determinism - same mnemonic produces same keys (much simpler!)
    let signing_key_2 =
        generate_ed25519_from_mnemonic(&mnemonic, "", "test-encrypted-personal-data")?;

    // The encryption is deterministic from the ed25519 key itself - no salt needed!
    assert_eq!(signing_key.to_bytes(), signing_key_2.to_bytes());

    // Test that same key produces different ciphertext (due to random nonces) but can decrypt both
    let encrypted_again = Ed25519EncryptedContent::encrypt(&plaintext, &signing_key)?;
    let decrypted_again = encrypted_again.decrypt(&signing_key)?;
    let data_again: PersonalData = postcard::from_bytes(&decrypted_again)?;

    assert_eq!(test_data, data_again); // Same data
    assert_ne!(encrypted_content.nonce, encrypted_again.nonce); // Different nonces
    assert_ne!(encrypted_content.ciphertext, encrypted_again.ciphertext); // Different ciphertext

    info!("✅ Key determinism verified - same mnemonic always produces same ed25519 key!");

    // Test 5: Verify different data produces different ciphertext
    let different_data = PersonalData {
        name: "Different User".to_string(),
        email: "different@example.com".to_string(),
        notes: "Different notes".to_string(),
        created_at: 1640995300,
    };

    let different_plaintext = postcard::to_stdvec(&different_data)?;
    let different_encrypted = Ed25519EncryptedContent::encrypt(&different_plaintext, &signing_key)?;

    // Nonces should be different (random)
    assert_ne!(encrypted_content.nonce, different_encrypted.nonce);
    // Ciphertext should be different
    assert_ne!(encrypted_content.ciphertext, different_encrypted.ciphertext);
    info!("✅ Different data produces different ciphertext!");

    println!("\n🎉 All encryption tests passed!");
    println!("📋 Test Results:");
    println!("   Original: {test_data:?}");
    println!("   Decrypted: {decrypted_data:?}");
    println!("   Keys match: ✅");
    println!("   Data integrity: ✅");
    println!("   Nonce uniqueness: ✅");

    Ok(())
}

/// Test mnemonic persistence and recovery
async fn test_mnemonic_persistence() -> Result<()> {
    info!("🧪 Testing mnemonic persistence...");

    let temp_dir = TempDir::new()?;
    let keypair_file = temp_dir.path().join("test_keypair.json");

    // Test data
    let test_data = PersonalData {
        name: "Persistent Test".to_string(),
        email: "persistent@example.com".to_string(),
        notes: "Testing persistence".to_string(),
        created_at: 1640995400,
    };

    // Generate and save mnemonic
    let original_mnemonic = MnemonicPhrase::generate()?;
    let keypair_info = serde_json::json!({
        "mnemonic_phrase": original_mnemonic.phrase(),
        "public_key_hex": "test_public_key",
        "custom_store_key": 1001
    });

    fs::write(&keypair_file, serde_json::to_string_pretty(&keypair_info)?)?;
    info!("💾 Saved test keypair to: {:?}", keypair_file);

    // Load and verify mnemonic
    let keypair_json = fs::read_to_string(&keypair_file)?;
    let loaded_info: serde_json::Value = serde_json::from_str(&keypair_json)?;
    let mnemonic_phrase = loaded_info["mnemonic_phrase"].as_str().unwrap();

    let recovered_mnemonic =
        MnemonicPhrase::from_phrase(mnemonic_phrase, bip39::Language::English)?;

    // Verify same mnemonic produces same keys (much simpler with ed25519!)
    let original_signing_key =
        generate_ed25519_from_mnemonic(&original_mnemonic, "", "persistence-test")?;

    let recovered_signing_key =
        generate_ed25519_from_mnemonic(&recovered_mnemonic, "", "persistence-test")?;

    assert_eq!(
        original_signing_key.to_bytes(),
        recovered_signing_key.to_bytes()
    );
    info!("✅ Mnemonic persistence verified!");

    // Test encryption/decryption with recovered key
    let plaintext = postcard::to_stdvec(&test_data)?;
    let encrypted = Ed25519EncryptedContent::encrypt(&plaintext, &original_signing_key)?;
    let decrypted = encrypted.decrypt(&recovered_signing_key)?;
    let recovered_data: PersonalData = postcard::from_bytes(&decrypted)?;

    assert_eq!(test_data, recovered_data);
    info!("✅ Cross-key encryption/decryption verified!");

    println!("\n🎉 Mnemonic persistence tests passed!");
    println!("📋 Results:");
    println!("   Mnemonic saved and loaded: ✅");
    println!("   Key recovery: ✅");
    println!("   Cross-key operations: ✅");

    Ok(())
}

/// Test security properties
async fn test_security_properties() -> Result<()> {
    info!("🧪 Testing security properties...");

    let data1 = PersonalData {
        name: "User 1".to_string(),
        email: "user1@example.com".to_string(),
        notes: "First user data".to_string(),
        created_at: 1640995500,
    };

    let data2 = PersonalData {
        name: "User 2".to_string(),
        email: "user2@example.com".to_string(),
        notes: "Second user data".to_string(),
        created_at: 1640995600,
    };

    // Different mnemonics should produce different keys
    let mnemonic1 = MnemonicPhrase::generate()?;
    let mnemonic2 = MnemonicPhrase::generate()?;

    let key1 = generate_ed25519_from_mnemonic(&mnemonic1, "", "security-test")?;
    let key2 = generate_ed25519_from_mnemonic(&mnemonic2, "", "security-test")?;

    assert_ne!(key1.to_bytes(), key2.to_bytes());
    info!("✅ Different mnemonics produce different keys!");

    // Key1 should not decrypt data encrypted with Key2
    let plaintext1 = postcard::to_stdvec(&data1)?;
    let plaintext2 = postcard::to_stdvec(&data2)?;

    let encrypted1 = Ed25519EncryptedContent::encrypt(&plaintext1, &key1)?;
    let encrypted2 = Ed25519EncryptedContent::encrypt(&plaintext2, &key2)?;

    // Should be able to decrypt with correct key
    let decrypted1 = encrypted1.decrypt(&key1)?;
    let recovered_data1: PersonalData = postcard::from_bytes(&decrypted1)?;
    assert_eq!(data1, recovered_data1);

    // Should NOT be able to decrypt with wrong key
    let wrong_key_result = encrypted2.decrypt(&key1);
    assert!(wrong_key_result.is_err());
    info!("✅ Wrong key cannot decrypt data!");

    // Test nonce uniqueness
    let encrypted1_again = Ed25519EncryptedContent::encrypt(&plaintext1, &key1)?;
    assert_ne!(encrypted1.nonce, encrypted1_again.nonce);
    assert_ne!(encrypted1.ciphertext, encrypted1_again.ciphertext);
    info!("✅ Nonce uniqueness ensures different ciphertext!");

    println!("\n🎉 Security property tests passed!");
    println!("📋 Results:");
    println!("   Key isolation: ✅");
    println!("   Decryption fails with wrong key: ✅");
    println!("   Nonce uniqueness: ✅");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("test_encrypted_personal_data=info")
        .init();

    println!("🔐 Encrypted Personal Data - Comprehensive Tests");
    println!("===============================================\n");

    // Run all tests
    test_encryption_cycle().await?;
    println!();

    test_mnemonic_persistence().await?;
    println!();

    test_security_properties().await?;
    println!();

    println!("🎉 ALL TESTS PASSED! 🎉");
    println!("\nThe encrypted personal data system is working correctly:");
    println!("• ✅ Encryption/decryption cycle");
    println!("• ✅ Mnemonic-based key derivation");
    println!("• ✅ Key persistence and recovery");
    println!("• ✅ Security isolation");
    println!("• ✅ Nonce-based security");
    println!("\nReady for relay integration! 🚀");

    Ok(())
}
