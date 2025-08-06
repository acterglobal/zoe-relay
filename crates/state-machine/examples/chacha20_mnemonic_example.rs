use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use zoe_state_machine::{CreateGroupConfig, DigitalGroupAssistant, GroupSettings, MnemonicPhrase};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 ChaCha20-Poly1305 + Mnemonic Keyphrase Example");
    println!("===============================================\n");

    // Create a DGA instance
    let mut dga = DigitalGroupAssistant::new();

    // Create signing keys for users
    let mut rng = rand::thread_rng();
    let alice_key = SigningKey::generate(&mut rng);

    // Generate a mnemonic phrase for the group encryption key
    let mnemonic = MnemonicPhrase::generate()?;
    println!("📝 Generated mnemonic phrase:");
    println!("{}\n", mnemonic.phrase());

    // Important: In a real application, users would write this down securely!
    println!("⚠️  IMPORTANT: In a real application, users must securely store this phrase!");
    println!("    This phrase can recover the group encryption key.\n");

    // Create a group key from the mnemonic
    let group_name = "Secret Project Team";
    let passphrase = "additional-security-passphrase"; // Optional but recommended
    let timestamp = chrono::Utc::now().timestamp() as u64;

    let encryption_key = DigitalGroupAssistant::create_key_from_mnemonic(
        &mnemonic, passphrase, group_name, timestamp,
    )?;

    println!("🔑 Created encryption key using ChaCha20-Poly1305");
    println!("Key ID: {:?}", hex::encode(&encryption_key.key_id));

    // Alice creates a group with the mnemonic-derived key
    let group_config = CreateGroupConfig {
        name: group_name.to_string(),
        description: Some("A secure group using ChaCha20 and mnemonic phrases".to_string()),
        metadata: {
            let mut metadata = BTreeMap::new();
            metadata.insert("encryption".to_string(), "chacha20-poly1305".to_string());
            metadata.insert("key_derivation".to_string(), "bip39+argon2".to_string());
            metadata
        },
        settings: GroupSettings::default(),
        encryption_key: Some(encryption_key.clone()),
    };

    let create_result = dga.create_group(group_config, &alice_key, timestamp)?;

    println!("✅ Created group: {}", create_result.group_id);
    println!("   Using ChaCha20-Poly1305 encryption");
    println!("   Key derived from mnemonic phrase\n");

    // Demonstrate key recovery - Bob can recover the same key using the mnemonic
    println!("🔄 Demonstrating key recovery...");

    // Bob recovers the key using the same mnemonic and parameters
    // In practice, Bob would have received:
    // 1. The mnemonic phrase (securely shared)
    // 2. The passphrase (if used)
    // 3. The group name
    // 4. The salt (from the key derivation info)

    let derivation_info = encryption_key.derivation_info.as_ref().unwrap();
    let mut salt_array = [0u8; 32];
    salt_array.copy_from_slice(&derivation_info.salt);

    let recovered_key = DigitalGroupAssistant::recover_key_from_mnemonic(
        &mnemonic,
        passphrase,
        group_name,
        &salt_array,
        timestamp,
    )?;

    // Verify the keys are identical
    if encryption_key.key == recovered_key.key {
        println!("✅ Key recovery successful! Keys match perfectly.");
    } else {
        println!("❌ Key recovery failed! Keys don't match.");
        return Err("Key recovery failed".into());
    }

    // Test encryption/decryption
    println!("\n🔐 Testing encryption/decryption...");
    let test_message = b"This is a secret message encrypted with ChaCha20-Poly1305!";

    let encrypted = encryption_key.encrypt_content(test_message)?;
    println!("Encrypted {} bytes", encrypted.ciphertext.len());
    println!("Nonce: {}", hex::encode(encrypted.nonce));

    let decrypted = encryption_key.decrypt_content(&encrypted)?;
    println!("Decrypted: {}", String::from_utf8(decrypted)?);

    println!("\n🎉 All tests passed!");
    println!("\n📋 Summary:");
    println!("- ✅ Generated BIP39 mnemonic phrase (24 words)");
    println!("- ✅ Derived encryption key using Argon2 + ChaCha20-Poly1305");
    println!("- ✅ Created encrypted group");
    println!("- ✅ Demonstrated key recovery from mnemonic");
    println!("- ✅ Tested encryption/decryption roundtrip");

    println!("\n🔐 Security Benefits:");
    println!("- ChaCha20-Poly1305: Fast, secure, constant-time");
    println!("- BIP39 mnemonic: Human-readable key backup");
    println!("- Argon2: Memory-hard key derivation");
    println!("- Salt: Prevents rainbow table attacks");
    println!("- Optional passphrase: Additional security layer");

    Ok(())
}
