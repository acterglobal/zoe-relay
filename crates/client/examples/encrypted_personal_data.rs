use anyhow::{Result, anyhow};
use bip39::Language;
use clap::{Arg, Command};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tarpc::context;
use tracing::{debug, info};
use zoe_client::RelayClient;
use zoe_wire_protocol::{
    Content, Ed25519EncryptedContent, Kind, Message, MessageFull, MnemonicPhrase, StoreKey, Tag,
    generate_ed25519_from_mnemonic,
};

/// Personal data structure that we'll encrypt and store
#[derive(Serialize, Deserialize, Debug, Clone)]
struct PersonalData {
    name: String,
    email: String,
    notes: String,
    created_at: u64,
}

/// Saved keypair information for persistence (much simpler now!)
#[derive(Serialize, Deserialize, Debug)]
struct KeypairInfo {
    mnemonic_phrase: String,
    public_key_hex: String,
    custom_store_key: u32,
}

/// Configuration for our encrypted storage example
struct EncryptedStorageConfig {
    relay_addr: SocketAddr,
    server_key: VerifyingKey,
    keypair_file: String,
    client_key: SigningKey,
    custom_store_key: u32,
}

struct EncryptedPersonalDataClient {
    config: EncryptedStorageConfig,
    relay_client: RelayClient,
}

impl EncryptedPersonalDataClient {
    async fn new(config: EncryptedStorageConfig) -> Result<Self> {
        let relay_client = RelayClient::new(
            config.client_key.clone(),
            config.server_key,
            config.relay_addr,
        )
        .await?;

        Ok(Self {
            config,
            relay_client,
        })
    }

    /// Store encrypted personal data using ed25519-derived encryption (much simpler!)
    async fn store_encrypted_data(&mut self, data: PersonalData) -> Result<()> {
        info!("🔐 Storing encrypted personal data...");

        // Generate or load ed25519 keypair from mnemonic (only need mnemonic!)
        let (_mnemonic, signing_keypair) = self.get_or_create_keypair()?;

        // Serialize the personal data with postcard (consistent with codebase)
        let plaintext = postcard::to_stdvec(&data)?;
        info!("📦 Serialized personal data: {} bytes", plaintext.len());

        // Encrypt directly using ed25519 private key - much simpler!
        let encrypted_content = Ed25519EncryptedContent::encrypt(&plaintext, &signing_keypair)?;
        info!(
            "🔒 Encrypted data with nonce: {:02x?}",
            encrypted_content.nonce
        );

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        // Create message with ed25519-encrypted content
        let message = Message::new_v0_ed25519_encrypted(
            encrypted_content,
            signing_keypair.verifying_key(),
            timestamp,
            Kind::Store(StoreKey::CustomKey(self.config.custom_store_key)),
            vec![Tag::Protected], // Mark as protected since it's personal data
        );

        // Sign and send the message
        let message_full = MessageFull::new(message, &signing_keypair)
            .map_err(|e| anyhow!("Failed to create signed message: {}", e))?;
        let (messages_service, _) = self.relay_client.connect_message_service().await?;

        let publish_result = messages_service
            .publish(context::current(), message_full)
            .await??;

        info!("✅ Successfully stored encrypted personal data");
        if let Some(stream_id) = publish_result.global_stream_id() {
            info!("📝 Stream ID: {}", stream_id);
        } else {
            info!("⚠️ Message was expired and not stored");
        }
        info!(
            "🔑 Public key: {}",
            hex::encode(signing_keypair.verifying_key().to_bytes())
        );
        info!("🗝️  Custom store key: {}", self.config.custom_store_key);
        info!("💡 Use these with the 'read' command to retrieve your data");
        info!("🎯 Recovery: Only need your mnemonic phrase - no salt or timestamp required!");

        Ok(())
    }

    /// Read and decrypt personal data using ed25519 private key (much simpler!)
    async fn read_encrypted_data(&mut self) -> Result<()> {
        info!("🔍 Reading encrypted personal data...");

        // Load the ed25519 keypair from mnemonic (only need mnemonic!)
        let (_mnemonic, signing_keypair) = self.load_keypair()?;

        // Fetch the stored message from relay
        let (messages_service, _) = self.relay_client.connect_message_service().await?;

        let message_opt = messages_service
            .user_data(
                context::current(),
                signing_keypair.verifying_key(),
                StoreKey::CustomKey(self.config.custom_store_key),
            )
            .await??;

        let message_full = message_opt.ok_or_else(|| {
            anyhow!("No encrypted data found for this key and store key combination")
        })?;

        info!("📨 Retrieved message from relay service");

        // Extract the ed25519-encrypted content
        let encrypted_content = match &message_full.message.as_ref() {
            Message::MessageV0(msg) => match &msg.content {
                Content::Ed25519Encrypted(content) => content,
                Content::ChaCha20Poly1305(_) => {
                    return Err(anyhow!(
                        "Found legacy ChaCha20 content, expected Ed25519-encrypted"
                    ));
                }
                Content::Raw(_) => return Err(anyhow!("Expected encrypted content, found raw")),
            },
        };

        info!(
            "🔓 Decrypting data with nonce: {:02x?}",
            encrypted_content.nonce
        );

        // Decrypt directly using ed25519 private key - much simpler!
        let plaintext = encrypted_content.decrypt(&signing_keypair)?;

        // Deserialize the personal data with postcard (consistent with codebase)
        let personal_data: PersonalData = postcard::from_bytes(&plaintext)?;

        info!("✅ Successfully decrypted personal data:");
        println!("\n📋 Personal Data:");
        println!("   Name: {}", personal_data.name);
        println!("   Email: {}", personal_data.email);
        println!("   Notes: {}", personal_data.notes);
        println!("   Created: {}", personal_data.created_at);
        println!("🎯 Decryption used only the mnemonic phrase - no additional keys needed!");
        println!();

        Ok(())
    }

    /// Get or create a keypair, saving mnemonic to file for later use
    fn get_or_create_keypair(&self) -> Result<(MnemonicPhrase, SigningKey)> {
        if Path::new(&self.config.keypair_file).exists() {
            info!(
                "📁 Loading existing keypair from: {}",
                self.config.keypair_file
            );
            self.load_keypair()
        } else {
            info!("🔑 Generating new keypair and mnemonic...");
            let mnemonic = MnemonicPhrase::generate()?;

            // Generate ed25519 signing key from mnemonic
            let signing_key = generate_ed25519_from_mnemonic(
                &mnemonic,
                "", // no passphrase
                "encrypted-personal-data",
            )?;

            // Save keypair info to file
            let keypair_info = KeypairInfo {
                mnemonic_phrase: mnemonic.phrase().to_string(),
                public_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
                custom_store_key: self.config.custom_store_key,
            };

            let keypair_json = serde_json::to_string_pretty(&keypair_info)?;
            fs::write(&self.config.keypair_file, keypair_json)?;

            info!("💾 Saved keypair info to: {}", self.config.keypair_file);
            info!("📝 Mnemonic phrase (keep this safe!):");
            println!("   {}", mnemonic.phrase());
            println!();

            Ok((mnemonic, signing_key))
        }
    }

    /// Load an existing keypair from file
    fn load_keypair(&self) -> Result<(MnemonicPhrase, SigningKey)> {
        let keypair_json = fs::read_to_string(&self.config.keypair_file)?;
        let keypair_info: KeypairInfo = serde_json::from_str(&keypair_json)?;

        let mnemonic =
            MnemonicPhrase::from_phrase(&keypair_info.mnemonic_phrase, Language::English)?;
        let signing_key = generate_ed25519_from_mnemonic(
            &mnemonic,
            "", // no passphrase
            "encrypted-personal-data",
        )?;

        // Verify the public keys match
        let expected_public_key = hex::encode(signing_key.verifying_key().to_bytes());
        if expected_public_key != keypair_info.public_key_hex {
            return Err(anyhow!(
                "Public key mismatch! Expected: {}, got: {}",
                keypair_info.public_key_hex,
                expected_public_key
            ));
        }

        debug!("✅ Keypair loaded and verified");
        Ok((mnemonic, signing_key))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("encrypted_personal_data=info,zoe_client=debug")
        .init();

    println!("🔐 Encrypted Personal Data Storage Example");
    println!("==========================================\n");

    let matches = Command::new("encrypted-personal-data")
        .about("Store and retrieve encrypted personal data using ed25519 keypair from mnemonic")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Relay server address")
                .default_value("127.0.0.1:5678"),
        )
        .arg(
            Arg::new("server-key")
                .short('s')
                .long("server-key")
                .value_name("HEX")
                .help("Server's public key (64 hex characters)")
                .required(true),
        )
        .arg(
            Arg::new("client-key")
                .short('c')
                .long("client-key")
                .value_name("HEX")
                .help("Client's private key (64 hex characters, optional - will generate if not provided)"),
        )
        .arg(
            Arg::new("keypair-file")
                .short('k')
                .long("keypair-file")
                .value_name("FILE")
                .help("File to store/load keypair information")
                .default_value("personal_data_keypair.json"),
        )
        .arg(
            Arg::new("store-key")
                .long("store-key")
                .value_name("NUMBER")
                .help("Custom store key number")
                .default_value("1001"),
        )
        .subcommand(
            Command::new("store")
                .about("Store encrypted personal data")
                .arg(
                    Arg::new("name")
                        .short('n')
                        .long("name")
                        .value_name("NAME")
                        .help("Your name")
                        .required(true),
                )
                .arg(
                    Arg::new("email")
                        .short('e')
                        .long("email")
                        .value_name("EMAIL")
                        .help("Your email address")
                        .required(true),
                )
                .arg(
                    Arg::new("notes")
                        .long("notes")
                        .value_name("NOTES")
                        .help("Additional notes")
                        .default_value("Stored via encrypted relay example"),
                ),
        )
        .subcommand(
            Command::new("read")
                .about("Read and decrypt stored personal data"),
        )
        .subcommand_required(true)
        .get_matches();

    // Parse global arguments
    let relay_addr: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow!("Invalid relay address: {}", e))?;

    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes =
        hex::decode(server_key_hex).map_err(|e| anyhow!("Invalid server key hex: {}", e))?;
    if server_key_bytes.len() != 32 {
        return Err(anyhow!("Server key must be 32 bytes (64 hex characters)"));
    }
    let server_key = VerifyingKey::try_from(server_key_bytes.as_slice())
        .map_err(|e| anyhow!("Invalid server key: {}", e))?;

    let client_key = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let client_key_bytes =
            hex::decode(client_key_hex).map_err(|e| anyhow!("Invalid client key hex: {}", e))?;
        if client_key_bytes.len() != 32 {
            return Err(anyhow!("Client key must be 32 bytes (64 hex characters)"));
        }
        SigningKey::try_from(client_key_bytes.as_slice())
            .map_err(|e| anyhow!("Invalid client key: {}", e))?
    } else {
        // Generate a random client key for relay communication
        SigningKey::generate(&mut OsRng)
    };

    let keypair_file = matches.get_one::<String>("keypair-file").unwrap().clone();
    let custom_store_key: u32 = matches
        .get_one::<String>("store-key")
        .unwrap()
        .parse()
        .map_err(|e| anyhow!("Invalid store key number: {}", e))?;

    let config = EncryptedStorageConfig {
        relay_addr,
        server_key,
        keypair_file,
        client_key,
        custom_store_key,
    };

    let mut client = EncryptedPersonalDataClient::new(config).await?;

    // Handle subcommands
    match matches.subcommand() {
        Some(("store", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap().clone();
            let email = sub_matches.get_one::<String>("email").unwrap().clone();
            let notes = sub_matches.get_one::<String>("notes").unwrap().clone();

            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();

            let personal_data = PersonalData {
                name,
                email,
                notes,
                created_at: timestamp,
            };

            client.store_encrypted_data(personal_data).await?;
        }
        Some(("read", _)) => {
            client.read_encrypted_data().await?;
        }
        _ => unreachable!(), // clap ensures subcommand is required
    }

    Ok(())
}
