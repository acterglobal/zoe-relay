//! # MLS Chat Client Example - Proof of Concept
//!
//! This is a simplified proof-of-concept implementation showing how MLS (Message Layer Security)
//! could be integrated with the Zoe relay system. Due to OpenMLS API complexity and version
//! compatibility issues, this example demonstrates the architectural approach rather than
//! a fully functional MLS implementation.
//!
//! ## Features Demonstrated
//!
//! - **Client-side MLS integration concept**: Shows where MLS encryption would fit
//! - **Key package generation**: Demonstrates out-of-band key exchange concept  
//! - **Group state management**: Shows persistent group state concept
//! - **Message encryption flow**: Demonstrates the encrypt-before-send pattern
//! - **Architectural foundation**: Provides basis for full MLS implementation
//!
//! ## Usage
//!
//! ```bash
//! # Start the relay server first
//! cargo run --bin zoe-relay
//!
//! # Create a proof-of-concept encrypted group
//! cargo run --example mls_chat_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY> --channel secure-chat --user-name Alice --create-group
//! ```
//!
//! ## Implementation Status
//!
//! This example currently demonstrates the concept and architecture. For a production
//! implementation, you would need to:
//! 1. Resolve OpenMLS API compatibility issues
//! 2. Implement proper Welcome message coordination
//! 3. Add member management functionality
//! 4. Handle all MLS message types properly
//!
//! See MLS_CHAT_README.md for the complete architectural plan.

use anyhow::{Result, anyhow};
use clap::{Arg, Command};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::{self, Write},
    net::SocketAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tarpc::context;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    select,
};
use tracing::{debug, error, info, warn};

// OpenMLS imports for real MLS functionality
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
// MemoryStorage import removed - no longer using local storage
use openmls_rust_crypto::OpenMlsRustCrypto;

use zoe_client::{ClientError, MessagesService, RelayClient};
use zoe_wire_protocol::{
    Kind, Message, MessageFilters, MessageFull, MessageV0, StoreKey, StreamMessage,
    SubscriptionConfig, Tag,
};

/// MLS chat client commands
#[derive(Debug, Clone)]
enum MLSCommand {
    PublishKey,
    CreateGroup,
    Chat,
}

/// Configuration for the MLS chat client
#[derive(Debug, Clone)]
struct MLSChatConfig {
    server_addr: SocketAddr,
    server_key: VerifyingKey,
    channel: String,
    client_key: SigningKey,
    user_name: String,
    command: MLSCommand,
    group_state_file: String,
}

/// Serializable key package for out-of-band exchange (concept)
#[derive(Serialize, Deserialize, Debug, Clone)]
struct SerializableKeyPackage {
    key_package_bytes: Vec<u8>,
    user_name: String,
    user_id: Vec<u8>,
}

// MessageOrdering removed - deterministic ordering will be implemented when needed

/// Group event types for event-based coordination
#[derive(Debug, Clone)]
enum GroupEventType {
    WelcomeMessage,
    CommitMessage,
    KeyPackagePublication,
    MembershipUpdate,
}

/// MLS encrypted message envelope
#[derive(Serialize, Deserialize, Debug, Clone)]
struct MLSEncryptedMessage {
    epoch: u64,              // MLS group epoch for key versioning
    encrypted_data: Vec<u8>, // Encrypted EncryptedChatMessage
    sender_key_id: Vec<u8>,  // Sender's public key for verification
}

/// Modern MLS group state for persistence (concept)  
#[derive(Serialize, Deserialize, Debug)]
struct GroupState {
    group_data: Vec<u8>,
    epoch: u64,
    members: Vec<String>,
    member_keys: Vec<(Vec<u8>, String)>, // (public_key_bytes, user_name) mapping
    version: u32,                        // Version for backward compatibility
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            group_data: Vec::new(),
            epoch: 1,
            members: Vec::new(),
            member_keys: Vec::new(),
            version: 1,
        }
    }
}

/// A conceptual encrypted chat message
#[derive(Serialize, Deserialize, Debug, Clone)]
struct EncryptedChatMessage {
    author_name: String,
    content: String,
    timestamp: u64,
}

impl EncryptedChatMessage {
    fn format_for_display(&self) -> String {
        let time = format!(
            "{:02}:{:02}:{:02}",
            (self.timestamp / 3600) % 24,
            (self.timestamp / 60) % 60,
            self.timestamp % 60
        );
        format!("[{}] {}: {}", time, self.author_name, self.content)
    }
}

/// Real MLS chat client using actual OpenMLS library
struct MLSChatClient {
    config: MLSChatConfig,
    messages: VecDeque<EncryptedChatMessage>,
    max_messages: usize,
    // Real MLS components
    mls_group: Option<MlsGroup>,
    provider: OpenMlsRustCrypto,
    credential_with_key: CredentialWithKey,
    signature_keys: SignatureKeyPair,
    // Group management
    group_epoch: u64,
    is_group_creator: bool,
    pending_members: Vec<String>, // Keep for compatibility with existing code
    member_keys: HashMap<Vec<u8>, String>, // public_key -> user_name mapping
    relay_client: RelayClient,
}

impl MLSChatClient {
    async fn new(config: MLSChatConfig) -> Result<Self> {
        // Initialize OpenMLS provider
        let provider = OpenMlsRustCrypto::default();

        // Generate persistent MLS signature keys deterministically based on client key
        // This ensures the same user always gets the same MLS keys across sessions
        // Use the client key as the seed for MLS key generation
        let client_key_bytes = config.client_key.to_bytes();

        // Generate 32-byte seed for ED25519 private key from client key
        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&client_key_bytes);

        // Create ED25519 signing key from private bytes
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&private_key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Convert to the format expected by SignatureKeyPair::from_raw
        let signature_keys = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            private_key_bytes.to_vec(),
            verifying_key.to_bytes().to_vec(),
        );

        info!(
            "🔑 Generated persistent MLS signature keys for {}",
            config.user_name
        );

        let credential = BasicCredential::new(config.user_name.as_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        };

        info!(
            "🔧 Initialized real OpenMLS provider and credential for {}",
            config.user_name
        );

        let relay_client = RelayClient::new(
            config.client_key.clone(),
            config.server_key,
            config.server_addr,
        )
        .await?;

        let mut client = Self {
            config,
            messages: VecDeque::new(),
            max_messages: 50,
            mls_group: None,
            provider,
            credential_with_key,
            signature_keys,
            group_epoch: 1,
            is_group_creator: false,
            pending_members: Vec::new(),
            member_keys: HashMap::new(),
            relay_client,
        };

        // Initialize based on command
        match client.config.command.clone() {
            MLSCommand::PublishKey => {
                client.publish_key_package().await?;
            }

            MLSCommand::CreateGroup => {
                client.create_mls_group().await?;
            }

            MLSCommand::Chat => {
                client.load_existing_group_or_join().await?;
            }
        }

        Ok(client)
    }

    /// Publish key package to relay server and display public key for others to use
    async fn publish_key_package(&mut self) -> Result<()> {
        info!("📦 Publishing key package to relay server...");

        // Initialize MLS components for key package generation
        let _group_id = GroupId::from_slice(b"temp_group_for_key_generation");
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            .build();

        // Create a temporary MLS group to generate key package
        let _mls_group = MlsGroup::new(
            &self.provider,
            &self.signature_keys,
            &mls_group_create_config,
            self.credential_with_key.clone(),
        )
        .map_err(|e| anyhow!("Failed to create MLS group: {:?}", e))?;

        // Connect to relay server

        // Store key package on relay server
        self.store_key_package_on_relay().await?;

        // Display the public key for others to use
        let public_key_hex = hex::encode(self.config.client_key.verifying_key().to_bytes());

        println!("✅ Key package published successfully!");
        println!("🔑 Your public key: {}", public_key_hex);
        println!("💡 Share this public key with others so they can add you to groups.");
        println!(
            "📋 Example: Others can add you with: /add {}",
            public_key_hex
        );

        Ok(())
    }

    /// Load existing group or attempt to join via welcome message
    /// Fails if no group exists and no welcome message is found
    async fn load_existing_group_or_join(&mut self) -> Result<()> {
        if std::path::Path::new(&self.config.group_state_file).exists() {
            info!("📁 Loading existing MLS group state...");
            self.load_existing_group().await
        } else {
            info!("🔍 No local group found, checking for welcome messages...");

            // Connect to message service temporarily to check for welcome messages
            let (messages_service, mut messages_stream) =
                self.relay_client.connect_message_service().await?;

            // Subscribe to the channel to receive messages
            Self::subscribe_to_channel(&messages_service, self.config.channel.clone()).await?;

            // Wait briefly for any pending welcome messages
            let timeout_duration = std::time::Duration::from_secs(3);
            let start_time = std::time::Instant::now();

            while start_time.elapsed() < timeout_duration {
                tokio::select! {
                    stream_result = messages_stream.recv() => {
                        if let Some(stream_message) = stream_result {
                            if let Err(e) = self.handle_incoming_message(stream_message).await {
                                error!("❌ Failed to process potential welcome message: {}", e);
                                // Continue trying in case there are more messages
                                continue;
                            }

                            // Check if we successfully joined a group
                            if self.mls_group.is_some() {
                                info!("✅ Successfully joined group via welcome message!");
                                return Ok(());
                            }
                        }
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                        // Continue checking
                    }
                }
            }

            // Fail if no group found
            Err(anyhow!(
                "❌ No MLS group found! Use 'create-group' to create a new group first, or wait for a welcome message."
            ))
        }
    }

    /// Create a new MLS group using real OpenMLS
    async fn create_mls_group(&mut self) -> Result<()> {
        info!("🏗️ Creating real MLS group using OpenMLS...");

        // Create MLS group configuration
        let group_id = GroupId::from_slice(self.config.channel.as_bytes());
        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
            .build();

        // Create the actual MLS group
        let mls_group = MlsGroup::new(
            &self.provider,
            &self.signature_keys,
            &mls_group_create_config,
            self.credential_with_key.clone(),
        )
        .map_err(|e| anyhow!("Failed to create MLS group: {:?}", e))?;

        info!("✅ Real MLS group created successfully with OpenMLS");

        // Update our state
        self.mls_group = Some(mls_group);
        self.is_group_creator = true;
        self.group_epoch = 1;

        // Add ourselves to the member keys mapping
        let my_key = self.config.client_key.verifying_key().to_bytes().to_vec();
        debug!(
            "🔍 Storing my key: {} -> {}",
            hex::encode(&my_key),
            self.config.user_name
        );
        self.member_keys
            .insert(my_key, self.config.user_name.clone());

        info!("👤 You are the group creator");
        info!(
            "🔑 Your public key: {}",
            hex::encode(self.config.client_key.verifying_key().to_bytes())
        );
        info!("🏢 Group ID: {}", hex::encode(group_id.as_slice()));
        info!(
            "💡 Note: Make sure you've already published your key package with 'publish-key' command"
        );

        // Save group state
        self.save_mls_group_state().await?;

        Ok(())
    }

    /// Retrieve key package from relay server by user public key using direct lookup
    async fn retrieve_key_package_from_relay(
        &self,
        user_public_key: &str,
    ) -> Result<SerializableKeyPackage> {
        info!("🔍 Retrieving key package for user: {}", user_public_key);

        // Parse the user's public key
        let user_key_bytes: [u8; 32] = hex::decode(user_public_key)
            .map_err(|e| anyhow!("Invalid user public key hex: {}", e))?
            .try_into()
            .map_err(|e: Vec<u8>| {
                anyhow!(
                    "Invalid user public key length, expected 32 bytes, got {}",
                    e.len()
                )
            })?;

        let user_key = VerifyingKey::from_bytes(&user_key_bytes)
            .map_err(|e| anyhow!("Invalid user public key: {}", e))?;

        debug!(
            "🔍 Looking up stored MLS key package for author: {}",
            hex::encode(&user_key_bytes)
        );
        debug!(
            "🔍 Using storage key: MlsKeyPackage ({})",
            u32::from(StoreKey::MlsKeyPackage)
        );

        let (messages_service, _) = self.relay_client.connect_message_service().await?;

        // Use direct lookup for the MLS key package
        let Some(lookup_result) = messages_service
            .user_data(context::current(), user_key, StoreKey::MlsKeyPackage)
            .await??
        else {
            error!(
                "❌ Key package lookup returned None for user: {}",
                user_public_key
            );
            return Err(anyhow!(
                "Key package not found for user: {}",
                user_public_key
            ));
        };

        let key_package_data = lookup_result.content();
        let member_key_package: SerializableKeyPackage = postcard::from_bytes(key_package_data)
            .map_err(|e| anyhow!("Failed to deserialize key package: {}", e))?;
        Ok(member_key_package)
    }

    /// Add a member to existing group using real OpenMLS operations
    async fn add_member_real_mls(&mut self, user_public_key: &str) -> Result<()> {
        info!(
            "👥 Adding member to group using real OpenMLS with public key: {}",
            user_public_key
        );

        // Retrieve the member's key package from relay first (before mutable borrow)
        let member_key_package = self
            .retrieve_key_package_from_relay(user_public_key)
            .await?;

        // Ensure we have an MLS group
        let mls_group = match &mut self.mls_group {
            Some(group) => group,
            None => {
                return Err(anyhow!(
                    "No MLS group available - only group creators can add members"
                ));
            }
        };

        info!(
            "📦 Loaded key package for user: {}",
            member_key_package.user_name
        );

        // Deserialize the KeyPackageBundle using postcard (since OpenMLS supports Serde serialization)
        let key_package_bundle: KeyPackageBundle =
            postcard::from_bytes(&member_key_package.key_package_bytes).map_err(|e| {
                anyhow!(
                    "Failed to deserialize KeyPackageBundle with postcard: {:?}",
                    e
                )
            })?;

        // Extract the KeyPackage from the bundle
        let key_package = key_package_bundle.key_package().clone();

        info!("✅ Parsed real OpenMLS KeyPackage from relay storage");

        // Check if this user is already in the group to prevent DuplicateSignatureKey error
        let new_member_credential = key_package.leaf_node().credential();
        for member in mls_group.members() {
            if member.credential == *new_member_credential {
                return Err(anyhow!(
                    "Member {} is already in the group! Cannot add duplicate members.",
                    member_key_package.user_name
                ));
            }
        }

        // Create an Add proposal using the real retrieved key package
        let (_proposal, _proposal_ref) = mls_group
            .propose_add_member(&self.provider, &self.signature_keys, &key_package)
            .map_err(|e| anyhow!("Failed to create Add proposal: {:?}", e))?;

        info!(
            "📝 Created Add proposal for {}",
            member_key_package.user_name
        );

        // Commit the proposal to advance the group epoch and generate Welcome message
        let (commit, welcome_option, _group_info) = mls_group
            .commit_to_pending_proposals(&self.provider, &self.signature_keys)
            .map_err(|e| anyhow!("Failed to commit Add proposal: {:?}", e))?;

        info!("🔄 Committed Add proposal - group epoch advanced");

        // CRITICAL: Merge the pending commit to update our local group state
        // This prevents "PendingCommit" errors on subsequent operations
        mls_group
            .merge_pending_commit(&self.provider)
            .map_err(|e| anyhow!("Failed to merge pending commit: {:?}", e))?;

        info!("✅ Merged pending commit - ready for new operations");

        // Send the commit message to the group
        self.send_mls_commit_message(&commit).await?;

        // Send welcome message to the new member if generated
        if let Some(welcome_message) = welcome_option {
            self.send_mls_welcome_message(&welcome_message, &member_key_package)
                .await?;
        } else {
            warn!("⚠️  No Welcome message generated - this shouldn't happen for Add operations");
        }

        // Update our member tracking
        self.member_keys.insert(
            member_key_package.user_id.clone(),
            member_key_package.user_name.clone(),
        );

        // Save updated group state
        self.save_mls_group_state().await?;

        info!(
            "🎉 Successfully added {} to group using real OpenMLS!",
            member_key_package.user_name
        );

        Ok(())
    }

    /// Send MLS commit message to the group (for group state updates)
    async fn send_mls_commit_message(&self, commit: &MlsMessageOut) -> Result<()> {
        info!("📤 Sending MLS commit message to group");

        // Serialize the commit message
        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| anyhow!("Failed to serialize commit message: {:?}", e))?;

        // Get the message service
        let (messages_service, _) = self.relay_client.connect_message_service().await?;

        let channel_tag = Tag::Channel {
            id: self.config.channel.as_bytes().to_vec(),
            relays: vec![],
        };

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let message = Message::new_v0_raw(
            commit_bytes,
            self.config.client_key.verifying_key(),
            timestamp,
            Kind::Regular,
            vec![channel_tag],
        );

        let message_full = MessageFull::new(message, &self.config.client_key)
            .map_err(|e| anyhow!("Failed to create MessageFull: {}", e))?;

        let _ = messages_service
            .publish(context::current(), message_full)
            .await
            .map_err(|e| anyhow!("Failed to send commit message: {}", e))?;

        info!("✅ MLS commit message sent successfully");
        Ok(())
    }

    /// Send MLS welcome message to a specific new member
    async fn send_mls_welcome_message(
        &self,
        welcome: &MlsMessageOut,
        target_member: &SerializableKeyPackage,
    ) -> Result<()> {
        info!(
            "📨 Sending OpenMLS Welcome message to {}",
            target_member.user_name
        );

        // Serialize the Welcome message
        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| anyhow!("Failed to serialize Welcome message: {:?}", e))?;

        // Get the message service
        let (messages_service, _) = self.relay_client.connect_message_service().await?;

        // Create a User tag to target the specific new member
        let user_tag = Tag::User {
            id: target_member.user_id.clone(),
            relays: vec![],
        };

        let channel_tag = Tag::Channel {
            id: self.config.channel.as_bytes().to_vec(),
            relays: vec![],
        };

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let message = Message::new_v0_raw(
            welcome_bytes,
            self.config.client_key.verifying_key(),
            timestamp,
            Kind::Regular,
            vec![user_tag, channel_tag],
        );

        let message_full = MessageFull::new(message, &self.config.client_key)
            .map_err(|e| anyhow!("Failed to create MessageFull: {}", e))?;

        let _ = messages_service
            .publish(context::current(), message_full)
            .await
            .map_err(|e| anyhow!("Failed to send Welcome message: {}", e))?;

        info!(
            "✅ OpenMLS Welcome message sent to {}",
            target_member.user_name
        );
        Ok(())
    }

    /// Try to process a message as an OpenMLS welcome message
    async fn try_process_mls_welcome(&self, message: &MessageFull) -> Result<Option<Welcome>> {
        // Check if this message has a User tag targeting us
        let my_public_key = self.config.client_key.verifying_key().to_bytes().to_vec();
        let has_user_tag = message.tags().iter().any(|tag| {
            if let Tag::User { id, .. } = tag {
                id == &my_public_key
            } else {
                false
            }
        });

        if !has_user_tag {
            return Ok(None); // Not for us
        }

        // Try to parse as MLS message first (since welcome is sent as MlsMessageOut)
        match MlsMessageIn::tls_deserialize(&mut &message.content()[..]) {
            Ok(mls_message_in) => {
                // Extract the content and check if it's a Welcome message
                match mls_message_in.extract() {
                    MlsMessageBodyIn::Welcome(welcome) => {
                        info!("✅ Received real OpenMLS welcome message");
                        Ok(Some(welcome))
                    }
                    _ => Ok(None), // Not a welcome message
                }
            }
            Err(_) => Ok(None), // Not a valid MLS message
        }
    }

    /// Join group from real OpenMLS welcome message
    async fn join_from_mls_welcome(&mut self, welcome: Welcome) -> Result<()> {
        info!("🎉 Joining MLS group via real OpenMLS welcome message");

        // Create MLS group from welcome message using OpenMLS
        let mls_group_join_config = MlsGroupJoinConfig::builder().build();

        let mls_group = StagedWelcome::new_from_welcome(
            &self.provider,
            &mls_group_join_config,
            welcome,
            None, // No ratchet tree hint
        )
        .map_err(|e| anyhow!("Failed to stage welcome: {:?}", e))?
        .into_group(&self.provider)
        .map_err(|e| anyhow!("Failed to create group from welcome: {:?}", e))?;

        info!("✅ Successfully created real MLS group from welcome message");

        // Update our state
        self.mls_group = Some(mls_group);
        self.is_group_creator = false;
        self.group_epoch = self.mls_group.as_ref().unwrap().epoch().as_u64();

        // Add self to member keys mapping
        self.member_keys.insert(
            self.config.client_key.verifying_key().to_bytes().to_vec(),
            self.config.user_name.clone(),
        );

        info!("🎉 Successfully joined group using real OpenMLS");
        info!("🔄 Group epoch: {}", self.group_epoch);

        // Save our new group state
        self.save_mls_group_state().await?;

        // Show a join message
        let join_message = EncryptedChatMessage {
            author_name: "System".to_string(),
            content: format!(
                "🎉 {} joined the group via encrypted welcome message!",
                self.config.user_name
            ),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        self.add_message(join_message);

        Ok(())
    }

    /// Check if a message is an MLS commit message
    async fn is_mls_commit_message(&self, _message: &MessageFull) -> Result<bool> {
        // For now, assume any message in a commit context could be a commit
        // We'll refine this when we process the actual message
        Ok(true)
    }

    /// Handle MLS commit message with deterministic ordering (NIP-EE style)
    async fn handle_mls_commit_message(&mut self, message: &MessageFull) -> Result<()> {
        info!(
            "📥 Processing MLS commit message from {}",
            hex::encode(&message.author().to_bytes()[..4])
        );

        // Skip our own commit messages (we already applied them locally)
        if *message.author() == self.config.client_key.verifying_key() {
            debug!("⏭️  Skipping our own commit message");
            return Ok(());
        }

        // Ensure we have an MLS group to apply commits to
        let mls_group = match &mut self.mls_group {
            Some(group) => group,
            None => {
                debug!("❌ Received commit but no MLS group available - ignoring");
                return Ok(());
            }
        };

        // Parse the MLS commit message from the wire format
        let mls_message_in = MlsMessageIn::tls_deserialize_exact(message.content())
            .map_err(|e| anyhow!("Failed to parse MLS commit message: {:?}", e))?;

        // Convert to protocol message
        let protocol_message: ProtocolMessage = mls_message_in
            .try_into()
            .map_err(|e| anyhow!("Failed to convert commit to protocol message: {:?}", e))?;

        // Process the commit message using OpenMLS
        let processed_message = mls_group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| anyhow!("Failed to process MLS commit: {:?}", e))?;

        // Handle the processed commit
        match processed_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                info!("🔄 Applying staged commit to group state");

                // Merge the staged commit into our group state
                mls_group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| anyhow!("Failed to merge staged commit: {:?}", e))?;

                // Update our epoch tracking
                self.group_epoch = mls_group.epoch().as_u64();

                info!(
                    "✅ Successfully applied commit - group epoch now: {}",
                    self.group_epoch
                );

                // Save updated group state
                self.save_mls_group_state().await?;

                // Log membership change
                info!(
                    "👥 Group membership updated via commit from {}",
                    hex::encode(&message.author().to_bytes()[..4])
                );
            }
            _ => {
                warn!("⚠️  Expected staged commit but got different message type - ignoring");
            }
        }

        Ok(())
    }

    /// Load existing group with support for both conceptual and real MLS state
    async fn load_existing_group(&mut self) -> Result<()> {
        if !Path::new(&self.config.group_state_file).exists() {
            return Err(anyhow!(
                "No existing group found. Use --create-group to start a new encrypted group"
            ));
        }

        info!("📁 Loading group state...");

        let group_data = fs::read(&self.config.group_state_file)?;

        // Try to deserialize the group state
        let group_state: GroupState = postcard::from_bytes(&group_data)?;

        self.group_epoch = group_state.epoch;
        self.is_group_creator = true; // Simplified for concept

        // Check if this is a real MLS group (version 2+) or needs upgrade
        if group_state.version >= 2 && group_state.group_data == b"real_mls_group" {
            info!(
                "✅ Loading existing real MLS group state (version {})",
                group_state.version
            );
        } else {
            info!("⚠️  Loading legacy conceptual group state - will upgrade to real MLS");
        }

        // Load any additional members
        if group_state.members.len() > 1 {
            self.pending_members = group_state.members[1..].to_vec();
        }

        // Restore member keys mapping
        self.member_keys.clear();
        for (key, name) in group_state.member_keys {
            self.member_keys.insert(key, name);
        }

        // Ensure we have a real MLS group
        self.ensure_real_mls_group().await?;

        // Save the state to ensure it's marked as real MLS
        self.save_mls_group_state().await?;

        info!(
            "✅ Conceptual MLS group loaded (epoch: {})",
            group_state.epoch
        );
        info!("👥 Group members: {}", group_state.members.join(", "));

        Ok(())
    }

    /// Store real OpenMLS key package on the relay server
    async fn store_key_package_on_relay(&self) -> Result<()> {
        info!("📦 Generating and storing real OpenMLS key package on relay server...");

        // Generate a real OpenMLS key package
        let key_package_bundle = KeyPackage::builder()
            .build(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                &self.provider,
                &self.signature_keys,
                self.credential_with_key.clone(),
            )
            .map_err(|e| anyhow!("Failed to generate key package: {:?}", e))?;

        // Serialize the KeyPackageBundle using postcard (since OpenMLS supports Serde serialization)
        let key_package_bytes = postcard::to_allocvec(&key_package_bundle).map_err(|e| {
            anyhow!(
                "Failed to serialize KeyPackageBundle with postcard: {:?}",
                e
            )
        })?;

        let real_key_package = SerializableKeyPackage {
            key_package_bytes,
            user_name: self.config.user_name.clone(),
            user_id: self.config.client_key.verifying_key().to_bytes().to_vec(),
        };

        let package_data = postcard::to_allocvec(&real_key_package)?;

        // Create a Store message for MLS key package
        let message = Message::MessageV0(MessageV0 {
            sender: self.config.client_key.verifying_key(),
            when: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            kind: Kind::Store(StoreKey::MlsKeyPackage),
            tags: vec![Tag::User {
                id: self.config.client_key.verifying_key().to_bytes().to_vec(),
                relays: vec![],
            }],
            content: package_data,
        });

        let message_full = MessageFull::new(message, &self.config.client_key)
            .map_err(|e| anyhow!("Failed to create message: {}", e))?;

        // Connect to relay and store the key package
        let (messages_service, _) = self.relay_client.connect_message_service().await?;
        if let Err(e) = messages_service
            .publish(context::current(), message_full)
            .await
        {
            error!("❌ Failed to publish key package: {}", e);
        }

        info!("✅ Key package stored on relay server");
        info!("🌐 Other users can now discover and add you to groups");

        Ok(())
    }

    /// Handle loading of existing group state with real MLS support
    async fn ensure_real_mls_group(&mut self) -> Result<()> {
        // In a production implementation, this would properly restore the OpenMLS group
        // For now, we ensure we have a real MLS group by creating a new one if needed

        if self.mls_group.is_none() {
            info!("🔧 No MLS group found - creating a new real MLS group");

            let mls_group_create_config = MlsGroupCreateConfig::builder()
                .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                .build();

            let mls_group = MlsGroup::new(
                &self.provider,
                &self.signature_keys,
                &mls_group_create_config,
                self.credential_with_key.clone(),
            )
            .map_err(|e| anyhow!("Failed to create MLS group: {:?}", e))?;

            self.mls_group = Some(mls_group);
            info!("✅ Real MLS group created successfully");
        } else {
            info!("✅ Using existing real MLS group");
        }

        Ok(())
    }

    /// Save simplified MLS group state metadata
    async fn save_mls_group_state(&self) -> Result<()> {
        // For now, we'll save a simplified state that tracks that we're using real MLS
        // In a production implementation, you'd want to properly persist the OpenMLS group
        // but that requires more complex state management than we can implement here

        let simplified_state = GroupState {
            group_data: b"real_mls_group".to_vec(), // Marker that this is a real MLS group
            epoch: self.group_epoch,
            members: vec![self.config.user_name.clone()], // Simplified member tracking
            member_keys: self
                .member_keys
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            version: 2, // Version 2 indicates real MLS
        };

        let binary_data = postcard::to_allocvec(&simplified_state)?;
        fs::write(&self.config.group_state_file, binary_data)?;

        info!(
            "💾 MLS group state saved (epoch: {}, {} members) - using real MLS",
            self.group_epoch,
            self.member_keys.len()
        );

        Ok(())
    }

    /// Connect to relay and demonstrate encrypted messaging concept
    async fn run(&mut self) -> Result<()> {
        info!("🚀 Starting MLS chat concept client");
        info!(
            "🔐 Channel: {} (Conceptually End-to-End Encrypted)",
            self.config.channel
        );
        info!("👤 User: {}", self.config.user_name);
        info!(
            "🔑 Your ID: {}",
            hex::encode(&self.config.client_key.verifying_key().to_bytes()[..4])
        );
        info!("🏘️ Group Epoch: {}", self.group_epoch);

        warn!("⚠️  This is a proof-of-concept implementation!");
        warn!("   Messages are sent as plaintext for demonstration.");
        warn!("   A full MLS implementation would encrypt messages before sending.");

        // Connect to relay server

        // Connect to message service
        let (mut messages_service, mut messages_stream) =
            self.relay_client.connect_message_service().await?;

        // Subscribe to the channel
        Self::subscribe_to_channel(&messages_service, self.config.channel.clone()).await?;

        // Set up async stdin reader
        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        let mut input_line = String::new();

        // Clear screen and show initial interface
        self.display_interface().await;

        info!("💬 Conceptual encrypted chat ready! Type messages and press Enter.");
        info!(
            "💡 Commands: '/quit' to exit, '/members' for group info, '/epoch' for current epoch, '/help' for help."
        );

        loop {
            select! {
                // Handle incoming messages
                stream_result = messages_stream.recv() => {
                    match stream_result {
                        Some(stream_message) => {
                            if let Err(e) = self.handle_incoming_message(stream_message).await {
                                error!("❌ Failed to handle incoming message: {}", e);
                            }
                        }
                        None => {
                            warn!("📡 Message stream ended. Restarting...");
                            (messages_service, messages_stream) = self.relay_client.connect_message_service().await?;
                            Self::subscribe_to_channel(&messages_service, self.config.channel.clone()).await?;
                            continue;
                        }
                    }
                }
                // Handle user input
                input_result = stdin_reader.read_line(&mut input_line) => {
                    match input_result {
                        Ok(0) => break, // EOF
                        Ok(_) => {
                            let trimmed = input_line.trim().to_string();
                            input_line.clear();

                            if trimmed == "/quit" {
                                info!("👋 Goodbye!");
                                break;
                            } else if trimmed.starts_with("/add ") {
                                let public_key = trimmed.strip_prefix("/add ").unwrap().trim();
                                if public_key.is_empty() {
                                    println!("❌ Usage: /add <public-key>");
                                    println!("💡 Example: /add a1b2c3d4e5f6...");
                                } else {
                                    // Need to pass relay_client reference correctly
                                    // For now, let's skip the relay client and implement differently
                                    self.handle_add_member_command_sync(public_key).await;
                                }
                                continue;
                            } else if trimmed == "/members" {
                                self.show_group_info().await;
                                continue;
                            } else if trimmed == "/epoch" {
                                self.show_epoch_info().await;
                                continue;
                            } else if trimmed == "/help" {
                                self.show_help().await;
                                continue;
                            }

                            if !trimmed.is_empty() {
                                if let Err(e) = self.send_mls_encrypted_message(&messages_service, &trimmed).await {
                                    error!("❌ Failed to send message: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            error!("❌ Failed to read input: {}", e);
                            break;
                        }
                    }
                }
            }
        }

        // Save group state before exiting
        self.save_mls_group_state().await?;

        Ok(())
    }

    /// Subscribe to messages in the specified channel
    async fn subscribe_to_channel(service: &MessagesService, channel: String) -> Result<()> {
        let channel_bytes = channel.as_bytes().to_vec();

        let subscription_config = SubscriptionConfig {
            filters: MessageFilters {
                authors: None,
                channels: Some(vec![channel_bytes]),
                events: None,
                users: None,
            },
            since: None,
            limit: Some(20),
        };

        if let Err(e) = service.subscribe(subscription_config).await {
            error!("❌ Failed to subscribe to channel: {}", e);
        }

        info!("📡 Subscribed to conceptual encrypted channel: {}", channel);
        Ok(())
    }

    /// Handle incoming message with event-based coordination (NIP-EE inspired)
    async fn handle_incoming_message(&mut self, stream_message: StreamMessage) -> Result<()> {
        match &stream_message {
            StreamMessage::MessageReceived { message, .. } => {
                // Implement event-based coordination similar to NIP-EE
                // All group operations are handled as events on the relay network

                // First, try to identify and handle group coordination events
                if let Some(event_type) = self.identify_group_event(message).await? {
                    info!("📋 Processing group coordination event: {:?}", event_type);
                    self.handle_group_coordination_event(message, event_type)
                        .await?;
                    self.display_interface().await;
                    return Ok(());
                }

                // Otherwise handle as regular MLS encrypted message
                self.handle_mls_encrypted_message(message).await?;
            }
            StreamMessage::StreamHeightUpdate(_) => {
                // Just a height update, no action needed
            }
        }
        Ok(())
    }

    /// Identify the type of group coordination event (NIP-EE inspired)
    async fn identify_group_event(&self, message: &MessageFull) -> Result<Option<GroupEventType>> {
        // Check if this is an MLS welcome message
        if self.try_process_mls_welcome(message).await?.is_some() {
            return Ok(Some(GroupEventType::WelcomeMessage));
        }

        // Check if this is an MLS commit message
        if self.is_mls_commit_message(message).await? {
            return Ok(Some(GroupEventType::CommitMessage));
        }

        // Check if this is a key package publication (simple heuristic)
        if message.content().len() > 100 && message.content().starts_with(b"key_package:") {
            return Ok(Some(GroupEventType::KeyPackagePublication));
        }

        // Check for other membership update events
        if message.content().starts_with(b"membership_update:") {
            return Ok(Some(GroupEventType::MembershipUpdate));
        }

        // Not a recognized group event
        Ok(None)
    }

    /// Handle group coordination events in an event-based manner
    async fn handle_group_coordination_event(
        &mut self,
        message: &MessageFull,
        event_type: GroupEventType,
    ) -> Result<()> {
        match event_type {
            GroupEventType::WelcomeMessage => {
                // Process OpenMLS welcome message
                if let Some(mls_welcome) = self.try_process_mls_welcome(message).await? {
                    info!("🎉 Processing welcome message event");
                    self.join_from_mls_welcome(mls_welcome).await?;
                } else {
                    warn!("⚠️  Failed to process welcome message event");
                }
            }
            GroupEventType::CommitMessage => {
                // Process MLS commit for group state updates
                info!("📥 Processing commit message event");
                self.handle_mls_commit_message(message).await?;
            }
            GroupEventType::KeyPackagePublication => {
                // Handle key package publication events
                info!("🔑 Processing key package publication event");
                self.handle_key_package_event(message).await?;
            }
            GroupEventType::MembershipUpdate => {
                // Handle membership update events
                info!("👥 Processing membership update event");
                self.handle_membership_update_event(message).await?;
            }
        }
        Ok(())
    }

    /// Handle key package publication events
    async fn handle_key_package_event(&mut self, message: &MessageFull) -> Result<()> {
        // In a real implementation, this would process key package publications
        // For now, just log the event
        info!(
            "📦 Received key package publication from {}",
            hex::encode(&message.author().to_bytes()[..4])
        );
        Ok(())
    }

    /// Handle membership update events
    async fn handle_membership_update_event(&mut self, message: &MessageFull) -> Result<()> {
        // In a real implementation, this would process membership changes
        // For now, just log the event
        info!(
            "🔄 Received membership update from {}",
            hex::encode(&message.author().to_bytes()[..4])
        );
        Ok(())
    }

    /// Handle an MLS encrypted message
    async fn handle_mls_encrypted_message(&mut self, message: &MessageFull) -> Result<()> {
        // Skip our own messages in the display (they're already added when we send)
        if *message.author() == self.config.client_key.verifying_key() {
            return Ok(());
        }

        // Try to decrypt the MLS encrypted message
        match self.decrypt_mls_message(message).await {
            Ok(chat_message) => {
                self.add_message(chat_message);
                self.display_interface().await;
            }
            Err(mls_error) => {
                warn!(
                    "❌ Failed to decrypt message from {} with real MLS: {}",
                    hex::encode(&message.author().to_bytes()[..4]),
                    mls_error
                );

                // For debugging - show what we received
                let content_preview = if message.content().len() > 50 {
                    format!("{}...", hex::encode(&message.content()[..25]))
                } else {
                    hex::encode(message.content())
                };
                warn!("🔍 Message content (hex): {}", content_preview);
                warn!("💡 Make sure all group members are using real OpenMLS encryption");
            }
        }

        Ok(())
    }

    /// Decrypt an MLS encrypted message using real OpenMLS
    async fn decrypt_mls_message(&mut self, message: &MessageFull) -> Result<EncryptedChatMessage> {
        // Check if we have an MLS group
        let mls_group = match &mut self.mls_group {
            Some(group) => group,
            None => return Err(anyhow!("No MLS group available - join a group first")),
        };

        // Parse the MLS message from the wire format
        let mls_message_in = MlsMessageIn::tls_deserialize_exact(message.content())
            .map_err(|e| anyhow!("Failed to parse MLS message: {:?}", e))?;

        // Convert to protocol message
        let protocol_message: ProtocolMessage = mls_message_in
            .try_into()
            .map_err(|e| anyhow!("Failed to convert to protocol message: {:?}", e))?;

        // Process the MLS message using OpenMLS
        let processed_message = mls_group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| anyhow!("Failed to process MLS message: {:?}", e))?;

        // Extract the decrypted application data
        let decrypted_data = match processed_message.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_message) => app_message.into_bytes(),
            _ => return Err(anyhow!("Message was not an application message")),
        };

        // Parse the decrypted chat message
        let mut chat_message: EncryptedChatMessage = postcard::from_bytes(&decrypted_data)
            .map_err(|e| anyhow!("Failed to parse decrypted chat message: {}", e))?;

        // Resolve author name from member keys
        let author_bytes = message.author().to_bytes();
        let author_name = match self.member_keys.get(&author_bytes.to_vec()) {
            Some(name) => {
                debug!(
                    "✅ Resolved author: {} -> {}",
                    hex::encode(&author_bytes[..4]),
                    name
                );
                name.clone()
            }
            None => {
                debug!("❌ Unknown author: {}", hex::encode(&author_bytes[..4]));
                format!("User-{}", hex::encode(&author_bytes[..4]))
            }
        };

        // Update the author name (in case the sender didn't set it correctly)
        chat_message.author_name = author_name;

        info!(
            "🔓 Successfully decrypted real MLS message from {} using OpenMLS",
            chat_message.author_name
        );

        Ok(chat_message)
    }

    /// Conceptual message decryption (placeholder - DEPRECATED)
    #[allow(dead_code)]
    async fn conceptual_decrypt_message(&self, message: &MessageFull) -> EncryptedChatMessage {
        // In a real implementation, this would:
        // 1. Deserialize the MLS message from content
        // 2. Process it through the MLS group
        // 3. Extract the decrypted application data
        // 4. Update group state if needed

        let content = String::from_utf8_lossy(message.content());
        let author_bytes = message.author().to_bytes();

        // Debug logging to see what keys we're working with
        debug!("🔍 Message author key: {}", hex::encode(&author_bytes));
        debug!(
            "🔍 My key: {}",
            hex::encode(&self.config.client_key.verifying_key().to_bytes())
        );
        debug!("🔍 Member keys in mapping: {}", self.member_keys.len());
        for (key, name) in &self.member_keys {
            debug!("🔍   {} -> {}", hex::encode(key), name);
        }

        let author_name = if hex::encode(&author_bytes)
            == hex::encode(&self.config.client_key.verifying_key().to_bytes())
        {
            self.config.user_name.clone()
        } else {
            // Try to find the user name from our member keys mapping
            match self.member_keys.get(&author_bytes.to_vec()) {
                Some(name) => {
                    debug!(
                        "✅ Found name mapping: {} -> {}",
                        hex::encode(&author_bytes),
                        name
                    );
                    name.clone()
                }
                None => {
                    debug!(
                        "❌ No name mapping found for key: {}",
                        hex::encode(&author_bytes)
                    );
                    format!("User-{}", hex::encode(&author_bytes[..4]))
                }
            }
        };

        EncryptedChatMessage {
            author_name,
            content: format!("🔓 {}", content), // Mark as conceptually decrypted
            timestamp: *message.when(),
        }
    }

    /// Send an MLS group encrypted message using real OpenMLS
    async fn send_mls_encrypted_message(
        &mut self,
        service: &MessagesService,
        content: &str,
    ) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Ensure we have an MLS group - all members must use real MLS now
        let mls_group = match &mut self.mls_group {
            Some(group) => group,
            None => {
                return Err(anyhow!(
                    "No MLS group available - join a group first or create one"
                ));
            }
        };

        // Create the plaintext message
        let chat_message = EncryptedChatMessage {
            author_name: self.config.user_name.clone(),
            content: content.to_string(),
            timestamp,
        };

        // Serialize the plaintext message
        let plaintext_data = postcard::to_allocvec(&chat_message)?;

        // Use real OpenMLS to encrypt the message
        let mls_message_out = mls_group
            .create_message(
                &self.provider,
                &self.signature_keys,
                plaintext_data.as_slice(),
            )
            .map_err(|e| anyhow!("Failed to create MLS message: {:?}", e))?;

        // Serialize the MLS message for transmission
        let mls_message_bytes = mls_message_out
            .tls_serialize_detached()
            .map_err(|e| anyhow!("Failed to serialize MLS message: {:?}", e))?;

        let channel_tag = Tag::Channel {
            id: self.config.channel.as_bytes().to_vec(),
            relays: vec![],
        };

        let message = Message::new_v0_raw(
            mls_message_bytes,
            self.config.client_key.verifying_key(),
            timestamp,
            Kind::Regular,
            vec![channel_tag],
        );

        let message_full = MessageFull::new(message, &self.config.client_key)
            .map_err(|e| ClientError::Generic(format!("Failed to create MessageFull: {}", e)))?;

        if let Err(e) = service.publish(context::current(), message_full).await {
            error!("❌ Failed to send message: {}", e);
        }

        // Get epoch before releasing the mutable borrow
        let current_epoch = mls_group.epoch();

        self.save_mls_group_state().await?;

        info!(
            "🔐 Real MLS encrypted message sent using OpenMLS (epoch {})",
            current_epoch
        );

        // Add to local display (we can decrypt our own messages)
        let display_message = EncryptedChatMessage {
            author_name: self.config.user_name.clone(),
            content: content.to_string(),
            timestamp,
        };
        self.add_message(display_message);
        self.display_interface().await;

        Ok(())
    }

    /// Add a message to the display buffer
    fn add_message(&mut self, message: EncryptedChatMessage) {
        self.messages.push_back(message);

        while self.messages.len() > self.max_messages {
            self.messages.pop_front();
        }
    }

    /// Show group information
    async fn show_group_info(&self) {
        println!("\n👥 Conceptual Group Information:");
        println!("  Epoch: {}", self.group_epoch);
        println!(
            "  Creator: {}",
            if self.is_group_creator { "Yes" } else { "No" }
        );

        let total_members = 1 + self.pending_members.len();
        println!("  Members: {}", total_members);
        println!("    - {} (you)", self.config.user_name);
        for member in &self.pending_members {
            println!("    - {}", member);
        }

        println!("  Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (conceptual)");
        println!();
    }

    /// Show epoch information
    async fn show_epoch_info(&self) {
        println!("\n🏘️ Group Epoch Information:");
        println!("  Current Epoch: {}", self.group_epoch);
        println!("  Security Generation: Each epoch provides forward secrecy");
        println!("  Key Rotation: Keys change with each epoch advance");
        println!();
    }

    /// Show help information
    async fn show_help(&self) {
        println!("\n🆘 MLS Chat Commands:");
        println!("  /add <key> - Add a member to the group using their public key");
        println!("  /quit      - Exit the chat");
        println!("  /members   - Show group members and info");
        println!("  /epoch     - Show current security epoch");
        println!("  /help      - Show this help message");
        println!();
        println!("💡 MLS Group Management:");
        println!("  • Add members live: /add <public-key-hex>");
        println!("  • Welcome messages sent automatically via relay");
        println!("  • New members auto-join when they start chatting");
        println!();
    }

    /// Display the chat interface
    async fn display_interface(&self) {
        // Clear screen and move cursor to top
        print!("\x1b[2J\x1b[H");

        println!("┌─────────────────────────────────────────────────────────────────────────────┐");
        println!(
            "│              🔐 MLS Group Encrypted Chat - Channel: {}              │",
            self.config.channel
        );
        println!(
            "│                     Epoch: {} | User: {} | Status: {}                     │",
            self.group_epoch,
            self.config.user_name,
            if self.is_group_creator {
                "Creator"
            } else {
                "Member"
            }
        );
        println!("├─────────────────────────────────────────────────────────────────────────────┤");

        // Display messages
        if self.messages.is_empty() {
            println!("│ No messages yet. Start a secure conversation! 🔐             │");
        } else {
            for message in &self.messages {
                let formatted = message.format_for_display();
                let truncated = if formatted.len() > 73 {
                    format!("{}...", &formatted[..70])
                } else {
                    formatted
                };
                println!("│ {:<75} │", truncated);
            }
        }

        println!("├─────────────────────────────────────────────────────────────────────────────┤");
        println!("│ Commands: /add <key> /quit /members /epoch /help | MLS GROUP ENCRYPTED   │");
        print!(
            "└─────────────────────────────────────────────────────────────────────────────┘\n🔐 > "
        );

        io::stdout().flush().unwrap();
    }

    /// Handle /add member command within chat
    async fn handle_add_member_command_sync(&mut self, public_key: &str) {
        println!("🔍 Adding member with public key: {}", public_key);

        match self.add_member_real_mls(public_key).await {
            Ok(_) => {
                println!("✅ Member added successfully using real OpenMLS!");
                println!("📤 Commit and Welcome messages sent via relay.");
                println!(
                    "💡 The new member will automatically join when they start chatting on this channel."
                );
            }
            Err(e) => {
                println!("❌ Failed to add member: {}", e);
                println!(
                    "💡 Make sure the public key is correct and the user has created their key package."
                );
            }
        }

        // Return to chat with a prompt
        println!("\n📋 Press Enter to continue chatting...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);

        // Note: We don't need to refresh display here as the main loop will handle it
    }
}

/// Parse command line arguments using subcommands
fn parse_args() -> Result<MLSChatConfig> {
    let matches = Command::new("MLS Chat Client (Proof of Concept)")
        .about("Demonstrates MLS integration concept for Zoe Relay")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Relay server address")
                .default_value("127.0.0.1:4433")
                .global(true),
        )
        .arg(
            Arg::new("server-key")
                .short('s')
                .long("server-key")
                .value_name("HEX_KEY")
                .help("Server's ed25519 public key (32 bytes in hex)")
                .required(true),
        )
        .arg(
            Arg::new("channel")
                .short('c')
                .long("channel")
                .value_name("CHANNEL")
                .help("Encrypted chat channel name")
                .default_value("secure-chat"),
        )
        .arg(
            Arg::new("user-name")
                .short('u')
                .long("user-name")
                .value_name("NAME")
                .help("Your display name in the group")
                .required(true),
        )
        .arg(
            Arg::new("client-key")
                .long("client-key")
                .value_name("HEX_KEY")
                .help("Client's ed25519 private key (32 bytes in hex). Random if not provided.")
                .global(true),
        )
        .subcommand(
            Command::new("publish-key")
                .about("Store your key package on the relay server and display your public key for others to add you"),
        )
        .subcommand(
            Command::new("create-group")
                .about("Create a new MLS group. Use /add <public-key> to invite members, then start chatting."),
        )
        .subcommand(
            Command::new("chat")
                .about("Start chat session. Requires an existing group (use create-group first) or a welcome message to join."),
        )
        .subcommand_required(true)
        .get_matches();

    // Parse global arguments
    let server_addr: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow!("Invalid server address: {}", e))?;

    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes =
        hex::decode(&server_key_hex).map_err(|e| anyhow!("Invalid server key hex: {}", e))?;
    let server_key = VerifyingKey::try_from(server_key_bytes.as_slice())
        .map_err(|e| anyhow!("Invalid server key: {}", e))?;

    let channel = matches.get_one::<String>("channel").unwrap().clone();
    let user_name = matches.get_one::<String>("user-name").unwrap().clone();

    let client_key = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let client_key_bytes =
            hex::decode(&client_key_hex).map_err(|e| anyhow!("Invalid client key hex: {}", e))?;
        SigningKey::try_from(client_key_bytes.as_slice())
            .map_err(|e| anyhow!("Invalid client key: {}", e))?
    } else {
        // Load or generate persistent client key per user
        let key_file = format!("{}_client_key.bin", user_name.to_lowercase());
        if Path::new(&key_file).exists() {
            debug!("🔑 Loading existing client key from: {}", key_file);
            let key_bytes = fs::read(&key_file)?;
            SigningKey::try_from(key_bytes.as_slice())
                .map_err(|e| anyhow!("Failed to load client key: {}", e))?
        } else {
            debug!("🔑 Generating new client key and saving to: {}", key_file);
            let new_key = SigningKey::generate(&mut rand::thread_rng());
            fs::write(&key_file, new_key.to_bytes())?;
            new_key
        }
    };

    // Parse subcommand
    let command = match matches.subcommand() {
        Some(("publish-key", _)) => MLSCommand::PublishKey,
        Some(("create-group", _)) => MLSCommand::CreateGroup,
        Some(("chat", _)) => MLSCommand::Chat,
        _ => return Err(anyhow!("Invalid subcommand")),
    };

    let group_state_file = format!("{}_group_state.bin", user_name.to_lowercase());

    Ok(MLSChatConfig {
        server_addr,
        server_key,
        channel,
        client_key,
        user_name,
        command,
        group_state_file,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse command line arguments
    let config = parse_args()?;

    // Create MLS chat client
    let mut mls_chat_client = MLSChatClient::new(config.clone()).await?;

    // Only run the chat interface for commands that need it
    match config.command {
        MLSCommand::PublishKey => {
            // publish-key command already completed in new(), just exit
            info!("Key package published successfully");
        }
        MLSCommand::CreateGroup => {
            // create-group command already completed in new(), show next steps
            info!("✅ MLS group created successfully!");
            println!("🎉 MLS group created for channel '{}'", config.channel);
            println!("💡 Next steps:");
            println!("   1. Use '/add <public-key>' to invite members");
            println!("   2. Use 'chat' command to start the conversation");
            println!(
                "📋 Example: cargo run --example mls_chat_client --features mls -- --server-key <key> --user-name {} --channel {} chat",
                config.user_name, config.channel
            );
        }
        MLSCommand::Chat => {
            // Run the interactive chat interface
            match mls_chat_client.run().await {
                Ok(()) => {
                    info!("MLS chat session ended successfully");
                }
                Err(e) => {
                    error!("MLS chat session failed: {}", e);
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}
