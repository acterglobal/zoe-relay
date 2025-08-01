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
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    select,
};
use tracing::{debug, error, info, warn};

use zoe_client::{ClientError, MessagesService, RelayClient};
use zoe_wire_protocol::{
    Kind, Message, MessageFilters, MessageFull, MessagesServiceRequest, StreamMessage,
    SubscriptionConfig, Tag,
};

/// MLS chat client commands
#[derive(Debug, Clone)]
enum MLSCommand {
    CreateGroup,
    AddMember { key_package_file: String },
    Join { welcome_file: String },
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

/// Welcome message for joining groups
#[derive(Serialize, Deserialize, Debug, Clone)]
struct WelcomeMessage {
    group_name: String,
    existing_members: Vec<String>,
    new_member: String,
    epoch: u64,
    welcome_data: Vec<u8>,
    member_keys: Vec<(Vec<u8>, String)>, // Share the member key mappings
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
#[derive(Debug, Clone)]
struct EncryptedChatMessage {
    author_name: String,
    content: String,
    timestamp: u64,
    epoch: u64,
}

impl EncryptedChatMessage {
    fn format_for_display(&self) -> String {
        let time = format!(
            "{:02}:{:02}:{:02}",
            (self.timestamp / 3600) % 24,
            (self.timestamp / 60) % 60,
            self.timestamp % 60
        );
        format!(
            "[{}] [E{}] {}: {}",
            time, self.epoch, self.author_name, self.content
        )
    }
}

/// Simplified MLS chat client demonstrating the integration concept
struct MLSChatClient {
    config: MLSChatConfig,
    messages: VecDeque<EncryptedChatMessage>,
    max_messages: usize,
    // MLS components would go here in a full implementation:
    // mls_group: Option<MlsGroup>,
    // provider: OpenMlsRustCrypto,
    // signature_keys: SignatureKeyPair,
    group_epoch: u64,
    is_group_creator: bool,
    pending_members: Vec<String>,
    member_keys: HashMap<Vec<u8>, String>, // public_key -> user_name mapping
}

impl MLSChatClient {
    async fn new(config: MLSChatConfig) -> Result<Self> {
        let mut client = Self {
            config,
            messages: VecDeque::new(),
            max_messages: 50,
            group_epoch: 1,
            is_group_creator: false,
            pending_members: Vec::new(),
            member_keys: HashMap::new(),
        };

        // Initialize based on command
        match client.config.command.clone() {
            MLSCommand::CreateGroup => {
                client.create_mls_group_concept().await?;
            }
            MLSCommand::AddMember { key_package_file } => {
                client.load_existing_group_concept().await?;
                client.add_member_concept(&key_package_file).await?;
            }
            MLSCommand::Join { welcome_file } => {
                client.join_from_welcome_concept(&welcome_file).await?;
            }
            MLSCommand::Chat => {
                client.load_existing_group_concept().await?;
            }
        }

        Ok(client)
    }

    /// Demonstrate MLS group creation concept
    async fn create_mls_group_concept(&mut self) -> Result<()> {
        info!("🔐 Creating conceptual MLS group...");

        // In a real implementation, this would:
        // 1. Initialize OpenMLS provider and storage
        // 2. Create MLS credentials and signature keys
        // 3. Create MLS group with proper configuration
        // 4. Generate key packages for sharing

        self.is_group_creator = true;
        self.group_epoch = 1;

        // Add self to member keys mapping
        let my_key = self.config.client_key.verifying_key().to_bytes().to_vec();
        debug!(
            "🔍 Storing my key: {} -> {}",
            hex::encode(&my_key),
            self.config.user_name
        );
        self.member_keys
            .insert(my_key, self.config.user_name.clone());

        info!("✅ Conceptual MLS group created successfully");

        // Generate mock key package for demonstration
        self.export_key_package_concept().await?;

        // Save mock group state
        self.save_group_state_concept().await?;

        Ok(())
    }

    /// Legacy method for demonstration - now shows proper workflow
    async fn join_mls_group_concept(&mut self) -> Result<()> {
        info!("❓ To join a group, you need a Welcome message from the group creator.");
        info!("📋 Proper workflow:");
        info!("   1. Create your key package: 'create-group' (generates keypackage.bin)");
        info!("   2. Share your key package with the group creator");
        info!("   3. Group creator adds you: 'add-member --key-package your_keypackage.bin'");
        info!("   4. Group creator shares the welcome message with you");
        info!("   5. Join using: 'join --welcome welcome_yourname.bin'");

        return Err(anyhow!(
            "Use 'join --welcome <file>' subcommand with a Welcome message to join a group"
        ));
    }

    /// Join a group using a Welcome message (demonstrates the complete flow)
    async fn join_from_welcome_concept(&mut self, welcome_file: &str) -> Result<()> {
        info!(
            "🎉 Joining MLS group using Welcome message: {}",
            welcome_file
        );

        // Check if welcome file exists
        if !Path::new(welcome_file).exists() {
            return Err(anyhow!("Welcome file not found: {}", welcome_file));
        }

        // In a real implementation, this would:
        // 1. Load and validate the Welcome message
        // 2. Create StagedWelcome from the Welcome message
        // 3. Process the welcome to join the group
        // 4. Derive group keys and establish encryption state

        // Load the conceptual welcome message first
        let welcome_data = fs::read(welcome_file)?;
        let welcome_info: WelcomeMessage = postcard::from_bytes(&welcome_data)?;

        info!("✅ Successfully joined group via Welcome message (concept)");
        self.is_group_creator = false;
        self.group_epoch = 2; // New member joins at next epoch

        // Add self to member keys mapping
        self.member_keys.insert(
            self.config.client_key.verifying_key().to_bytes().to_vec(),
            self.config.user_name.clone(),
        );

        // Import member key mappings from the welcome message
        let member_count = welcome_info.member_keys.len();
        for (key, name) in welcome_info.member_keys {
            debug!("🔍 Importing member key: {} -> {}", hex::encode(&key), name);
            self.member_keys.insert(key, name);
        }

        info!(
            "👥 Imported {} member key mappings from welcome message",
            member_count
        );

        info!(
            "👥 Joined group '{}' with {} existing members",
            welcome_info.group_name,
            welcome_info.existing_members.len()
        );

        // Save our new group state
        self.save_group_state_concept().await?;

        Ok(())
    }

    /// Add a member to existing group (demonstrates member management)
    async fn add_member_concept(&mut self, member_file: &str) -> Result<()> {
        info!(
            "👥 Adding member to group using key package: {}",
            member_file
        );

        // Check if member key package exists
        if !Path::new(member_file).exists() {
            return Err(anyhow!(
                "Member key package file not found: {}",
                member_file
            ));
        }

        // Load the member's key package
        let key_package_data = fs::read(member_file)?;
        let member_key_package: SerializableKeyPackage = postcard::from_bytes(&key_package_data)?;

        info!(
            "📦 Loaded key package for user: {}",
            member_key_package.user_name
        );

        // In a real implementation, this would:
        // 1. Validate the key package
        // 2. Create an Add proposal for the new member
        // 3. Commit the proposal to the group
        // 4. Generate a Welcome message for the new member
        // 5. Update group state to new epoch

        // Simulate adding the member
        self.pending_members
            .push(member_key_package.user_name.clone());
        self.group_epoch += 1; // Epoch advances when group membership changes

        // Add member to key mapping (simulated - in real MLS this would come from the key package)
        debug!(
            "🔍 Storing member key: {} -> {}",
            hex::encode(&member_key_package.user_id),
            member_key_package.user_name
        );
        self.member_keys.insert(
            member_key_package.user_id.clone(),
            member_key_package.user_name.clone(),
        );

        info!(
            "✅ Added {} to group (concept)",
            member_key_package.user_name
        );
        info!("🔄 Group epoch advanced to: {}", self.group_epoch);

        // Generate Welcome message for the new member
        self.generate_welcome_message_concept(&member_key_package)
            .await?;

        // Save updated group state
        self.save_group_state_concept().await?;

        Ok(())
    }

    /// Generate Welcome message for a new member
    async fn generate_welcome_message_concept(
        &self,
        member_package: &SerializableKeyPackage,
    ) -> Result<()> {
        info!(
            "📨 Generating Welcome message for: {}",
            member_package.user_name
        );

        // Create Welcome message with group information
        let welcome_message = WelcomeMessage {
            group_name: self.config.channel.clone(),
            existing_members: vec![self.config.user_name.clone()],
            new_member: member_package.user_name.clone(),
            epoch: self.group_epoch,
            welcome_data: b"conceptual_welcome_data".to_vec(),
            member_keys: self
                .member_keys
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };

        let filename = format!("welcome_{}.bin", member_package.user_name.to_lowercase());
        let binary_data = postcard::to_allocvec(&welcome_message)?;
        fs::write(&filename, binary_data)?;

        info!("💾 Welcome message saved to: {} (binary format)", filename);
        info!(
            "📨 Share this file with {} to complete group joining",
            member_package.user_name
        );

        Ok(())
    }

    /// Load existing group concept
    async fn load_existing_group_concept(&mut self) -> Result<()> {
        if !Path::new(&self.config.group_state_file).exists() {
            return Err(anyhow!(
                "No existing group found. Use --create-group to start a new encrypted group"
            ));
        }

        info!("📁 Loading conceptual MLS group state...");

        let group_data = fs::read(&self.config.group_state_file)?;

        // Try to deserialize with migration support
        let group_state: GroupState = postcard::from_bytes(&group_data)?;

        self.group_epoch = group_state.epoch;
        self.is_group_creator = true; // Simplified for concept

        // Load any additional members
        if group_state.members.len() > 1 {
            self.pending_members = group_state.members[1..].to_vec();
        }

        // Restore member keys mapping
        self.member_keys.clear();
        for (key, name) in group_state.member_keys {
            self.member_keys.insert(key, name);
        }

        info!(
            "✅ Conceptual MLS group loaded (epoch: {})",
            group_state.epoch
        );
        info!("👥 Group members: {}", group_state.members.join(", "));

        Ok(())
    }

    /// Export conceptual key package
    async fn export_key_package_concept(&self) -> Result<()> {
        info!("📦 Generating conceptual key package...");

        // In a real implementation, this would generate actual MLS key package
        let mock_key_package = SerializableKeyPackage {
            key_package_bytes: b"mock_key_package_data".to_vec(),
            user_name: self.config.user_name.clone(),
            user_id: self.config.client_key.verifying_key().to_bytes().to_vec(),
        };

        let filename = format!("{}_keypackage.bin", self.config.user_name.to_lowercase());
        let binary_data = postcard::to_allocvec(&mock_key_package)?;
        fs::write(&filename, binary_data)?;

        info!(
            "💾 Conceptual key package exported to: {} (binary format)",
            filename
        );
        info!("📨 In a full implementation, share this with others to join the group");

        Ok(())
    }

    /// Save conceptual group state with improved persistence
    async fn save_group_state_concept(&self) -> Result<()> {
        let mut all_members = vec![self.config.user_name.clone()];
        all_members.extend(self.pending_members.clone());

        let state = GroupState {
            group_data: b"mock_group_data".to_vec(),
            epoch: self.group_epoch,
            members: all_members,
            member_keys: self
                .member_keys
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            version: 1,
        };

        let binary_data = postcard::to_allocvec(&state)?;
        fs::write(&self.config.group_state_file, binary_data)?;

        debug!(
            "💾 Conceptual group state saved to: {}",
            self.config.group_state_file
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
        let relay_client = RelayClient::new(
            self.config.client_key.clone(),
            self.config.server_key,
            self.config.server_addr,
        )
        .await?;

        // Connect to message service
        let (mut messages_service, mut messages_stream) =
            relay_client.connect_message_service().await?;

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
                            (messages_service, messages_stream) = relay_client.connect_message_service().await?;
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
                                if let Err(e) = self.send_conceptual_encrypted_message(&messages_service, &trimmed).await {
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
        self.save_group_state_concept().await?;

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

        let subscribe_request = MessagesServiceRequest::Subscribe(subscription_config);
        service.send_raw(subscribe_request).await?;

        info!("📡 Subscribed to conceptual encrypted channel: {}", channel);
        Ok(())
    }

    /// Handle incoming message (conceptual decryption)
    async fn handle_incoming_message(&mut self, stream_message: StreamMessage) -> Result<()> {
        match &stream_message {
            StreamMessage::MessageReceived { message, .. } => {
                // In a real implementation, this would decrypt the MLS message
                // For now, we'll treat the content as conceptually encrypted
                let conceptual_message = self.conceptual_decrypt_message(message).await;
                self.add_message(conceptual_message);
                self.display_interface().await;

                // Conceptually save group state (epoch might advance)
                self.save_group_state_concept().await?;
            }
            StreamMessage::StreamHeightUpdate(_) => {
                // Just a height update, no action needed
            }
        }
        Ok(())
    }

    /// Conceptual message decryption (placeholder)
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
            epoch: self.group_epoch,
        }
    }

    /// Send a conceptually encrypted message
    async fn send_conceptual_encrypted_message(
        &mut self,
        service: &MessagesService,
        content: &str,
    ) -> Result<()> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // In a real implementation, this would:
        // 1. Create an MLS application message
        // 2. Encrypt the content using the group keys
        // 3. Serialize the encrypted MLS message
        // 4. Send the encrypted bytes

        warn!("⚠️  Sending as plaintext - real implementation would encrypt with MLS");

        let conceptual_encrypted_content = format!("🔐 MLS-ENCRYPTED: {}", content);

        let channel_tag = Tag::Channel {
            id: self.config.channel.as_bytes().to_vec(),
            relays: vec![],
        };

        let message = Message::new_v0(
            conceptual_encrypted_content.as_bytes().to_vec(),
            self.config.client_key.verifying_key(),
            timestamp,
            Kind::Regular,
            vec![channel_tag],
        );

        let message_full = MessageFull::new(message, &self.config.client_key)
            .map_err(|e| ClientError::Generic(format!("Failed to create MessageFull: {}", e)))?;

        service.publish(message_full).await?;

        // Conceptually advance epoch periodically
        if rand::random::<u8>() % 10 == 0 {
            self.group_epoch += 1;
            info!("🔄 Conceptual epoch advanced to: {}", self.group_epoch);
        }

        self.save_group_state_concept().await?;

        info!("🔐 Conceptually encrypted message sent");
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
        println!("  /quit     - Exit the chat");
        println!("  /members  - Show group members and info");
        println!("  /epoch    - Show current security epoch");
        println!("  /help     - Show this help message");
        println!();
        println!("💡 MLS Group Management:");
        println!("  • To add members: restart with 'add-member --key-package <file>'");
        println!("  • To join via welcome: use 'join --welcome <file>'");
        println!("  • To resume chat: use 'chat' subcommand");
        println!();
    }

    /// Display the chat interface
    async fn display_interface(&self) {
        // Clear screen and move cursor to top
        print!("\x1b[2J\x1b[H");

        println!("┌─────────────────────────────────────────────────────────────────────────────┐");
        println!(
            "│              🔐 MLS Encrypted Chat (Concept) - Channel: {}              │",
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
            println!(
                "│ No messages yet. Start a conceptually secure conversation! 🔐             │"
            );
            println!(
                "│ Note: This proof of concept shows architecture, not actual encryption     │"
            );
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
        println!("│ Commands: /quit /members /epoch | This is a proof-of-concept demo         │");
        print!(
            "└─────────────────────────────────────────────────────────────────────────────┘\n🔐 > "
        );

        io::stdout().flush().unwrap();
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
            Command::new("create-group")
                .about("Create a new MLS group and generate key package for sharing"),
        )
        .subcommand(
            Command::new("add-member")
                .about("Add a member to existing group using their key package")
                .arg(
                    Arg::new("key-package")
                        .short('k')
                        .long("key-package")
                        .value_name("FILE")
                        .help("Key package file from the user to add")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("join")
                .about("Join a group using a Welcome message")
                .arg(
                    Arg::new("welcome")
                        .short('w')
                        .long("welcome")
                        .value_name("FILE")
                        .help("Welcome message file from group creator")
                        .required(true),
                ),
        )
        .subcommand(Command::new("chat").about("Resume existing chat session in a group"))
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
        Some(("create-group", _)) => MLSCommand::CreateGroup,
        Some(("add-member", sub_matches)) => {
            let key_package_file = sub_matches
                .get_one::<String>("key-package")
                .unwrap()
                .clone();
            MLSCommand::AddMember { key_package_file }
        }
        Some(("join", sub_matches)) => {
            let welcome_file = sub_matches.get_one::<String>("welcome").unwrap().clone();
            MLSCommand::Join { welcome_file }
        }
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

    // Create and run MLS chat client
    let mut mls_chat_client = MLSChatClient::new(config).await?;

    match mls_chat_client.run().await {
        Ok(()) => {
            info!("MLS chat concept session ended successfully");
        }
        Err(e) => {
            error!("MLS chat concept session failed: {}", e);
            return Err(e);
        }
    }

    Ok(())
}
