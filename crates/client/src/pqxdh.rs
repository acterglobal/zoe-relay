//! PQXDH inbox management and session helpers
//!
//! This module provides high-level abstractions for:
//! 1. Publishing and discovering PQXDH inboxes
//! 2. Establishing PQXDH sessions for secure communication

use crate::MessagesService;
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zoe_wire_protocol::{
    inbox::pqxdh::{
        PqxdhSharedSecret, PqxdhInbox, PqxdhInitialPayload, InboxType, generate_pqxdh_prekeys, pqxdh_initiate,
        encrypt_pqxdh_session_message, decrypt_pqxdh_session_message,
    },
    Filter, Kind, Message, MessageFilters, MessageFull, PqxdhInboxProtocol, StoreKey, SubscriptionConfig, Tag, VerifyingKey,
};

/// High-level PQXDH inbox management functions
/// 
/// These functions accept a `MessagesService` to allow reuse of existing connections
/// rather than creating new ones for each operation.

/// Publish a PQXDH inbox for a specific protocol
pub async fn publish_pqxdh_inbox<T: Serialize>(
    messages_service: &MessagesService,
    client_keypair: &zoe_wire_protocol::KeyPair,
    protocol: PqxdhInboxProtocol,
    inbox_data: &T,
) -> Result<Tag> {
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    
    // Create storage message for the PQXDH inbox
    let inbox_message = Message::new_typed(
        inbox_data,
        client_keypair.public_key(),
        timestamp,
        Kind::Store(StoreKey::PqxdhInbox(protocol)),
        vec![],
    )?;
    
    let inbox_message_full = MessageFull::new(inbox_message, client_keypair)
        .map_err(|e| anyhow::anyhow!("Failed to create MessageFull for inbox: {}", e))?;

    let target_tag = Tag::from(&inbox_message_full);
    
    // Publish the inbox
    messages_service
        .publish(tarpc::context::current(), inbox_message_full)
        .await
        .context("Failed to publish PQXDH inbox")?
        .context("Publish returned error")?;
    
    Ok(target_tag)
}

/// Discover a PQXDH inbox from another user
pub async fn fetch_pqxdh_inbox<T: for<'de> Deserialize<'de>>(
    messages_service: &MessagesService,
    provider_key: &VerifyingKey,
    protocol: PqxdhInboxProtocol,
) -> Result<Option<(T, Tag)>> {
    let provider_user_id = *provider_key.id();
    let store_key = StoreKey::PqxdhInbox(protocol);
    
    let user_data_result = messages_service
        .user_data(tarpc::context::current(), provider_user_id, store_key)
        .await
        .context("Failed to query user data")?;
    
    if let Some(message_full) = user_data_result? {
        let content_bytes = message_full.raw_content()
            .context("Message does not contain raw content")?;
        
        let inbox_data: T = postcard::from_bytes(content_bytes)
            .context("Failed to deserialize PQXDH inbox data")?;
        
        Ok(Some((inbox_data, Tag::from(&message_full))))
    } else {
        Ok(None)
    }
}

/// A PQXDH session for secure communication
pub struct PqxdhSession {
    shared_secret: PqxdhSharedSecret,
    sequence_number: AtomicU64,
    /// Randomized channel ID for session messages (provides unlinkability)
    session_channel_id: [u8; 32],
}

impl PqxdhSession {
    /// Get the channel tag for this session (for subscribing to session messages)
    pub fn channel_tag(&self) -> Tag {
        Tag::Channel {
            id: self.session_channel_id.to_vec(),
            relays: vec![],
        }
    }
    
    /// Get the channel ID as bytes (for filtering)
    pub fn channel_id(&self) -> &[u8; 32] {
        &self.session_channel_id
    }

    /// Initiate a PQXDH session with a target user using an already loaded inbox
    pub async fn initiate<T: Serialize, R: for<'de> Deserialize<'de>>(
        messages_service: &MessagesService,
        client_keypair: &zoe_wire_protocol::KeyPair,
        inbox: &PqxdhInbox,
        initial_payload: &T,
    ) -> Result<(Self, Option<R>)> {
        // Extract the prekey bundle from the inbox
        let prekey_bundle = &inbox.pqxdh_prekeys;
        
        // Generate randomized channel ID for session messages
        let mut rng = rand::thread_rng();
        let mut session_channel_id = [0u8; 32];
        rng.fill_bytes(&mut session_channel_id);
        
        // Serialize the initial payload
        let user_payload_bytes = postcard::to_stdvec(initial_payload)
            .context("Failed to serialize initial payload")?;
        
        // Create the combined initial payload with channel ID
        let initial_payload_struct = PqxdhInitialPayload {
            user_payload: user_payload_bytes,
            session_channel_id,
        };
        
        let combined_payload_bytes = postcard::to_stdvec(&initial_payload_struct)
            .context("Failed to serialize combined initial payload")?;
        
        // Initiate PQXDH
        let (initial_message, shared_secret) = pqxdh_initiate(
            client_keypair,
            prekey_bundle,
            &combined_payload_bytes,
            &mut rng,
        )?;
        
        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_message);
        let message_content = postcard::to_stdvec(&pqxdh_content)
            .context("Failed to serialize PQXDH content")?;
        
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            message_content,
            client_keypair.public_key(),
            timestamp,
            Kind::Emphemeral(0),
            vec![], // No tags initially - we'll use the derived tag from MessageFull
        );
        
        let message_full = MessageFull::new(message, client_keypair)
            .map_err(|e| anyhow::anyhow!("Failed to create message: {}", e))?;
        
        // The initial message will be routed using its derived tag (Tag::Event with message ID)
        // This is automatically created by Tag::from(&MessageFull)
        
        messages_service
            .publish(tarpc::context::current(), message_full)
            .await
            .context("Failed to publish PQXDH initial message")?
            .context("Publish returned error")?;
        
        let session = Self {
            shared_secret,
            sequence_number: AtomicU64::new(1),
            session_channel_id,
        };
        
        // For now, return None for the response - in a full implementation,
        // this would wait for and decrypt the response
        Ok((session, None))
    }
    
    /// Send a message in an established PQXDH session
    pub async fn send_message<T: Serialize>(
        &self,
        messages_service: &MessagesService,
        client_keypair: &zoe_wire_protocol::KeyPair,
        payload: &T,
    ) -> Result<()> {
        
        // Serialize the payload
        let payload_bytes = postcard::to_stdvec(payload)
            .context("Failed to serialize payload")?;
        
        // Encrypt as session message
        let sequence = self.sequence_number.fetch_add(1, Ordering::SeqCst);
        let mut rng = rand::thread_rng();
        let session_message = encrypt_pqxdh_session_message(
            &self.shared_secret,
            &payload_bytes,
            sequence,
            &mut rng,
        )?;
        
        // Send the session message
        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Session(session_message);
        let message_content = postcard::to_stdvec(&pqxdh_content)
            .context("Failed to serialize PQXDH session content")?;
        
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            message_content,
            client_keypair.public_key(),
            timestamp,
            Kind::Emphemeral(0),
            vec![Tag::Channel {
                id: self.session_channel_id.to_vec(),
                relays: vec![],
            }],
        );
        
        let message_full = MessageFull::new(message, client_keypair)
            .map_err(|e| anyhow::anyhow!("Failed to create session message: {}", e))?;
        
        messages_service
            .publish(tarpc::context::current(), message_full)
            .await
            .context("Failed to publish PQXDH session message")?
            .context("Session message publish returned error")?;
        
        Ok(())
    }
    
    /// Extract user payload from a PQXDH initial message (for responders)
    /// 
    /// This helper extracts the actual user payload from the encrypted initial message,
    /// which contains both the user data and the session channel ID.
    pub fn extract_initial_payload<R: for<'de> Deserialize<'de>>(
        decrypted_payload: &[u8],
    ) -> Result<(R, [u8; 32])> {
        // Deserialize the PqxdhInitialPayload structure
        let initial_payload: PqxdhInitialPayload = postcard::from_bytes(decrypted_payload)
            .context("Failed to deserialize PqxdhInitialPayload")?;
        
        // Deserialize the user payload
        let user_payload: R = postcard::from_bytes(&initial_payload.user_payload)
            .context("Failed to deserialize user payload from initial message")?;
        
        Ok((user_payload, initial_payload.session_channel_id))
    }
    
    /// Create a PQXDH session from an established shared secret and channel ID (for responders)
    pub fn from_shared_secret(
        shared_secret: PqxdhSharedSecret,
        session_channel_id: [u8; 32],
    ) -> Self {
        Self {
            shared_secret,
            sequence_number: AtomicU64::new(1),
            session_channel_id,
        }
    }
    
    /// Decrypt a received PQXDH session message
    pub fn decrypt_message<T: for<'de> Deserialize<'de>>(
        &self,
        session_message: &zoe_wire_protocol::inbox::pqxdh::PqxdhSessionMessage,
    ) -> Result<T> {
        let decrypted_bytes = decrypt_pqxdh_session_message(&self.shared_secret, session_message)?;
        let payload: T = postcard::from_bytes(&decrypted_bytes)
            .context("Failed to deserialize decrypted payload")?;
        Ok(payload)
    }
}

/// Send a PQXDH initial message using derived tags (privacy-preserving approach)
/// 
/// This function creates and sends a PQXDH initial message that uses the derived tag
/// (message hash) instead of user tags for privacy. Returns the derived tag that
/// the recipient should listen for.
pub async fn send_pqxdh_initial_message(
    messages_service: &MessagesService,
    client_keypair: &zoe_wire_protocol::KeyPair,
    initial_message: zoe_wire_protocol::inbox::pqxdh::PqxdhInitialMessage,
) -> Result<Tag> {
    let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_message);
    let message_content = postcard::to_stdvec(&pqxdh_content)
        .context("Failed to serialize PQXDH content")?;
    
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let message = Message::new_v0(
        message_content,
        client_keypair.public_key(),
        timestamp,
        Kind::Emphemeral(0),
        vec![], // No tags initially - we'll use the derived tag from MessageFull
    );
    
    let message_full = MessageFull::new(message, client_keypair)
        .map_err(|e| anyhow::anyhow!("Failed to create message: {}", e))?;
    
    // Get the derived tag that recipients should listen for
    let derived_tag = Tag::from(&message_full);
    
    messages_service
        .publish(tarpc::context::current(), message_full)
        .await
        .context("Failed to publish PQXDH initial message")?
        .context("Publish returned error")?;
    
    Ok(derived_tag)
}

/// A complete PQXDH protocol handler that encapsulates all session management,
/// key observation, subscription handling, and message routing logic.
/// 
/// This provides a high-level abstraction over the entire PQXDH workflow:
/// - Inbox publishing and discovery
/// - Session establishment with privacy-preserving tags
/// - Message sending/receiving with proper channel management
/// - Automatic subscription management for both initial and session messages
pub struct PqxdhProtocolHandler<'a, T> {
    messages_service: MessagesService,
    client_keypair: &'a zoe_wire_protocol::KeyPair,
    protocol: PqxdhInboxProtocol,
    /// Active sessions keyed by target user ID
    sessions: BTreeMap<Vec<u8>, PqxdhSession>,
    /// Subscription ID for listening to initial messages (author-based)
    inbox_tag: Option<Tag>,
    /// Subscription IDs for session channels
    session_subscriptions: BTreeMap<Vec<u8>, Tag>,
    /// Private keys for responding to initial messages (if we're a service provider)
    private_keys: Option<zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys>,
    _phantom: std::marker::PhantomData<T>,
}

impl<'a, T> PqxdhProtocolHandler<'a, T> 
where 
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
{
    /// Create a new protocol handler for a specific PQXDH protocol
    /// 
    /// This creates a handler that can be used either as:
    /// - **Service Provider**: Call `publish_service()` then `start_listening_for_clients()`
    /// - **Client**: Call `connect_to_service()` then `send_message()`
    pub async fn new(
        client: &'a crate::RelayClient,
        protocol: PqxdhInboxProtocol,
    ) -> Result<Self> {
        let (messages_service, _stream) = client
            .connect_message_service()
            .await
            .context("Failed to connect to message service")?;
        
        Ok(Self {
            messages_service,
            client_keypair: client.keypair(),
            protocol,
            sessions: BTreeMap::new(),
            inbox_tag: None,
            session_subscriptions: BTreeMap::new(),
            private_keys: None,
            _phantom: std::marker::PhantomData,
        })
    }
    
    /// Publish a service inbox for this protocol (SERVICE PROVIDERS ONLY)
    /// 
    /// This makes the current client discoverable as a service provider for the given protocol.
    /// Only call this if you want to provide a service that others can connect to.
    /// 
    /// After calling this, call `start_listening_for_clients()` to begin accepting connections.
    pub async fn publish_service(&mut self, force_overwrite: bool) -> Result<Tag> {
        if self.inbox_tag.is_some() && !force_overwrite {
            return Err(anyhow::anyhow!("Inbox already published, use force_overwrite to overwrite"));
        }
        
        // Generate prekey bundle with private keys
        let (prekey_bundle, private_keys) = create_pqxdh_prekey_bundle_with_private_keys(
            self.client_keypair, 
            5
        )?;
        
        // Store private keys for responding to initial messages
        self.private_keys = Some(private_keys);
        
        // Create inbox
        let inbox = PqxdhInbox::new(
            InboxType::Public,
            prekey_bundle,
            Some(1024), // Max message size
            None,       // No expiration
        );
        
        // Publish using helper
        let tag = publish_pqxdh_inbox(
            &self.messages_service,
            self.client_keypair,
            self.protocol.clone(),
            &inbox,
        ).await?;

        self.inbox_tag = Some(tag.clone());

        Ok(tag)
    }

    /// Get the inbox tag for this service
    pub fn inbox_tag(&self) -> &Option<Tag> {
        &self.inbox_tag
    }

    /// Set the inbox for this service
    pub fn set_inbox_tag(&mut self, inbox_tag: Tag) {
        self.inbox_tag = Some(inbox_tag);
    }

    /// Connect to a service provider's inbox (CLIENTS ONLY)
    /// 
    /// This discovers the target service provider's inbox and establishes a secure PQXDH session.
    /// Use this when you want to connect to a service as a client.
    /// 
    /// After calling this, use `send_message()` to send additional messages to the service.
    pub async fn connect_to_service(
        &mut self, 
        target_service_key: &VerifyingKey,
        initial_message: &T,
    ) -> Result<()> {
        // Discover inbox
        let (inbox, _tag) = fetch_pqxdh_inbox(
            &self.messages_service,
            target_service_key,
            self.protocol.clone(),
        )
        .await?
        .context("Target inbox not found")?;
        
        // Establish session
        let (session, _response): (PqxdhSession, Option<T>) = PqxdhSession::initiate(
            &self.messages_service,
            self.client_keypair,
            &inbox,
            initial_message,
        ).await?;
        
        // Store session
        let target_id = target_service_key.id().to_vec();
        self.sessions.insert(target_id.clone(), session);
        
        // Subscribe to the session channel for responses
        let session = &self.sessions[&target_id];
        let channel_config = SubscriptionConfig {
            filters: MessageFilters {
                filters: Some(vec![
                    Filter::Channel(session.channel_id().to_vec()),
                ]),
            },
            since: None,
            limit: None,
        };
        
        let subscription_id = self.messages_service
            .subscribe(channel_config)
            .await
            .context("Failed to subscribe to session channel")?;
            
        self.session_subscriptions.insert(target_id, subscription_id);
        
        Ok(())
    }
    
    /// Send a message to an established session (CLIENTS ONLY)
    /// 
    /// Use this to send additional messages after calling `connect_to_service()`.
    /// The message will be sent over the established secure PQXDH session.
    pub async fn send_message(&self, target_service_key: &VerifyingKey, message: &T) -> Result<()> {
        let target_id = target_service_key.id().to_vec();
        let session = self.sessions.get(&target_id)
            .context("No active session with target")?;
            
        session.send_message(&self.messages_service, self.client_keypair, message).await
    }
    
    /// Start listening for client connections (SERVICE PROVIDERS ONLY)
    /// 
    /// Call this after `publish_service()` to begin accepting client connections.
    /// This sets up subscriptions to receive initial PQXDH messages from clients.
    pub async fn start_listening_for_clients(&mut self) -> Result<()> {
        if self.private_keys.is_none() {
            return Err(anyhow::anyhow!("Must call publish_service() before listening for clients"));
        }

        let Some(tag) = &self.inbox_tag else {
            return Err(anyhow::anyhow!("Must no tag set"));
        };
        
        // Subscribe to messages from any author (we'll filter by PQXDH content)
        // In a real implementation, this might be more sophisticated
        let _config = SubscriptionConfig {
            filters: MessageFilters {
                filters: Some(vec![Filter::Tag(tag.clone())]),
            },
            since: None,
            limit: None,
        };
        
        // Note: This is a simplified version - the actual subscription logic
        // would need to be more sophisticated to handle the privacy-preserving tags
        
        Ok(())
    }
}

/// Helper function to create a PQXDH prekey bundle with private keys for testing
pub fn create_pqxdh_prekey_bundle_with_private_keys(
    identity_keypair: &zoe_wire_protocol::KeyPair,
    num_one_time_keys: usize,
) -> Result<(
    zoe_wire_protocol::inbox::pqxdh::PqxdhPrekeyBundle,
    zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys,
)> {
    let mut rng = rand::thread_rng();
    generate_pqxdh_prekeys(identity_keypair, num_one_time_keys, &mut rng)
        .map_err(|e| anyhow::anyhow!("Failed to generate PQXDH prekeys: {}", e))
}