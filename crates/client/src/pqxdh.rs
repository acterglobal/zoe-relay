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
use std::time::{SystemTime, UNIX_EPOCH};
use zoe_wire_protocol::{
    Kind, Message, MessageFull, PqxdhInboxProtocol, StoreKey, Tag, VerifyingKey,
    inbox::pqxdh::{
        InboxType, PqxdhInbox, PqxdhInitialPayload, PqxdhSharedSecret,
        decrypt_pqxdh_session_message, encrypt_pqxdh_session_message, generate_pqxdh_prekeys,
        pqxdh_initiate,
    },
    keys::Id as KeyId,
};

/// High-level PQXDH inbox management functions
///
/// These functions accept a `MessagesService` to allow reuse of existing connections
/// rather than creating new ones for each operation.
///
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
        let content_bytes = message_full
            .raw_content()
            .context("Message does not contain raw content")?;

        let inbox_data: T = postcard::from_bytes(content_bytes)
            .context("Failed to deserialize PQXDH inbox data")?;

        Ok(Some((inbox_data, Tag::from(&message_full))))
    } else {
        Ok(None)
    }
}

/// A PQXDH session for secure communication
#[derive(Serialize, Deserialize, Clone)]
pub struct PqxdhSession {
    shared_secret: PqxdhSharedSecret,
    /// Current sequence number for this session (stored as u64 for serialization)
    sequence_number: u64,
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
        target_tags: Vec<Tag>,
        initial_payload: &T,
    ) -> Result<(Self, Option<R>)> {
        // Extract the prekey bundle from the inbox
        let prekey_bundle = &inbox.pqxdh_prekeys;

        // Generate randomized channel ID for session messages
        let mut rng = rand::thread_rng();
        let mut session_channel_id = [0u8; 32];
        rng.fill_bytes(&mut session_channel_id);

        // Serialize the initial payload
        let user_payload_bytes =
            postcard::to_stdvec(initial_payload).context("Failed to serialize initial payload")?;

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
        let message_content =
            postcard::to_stdvec(&pqxdh_content).context("Failed to serialize PQXDH content")?;

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            message_content,
            client_keypair.public_key(),
            timestamp,
            Kind::Emphemeral(0),
            target_tags,
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
            sequence_number: 1,
            session_channel_id,
        };

        // For now, return None for the response - in a full implementation,
        // this would wait for and decrypt the response
        Ok((session, None))
    }

    /// Get the next sequence number and increment the internal counter
    pub fn next_sequence_number(&mut self) -> u64 {
        let current = self.sequence_number;
        self.sequence_number += 1;
        current
    }

    /// Send a message in an established PQXDH session
    pub async fn send_message<T: Serialize>(
        &mut self,
        messages_service: &MessagesService,
        client_keypair: &zoe_wire_protocol::KeyPair,
        payload: &T,
    ) -> Result<()> {
        // Serialize the payload
        let payload_bytes = postcard::to_stdvec(payload).context("Failed to serialize payload")?;

        // Encrypt as session message
        let sequence = self.next_sequence_number();
        let mut rng = rand::thread_rng();
        let session_message =
            encrypt_pqxdh_session_message(&self.shared_secret, &payload_bytes, sequence, &mut rng)?;

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
            sequence_number: 1,
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
    let message_content =
        postcard::to_stdvec(&pqxdh_content).context("Failed to serialize PQXDH content")?;

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

/// Serializable state for a PQXDH protocol handler
///
/// This structure contains all the persistent state needed to restore a
/// PqxdhProtocolHandler across application restarts. It excludes runtime
/// dependencies like the messages manager and client keypair.
#[derive(Serialize, Deserialize, Clone)]
pub struct PqxdhProtocolState {
    /// The PQXDH protocol variant being used
    pub protocol: PqxdhInboxProtocol,
    /// Active sessions keyed by target user ID
    pub sessions: BTreeMap<KeyId, PqxdhSession>,
    pub inbox_tag: Option<Tag>,
    /// Private keys for responding to initial messages (if we're a service provider)
    pub private_keys: Option<zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys>,
}

impl PqxdhProtocolState {
    /// Create a new empty protocol state
    pub fn new(protocol: PqxdhInboxProtocol) -> Self {
        Self {
            protocol,
            sessions: BTreeMap::new(),
            inbox_tag: None,
            private_keys: None,
        }
    }
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
    messages_manager: &'a crate::services::MessagesManager,
    client_keypair: &'a zoe_wire_protocol::KeyPair,
    /// Persistent state that can be serialized and restored
    state: PqxdhProtocolState,
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
    ///
    /// # Arguments
    /// * `messages_manager` - The messages manager to use for message operations
    /// * `client_keypair` - The client's keypair for signing and encryption
    /// * `protocol` - The specific PQXDH protocol variant to use
    pub fn new(
        messages_manager: &'a crate::services::MessagesManager,
        client_keypair: &'a zoe_wire_protocol::KeyPair,
        protocol: PqxdhInboxProtocol,
    ) -> Self {
        Self {
            messages_manager,
            client_keypair,
            state: PqxdhProtocolState::new(protocol),
            _phantom: std::marker::PhantomData,
        }
    }

    /// Create a protocol handler from existing serialized state
    ///
    /// This allows restoring a handler across application restarts by loading
    /// previously serialized state from a database or file.
    ///
    /// # Arguments
    /// * `messages_manager` - The messages manager to use for message operations
    /// * `client_keypair` - The client's keypair for signing and encryption
    /// * `state` - Previously serialized protocol state
    pub fn from_state(
        messages_manager: &'a crate::services::MessagesManager,
        client_keypair: &'a zoe_wire_protocol::KeyPair,
        state: PqxdhProtocolState,
    ) -> Self {
        Self {
            messages_manager,
            client_keypair,
            state,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Get the current state for serialization and persistence
    ///
    /// This returns a clone of the internal state that can be serialized
    /// and stored in a database for later restoration.
    pub fn get_state(&self) -> PqxdhProtocolState {
        self.state.clone()
    }

    /// Publish a service inbox for this protocol (SERVICE PROVIDERS ONLY)
    ///
    /// This makes the current client discoverable as a service provider for the given protocol.
    /// Only call this if you want to provide a service that others can connect to.
    ///
    /// After calling this, call `start_listening_for_clients()` to begin accepting connections.
    pub async fn publish_service(&mut self, force_overwrite: bool) -> Result<Tag> {
        if self.state.inbox_tag.is_some() && !force_overwrite {
            return Err(anyhow::anyhow!(
                "Inbox already published, use force_overwrite to overwrite"
            ));
        }

        // Generate prekey bundle with private keys
        let (prekey_bundle, private_keys) =
            create_pqxdh_prekey_bundle_with_private_keys(self.client_keypair, 5)?;

        // Store private keys for responding to initial messages
        self.state.private_keys = Some(private_keys);

        // Create inbox
        let inbox = PqxdhInbox::new(
            InboxType::Public,
            prekey_bundle,
            Some(1024), // Max message size
            None,       // No expiration
        );

        // Publish using helper
        let tag = publish_pqxdh_inbox(
            self.messages_manager.messages_service(),
            self.client_keypair,
            self.state.protocol.clone(),
            &inbox,
        )
        .await?;

        // Create subscription for this inbox tag
        let _stream = self
            .messages_manager
            .catch_up_and_subscribe((&tag).into(), None)
            .await
            .context("Failed to create inbox subscription")?;

        // Note: With the new state-based approach, we don't track individual subscription IDs
        // The MessagesManager handles all subscription state internally
        self.state.inbox_tag = Some(tag.clone());

        Ok(tag)
    }

    /// Get the inbox subscription tag for this service
    pub fn inbox_tag(&self) -> &Option<Tag> {
        &self.state.inbox_tag
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
    ) -> Result<impl futures::Stream<Item = Box<MessageFull>> + 'a> {
        // Discover inbox
        let (inbox, inbox_tag) = fetch_pqxdh_inbox(
            self.messages_manager.messages_service(),
            target_service_key,
            self.state.protocol.clone(),
        )
        .await?
        .context("Target inbox not found")?;

        // Establish session
        let (session, _response): (PqxdhSession, Option<T>) = PqxdhSession::initiate(
            self.messages_manager.messages_service(),
            self.client_keypair,
            &inbox,
            vec![inbox_tag],
            initial_message,
        )
        .await?;

        // Store session
        let target_id = target_service_key.id();
        self.state.sessions.insert(*target_id, session);

        // Subscribe to the session channel for responses
        let session = &self.state.sessions[target_id];
        let channel_tag = Tag::Channel {
            id: session.channel_id().to_vec(),
            relays: vec![],
        };

        self.messages_manager
            .catch_up_and_subscribe((&channel_tag).into(), None)
            .await
            .context("Failed to subscribe to session channel")
    }

    /// Send a message to an established session (CLIENTS ONLY)
    ///
    /// Use this to send additional messages after calling `connect_to_service()`.
    /// The message will be sent over the established secure PQXDH session.
    pub async fn send_message(
        &mut self,
        target_service_key: &VerifyingKey,
        message: &T,
    ) -> Result<()> {
        let target_id = target_service_key.id();
        let session = self
            .state
            .sessions
            .get_mut(target_id)
            .context("No active session with target")?;

        session
            .send_message(
                self.messages_manager.messages_service(),
                self.client_keypair,
                message,
            )
            .await
    }

    /// Start listening for client connections (SERVICE PROVIDERS ONLY)
    ///
    /// Call this after `publish_service()` to begin accepting client connections.
    /// This returns a stream of PQXDH messages that should be processed.
    ///
    /// # Returns
    /// A stream of PQXDH messages that the caller should process
    pub fn start_listening_for_clients(&self) -> Result<()> {
        // ) -> Result<impl futures::Stream<Item = zoe_wire_protocol::StreamMessage>> {
        todo!();
        // if self.state.private_keys.is_none() {
        //     anyhow::bail!("Must call publish_service() before listening for clients");
        // }

        // let Some(_subscription_id) = &self.state.inbox_subscription_id else {
        //     anyhow::bail!("No inbox subscription found - did you call publish_service()?");
        // };

        // Get a filtered stream for PQXDH messages
        // The subscription was already created in publish_service()
        // let pqxdh_stream = self.messages_manager.filtered_stream_fn(move |stream_message| {
        //     match stream_message {
        //         zoe_wire_protocol::StreamMessage::MessageReceived { message, .. } => {
        //             // Check if this is a PQXDH message
        //             Self::is_pqxdh_message(message)
        //         }
        //         zoe_wire_protocol::StreamMessage::StreamHeightUpdate(_) => false,
        //     }
        // });

        // tracing::info!("PQXDH: Started listening for client connections");

        // Ok(pqxdh_stream)
    }

    /// Check if a message is a PQXDH protocol message
    ///
    /// This is a helper function to identify PQXDH messages based on their content
    /// or other characteristics. For now, it's a placeholder that returns true.
    fn is_pqxdh_message(_message: &zoe_wire_protocol::MessageFull) -> bool {
        // TODO: Implement proper PQXDH message detection
        // This might involve:
        // - Checking message content type
        // - Looking for PQXDH-specific headers or metadata
        // - Validating message structure
        true
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

#[cfg(test)]
mod tests {
    use super::*;
    use zoe_wire_protocol::KeyPair;

    #[test]
    fn test_pqxdh_session_serialization() {
        // Create a test session
        let shared_secret = PqxdhSharedSecret {
            shared_key: [42u8; 32],
            consumed_one_time_key_ids: vec!["key1".to_string(), "key2".to_string()],
        };
        let session_channel_id = [1u8; 32];

        let session = PqxdhSession::from_shared_secret(shared_secret, session_channel_id);

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&session).expect("Failed to serialize session");
        let deserialized: PqxdhSession =
            postcard::from_bytes(&serialized).expect("Failed to deserialize session");

        // Verify the data is preserved
        assert_eq!(
            session.shared_secret.shared_key,
            deserialized.shared_secret.shared_key
        );
        assert_eq!(
            session.shared_secret.consumed_one_time_key_ids,
            deserialized.shared_secret.consumed_one_time_key_ids
        );
        assert_eq!(session.sequence_number, deserialized.sequence_number);
        assert_eq!(session.session_channel_id, deserialized.session_channel_id);
    }

    #[test]
    fn test_pqxdh_protocol_state_serialization() {
        let protocol = PqxdhInboxProtocol::EchoService;
        let mut state = PqxdhProtocolState::new(protocol.clone());

        // Add some test data
        state.inbox_tag = Some(Tag::Channel {
            id: vec![1, 2, 3, 4],
            relays: vec![],
        });

        let target_id: KeyId = [1u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [99u8; 32],
            consumed_one_time_key_ids: vec!["consumed_key".to_string()],
        };
        let session = PqxdhSession::from_shared_secret(shared_secret, [5u8; 32]);
        state.sessions.insert(target_id, session);

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&state).expect("Failed to serialize state");
        let deserialized: PqxdhProtocolState =
            postcard::from_bytes(&serialized).expect("Failed to deserialize state");

        // Verify the data is preserved
        assert_eq!(state.protocol, deserialized.protocol);
        assert_eq!(state.inbox_tag, deserialized.inbox_tag);
        assert_eq!(state.sessions.len(), deserialized.sessions.len());

        // Verify session data
        let original_session = &state.sessions[&target_id];
        let deserialized_session = &deserialized.sessions[&target_id];
        assert_eq!(
            original_session.shared_secret.shared_key,
            deserialized_session.shared_secret.shared_key
        );
        assert_eq!(
            original_session.sequence_number,
            deserialized_session.sequence_number
        );
        assert_eq!(
            original_session.session_channel_id,
            deserialized_session.session_channel_id
        );
    }

    #[test]
    fn test_pqxdh_private_keys_serialization() -> Result<()> {
        // Generate test keypair with random data
        let mut rng = rand::thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        // Generate prekey bundle with private keys (creates random keys)
        let (_prekey_bundle, private_keys) =
            create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3)?;

        // Test serialization round-trip
        let serialized = postcard::to_stdvec(&private_keys)?;
        let deserialized: zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys =
            postcard::from_bytes(&serialized)?;

        // Verify the data is preserved by comparing the keys directly (now that serde works)
        // We can't use PartialEq on StaticSecret, so we compare the bytes
        assert_eq!(
            private_keys.signed_prekey_private.to_bytes(),
            deserialized.signed_prekey_private.to_bytes()
        );
        assert_eq!(
            private_keys.one_time_prekey_privates.len(),
            deserialized.one_time_prekey_privates.len()
        );
        assert_eq!(
            private_keys.pq_signed_prekey_private,
            deserialized.pq_signed_prekey_private
        );
        assert_eq!(
            private_keys.pq_one_time_prekey_privates,
            deserialized.pq_one_time_prekey_privates
        );

        // Verify one-time keys (should be random and different each time)
        for (key_id, original_key) in &private_keys.one_time_prekey_privates {
            let deserialized_key = &deserialized.one_time_prekey_privates[key_id];
            assert_eq!(original_key.to_bytes(), deserialized_key.to_bytes());
        }

        // Verify that keys are actually random by generating another set
        let (_prekey_bundle2, private_keys2) =
            create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3)?;
        assert_ne!(
            private_keys.signed_prekey_private.to_bytes(),
            private_keys2.signed_prekey_private.to_bytes(),
            "Keys should be randomly generated and different"
        );

        Ok(())
    }
}
