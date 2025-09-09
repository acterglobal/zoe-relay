use eyeball::{AsyncLock, ObservableWriteGuard, SharedObservable};
use futures::StreamExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{error, warn};
use zoe_wire_protocol::{Content, Filter};
use zoe_wire_protocol::{
    KeyId, Kind, Message, MessageFull, PqxdhInboxProtocol, StoreKey, Tag, VerifyingKey,
    inbox::pqxdh::{
        InboxType, PqxdhInbox, PqxdhInitialPayload, generate_pqxdh_prekeys, pqxdh_initiate,
    },
};

use crate::pqxdh::PqxdhMessageListener;

use super::{
    PqxdhError, PqxdhProtocolState, PqxdhSession, PqxdhSessionId, PqxdhTarpcTransport, Result,
};

/// A complete PQXDH protocol handler that encapsulates all session management,
/// key observation, subscription handling, and message routing logic.
///
/// This provides a high-level abstraction over the entire PQXDH workflow with
/// automatic state management and persistence support. It can operate in two modes:
///
/// ## Service Provider Mode
/// - Publishes a PQXDH inbox for clients to discover
/// - Listens for incoming client connections
/// - Manages multiple concurrent client sessions
/// - Handles initial message decryption and session establishment
///
/// ## Client Mode  
/// - Discovers and connects to service provider inboxes
/// - Establishes secure sessions with service providers
/// - Sends messages over established sessions
/// - Manages session state and channel subscriptions
///
/// ## Key Features
/// - **State Persistence**: All state can be serialized and restored across restarts
/// - **State Observation**: Observable state changes via broadcast channels for reactive programming
/// - **Automatic Subscriptions**: Handles message routing and channel management
/// - **Session Management**: Tracks multiple concurrent sessions by user ID
/// - **Privacy Preserving**: Uses randomized channel IDs and derived tags
/// - **Type Safety**: Generic over message payload types with compile-time safety
#[derive(Clone)]
pub struct PqxdhProtocolHandler<T: crate::services::MessagesManagerTrait> {
    messages_manager: Arc<T>,
    client_keypair: Arc<zoe_wire_protocol::KeyPair>,
    /// Observable state that can be subscribed to for reactive programming
    pub(crate) state: SharedObservable<PqxdhProtocolState, AsyncLock>,
}

impl<T: crate::services::MessagesManagerTrait + 'static> PqxdhProtocolHandler<T> {
    /// Creates a new protocol handler for a specific PQXDH protocol
    ///
    /// This creates a fresh handler with empty state that can be used either as:
    /// - **Service Provider**: Call `publish_service()` then use `inbox_stream()`
    /// - **Client**: Call `connect_to_service()` then `send_message()`
    ///
    /// # Arguments
    /// * `messages_manager` - The messages manager to use for message operations
    /// * `client_keypair` - The client's keypair for signing and encryption
    /// * `protocol` - The specific PQXDH protocol variant to use
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use zoe_wire_protocol::*;
    /// # async fn example() -> Result<()> {
    /// # let messages_manager = todo!();
    /// # let keypair = todo!();
    /// let handler = PqxdhProtocolHandler::new(
    ///     &messages_manager,
    ///     &keypair,
    ///     PqxdhInboxProtocol::EchoService
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        messages_manager: Arc<T>,
        client_keypair: Arc<zoe_wire_protocol::KeyPair>,
        protocol: PqxdhInboxProtocol,
    ) -> Self {
        let initial_state = PqxdhProtocolState::new(protocol);
        let state = SharedObservable::new_async(initial_state);

        Self {
            messages_manager,
            client_keypair,
            state,
        }
    }

    /// Creates a protocol handler from existing serialized state
    ///
    /// This allows restoring a handler across application restarts by loading
    /// previously serialized state from a database or file. All sessions and
    /// cryptographic state will be restored to their previous state.
    ///
    /// # Arguments
    /// * `messages_manager` - The messages manager to use for message operations
    /// * `client_keypair` - The client's keypair for signing and encryption
    /// * `state` - Previously serialized protocol state
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use zoe_wire_protocol::*;
    /// # async fn example() -> Result<()> {
    /// # let messages_manager = todo!();
    /// # let keypair = todo!();
    /// // Load state from storage
    /// let saved_state: PqxdhProtocolState = load_from_database()?;
    ///
    /// // Restore handler with previous state
    /// let handler = PqxdhProtocolHandler::from_state(
    ///     &messages_manager,
    ///     &keypair,
    ///     saved_state
    /// );
    /// # Ok(())
    /// # }
    /// # fn load_from_database() -> Result<PqxdhProtocolState> { todo!() }
    /// ```
    pub fn from_state(
        messages_manager: Arc<T>,
        client_keypair: Arc<zoe_wire_protocol::KeyPair>,
        state: PqxdhProtocolState,
    ) -> Self {
        let state = SharedObservable::new_async(state);

        Self {
            messages_manager,
            client_keypair,
            state,
        }
    }

    /// Subscribe to state changes for reactive programming
    ///
    /// This method returns a broadcast receiver that can be used to observe changes to the
    /// protocol handler's internal state. This is useful for building reactive UIs
    /// or implementing state-dependent logic that needs to respond to changes in
    /// session state, inbox status, or other protocol state.
    ///
    /// # Returns
    /// Returns a `broadcast::Receiver<PqxdhProtocolState>` that receives state updates
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let handler: PqxdhProtocolHandler = todo!();
    /// // Subscribe to state changes
    /// let mut state_receiver = handler.subscribe_to_state();
    ///
    /// // Get current state
    /// let current_state = handler.current_state();
    /// println!("Current sessions: {}", current_state.sessions.len());
    ///
    /// // Watch for state changes
    /// let mut state_stream = state_receiver.subscribe();
    /// while let Some(new_state) = state_stream.next().await {
    ///     println!("State updated! Sessions: {}", new_state.sessions.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn subscribe_to_state(&self) -> eyeball::Subscriber<PqxdhProtocolState, AsyncLock> {
        self.state.subscribe().await
    }

    /// Publishes a service inbox for this protocol (SERVICE PROVIDERS ONLY)
    ///
    /// This makes the current client discoverable as a service provider for the given protocol.
    /// It generates fresh prekey bundles, publishes the inbox to the message store, and sets up
    /// the necessary subscriptions for receiving client connections.
    ///
    /// Only call this if you want to provide a service that others can connect to.
    /// After calling this, use `inbox_stream()` to listen for incoming client messages.
    ///
    /// # Arguments
    /// * `force_overwrite` - If true, overwrites any existing published inbox
    ///
    /// # Returns
    /// Returns the `Tag` of the published inbox
    ///
    /// # Errors
    /// Returns an error if an inbox is already published and `force_overwrite` is false,
    /// or if the publishing process fails.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// // Publish service for clients to discover
    /// let inbox_tag = handler.publish_service(false).await?;
    /// println!("Service published with tag: {:?}", inbox_tag);
    ///
    /// // Now listen for client connections
    /// let mut inbox_stream = Box::pin(handler.inbox_stream::<String>().await?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn publish_service(&self, force_overwrite: bool) -> Result<Tag> {
        let (inbox_tag, protocol) = {
            let current_state = self.state.get().await;
            (
                current_state.inbox_tag.clone(),
                current_state.protocol.clone(),
            )
        };

        if inbox_tag.is_some() && !force_overwrite {
            return Err(PqxdhError::InboxAlreadyPublished);
        }

        // Generate prekey bundle with private keys
        let (prekey_bundle, private_keys) =
            create_pqxdh_prekey_bundle_with_private_keys(&self.client_keypair, 5)?;

        // Create inbox
        let inbox = PqxdhInbox::new(
            InboxType::Public,
            prekey_bundle,
            Some(1024), // Max message size
            None,       // No expiration
        );

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Create storage message for the PQXDH inbox
        let inbox_message = Message::new_v0(
            Content::Raw(postcard::to_stdvec(&inbox)?),
            self.client_keypair.public_key(),
            timestamp,
            Kind::Store(StoreKey::PqxdhInbox(protocol)),
            vec![],
        );

        let inbox_message_full =
            MessageFull::new(inbox_message, &self.client_keypair).map_err(|e| {
                PqxdhError::MessageCreation(format!(
                    "Failed to create MessageFull for inbox: {}",
                    e
                ))
            })?;

        let target_tag = Tag::from(&inbox_message_full);

        // Publish the inbox
        self.messages_manager.publish(inbox_message_full).await?;

        // Update state and notify observers
        {
            let mut state = self.state.write().await;
            ObservableWriteGuard::update(&mut state, |state| {
                state.private_keys = Some(private_keys);
                state.inbox_tag = Some(target_tag.clone());
                state.inbox = Some(inbox);
            });
        }

        Ok(target_tag)
    }

    /// Connects to a service provider's inbox (CLIENTS ONLY)
    ///
    /// This discovers the target service provider's inbox and establishes a secure PQXDH session.
    /// It performs the full PQXDH key exchange protocol and sets up the necessary subscriptions
    /// for receiving responses from the service.
    ///
    /// Use this when you want to connect to a service as a client.
    /// After calling this, use `send_message()` to send additional messages to the service.
    ///
    /// # Arguments
    /// * `target_service_key` - The public key of the service provider to connect to
    /// * `initial_message` - The first message to send as part of the connection
    ///
    /// # Returns
    /// Returns a stream of messages from the service provider
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// # let service_key = todo!();
    /// // Connect to service and send initial message
    /// let mut response_stream = Box::pin(handler.connect_to_service::<String, String>(
    ///     &service_key,
    ///     &"Hello, service!".to_string()
    /// ).await?);
    ///
    /// // Listen for responses
    /// while let Some(message) = response_stream.next().await {
    ///     // Handle service responses
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_to_service<O, I>(
        &self,
        target_service_key: &VerifyingKey,
        initial_message: &O,
    ) -> Result<(PqxdhSessionId, PqxdhMessageListener<I>)>
    where
        O: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
        I: for<'de> serde::Deserialize<'de> + Clone + 'static,
    {
        let protocol = self.state.get().await.protocol.clone();
        // Discover inbox
        let (inbox, inbox_tag) = self.fetch_pqxdh_inbox(target_service_key, protocol).await?;

        // Establish session
        let session = self
            .initiate_session(
                target_service_key.clone(),
                &inbox,
                vec![inbox_tag],
                initial_message,
            )
            .await?;

        let my_session_id = session.my_session_channel_id;

        // Update state and notify observers
        {
            let mut state = self.state.write().await;
            ObservableWriteGuard::update(&mut state, |state| {
                if state
                    .sessions
                    .insert(KeyId::from_bytes(my_session_id), session)
                    .is_some()
                {
                    warn!("overwriting existing pqxdh session. Shouldn't happen");
                }
            });
        }

        Ok((
            my_session_id,
            self.listen_for_messages(my_session_id, true).await?,
        ))
    }

    pub async fn listen_for_messages<I>(
        &self,
        my_session_id: PqxdhSessionId,
        catch_up: bool,
    ) -> Result<PqxdhMessageListener<I>>
    where
        I: for<'de> serde::Deserialize<'de>,
    {
        let listening_tag = {
            let state = self.state.get().await;
            let Some(session) = state.sessions.get(&KeyId::from_bytes(my_session_id)) else {
                return Err(PqxdhError::SessionNotFound);
            };
            session.listening_channel_tag()
        };

        let messages_manager = self.messages_manager.clone();
        let state = self.state.clone();
        Ok(PqxdhMessageListener::new(
            messages_manager,
            my_session_id,
            state,
            listening_tag,
            catch_up,
        )
        .await?)
    }

    pub async fn tarpc_transport<Req, Resp>(
        &self,
        session_id: PqxdhSessionId,
    ) -> Result<PqxdhTarpcTransport<Req, Resp>>
    where
        Req: for<'de> serde::Deserialize<'de> + Send + 'static,
        Resp: serde::Serialize + Send + Sync + 'static,
        Self: Clone,
    {
        // Create the incoming stream first
        let stream = self
            .clone()
            .listen_for_messages::<Req>(session_id, false)
            .await?;

        // Create the transport with the stream and client
        Ok(PqxdhTarpcTransport::new(
            session_id,
            Box::pin(stream),
            self.clone(),
        ))
    }

    /// Sends a message to an established session (CLIENTS ONLY)
    ///
    /// Use this to send additional messages after calling `connect_to_service()`.
    /// The message will be encrypted and sent over the established secure PQXDH session
    /// using the session's private channel.
    ///
    /// # Arguments
    /// * `session_id` - The session ID of the established PQXDH session
    /// * `message` - The message payload to encrypt and send
    ///
    /// # Errors
    /// Returns an error if no active session exists with the given session ID
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// # let service_key = todo!();
    /// # let session_id = [0u8; 32]; // Session ID from established connection
    /// // First establish connection
    /// let _stream = handler.connect_to_service::<String, String>(&service_key, &"initial".to_string()).await?;
    ///
    /// // Send follow-up messages using session ID
    /// handler.send_message(&session_id, &"follow-up message".to_string()).await?;
    /// handler.send_message(&session_id, &"another message".to_string()).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn send_message<U>(&self, session_id: &PqxdhSessionId, message: &U) -> Result<()>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        self.send_message_inner(session_id, message, Kind::Regular)
            .await
    }

    pub async fn send_ephemeral_message<U>(
        &self,
        session_id: &PqxdhSessionId,
        message: &U,
        timeout: u32,
    ) -> Result<()>
    where
        U: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        self.send_message_inner(session_id, message, Kind::Ephemeral(timeout))
            .await
    }

    /// Creates a stream of messages that arrive to our inbox (SERVICE PROVIDERS ONLY)
    ///
    /// This method returns a stream of incoming messages from clients who are connecting
    /// to or communicating with this service. The stream includes both initial PQXDH
    /// messages (new client connections) and session messages (ongoing communication).
    ///
    /// # Returns
    /// Returns a stream of `(PqxdhSessionId, T)` tuples where:
    /// - `PqxdhSessionId` is the session ID for the client connection
    /// - `T` is the deserialized message payload from the client
    ///
    /// # Errors
    /// Returns an error if `publish_service()` has not been called first
    ///
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::pqxdh::*;
    /// # use futures::StreamExt;
    /// # async fn example() -> Result<()> {
    /// # let mut handler: PqxdhProtocolHandler = todo!();
    /// // First publish the service
    /// handler.publish_service(false).await?;
    ///
    /// // Then listen for client messages
    /// let mut inbox_stream = Box::pin(handler.inbox_stream::<String>().await?);
    /// while let Some((session_id, message)) = inbox_stream.next().await {
    ///     println!("Received message from session {:?}: {}", session_id, message);
    ///     
    ///     // Echo the message back to the client
    ///     handler.send_message(&session_id, &format!("Echo: {}", message)).await?;
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn inbox_stream<U>(&self) -> Result<impl futures::Stream<Item = (PqxdhSessionId, U)>>
    where
        U: for<'de> serde::Deserialize<'de>,
    {
        let inbox_tag = {
            let current_state = self.state.get().await;
            if current_state.private_keys.is_none() {
                return Err(PqxdhError::ServiceNotPublished);
            };

            let Some(inbox_tag) = &current_state.inbox_tag else {
                return Err(PqxdhError::NoInboxSubscription);
            };
            inbox_tag.clone()
        };

        self.messages_manager
            .ensure_contains_filter(Filter::from(inbox_tag.clone()))
            .await?;

        let stream = self
            .messages_manager
            .filtered_messages_stream(Filter::from(inbox_tag));

        let state = self.state.clone();
        let my_public_key = self.client_keypair.public_key().clone();

        let stream = stream.filter_map(move |message_full| {
            let state = state.clone();
            let my_public_key = my_public_key.clone();
            async move {
                Self::on_incoming_inbox_message::<U>(&state, &my_public_key, &message_full)
                    .await
                    .inspect_err(|e| {
                        error!(
                            msg_id = hex::encode(message_full.id().as_bytes()),
                            "error processing inbox message: {e}"
                        );
                    })
                    .ok()
            }
        });

        Ok(stream)
    }
}

#[async_trait::async_trait]
impl<Resp, T: crate::services::MessagesManagerTrait> super::PqxdhTarpcTransportSender<Resp>
    for PqxdhProtocolHandler<T>
where
    Resp: serde::Serialize + Send + Sync,
{
    async fn send_response(&self, session_id: &PqxdhSessionId, resp: &Resp) -> Result<()> {
        self.send_message_inner(session_id, &resp, Kind::Ephemeral(10))
            .await
    }
}

// Internal functions

impl<T: crate::services::MessagesManagerTrait> PqxdhProtocolHandler<T> {
    /// Fetch a PQXDH inbox using the trait method
    async fn fetch_pqxdh_inbox<U: for<'de> Deserialize<'de>>(
        &self,
        provider_key: &VerifyingKey,
        protocol: PqxdhInboxProtocol,
    ) -> Result<(U, Tag)> {
        let provider_user_id = *provider_key.id();
        let store_key = StoreKey::PqxdhInbox(protocol);

        let Some(message_full) = self
            .messages_manager
            .user_data(KeyId::from(*provider_user_id.as_bytes()), store_key)
            .await?
        else {
            return Err(PqxdhError::InboxNotFound);
        };

        let Some(content_bytes) = message_full.raw_content() else {
            return Err(PqxdhError::NoContent);
        };

        let inbox_data: U = postcard::from_bytes(content_bytes)?;

        Ok((inbox_data, Tag::from(&message_full)))
    }

    /// Initiates a PQXDH session with a target user using an already loaded inbox
    async fn initiate_session<U: Serialize>(
        &self,
        target_public_key: VerifyingKey,
        inbox: &PqxdhInbox,
        target_tags: Vec<Tag>,
        initial_payload: &U,
    ) -> Result<PqxdhSession> {
        // Extract the prekey bundle from the inbox
        let prekey_bundle = &inbox.pqxdh_prekeys;

        // Generate randomized channel ID for session messages
        let mut rng = rand::thread_rng();
        let mut session_channel_id_prefix = PqxdhSessionId::default();
        rng.fill_bytes(&mut session_channel_id_prefix);

        let their_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(target_public_key.id().as_ref());
            hasher.finalize()
        };

        let my_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(self.client_keypair.public_key().id().as_ref());
            hasher.finalize()
        };

        // Create the combined initial payload with channel ID
        let initial_payload_struct = PqxdhInitialPayload {
            user_payload: initial_payload,
            session_channel_id_prefix,
        };

        let combined_payload_bytes = postcard::to_stdvec(&initial_payload_struct)?;

        // Initiate PQXDH
        let (initial_message, shared_secret) = pqxdh_initiate(
            &self.client_keypair,
            prekey_bundle,
            &combined_payload_bytes,
            &mut rng,
        )
        .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_message);

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            Content::PqxdhEncrypted(pqxdh_content),
            self.client_keypair.public_key(),
            timestamp,
            Kind::Ephemeral(0),
            target_tags,
        );

        let message_full = MessageFull::new(message, &self.client_keypair).map_err(|e| {
            PqxdhError::MessageCreation(format!("Failed to create initial message: {}", e))
        })?;

        // The initial message will be routed using its derived tag (Tag::Event with message ID)
        // This is automatically created by Tag::from(&MessageFull)

        self.messages_manager.publish(message_full).await?;

        Ok(PqxdhSession {
            shared_secret,
            sequence_number: 1,
            my_session_channel_id: my_session_channel_id.into(),
            their_session_channel_id: their_session_channel_id.into(),
            their_key: target_public_key,
        })
    }

    async fn on_incoming_inbox_message<U>(
        state: &SharedObservable<PqxdhProtocolState, AsyncLock>,
        my_public_key: &VerifyingKey,
        message_full: &MessageFull,
    ) -> Result<(PqxdhSessionId, U)>
    where
        U: for<'de> serde::Deserialize<'de>,
    {
        let msg_id_hex = hex::encode(message_full.id().as_bytes());
        let Some(pqxdh_content) = message_full.content().as_pqxdh_encrypted() else {
            warn!(
                msg_id = msg_id_hex,
                "not the proper content type on message"
            );
            return Err(PqxdhError::InvalidContentType);
        };

        let (private_keys, prekey_bundle) = {
            let current_state = state.get().await;
            let Some(private_keys) = current_state.private_keys else {
                error!(msg_id = msg_id_hex, "no private keys");
                return Err(PqxdhError::NoPrivateKeys);
            };
            let Some(ref inbox) = current_state.inbox else {
                error!(msg_id = msg_id_hex, "no inbox");
                return Err(PqxdhError::NoInbox);
            };
            (private_keys.clone(), inbox.pqxdh_prekeys.clone())
        };

        let initial_msg = match pqxdh_content {
            zoe_wire_protocol::PqxdhEncryptedContent::Initial(initial_msg) => initial_msg,
            _ => {
                warn!(
                    msg_id = msg_id_hex,
                    "not an inbox initial message. ignoring incoming message."
                );
                return Err(PqxdhError::NotInitialMessage);
            }
        };

        let (decrypted_payload, shared_secret) =
            zoe_wire_protocol::inbox::pqxdh::pqxdh_crypto::pqxdh_respond(
                initial_msg,
                &private_keys,
                &prekey_bundle,
            )
            .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        // Deserialize the PqxdhInitialPayload structure with the user payload type
        let initial_payload: PqxdhInitialPayload<U> = postcard::from_bytes(&decrypted_payload)?;

        let PqxdhInitialPayload {
            user_payload: user_message,
            session_channel_id_prefix,
        } = initial_payload;

        let my_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(my_public_key.id().as_ref());
            hasher.finalize().into()
        };

        let their_session_channel_id = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&session_channel_id_prefix);
            hasher.update(message_full.author().id().as_ref());
            hasher.finalize().into()
        };

        // Create session
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            my_session_channel_id,
            their_session_channel_id,
            message_full.author().clone(),
        );

        // Update state
        let mut current_state = state.write().await;
        ObservableWriteGuard::update(&mut current_state, |state| {
            if state
                .sessions
                .insert(KeyId::from_bytes(my_session_channel_id), session)
                .is_some()
            {
                error!("overwriting existing pqxdh session. Shouldn't happen");
            }
        });

        Ok((my_session_channel_id, user_message))
    }

    async fn send_message_inner<U>(
        &self,
        session_id: &PqxdhSessionId,
        message: &U,
        kind: Kind,
    ) -> Result<()>
    where
        U: serde::Serialize,
    {
        let full_msg = {
            let mut current_state = self.state.write().await;
            let Some(mut session) = current_state
                .sessions
                .get(&KeyId::from_bytes(*session_id))
                .cloned()
            else {
                return Err(PqxdhError::SessionNotFound);
            };

            let msg = session.gen_next_message(&self.client_keypair, message, kind)?;

            ObservableWriteGuard::update(&mut current_state, |state: &mut PqxdhProtocolState| {
                state
                    .sessions
                    .insert(KeyId::from_bytes(*session_id), session); // re-add the changed session
            });

            msg
        };

        self.messages_manager.publish(full_msg).await?;

        Ok(())
    }
}

pub(crate) fn create_pqxdh_prekey_bundle_with_private_keys(
    identity_keypair: &zoe_wire_protocol::KeyPair,
    num_one_time_keys: usize,
) -> Result<(
    zoe_wire_protocol::inbox::pqxdh::PqxdhPrekeyBundle,
    zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys,
)> {
    let mut rng = rand::thread_rng();
    generate_pqxdh_prekeys(identity_keypair, num_one_time_keys, &mut rng)
        .map_err(|e| PqxdhError::KeyGeneration(format!("Failed to generate PQXDH prekeys: {}", e)))
}
