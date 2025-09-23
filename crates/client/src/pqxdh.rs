//! Post-Quantum Extended Diffie-Hellman (PQXDH) Protocol Implementation
//!
//! This module provides a complete, high-level implementation of the PQXDH protocol
//! for secure, post-quantum resistant communication. It includes both client and
//! service provider functionality with automatic session management.
//!
//! ## Core Components
//!
//! ### 1. Inbox Management
//! - **Publishing**: Service providers can publish PQXDH inboxes to advertise their availability
//! - **Discovery**: Clients can discover and fetch service provider inboxes
//! - **Privacy**: Uses type-safe protocols and deterministic serialization with postcard
//!
//! ### 2. Session Establishment
//! - **Initiation**: Clients can establish secure sessions with service providers
//! - **Privacy-Preserving**: Uses randomized channel IDs for unlinkable communication
//! - **Post-Quantum Security**: Leverages PQXDH for quantum-resistant key exchange
//!
//! ### 3. Message Communication
//! - **Session Messages**: Encrypted communication over established sessions
//! - **Channel Management**: Automatic subscription handling for session channels
//! - **Sequence Numbers**: Built-in replay protection with sequence numbering
//!
//! ### 4. State Management
//! - **Persistence**: Serializable state for application restarts
//! - **Session Tracking**: Automatic management of multiple concurrent sessions
//! - **Key Management**: Secure handling of private keys and prekey bundles
//! ## Usage Patterns
//!
//! ### Service Provider Pattern
//! ```rust,no_run
//! # use zoe_client::pqxdh::*;
//! # use zoe_wire_protocol::*;
//! # use futures::StreamExt;
//! # async fn example() -> Result<()> {
//! # let messages_manager = todo!();
//! # let keypair = todo!();
//! // 1. Create handler and publish service
//! let mut handler = PqxdhProtocolHandler::new(
//!     &messages_manager,
//!     &keypair,
//!     PqxdhInboxProtocol::EchoService
//! );
//! handler.publish_service(false).await?;
//!
//! // 2. Listen for incoming client connections
//! let mut inbox_stream = Box::pin(handler.inbox_stream::<String>().await?);
//! while let Some((session_id, message)) = inbox_stream.next().await {
//!     // Handle client messages
//!     println!("Received from {:?}: {}", session_id, message);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Client Pattern
//! ```rust,no_run
//! # use zoe_client::pqxdh::*;
//! # use zoe_wire_protocol::*;
//! # use futures::StreamExt;
//! # async fn example() -> Result<()> {
//! # let messages_manager = todo!();
//! # let keypair = todo!();
//! # let service_key = todo!();
//! # let session_id = [0u8; 32]; // Session ID obtained from connection
//! # let initial_message = "hello".to_string();
//! // 1. Create handler and connect to service
//! let mut handler = PqxdhProtocolHandler::new(
//!     &messages_manager,
//!     &keypair,
//!     PqxdhInboxProtocol::EchoService
//! );
//! let mut response_stream = Box::pin(handler.connect_to_service::<String, String>(
//!     &service_key,
//!     &initial_message
//! ).await?);
//!
//! // 2. Send additional messages using session ID
//! handler.send_message(&session_id, &"follow up message".to_string()).await?;
//!
//! // 3. Listen for responses
//! while let Some(response) = response_stream.next().await {
//!     println!("Received response: {}", response);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Features
//!
//! - **Post-Quantum Resistance**: Uses CRYSTALS-Kyber for key encapsulation
//! - **Forward Secrecy**: Each session uses ephemeral keys
//! - **Replay Protection**: Sequence numbers prevent message replay attacks
//! - **Unlinkability**: Randomized channel IDs prevent traffic analysis
//! - **Authentication**: All messages are cryptographically signed
//!
//! ## Error Handling
//!
//! This module uses a custom [`PqxdhError`] type that provides structured error handling
//! for all PQXDH operations. The error type includes specific variants for different
//! failure modes:
//!
//! - **Connection Errors**: `InboxNotFound`, `ServiceNotPublished`, `NoInboxSubscription`
//! - **Session Errors**: `SessionNotFound`, `InvalidSender`, `NotInitialMessage`
//! - **Cryptographic Errors**: `Crypto`, `KeyGeneration`, `PqxdhProtocol`
//! - **Message Errors**: `InvalidContentType`, `NotPqxdhMessage`, `MessageCreation`
//! - **Infrastructure Errors**: `Rpc`, `MessagesService`, `Serialization`
//!
//! ### Error Handling Example
//! ```rust,no_run
//! # use zoe_client::pqxdh::*;
//! # async fn example() -> Result<()> {
//! # let mut handler: PqxdhProtocolHandler = todo!();
//! match handler.publish_service(false).await {
//!     Ok(tag) => println!("Service published with tag: {:?}", tag),
//!     Err(PqxdhError::InboxAlreadyPublished) => {
//!         println!("Service already published, use force_overwrite=true");
//!     }
//!     Err(PqxdhError::KeyGeneration(msg)) => {
//!         eprintln!("Failed to generate keys: {}", msg);
//!     }
//!     Err(e) => eprintln!("Unexpected error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Serialization
//!
//! All data structures use `postcard` for efficient binary serialization,
//! providing compact wire formats and deterministic encoding for cryptographic
//! operations. This ensures compatibility with the project's binary-first
//! architecture and optimal network efficiency.

mod error;
mod handler;
mod message_listener;
mod session;
mod state;
mod transport;

pub use error::*;
pub use handler::*;
pub use message_listener::*;
pub use session::*;
pub use state::*;
pub use transport::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use eyeball::{AsyncLock, SharedObservable};
    use futures::stream;
    use mockall::predicate::*;
    use zoe_state_machine::messages::MockMessagesManagerTrait;

    use zoe_wire_protocol::{
        Content, KeyId, KeyPair, Kind, Message, MessageFull, PqxdhInboxProtocol, PqxdhSharedSecret,
        inbox::pqxdh::{InboxType, PqxdhInbox},
    };
    use zoe_wire_protocol::{PublishResult, StoreKey, Tag};

    #[test]
    fn test_pqxdh_session_serialization() {
        // Create a test session
        let shared_secret = PqxdhSharedSecret {
            shared_key: [42u8; 32],
            consumed_one_time_key_ids: vec!["key1".to_string(), "key2".to_string()],
        };
        let session_channel_id = [1u8; 32];

        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_channel_id,
            session_channel_id, // their_session_channel_id
            keypair.public_key(),
        );

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
        assert_eq!(
            session.my_session_channel_id,
            deserialized.my_session_channel_id
        );
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

        let target_id: KeyId = KeyId::from_bytes([1u8; 32]);
        let shared_secret = PqxdhSharedSecret {
            shared_key: [99u8; 32],
            consumed_one_time_key_ids: vec!["consumed_key".to_string()],
        };
        let keypair = KeyPair::generate(&mut rand::thread_rng());
        let session = PqxdhSession::from_shared_secret(
            shared_secret,
            [5u8; 32],
            [6u8; 32], // their_session_channel_id
            keypair.public_key(),
        );
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
            original_session.my_session_channel_id,
            deserialized_session.my_session_channel_id
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

    // Helper functions for tests
    fn create_test_keypair() -> KeyPair {
        KeyPair::generate(&mut rand::thread_rng())
    }

    fn create_test_inbox() -> PqxdhInbox {
        let keypair = Arc::new(create_test_keypair());
        let (prekey_bundle, _) = create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3).unwrap();
        PqxdhInbox::new(InboxType::Public, prekey_bundle, Some(1024), None)
    }

    fn create_test_message_full(content: Content, author: &KeyPair) -> MessageFull {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let message = Message::new_v0(
            content,
            author.public_key(),
            timestamp,
            Kind::Regular,
            vec![],
        );
        MessageFull::new(message, author).unwrap()
    }

    type TestPqxdhHandler = PqxdhProtocolHandler<MockMessagesManagerTrait>;

    #[tokio::test]
    async fn test_publish_service_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock the publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "123".to_string(),
            })
        });

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let result = handler.publish_service(false).await;
        assert!(result.is_ok());

        // Verify that the state was updated
        let state = handler.state.read().await;
        assert!(state.inbox_tag.is_some());
        assert!(state.private_keys.is_some());
        assert!(state.inbox.is_some());
    }

    /// Test service provider publish_service with already published inbox
    #[tokio::test]
    async fn test_publish_service_already_published() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Manually set inbox_tag to simulate already published state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
            },
        )
        .await;

        let result = handler.publish_service(false).await;
        assert!(matches!(result, Err(PqxdhError::InboxAlreadyPublished)));
    }

    /// Test service provider publish_service with force overwrite
    #[tokio::test]
    async fn test_publish_service_force_overwrite() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock the publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "123".to_string(),
            })
        });

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Manually set inbox_tag to simulate already published state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
            },
        )
        .await;

        let result = handler.publish_service(true).await;
        assert!(result.is_ok());
    }

    /// Test client connect_to_service functionality
    #[tokio::test]
    async fn test_connect_to_service_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let client_keypair = Arc::new(create_test_keypair());
        let service_keypair = create_test_keypair();
        let service_key = service_keypair.public_key();

        let test_inbox = create_test_inbox();

        // Mock user_data call to return the inbox
        let inbox_message = create_test_message_full(
            Content::Raw(postcard::to_stdvec(&test_inbox).unwrap()),
            &service_keypair,
        );
        mock_manager
            .expect_user_data()
            .with(
                eq(KeyId::from(*service_key.id())),
                eq(StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService)),
            )
            .times(1)
            .returning(move |_, _| Ok(Some(inbox_message.clone())));

        // Mock publish call for the initial PQXDH message
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "456".to_string(),
            })
        });

        // Mock catch_up_and_subscribe for listening to responses
        mock_manager
            .expect_catch_up_and_subscribe()
            .times(1)
            .returning(|_, _| Ok(Box::pin(stream::empty())));

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            client_keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let initial_message = "Hello, service!".to_string();
        let result = handler
            .connect_to_service::<String, String>(&service_key, &initial_message)
            .await;

        assert!(result.is_ok());
        let (session_id, _stream) = result.unwrap();

        // Drop the stream to release the borrow on handler
        drop(_stream);

        // Verify session was created
        let state = handler.state.read().await;
        assert!(state.sessions.contains_key(&KeyId::from_bytes(session_id)));
    }

    /// Test client connect_to_service with inbox not found
    #[tokio::test]
    async fn test_connect_to_service_inbox_not_found() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let client_keypair = Arc::new(create_test_keypair());
        let service_keypair = create_test_keypair();
        let service_key = service_keypair.public_key();

        // Mock user_data call to return None (inbox not found)
        mock_manager
            .expect_user_data()
            .with(
                eq(KeyId::from(*service_key.id())),
                eq(StoreKey::PqxdhInbox(PqxdhInboxProtocol::EchoService)),
            )
            .times(1)
            .returning(|_, _| Ok(None));

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            client_keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let initial_message = "Hello, service!".to_string();
        let result = handler
            .connect_to_service::<String, String>(&service_key, &initial_message)
            .await;

        assert!(matches!(result, Err(PqxdhError::InboxNotFound)));
    }

    /// Test send_message functionality
    #[tokio::test]
    async fn test_send_message_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "789".to_string(),
            })
        });

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Create a test session
        let session_id: PqxdhSessionId = [42u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [1u8; 32],
            consumed_one_time_key_ids: vec![],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [43u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        // Add session to state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state
                    .sessions
                    .insert(KeyId::from_bytes(session_id), test_session);
            },
        )
        .await;

        let message = "Test message".to_string();
        let result = handler.send_message(&session_id, &message).await;

        assert!(result.is_ok());
    }

    /// Test send_message with session not found
    #[tokio::test]
    async fn test_send_message_session_not_found() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let session_id: PqxdhSessionId = [42u8; 32];
        let message = "Test message".to_string();
        let result = handler.send_message(&session_id, &message).await;

        assert!(matches!(result, Err(PqxdhError::SessionNotFound)));
    }

    /// Test inbox_stream functionality for service providers
    #[tokio::test]
    async fn test_inbox_stream_success() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock ensure_contains_filter and filtered_messages_stream
        mock_manager
            .expect_ensure_contains_filter()
            .times(1)
            .returning(|_| Ok(()));

        mock_manager
            .expect_filtered_messages_stream()
            .times(1)
            .returning(|_| Box::pin(stream::empty()));

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Set up service provider state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
                let (_, private_keys) =
                    create_pqxdh_prekey_bundle_with_private_keys(&keypair, 3).unwrap();
                state.private_keys = Some(private_keys);
                state.inbox = Some(create_test_inbox());
            },
        )
        .await;

        let result = handler.inbox_stream::<String>().await;
        assert!(result.is_ok());
    }

    /// Test inbox_stream without published service
    #[tokio::test]
    async fn test_inbox_stream_service_not_published() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let result = handler.inbox_stream::<String>().await;
        assert!(matches!(result, Err(PqxdhError::ServiceNotPublished)));
    }

    /// Test state serialization and restoration
    #[tokio::test]
    async fn test_state_persistence() {
        let mock_manager = Arc::new(MockMessagesManagerTrait::new());
        let keypair = Arc::new(create_test_keypair());

        // Create handler with initial state
        let original_handler = TestPqxdhHandler::new(
            mock_manager.clone(),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Add some state
        let session_id: PqxdhSessionId = [99u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [2u8; 32],
            consumed_one_time_key_ids: vec!["test_key".to_string()],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [100u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        SharedObservable::<_, AsyncLock>::update(
            &original_handler.state,
            |state: &mut PqxdhProtocolState| {
                state
                    .sessions
                    .insert(KeyId::from_bytes(session_id), test_session);
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![4, 5, 6],
                    relays: vec![],
                });
            },
        )
        .await;

        // Serialize state
        let serialized_state = {
            let state = original_handler.state.read().await;
            postcard::to_stdvec(&*state).unwrap()
        };

        // Deserialize and create new handler
        let restored_state: PqxdhProtocolState = postcard::from_bytes(&serialized_state).unwrap();
        let restored_handler =
            TestPqxdhHandler::from_state(mock_manager.clone(), keypair.clone(), restored_state);

        // Verify state was restored correctly
        let restored_state = restored_handler.state.read().await;
        assert!(
            restored_state
                .sessions
                .contains_key(&KeyId::from_bytes(session_id))
        );
        assert_eq!(restored_state.protocol, PqxdhInboxProtocol::EchoService);
        assert_eq!(
            restored_state.inbox_tag,
            Some(Tag::Channel {
                id: vec![4, 5, 6],
                relays: vec![]
            })
        );
    }

    /// Test error handling for various scenarios
    #[tokio::test]
    async fn test_error_handling_scenarios() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Test RPC error during publish
        mock_manager
            .expect_publish()
            .times(1)
            .returning(|_| Err(crate::ClientError::Generic("Network error".to_string()).into()));

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let result = handler.publish_service(false).await;
        assert!(matches!(result, Err(PqxdhError::MessagesService(_))));
    }

    /// Test session management with multiple sessions
    #[tokio::test]
    async fn test_multiple_session_management() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Create multiple test sessions
        let session_ids = [[1u8; 32], [2u8; 32], [3u8; 32]];

        for (i, session_id) in session_ids.iter().enumerate() {
            let shared_secret = PqxdhSharedSecret {
                shared_key: [i as u8; 32],
                consumed_one_time_key_ids: vec![format!("key_{}", i)],
            };
            let test_session = PqxdhSession::from_shared_secret(
                shared_secret,
                *session_id,
                [(i + 10) as u8; 32], // their_session_channel_id
                keypair.public_key(),
            );

            SharedObservable::<_, AsyncLock>::update(
                &handler.state,
                |state: &mut PqxdhProtocolState| {
                    state
                        .sessions
                        .insert(KeyId::from_bytes(*session_id), test_session);
                },
            )
            .await;
        }

        // Verify all sessions are tracked
        let state = handler.state.read().await;
        assert_eq!(state.sessions.len(), 3);
        for session_id in &session_ids {
            assert!(state.sessions.contains_key(&KeyId::from_bytes(*session_id)));
        }
    }

    /// Test ephemeral message functionality
    #[tokio::test]
    async fn test_send_ephemeral_message() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock publish call
        mock_manager.expect_publish().times(1).returning(|_| {
            Ok(PublishResult::StoredNew {
                global_stream_id: "emp123".to_string(),
            })
        });

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Create a test session
        let session_id: PqxdhSessionId = [55u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [3u8; 32],
            consumed_one_time_key_ids: vec![],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [56u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        // Add session to state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state
                    .sessions
                    .insert(KeyId::from_bytes(session_id), test_session);
            },
        )
        .await;

        let message = "Ephemeral message".to_string();
        let result = handler
            .send_ephemeral_message(&session_id, &message, 60)
            .await;

        assert!(result.is_ok());
    }

    /// Test listen_for_messages functionality
    #[tokio::test]
    async fn test_listen_for_messages() {
        let mut mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock catch_up_and_subscribe
        mock_manager
            .expect_catch_up_and_subscribe()
            .times(1)
            .returning(|_, _| Ok(Box::pin(stream::empty())));

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        // Create a test session
        let session_id: PqxdhSessionId = [77u8; 32];
        let shared_secret = PqxdhSharedSecret {
            shared_key: [4u8; 32],
            consumed_one_time_key_ids: vec![],
        };
        let test_session = PqxdhSession::from_shared_secret(
            shared_secret,
            session_id,
            [78u8; 32], // their_session_channel_id
            keypair.public_key(),
        );

        // Add session to state

        SharedObservable::<_, AsyncLock>::update(
            &handler.state,
            |state: &mut PqxdhProtocolState| {
                state
                    .sessions
                    .insert(KeyId::from_bytes(session_id), test_session);
                state.inbox_tag = Some(Tag::Channel {
                    id: vec![1, 2, 3],
                    relays: vec![],
                });
            },
        )
        .await;

        let result = handler
            .listen_for_messages::<String>(session_id, true)
            .await;
        assert!(result.is_ok());
    }

    /// Test listen_for_messages with session not found
    #[tokio::test]
    async fn test_listen_for_messages_session_not_found() {
        let mock_manager = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        let handler = TestPqxdhHandler::new(
            Arc::new(mock_manager),
            keypair.clone(),
            PqxdhInboxProtocol::EchoService,
        );

        let session_id: PqxdhSessionId = [88u8; 32];
        let result = handler
            .listen_for_messages::<String>(session_id, true)
            .await;

        assert!(matches!(result, Err(PqxdhError::SessionNotFound)));
    }
}
