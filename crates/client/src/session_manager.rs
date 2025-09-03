//! Session Manager for automatic PQXDH state synchronization
//!
//! This module provides a state synchronization layer that:
//! - Uses a builder pattern for initialization and state loading
//! - Manages PQXDH protocol handlers and their state changes
//! - Automatically persists state changes to storage transparently
//! - Returns clones of specific types when requested
//! - Emits state change events for reactive programming
//!
//! The SessionManager acts as a central hub for PQXDH state management, providing:
//! - **Automatic Persistence**: State changes are immediately persisted to storage
//! - **Event Broadcasting**: State changes are broadcast to subscribers
//! - **Handler Management**: Registration and lifecycle management of PQXDH handlers
//! - **State Access**: Fast access to current states via cloning
//!
//! ## Usage Pattern
//!
//! ```rust,no_run
//! // Build the session manager (loads all states from storage)
//! let manager = SessionManager::builder(storage, messages_manager)
//!     .build()
//!     .await?;
//!
//! // Register PQXDH handlers for automatic state listening
//! manager.register_pqxdh_handler("handler_1".to_string(), handler).await?;
//!
//! // Get current state clones
//! let current_state = manager.get_pqxdh_state_clone("handler_1").await;
//!
//! // Subscribe to state changes
//! let mut state_changes = manager.subscribe_to_state_changes();
//! ```

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::sync::Arc;

use zoe_wire_protocol::KeyId;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use zoe_client_storage::{StateNamespace, StateStorage, StorageError};
use zoe_state_machine::{GroupDataUpdate, GroupManager};
use zoe_wire_protocol::PqxdhInboxProtocol;

use crate::pqxdh::PqxdhProtocolHandler;
use crate::services::MessagesManagerTrait;

/// Errors that can occur during session management operations
#[derive(Debug, thiserror::Error)]
pub enum SessionManagerError {
    /// Storage operation failed
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
    /// Serialization/deserialization failed
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// Handler registration failed
    #[error("Handler registration error: {0}")]
    HandlerRegistration(String),
    /// Client keypair not found
    #[error("Client keypair not found")]
    ClientKeypairNotFound,
}

/// Result type for session manager operations
pub type SessionManagerResult<T> = Result<T, SessionManagerError>;

/// State change events that can be broadcast to subscribers
#[derive(Debug, Clone)]
pub enum SessionStateChange {
    /// PQXDH protocol state changed
    PqxdhStateChanged { handler_id: String },
    /// Group manager state changed
    GroupManagerUpdate(GroupDataUpdate),
    /// Session was removed
    SessionRemoved {
        namespace: StateNamespace,
        key: Vec<u8>,
    },
}

/// Builder for creating a SessionManager with proper initialization
pub struct SessionManagerBuilder<S: StateStorage + 'static, M: MessagesManagerTrait + 'static> {
    storage: Arc<S>,
    messages_manager: Arc<M>,
    client_keypair: Option<Arc<zoe_wire_protocol::KeyPair>>,
}

impl<S: StateStorage + 'static, M: MessagesManagerTrait + 'static> SessionManagerBuilder<S, M> {
    /// Create a new SessionManager builder
    pub fn new(storage: Arc<S>, messages_manager: Arc<M>) -> Self {
        Self {
            storage,
            messages_manager,
            client_keypair: None,
        }
    }

    pub fn client_keypair(mut self, client_keypair: Arc<zoe_wire_protocol::KeyPair>) -> Self {
        self.client_keypair = Some(client_keypair);
        self
    }

    /// Build the SessionManager, loading all states from storage and setting up listeners
    pub async fn build(self) -> SessionManagerResult<SessionManager<S, M>> {
        let SessionManagerBuilder {
            storage,
            messages_manager,
            client_keypair,
        } = self;

        let client_keypair = client_keypair.ok_or(SessionManagerError::ClientKeypairNotFound)?;

        let states = SessionManager::load_pqxdh_states(
            storage.clone(),
            messages_manager.clone(),
            client_keypair.clone(),
            StateNamespace::PqxdhSession(KeyId::from(*client_keypair.id())),
        )
        .await?;

        // Create group manager instance and initialize listener
        let (group_manager, group_manager_task) =
            SessionManager::<S, M>::init_group_manager(storage.clone(), client_keypair.clone())
                .await?;

        let manager = SessionManager {
            storage,
            messages_manager,
            pqxdh_handlers: RwLock::new(BTreeMap::from_iter(states)),
            group_manager,
            group_manager_task,
            client_keypair,
        };

        tracing::info!("SessionManager built and initialized successfully");
        Ok(manager)
    }
}

/// State synchronization manager that automatically listens to and persists state changes.
///
/// This manager follows the persistent messenger pattern:
/// - External objects register with the manager
/// - The manager listens to their state changes
/// - State changes are automatically persisted to storage
/// - State change events are broadcast to subscribers
///
/// The SessionManager is designed to be long-lived and handles the lifecycle
/// of multiple PQXDH protocol handlers and group encryption sessions, automatically
/// managing their state persistence and providing reactive access to state changes.
pub struct SessionManager<S: StateStorage + 'static, M: MessagesManagerTrait + 'static> {
    /// Underlying state storage
    storage: Arc<S>,
    /// Messages manager for subscription and message handling
    messages_manager: Arc<M>,
    /// PQXDH handlers with their background listener tasks  
    pqxdh_handlers:
        RwLock<BTreeMap<PqxdhInboxProtocol, (Arc<PqxdhProtocolHandler<M>>, JoinHandle<()>)>>,
    /// Group manager instance with background listener task
    group_manager: Arc<GroupManager>,
    #[allow(dead_code)]
    group_manager_task: JoinHandle<()>,
    client_keypair: Arc<zoe_wire_protocol::KeyPair>,
}

impl<S: StateStorage + 'static, M: MessagesManagerTrait + 'static> SessionManager<S, M> {
    /// Create a new SessionManager builder
    ///
    /// # Arguments
    /// * `storage` - The state storage backend
    /// * `messages_manager` - The messages manager for subscription and message handling
    ///
    /// # Returns
    /// A SessionManagerBuilder for configuring and building the SessionManager
    pub fn builder(storage: Arc<S>, messages_manager: Arc<M>) -> SessionManagerBuilder<S, M> {
        SessionManagerBuilder::new(storage, messages_manager)
    }
    /// Get a reference to the underlying storage
    pub fn storage(&self) -> &Arc<S> {
        &self.storage
    }

    /// Get a reference to the messages manager
    pub fn messages_manager(&self) -> &Arc<M> {
        &self.messages_manager
    }

    pub async fn pqxdh_handler(
        &self,
        protocol: PqxdhInboxProtocol,
    ) -> SessionManagerResult<Arc<PqxdhProtocolHandler<M>>> {
        match self.pqxdh_handlers.write().await.entry(protocol.clone()) {
            Entry::Occupied(occupied) => Ok(occupied.get().0.clone()),
            Entry::Vacant(vacant) => {
                let handler = Arc::new(PqxdhProtocolHandler::new(
                    self.messages_manager.clone(),
                    self.client_keypair.clone(),
                    protocol.clone(),
                ));
                let (_idx, (handler_arc, listener_task)) = Self::init_pqxdh_handler(
                    self.storage.clone(),
                    protocol,
                    handler.clone(),
                    StateNamespace::PqxdhSession(KeyId::from(*self.client_keypair.id())),
                    true,
                )
                .await?;
                vacant.insert((handler_arc.clone(), listener_task));
                Ok(handler_arc)
            }
        }
    }
}

/// Group Manager Integration
impl<S: StateStorage + 'static, M: MessagesManagerTrait + 'static> SessionManager<S, M> {
    /// Initialize group manager with listener task
    async fn init_group_manager(
        storage: Arc<S>,
        client_keypair: Arc<zoe_wire_protocol::KeyPair>,
    ) -> SessionManagerResult<(Arc<GroupManager>, JoinHandle<()>)> {
        let namespace = StateNamespace::GroupSession(KeyId::from(*client_keypair.id()));
        let sessions: Vec<(Vec<u8>, zoe_state_machine::GroupSession)> = storage
            .list_namespace_data(&namespace)
            .await
            .map_err(SessionManagerError::Storage)?;

        let group_manager = Arc::new(
            GroupManager::builder()
                .with_sessions(sessions.into_iter().map(|(_, session)| session).collect())
                .build(),
        );
        let mut group_updates = group_manager.subscribe_to_updates();

        let task = tokio::spawn(async move {
            while let Ok(update) = group_updates.recv().await {
                tracing::debug!("Received group manager update: {:?}", update);
                match update {
                    GroupDataUpdate::GroupAdded(group_session)
                    | GroupDataUpdate::GroupUpdated(group_session) => {
                        if let Err(e) = storage
                            .store(
                                &namespace,
                                group_session.state.group_id.as_bytes(),
                                &group_session,
                            )
                            .await
                        {
                            tracing::error!(error=?e, "Failed to persist group session");
                        }
                    }
                    GroupDataUpdate::GroupRemoved(group_session) => {
                        if let Err(e) = storage
                            .delete(&namespace, group_session.state.group_id.as_bytes())
                            .await
                        {
                            tracing::error!(error=?e, "Failed to delete group session");
                        }
                    }
                }
            }
            tracing::info!("Group manager listener task ended");
        });

        tracing::info!("Group manager listener started");
        Ok((group_manager, task))
    }

    /// Get access to the group manager
    pub fn group_manager(&self) -> &Arc<GroupManager> {
        &self.group_manager
    }
}

/// Live Object Access and State Cloning
impl<S: StateStorage + 'static, M: MessagesManagerTrait + 'static> SessionManager<S, M> {
    /// Load PQXDH states from storage
    async fn load_pqxdh_states(
        storage: Arc<S>,
        messages_manager: Arc<M>,
        client_keypair: Arc<zoe_wire_protocol::KeyPair>,
        namespace: StateNamespace,
    ) -> SessionManagerResult<
        Vec<(
            PqxdhInboxProtocol,
            (Arc<PqxdhProtocolHandler<M>>, JoinHandle<()>),
        )>,
    > {
        let pqxdh_data = storage
            .list_namespace_data(&namespace)
            .await
            .map_err(SessionManagerError::Storage)?;

        let mut handlers = Vec::new();
        for (key, protocol_state) in pqxdh_data {
            let protocol = PqxdhInboxProtocol::from_bytes(&key)
                .map_err(|e| SessionManagerError::Serialization(e.to_string()))?;
            let handler = Arc::new(PqxdhProtocolHandler::from_state(
                messages_manager.clone(),
                client_keypair.clone(),
                protocol_state,
            ));
            handlers.push(
                Self::init_pqxdh_handler(
                    storage.clone(),
                    protocol,
                    handler,
                    namespace.clone(),
                    false,
                )
                .await?,
            );
        }

        tracing::info!("PQXDH state loading completed");
        Ok(handlers)
    }

    async fn init_pqxdh_handler(
        storage: Arc<S>,
        handler_id: PqxdhInboxProtocol,
        handler: Arc<PqxdhProtocolHandler<M>>,
        namespace: StateNamespace,
        persist_initial_state: bool,
    ) -> SessionManagerResult<(
        PqxdhInboxProtocol,
        (Arc<PqxdhProtocolHandler<M>>, JoinHandle<()>),
    )> {
        // Subscribe to state changes for this handler
        let mut subscriber = handler.subscribe_to_state().await;
        let handler_id_bytes = handler_id.into_bytes();
        if persist_initial_state {
            let initial_state = subscriber.get().await;
            // Persist initial state
            storage
                .store(&namespace, &handler_id_bytes, &initial_state)
                .await
                .map_err(SessionManagerError::Storage)?;
        }

        // Spawn background task to listen to state changes
        let storage_clone = storage.clone();
        let handler_id_clone = handler_id.clone();

        let listener_task = tokio::spawn(async move {
            tracing::info!("Started PQXDH state listener for handler: {handler_id_clone}");

            // Listen for state changes
            while let Some(new_state) = subscriber.next().await {
                // Only process if state actually changed (compare serialized forms)
                let _new_state_bytes = match postcard::to_stdvec(&new_state) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!(error=?e, "Failed to serialize PQXDH state for {handler_id_clone}");
                        continue;
                    }
                };

                // Persist to storage
                if let Err(e) = storage_clone
                    .store(&namespace, &handler_id_bytes, &new_state)
                    .await
                {
                    tracing::error!(error=?e, "Failed to persist PQXDH state for {handler_id_clone}");
                    continue;
                }

                // // Emit state change event
                // let event = SessionStateChange::PqxdhStateChanged {
                //     handler_id: handler_id_clone.clone(),
                // };

                // if let Err(e) = state_change_tx.send(event) {
                //     tracing::warn!("Failed to broadcast PQXDH state change event: {}", e);
                // }
            }

            tracing::debug!("PQXDH state listener ended for handler: {handler_id_clone}");
        });

        tracing::info!("Registered PQXDH handler: {}", handler_id);
        Ok((handler_id.clone(), (handler, listener_task)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // use std::collections::BTreeMap;
    use std::sync::Arc;
    // use tokio::time::{sleep, Duration};
    use rand::thread_rng;

    use zoe_client_storage::{StateNamespace, storage::MockStateStorage};

    use zoe_wire_protocol::{KeyPair, PqxdhInboxProtocol};

    use crate::pqxdh::PqxdhProtocolState;
    use crate::services::messages_manager::MockMessagesManagerTrait;

    fn create_test_keypair() -> KeyPair {
        let mut rng = thread_rng();
        KeyPair::generate_ed25519(&mut rng)
    }

    #[allow(dead_code)]
    fn create_test_namespace(keypair: &KeyPair) -> StateNamespace {
        StateNamespace::PqxdhSession(KeyId::from(*keypair.public_key().id()))
    }

    /// Test SessionManagerBuilder creation and configuration
    #[tokio::test]
    async fn test_session_manager_builder() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock storage to return empty data (no existing sessions)
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| Ok(Vec::new()));

        let builder = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone());

        assert!(builder.client_keypair.is_some());
        assert_eq!(
            builder.client_keypair.unwrap().public_key().id(),
            keypair.public_key().id()
        );
    }

    /// Test SessionManager creation through builder
    #[tokio::test]
    async fn test_session_manager_creation() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock storage to return empty data (no existing sessions)
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| Ok(Vec::new()));
        mock_storage
            .expect_list_namespace_data::<zoe_state_machine::GroupSession>()
            .returning(|_| Ok(Vec::new()));

        let manager = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone())
            .build()
            .await
            .expect("Failed to build SessionManager");

        assert_eq!(
            manager.client_keypair.public_key().id(),
            keypair.public_key().id()
        );
        assert_eq!(manager.pqxdh_handlers.read().await.len(), 0);
    }

    /// Test SessionManager creation without client keypair fails
    #[tokio::test]
    async fn test_session_manager_creation_without_keypair() {
        let mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();

        let result = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .build()
            .await;

        assert!(matches!(
            result,
            Err(SessionManagerError::ClientKeypairNotFound)
        ));
    }

    /// Test PQXDH handler creation and registration
    #[tokio::test]
    async fn test_pqxdh_handler_registration() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());
        let protocol = PqxdhInboxProtocol::EchoService;

        // Mock storage for initial load (empty)
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| Ok(Vec::new()));
        mock_storage
            .expect_list_namespace_data::<zoe_state_machine::GroupSession>()
            .returning(|_| Ok(Vec::new()));

        // Mock storage for initial state persistence
        mock_storage
            .expect_store::<PqxdhProtocolState>()
            .returning(|_, _, _| Ok(()));

        let manager = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone())
            .build()
            .await
            .expect("Failed to build SessionManager");

        // Request a PQXDH handler
        let handler = manager
            .pqxdh_handler(protocol.clone())
            .await
            .expect("Failed to get PQXDH handler");

        // Verify handler was created and registered
        assert_eq!(manager.pqxdh_handlers.read().await.len(), 1);
        assert!(manager.pqxdh_handlers.read().await.contains_key(&protocol));

        // Verify the handler has the correct configuration
        let _state = handler.subscribe_to_state().await.get().await;
        // Note: protocol field is private, so we can't directly compare it
        // The fact that we got a handler without errors indicates it was created correctly
    }

    /// Test PQXDH handler reuse (same protocol returns same handler)
    #[tokio::test]
    async fn test_pqxdh_handler_reuse() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());
        let protocol = PqxdhInboxProtocol::EchoService;

        // Mock storage for initial load (empty)
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| Ok(Vec::new()));
        mock_storage
            .expect_list_namespace_data::<zoe_state_machine::GroupSession>()
            .returning(|_| Ok(Vec::new()));

        // Mock storage for initial state persistence (should only be called once)
        mock_storage
            .expect_store::<PqxdhProtocolState>()
            .times(1)
            .returning(|_, _, _| Ok(()));

        let manager = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone())
            .build()
            .await
            .expect("Failed to build SessionManager");

        // Request the same handler twice
        let handler1 = manager
            .pqxdh_handler(protocol.clone())
            .await
            .expect("Failed to get first handler");
        let handler2 = manager
            .pqxdh_handler(protocol.clone())
            .await
            .expect("Failed to get second handler");

        // Should be the same Arc instance
        assert!(Arc::ptr_eq(&handler1, &handler2));
        assert_eq!(manager.pqxdh_handlers.read().await.len(), 1);
    }

    /// Test loading existing PQXDH states from storage
    #[tokio::test]
    async fn test_load_existing_pqxdh_states() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());
        let protocol = PqxdhInboxProtocol::EchoService;

        // Create existing state data
        let existing_state = PqxdhProtocolState::new(protocol.clone());
        let protocol_bytes = protocol.clone().into_bytes();
        let existing_data = vec![(protocol_bytes, existing_state)];

        // Mock storage to return existing PQXDH data
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(move |_| Ok(existing_data.clone()));

        // Mock storage to return empty group session data
        mock_storage
            .expect_list_namespace_data::<zoe_state_machine::GroupSession>()
            .returning(|_| Ok(Vec::new()));

        let manager = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone())
            .build()
            .await
            .expect("Failed to build SessionManager");

        // Should have loaded the existing handler
        assert_eq!(manager.pqxdh_handlers.read().await.len(), 1);
        assert!(manager.pqxdh_handlers.read().await.contains_key(&protocol));
    }

    /// Test error handling when storage operations fail
    #[tokio::test]
    async fn test_storage_error_handling() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock storage to fail on list_namespace_data for PQXDH
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| {
                Err(zoe_client_storage::StorageError::Serialization(
                    postcard::Error::DeserializeUnexpectedEnd,
                ))
            });

        let result = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone())
            .build()
            .await;

        assert!(matches!(result, Err(SessionManagerError::Storage(_))));
    }

    /// Test multiple different PQXDH protocols
    #[tokio::test]
    async fn test_multiple_pqxdh_protocols() {
        let mut mock_storage = MockStateStorage::new();
        let mock_messages = MockMessagesManagerTrait::new();
        let keypair = Arc::new(create_test_keypair());

        // Mock storage for initial load (empty)
        mock_storage
            .expect_list_namespace_data::<PqxdhProtocolState>()
            .returning(|_| Ok(Vec::new()));
        mock_storage
            .expect_list_namespace_data::<zoe_state_machine::GroupSession>()
            .returning(|_| Ok(Vec::new()));

        // Mock storage for initial state persistence (2 protocols)
        mock_storage
            .expect_store::<PqxdhProtocolState>()
            .times(2)
            .returning(|_, _, _| Ok(()));

        let manager = SessionManagerBuilder::new(Arc::new(mock_storage), Arc::new(mock_messages))
            .client_keypair(keypair.clone())
            .build()
            .await
            .expect("Failed to build SessionManager");

        // Request handlers for different protocols
        let handler1 = manager
            .pqxdh_handler(PqxdhInboxProtocol::EchoService)
            .await
            .expect("Failed to get handler1");
        let handler2 = manager
            .pqxdh_handler(PqxdhInboxProtocol::CustomProtocol(12345))
            .await
            .expect("Failed to get handler2");

        // Should have two different handlers
        assert!(!Arc::ptr_eq(&handler1, &handler2));
        assert_eq!(manager.pqxdh_handlers.read().await.len(), 2);
    }
}
