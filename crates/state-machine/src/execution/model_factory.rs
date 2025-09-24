use super::{
    error::{ExecutorError, ExecutorResult},
    store::ExecutorStore,
};
use async_trait::async_trait;
use zoe_app_primitives::{
    group::{
        app::GroupStateModel,
        events::{GroupId, roles::GroupRole},
    },
    identity::IdentityRef,
};
use zoe_wire_protocol::MessageId;
/// Factory trait for creating models from events
///
/// This trait handles the model-specific logic of creating new models from events.
/// The executor uses this to create models, then serializes them for storage.
#[async_trait]
pub trait ModelFactory {
    // regular state models
    type Model: GroupStateModel;
    // settings models are separate from regular content models
    // but must use the same PermissionState and ExecutiveKey types for consistency
    type SettingsModel: GroupStateModel<
            PermissionState = <<Self as ModelFactory>::Model as GroupStateModel>::PermissionState,
            ExecutiveKey = <<Self as ModelFactory>::Model as GroupStateModel>::ExecutiveKey,
        >;

    type Error: std::error::Error + Send + Sync + Into<ExecutorError>;

    async fn load_state<T: ExecutorStore>(store: &T) -> ExecutorResult<Box<Self>>;

    /// Create a permission context for a given actor and group
    ///
    /// This method should be implemented to provide the permission state for this event for execution.
    /// parameters:
    /// - actor: The identity of the actor performing the action
    /// - actor_role: The role of the actor performing the action, looked up in the group state using Member as default rol
    /// - state_message_id: The message ID of the _app_ state that the permission state is based on, looked up by the group
    ///   state as the last app state message before the events group_state_reference (or the inital message)
    ///
    async fn load_permission_context(
        &self,
        actor: &IdentityRef,
        group_id: GroupId,
        actor_role: GroupRole,
        state_message_id: MessageId,
    ) -> ExecutorResult<Option<<Self::Model as GroupStateModel>::PermissionState>>;

    /// Add executive references to an index, returns updated index data
    async fn add_to_index<K, E>(
        &self,
        store: &impl ExecutorStore,
        list_id: K,
        executive_refs: &[E],
    ) -> ExecutorResult<()>
    where
        K: serde::Serialize + Send + Sync + Clone,
        E: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Clone;

    /// Remove executive references from an index, returns updated index data
    async fn remove_from_index<K, E>(
        &self,
        store: &impl ExecutorStore,
        list_id: K,
        executive_refs: &[E],
    ) -> ExecutorResult<()>
    where
        K: serde::Serialize + Send + Sync + Clone,
        E: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Clone + PartialEq;

    /// Load models from an index - the factory reads the index data and loads the referenced models
    async fn load_models_from_index<K>(
        &self,
        store: &impl ExecutorStore,
        list_id: K,
    ) -> Result<Vec<Self::Model>, Self::Error>
    where
        K: serde::Serialize + Send + Sync + Clone;
}
