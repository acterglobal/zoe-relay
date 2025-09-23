use super::{
    error::{ExecutorError, ExecutorResult},
    store::ExecutorStore,
};
use async_trait::async_trait;
use zoe_app_primitives::{group::app::GroupStateModel, identity::IdentityRef};
use zoe_wire_protocol::MessageId;
/// Factory trait for creating models from events
///
/// This trait handles the model-specific logic of creating new models from events.
/// The executor uses this to create models, then serializes them for storage.
#[async_trait]
pub trait ModelFactory {
    type Model: GroupStateModel;
    type Error: std::error::Error + Send + Sync + Into<ExecutorError>;

    async fn load_state<T: ExecutorStore>(store: &T) -> ExecutorResult<Box<Self>>;

    /// Create a new model from an event
    ///
    /// This is called when an event creates a new model (e.g., CreateTextBlock).
    async fn create_model_from_event(
        &self,
        event: &<Self::Model as GroupStateModel>::Event,
        activity_id: MessageId,
    ) -> ExecutorResult<Option<Self::Model>>;

    /// Create a permission context for a given actor and group
    ///
    /// This method should be implemented to provide permission contexts for event execution.
    async fn load_permission_context(
        &self,
        actor: &IdentityRef,
        group_id: MessageId,
    ) -> ExecutorResult<Option<<Self::Model as GroupStateModel>::PermissionContext>>;

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
