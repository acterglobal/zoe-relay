use super::{
    error::{ExecutorError, ExecutorResult},
    store::ExecutorStore,
};
use async_trait::async_trait;
use zoe_app_primitives::{
    digital_groups_organizer::models::core::ActivityMeta,
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
pub trait ModelFactory<T: ExecutorStore>: Sized {
    // regular state models
    type Model: GroupStateModel;
    // settings models are separate from regular content models
    // but must use the same PermissionState and ExecutiveKey types for consistency
    type SettingsModel: GroupStateModel<
            PermissionState = <<Self as ModelFactory<T>>::Model as GroupStateModel>::PermissionState,
            ExecutiveKey = <<Self as ModelFactory<T>>::Model as GroupStateModel>::ExecutiveKey,
        >;

    type Error: std::error::Error + Send + Sync + Into<ExecutorError>;

    async fn load_state(store: &T) -> ExecutorResult<Self>;

    /// Create a permission context for a given actor and group
    ///
    /// This method should be implemented to provide the permission state for this event for execution.
    /// The factory should use its stored store reference (from load_state) to load app settings.
    /// parameters:
    /// - actor: The identity of the actor performing the action
    /// - group_id: The group ID for the permission context
    /// - actor_role: The role of the actor performing the action, looked up in the group state using Member as default rol
    /// - state_message_id: The message ID of the _app_ state that the permission state is based on, looked up by the group
    ///   state as the last app state message before the events group_state_reference (or the inital message)
    /// - group_permissions: The current group permissions from the group state (always present)
    ///
    async fn load_permission_context(
        &self,
        actor: &IdentityRef,
        group_id: GroupId,
        actor_role: GroupRole,
        state_message_id: MessageId,
        group_permissions: zoe_app_primitives::group::events::permissions::GroupPermissions,
    ) -> ExecutorResult<Option<<Self::Model as GroupStateModel>::PermissionState>>;

    /// Add executive references to an index, returns updated index data
    async fn add_to_index(
        &self,
        list_id: <Self::Model as GroupStateModel>::IndexKey,
        model_meta: &ActivityMeta,
    ) -> Vec<<Self::Model as GroupStateModel>::ExecutiveKey>;

    /// Remove executive references from an index, returns updated index data
    async fn remove_from_index(
        &self,
        list_id: <Self::Model as GroupStateModel>::IndexKey,
        model_meta: &ActivityMeta,
    ) -> Vec<<Self::Model as GroupStateModel>::ExecutiveKey>;

    async fn sync(&self) -> Result<(), Self::Error>;
}
