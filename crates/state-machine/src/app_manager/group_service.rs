use async_broadcast::Receiver;
use serde::de::DeserializeOwned;
use zoe_app_primitives::{
    group::{
        events::{GroupId, permissions::GroupPermissions, roles::GroupRole},
        states::GroupState,
    },
    identity::IdentityRef,
    protocol::AppProtocolVariant,
};
use zoe_wire_protocol::{ChaCha20Poly1305Content, MessageId};

use crate::{error::GroupResult, group::GroupDataUpdate};

/// Interface for requesting decryption services from the GroupManager
#[async_trait::async_trait]
pub trait GroupService: Send + Sync {
    fn message_group_receiver(&self) -> Receiver<GroupDataUpdate>;

    async fn current_group_states(&self) -> Vec<GroupState>;

    /// Decrypt an app message using the group's encryption key
    async fn decrypt_app_message<T: DeserializeOwned>(
        &self,
        group_id: &GroupId,
        encrypted_content: &ChaCha20Poly1305Content,
    ) -> GroupResult<T>;

    /// Get group state at a specific message ID for cross-channel validation
    async fn group_state_at_message(
        &self,
        group_id: &GroupId,
        message_id: MessageId,
    ) -> Option<GroupState>;

    /// Get current group state
    async fn current_group_state(&self, group_id: &GroupId) -> Option<GroupState>;

    /// Get actor role, app state message ID, and group permissions for permission validation
    ///
    /// This is a convenience function that optimizes the common case where
    /// we need the actor's role, the last app state message ID, and the group permissions
    /// for a specific group state reference and app combination.
    ///
    /// # Arguments
    /// * `group_id` - The group to query
    /// * `actor_identity_ref` - The actor whose role we want to look up
    /// * `group_state_reference` - The group message ID to reference for permissions
    /// * `app_id` - The app protocol variant to get state for
    ///
    /// # Returns
    /// A tuple of (actor_role, app_state_message_id, group_permissions). The actor_role defaults to Member
    /// if the actor is not found in the group. The app_state_message_id is always the
    /// initial group creation message ID as the baseline, or the last app settings update
    /// if one exists before the group state reference. The group_permissions are the current
    /// group permissions from the group state (always present).
    async fn get_permission_context(
        &self,
        group_id: &GroupId,
        actor_identity_ref: &IdentityRef,
        group_state_reference: MessageId,
        app_id: &AppProtocolVariant,
    ) -> (GroupRole, MessageId, GroupPermissions);

    /// Publish an app event to a group
    ///
    /// This is a generic method for publishing any app-specific event to a group.
    /// The app-specific logic (like DGO event creation) should be handled by the caller.
    ///
    /// # Arguments
    /// * `group_id` - The group to publish the event to
    /// * `app_tag` - The app channel tag to publish to
    /// * `event` - The app event to publish
    /// * `sender` - The keypair of the user publishing the event
    ///
    /// # Returns
    /// The published message containing the app event
    async fn publish_app_event<T: serde::Serialize + Send>(
        &self,
        group_id: &GroupId,
        app_tag: zoe_wire_protocol::ChannelId,
        event: T,
        sender: &zoe_wire_protocol::KeyPair,
    ) -> GroupResult<zoe_wire_protocol::MessageFull>;
}
