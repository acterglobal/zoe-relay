use async_broadcast::Receiver;
use zoe_app_primitives::{
    digital_groups_organizer::{
        events::core::{DgoActivityEvent, DgoActivityEventContent},
        indexing::keys::ExecuteReference,
    },
    group::events::GroupId,
    identity::IdentityType,
    protocol::AppProtocolVariant,
};
use zoe_wire_protocol::{KeyPair, MessageFull};

use crate::{
    apps::dgo::{DgoExecutor, DgoFactory},
    error::{GroupError, GroupResult},
    execution::ExecutorStore,
    messages::MessagesManagerTrait,
};

use super::{AppManager, GroupService};

impl<
    M: MessagesManagerTrait + Clone + 'static,
    G: GroupService + Clone + 'static,
    S: ExecutorStore + Clone + 'static,
> AppManager<M, G, S>
{
    pub(super) async fn init_dgo_executor(store: &S) -> DgoExecutor<S> {
        DgoExecutor::new(DgoFactory::new(store.clone()), store.clone())
    }

    /// Publish a DGO activity event to a group
    ///
    /// This is a DGO-specific convenience method that handles the complete flow of publishing a DGO event:
    /// 1. Validates the group exists and has DGO app installed
    /// 2. Gets the current group state reference for permission validation
    /// 3. Creates the DGO activity event with proper identity and reference
    /// 4. Publishes the event through the generic publish_app_event method
    ///
    /// # Arguments
    /// * `group_id` - The group to publish the event to
    /// * `content` - The DGO activity event content
    /// * `sender` - The keypair of the user publishing the event
    ///
    /// # Returns
    /// The published message containing the DGO event
    pub async fn publish_dgo_event(
        &self,
        group_id: &GroupId,
        content: DgoActivityEventContent,
        sender: &KeyPair,
    ) -> GroupResult<MessageFull> {
        self.publish_dgo_event_with_identity(group_id, content, sender, IdentityType::Main)
            .await
    }

    pub async fn publish_dgo_event_with_identity(
        &self,
        group_id: &GroupId,
        content: DgoActivityEventContent,
        sender: &KeyPair,
        identity_type: IdentityType,
    ) -> GroupResult<MessageFull> {
        // Get the group session to access the current state
        let group_session = self
            .group_service
            .current_group_state(group_id)
            .await
            .ok_or_else(|| GroupError::GroupNotFound(format!("Group not found: {:?}", group_id)))?;

        // Get the DGO app's channel tag from the group's installed apps
        let app_tag = group_session
            .group_info
            .installed_apps
            .iter()
            .find(|app| app.app_id == AppProtocolVariant::DigitalGroupsOrganizer)
            .ok_or_else(|| GroupError::InvalidOperation("DGO app not found in group".to_string()))?
            .app_tag
            .clone();

        // Use the initial group creation message ID as the group state reference
        // This represents the current state for permission validation

        // Create the DGO activity event
        let dgo_event = DgoActivityEvent::new(identity_type, content, group_session.latest_event);

        // Publish the event through the generic publish_app_event method
        self.publish_app_event(group_id, app_tag, dgo_event, sender)
            .await
    }

    pub async fn subscribe_to_dgo_notification(&self, reference: ExecuteReference) -> Receiver<()> {
        self.dgo_executor.subscribe(reference).await
    }
}
