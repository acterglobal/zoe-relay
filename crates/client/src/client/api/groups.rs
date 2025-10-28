use std::sync::Arc;

use super::Client;
use crate::error::Result;
use async_stream::stream;
use eyeball_im::VectorDiff;
use futures::Stream;
use zoe_app_primitives::{
    group::events::{
        GroupId, GroupInfoUpdateContent, permissions::GroupAction, roles::GroupRole,
        settings::GroupSettings,
    },
    icon::Icon,
    identity::IdentityRef,
    metadata::Metadata,
    protocol::InstalledApp,
};
use zoe_state_machine::{
    group::{CreateGroupBuilder, CreateGroupResult, GroupDataUpdate},
    index::RankedIndex,
    state::GroupState,
};

use zoe_wire_protocol::{KeyPair, MessageId};

#[derive(Debug, Eq, PartialEq)]
pub struct SimpleGroupView {
    /// The id of this group
    pub group_id: GroupId,

    /// Icon of the group
    pub icon: Option<Icon>,
    /// Visible Name
    pub name: String,
    /// Optional Description
    pub description: Option<String>,

    // global group settings as of now
    pub settings: GroupSettings,

    /// Installed applications in this group
    pub installed_apps: Vec<InstalledApp>,

    // what role this identitiy has in this group
    pub my_role: GroupRole,
}

impl SimpleGroupView {
    pub fn can_i(&self, action: GroupAction) -> bool {
        self.settings
            .permissions
            .can_perform_action(&self.my_role, action)
    }
}

impl SimpleGroupView {
    pub fn new(state: GroupState, id: &IdentityRef) -> Self {
        let my_role = state.member_role(id).unwrap_or(GroupRole::Member);
        let info = state.group_info;
        let mut me = Self {
            group_id: info.group_id,
            name: info.name,
            settings: info.settings,
            description: None,
            icon: None,
            installed_apps: info.installed_apps,
            my_role,
        };
        for m in info.metadata {
            match m {
                // we only take the first entry
                Metadata::Description(desc) if me.description.is_none() => {
                    me.description = Some(desc)
                }
                Metadata::Icon(icon) if me.icon.is_none() => me.icon = Some(icon),
                _ => {
                    // not supported yet
                }
            }
        }
        me
    }
}

/// High level Groups API
impl Client {
    /// Use the local keypair to create a new group
    pub async fn create_group(&self, builder: CreateGroupBuilder) -> Result<CreateGroupResult> {
        Ok(self
            .group_manager()
            .create_group(builder, self.keypair())
            .await?)
    }

    /// View the current groups and subscribe to updates
    pub async fn groups_view(
        &self,
    ) -> Result<(
        Vec<Arc<SimpleGroupView>>,
        impl Stream<Item = Vec<VectorDiff<Arc<SimpleGroupView>>>>,
        impl Stream<Item = ()>,
    )> {
        let (initial, mut updates_stream) = self.group_manager().groups_and_stream().await;
        let my_id = IdentityRef::Key(self.public_key());

        let mut live_index = RankedIndex::from_iter(initial.into_iter().map(|state| {
            (
                state.group_info.group_id.clone(),
                Arc::new(SimpleGroupView::new(state, &my_id)),
            )
        }));

        let current_state = live_index.values_cloned(); // just Arcs anyways
        let listener = live_index.batched_update_stream();

        let poller = stream!({
            loop {
                let Ok(update) = updates_stream.recv().await.inspect_err(|&e| {
                    tracing::error!("Error receiving group update: {}", e);
                }) else {
                    yield;
                    continue;
                };
                match update {
                    GroupDataUpdate::GroupAdded(group) => {
                        live_index.insert(
                            group.state.group_info.group_id.clone(),
                            Arc::new(SimpleGroupView::new(group.state, &my_id)),
                        );
                    }
                    GroupDataUpdate::GroupUpdated(group) => {
                        let group_id = group.state.group_info.group_id.clone();
                        live_index.remove_and_insert(
                            |s| s.group_id == group_id,
                            group_id.clone(),
                            Arc::new(SimpleGroupView::new(group.state, &my_id)),
                        );
                    }
                    GroupDataUpdate::GroupRemoved(session) => {
                        let group_id = session.state.group_info.group_id.clone();
                        live_index.remove_where(|s| s.group_id == group_id);
                    }
                }
                yield
            }
        });

        Ok((current_state, listener, poller))
    }

    pub async fn update_group(
        &self,
        group_id: &GroupId,
        update: GroupInfoUpdateContent,
    ) -> Result<MessageId> {
        self.update_group_with_sender(group_id, self.keypair(), update)
            .await
    }

    pub async fn update_group_with_sender(
        &self,
        group_id: &GroupId,
        sender: &KeyPair,
        update: GroupInfoUpdateContent,
    ) -> Result<MessageId> {
        Ok(self
            .group_manager()
            .publish_group_event(group_id, update.into(), sender)
            .await
            .map(|message| message.consume().0)?)
    }
}
