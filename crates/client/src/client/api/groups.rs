use std::sync::Arc;

use super::Client;
use crate::error::Result;
use async_stream::stream;
use eyeball_im::{VectorDiff, VectorSubscriber};
use futures::Stream;
use zoe_app_primitives::group::events::{GroupId, GroupInfo};
use zoe_state_machine::{
    group::{CreateGroupBuilder, CreateGroupResult, GroupDataUpdate},
    index::RankedIndex,
};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[derive(Debug, Eq, PartialEq, PartialOrd, Ord)]
pub struct SimpleGroupView {
    pub group_id: GroupId,
    pub name: String,
}

impl From<GroupInfo> for SimpleGroupView {
    fn from(info: GroupInfo) -> Self {
        Self {
            group_id: info.group_id,
            name: info.name,
        }
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

        let mut live_index = RankedIndex::from_iter(
            initial
                .into_iter()
                .map(|info| (info.group_id.clone(), Arc::new(SimpleGroupView::from(info)))),
        );

        let current_state = live_index.values_cloned(); // just Arcs anyways
        let listener = live_index.batched_update_stream();

        let poller = stream!({
            loop {
                let update = match updates_stream.recv().await {
                    Err(e) => {
                        tracing::error!("Error receiving group update: {}", e);
                        yield;
                        continue;
                    }
                    Ok(update) => update,
                };
                match update {
                    GroupDataUpdate::GroupAdded(group) => {
                        let info = group.state.group_info;
                        live_index
                            .insert(info.group_id.clone(), Arc::new(SimpleGroupView::from(info)));
                    }
                    GroupDataUpdate::GroupUpdated(group) => {
                        let info = group.state.group_info;
                        let group_id = info.group_id.clone();
                        live_index.remove_and_insert(
                            |s| s.group_id == group_id,
                            group_id.clone(),
                            Arc::new(SimpleGroupView::from(info)),
                        );
                    }
                    GroupDataUpdate::GroupRemoved(session) => {
                        let info = session.state.group_info;
                        live_index.remove_where(|s| s.group_id == info.group_id);
                    }
                }
                yield
            }
        });

        Ok((current_state, listener, poller))
    }
}
