use super::Client;

use crate::error::Result;
use crate::services::MessagesManagerTrait;
use zoe_state_machine::group::{CreateGroupBuilder, CreateGroupResult};
use zoe_wire_protocol::MessageId;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb)]
impl Client {
    pub async fn create_group(&self, create_group: CreateGroupBuilder) -> Result<MessageId> {
        let keypair = self.keypair();
        let manager = self.group_manager();
        let CreateGroupResult { group_id, message } =
            manager.create_group(create_group, &keypair).await?;
        let msg_manager = self.message_manager().clone();
        msg_manager.publish(message).await?;
        Ok(group_id)
    }
}
