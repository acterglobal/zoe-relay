use crate::RedisMessageStorage;
use std::sync::Arc;
use zoe_wire_protocol::{
    Hash, MessageError, MessageFull, MessageService as MessageServiceRpc, StoreKey, VerifyingKey,
};

#[derive(Clone)]
pub struct MessagesRpcService {
    pub store: Arc<RedisMessageStorage>,
}

impl MessagesRpcService {
    pub fn new(store: Arc<RedisMessageStorage>) -> Self {
        Self { store }
    }
}

impl MessageServiceRpc for MessagesRpcService {
    async fn publish(
        self,
        _context: ::tarpc::context::Context,
        message: MessageFull,
    ) -> Result<Option<String>, MessageError> {
        self.store
            .store_message(&message)
            .await
            .map_err(MessageError::from)
    }

    async fn message(
        self,
        _context: ::tarpc::context::Context,
        id: Hash,
    ) -> Result<Option<MessageFull>, MessageError> {
        self.store
            .get_message(id.as_bytes())
            .await
            .map_err(MessageError::from)
    }

    async fn user_data(
        self,
        _context: ::tarpc::context::Context,
        author: VerifyingKey,
        storage_key: StoreKey,
    ) -> Result<Option<MessageFull>, MessageError> {
        self.store
            .get_user_data(author.as_bytes(), storage_key)
            .await
            .map_err(MessageError::from)
    }
}
