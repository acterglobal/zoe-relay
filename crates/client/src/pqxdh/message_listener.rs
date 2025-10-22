use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use eyeball::{AsyncLock, SharedObservable};
use futures::{Stream, StreamExt};
use zoe_wire_protocol::{Filter, KeyId, MessageFull, PqxdhEncryptedContent, Tag};

use super::{PqxdhProtocolState, PqxdhSessionId, Result};
use crate::pqxdh::PqxdhError;
use zoe_state_machine::messages::MessagesManagerTrait;

pub struct PqxdhMessageListener<U> {
    inner: Pin<Box<dyn futures::Stream<Item = U> + Send>>,
}

impl<U> PqxdhMessageListener<U>
where
    U: for<'de> serde::Deserialize<'de>,
{
    pub(super) async fn new<T: MessagesManagerTrait>(
        messages_manager: Arc<T>,
        session_id: PqxdhSessionId,
        state: SharedObservable<super::PqxdhProtocolState, AsyncLock>,
        listening_tag: Tag,
        catch_up: bool,
    ) -> Result<Self> {
        // Subscribe to the session channel for responses
        let messages_stream = if catch_up {
            messages_manager
                .catch_up_and_subscribe((&listening_tag).into(), None)
                .await?
        } else {
            messages_manager
                .ensure_contains_filter(Filter::from(listening_tag.clone()))
                .await?;
            messages_manager.filtered_messages_stream(Filter::from(listening_tag))
        };

        let inner = Box::pin(messages_stream.filter_map(move |message_full| {
            let state = state.clone();
            let session_id = session_id.clone();
            async move {
                tracing::debug!(
                    "🔄 PQXDH handler received message: {}",
                    hex::encode(message_full.id().as_bytes())
                );
                Self::on_regular_message(&state, &message_full, &session_id)
                    .await
                    .inspect_err(|e| {
                        tracing::error!(
                            msg_id = hex::encode(message_full.id().as_bytes()),
                            "error processing inbox message: {e}"
                        );
                    })
                    .inspect(|_result| {
                        tracing::debug!(
                            "✅ PQXDH handler successfully processed message: {}",
                            hex::encode(message_full.id().as_bytes())
                        );
                    })
                    .ok()
            }
        }));
        Ok(Self { inner })
    }

    async fn on_regular_message(
        state: &SharedObservable<PqxdhProtocolState, AsyncLock>,
        message_full: &MessageFull,
        session_id: &PqxdhSessionId,
    ) -> Result<U> {
        let shared_secret = {
            let current_state = state.get().await;
            let Some(session) = current_state.sessions.get(&session_id.into()) else {
                return Err(PqxdhError::SessionNotFound);
            };

            if &session.their_key != message_full.author() {
                return Err(PqxdhError::InvalidSender);
            };
            session.shared_secret.clone()
        };

        let Some(PqxdhEncryptedContent::Session(pqxdh_content)) =
            message_full.content().as_pqxdh_encrypted()
        else {
            return Err(PqxdhError::NotPqxdhMessage);
        };

        let decrypted_bytes =
            zoe_wire_protocol::inbox::pqxdh::pqxdh_crypto::decrypt_pqxdh_session_message(
                &shared_secret,
                pqxdh_content,
            )
            .map_err(|e| PqxdhError::Crypto(e.to_string()))?;
        Ok(postcard::from_bytes(&decrypted_bytes)?)
    }
}

impl<U> Stream for PqxdhMessageListener<U>
where
    U: for<'de> serde::Deserialize<'de>,
{
    type Item = U;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        this.inner.poll_next_unpin(cx)
    }
}
