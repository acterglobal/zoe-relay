use futures::{Sink, Stream};

use std::pin::Pin;
use std::task::{Context, Poll};

use super::{PqxdhSessionId, Result};

#[async_trait::async_trait]
pub trait PqxdhTarpcTransportSender<Resp>
where
    Resp: serde::Serialize + Send + Sync,
{
    async fn send_response(&self, session_id: &PqxdhSessionId, resp: &Resp) -> Result<()>;
}

/// A tarpc transport that uses PQXDH for message delivery
///
/// This transport owns its incoming stream and manages outgoing messages
/// through a send callback function.
pub struct PqxdhTarpcTransport<Req, Resp> {
    /// Incoming message stream
    incoming_stream: Pin<Box<dyn Stream<Item = Req> + Send>>,
    /// Queue of outgoing messages to be sent
    outgoing_queue: tokio::sync::mpsc::UnboundedSender<Resp>,
    /// Background handle for the background task
    background_handle: tokio::task::JoinHandle<()>,
}

impl<Req, Resp> PqxdhTarpcTransport<Req, Resp>
where
    Req: for<'de> serde::Deserialize<'de> + Send,
    Resp: serde::Serialize + Send + Sync + 'static,
{
    /// Creates a new PQXDH transport for the given session
    ///
    /// This sets up the incoming message stream by calling `listen_for_messages`
    /// and initializes the outgoing message queue.
    pub(crate) fn new<T>(
        session_id: PqxdhSessionId,
        incoming_stream: Pin<Box<dyn Stream<Item = Req> + Send>>,
        client: T,
    ) -> Self
    where
        T: PqxdhTarpcTransportSender<Resp> + Send + Sync + 'static,
    {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Spawn a background task to handle outgoing responses
        let background_handle = {
            let tx = tx.clone();
            let session_id = session_id;
            tokio::spawn(async move {
                while let Some(resp) = rx.recv().await {
                    if let Err(e) = client.send_response(&session_id, &resp).await {
                        tracing::error!("Failed to send response: {e}. requeuing");
                        if let Err(e) = tx.send(resp) {
                            tracing::error!("Failed to requeue response: {e}");
                        }
                    }
                }
            })
        };

        Self {
            incoming_stream,
            outgoing_queue: tx,
            background_handle,
        }
    }
}

impl<Req, Resp> Drop for PqxdhTarpcTransport<Req, Resp> {
    fn drop(&mut self) {
        self.background_handle.abort();
    }
}

impl<Req, Resp> Stream for PqxdhTarpcTransport<Req, Resp>
where
    Req: for<'de> serde::Deserialize<'de> + Send,
    Resp: serde::Serialize + Send + Sync,
{
    type Item = std::result::Result<Req, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Poll the incoming stream for new requests
        let this = unsafe { self.get_unchecked_mut() };
        match this.incoming_stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(item)) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<Req, Resp> Sink<Resp> for PqxdhTarpcTransport<Req, Resp>
where
    Req: for<'de> serde::Deserialize<'de> + Send,
    Resp: serde::Serialize + Send + Sync,
{
    type Error = std::io::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        // Always ready to accept responses into our queue
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Resp) -> std::result::Result<(), Self::Error> {
        let this = unsafe { self.get_unchecked_mut() };
        this.outgoing_queue
            .send(item)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        // For now, we'll just return Ready since we queue messages and send them immediately
        // In a more sophisticated implementation, we might want to track pending sends
        // and only return Ready when all are confirmed sent
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), Self::Error>> {
        // Flush any remaining messages first
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
