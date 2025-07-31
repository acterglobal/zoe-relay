use anyhow::Result;

use std::pin::Pin;
use std::task::{Context, Poll};
use tarpc::serde_transport;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use tarpc::tokio_serde::{Deserializer, Serializer};
use tokio_util::codec::LengthDelimitedCodec;

use crate::StreamPair;
use serde::{Deserialize, Serialize};

/// Postcard serialization format for tarpc
#[derive(Default, Clone, Debug)]
pub struct PostcardFormat;

impl<Item> Serializer<Item> for PostcardFormat
where
    Item: Serialize,
{
    type Error = std::io::Error;

    fn serialize(self: Pin<&mut Self>, item: &Item) -> Result<bytes::Bytes, Self::Error> {
        let serialized = postcard::to_allocvec(item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(bytes::Bytes::from(serialized))
    }
}

impl<Item> Deserializer<Item> for PostcardFormat
where
    Item: for<'de> Deserialize<'de>,
{
    type Error = std::io::Error;

    fn deserialize(self: Pin<&mut Self>, src: &bytes::BytesMut) -> Result<Item, Self::Error> {
        postcard::from_bytes(src)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

impl AsyncRead for StreamPair {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for StreamPair {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(std::io::Error::other(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Create a postcard transport directly for manual service implementation
///
/// This is the core building block - use this to implement specific tarpc services
/// with proper type safety and full control over the request/response handling.
pub fn create_postcard_transport<Req, Resp>(
    streams: StreamPair,
) -> tarpc::serde_transport::Transport<
    StreamPair,
    tarpc::ClientMessage<Req>,
    tarpc::Response<Resp>,
    PostcardFormat,
>
where
    Req: for<'de> Deserialize<'de> + Send + 'static,
    Resp: Serialize + Send + 'static,
{
    let framed = tokio_util::codec::Framed::new(streams, LengthDelimitedCodec::new());
    serde_transport::new(framed, PostcardFormat)
}
