use quinn::{RecvStream, SendStream};
use tarpc::tokio_serde;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use tokio::io::AsyncWriteExt;

use super::postcard::PostcardFormat;

/// A pair of streams for bi-directional communication
#[derive(Debug)]
pub struct StreamPair {
    /// Stream for receiving data from the client
    pub recv: RecvStream,
    /// Stream for sending data to the client
    pub send: SendStream,
}

type WrappedStream = FramedRead<RecvStream, LengthDelimitedCodec>;
type WrappedSink = FramedWrite<SendStream, LengthDelimitedCodec>;

// only dealing with one half of the IO
type SerStream<I> = tokio_serde::Framed<WrappedStream, I, I, PostcardFormat>;
type DeSink<I> = tokio_serde::Framed<WrappedSink, I, I, PostcardFormat>;

impl StreamPair {
    pub async fn send_ack(&mut self) -> std::io::Result<()> {
        self.send.write_u8(1).await
    }

    pub fn unpack_transports<S, D>(self) -> (SerStream<S>, DeSink<D>) {
        let StreamPair { recv, send } = self;
        create_postcard_streams(recv, send)
    }
}

pub fn create_postcard_streams<S, D>(
    recv: RecvStream,
    send: SendStream,
) -> (SerStream<S>, DeSink<D>) {
    let wrapped_recv = FramedRead::new(recv, LengthDelimitedCodec::new());
    let wrapped_send = FramedWrite::new(send, LengthDelimitedCodec::new());
    let ser_stream = tokio_serde::Framed::new(wrapped_recv, PostcardFormat);
    let de_sink = tokio_serde::Framed::new(wrapped_send, PostcardFormat);
    (ser_stream, de_sink)
}
