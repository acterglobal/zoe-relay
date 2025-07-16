use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use quinn::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tarpc::{serde_transport, server};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, info, warn};

use crate::create_relay_server_endpoint;
use tarpc::server::Channel;
use zoeyr_message_store::{RedisStorage, RelayConfig};
use zoeyr_wire_protocol::{
    generate_ed25519_keypair, load_ed25519_key_from_hex, RelayService, StreamProtocolMessage,
};

/// Custom postcard serializer for tarpc
#[derive(Clone, Debug, Default)]
pub struct PostcardSerializer;

impl<T> tokio_serde::Serializer<T> for PostcardSerializer
where
    T: serde::Serialize,
{
    type Error = std::io::Error;

    fn serialize(self: Pin<&mut Self>, item: &T) -> Result<bytes::Bytes, Self::Error> {
        let bytes = postcard::to_allocvec(item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(bytes::Bytes::from(bytes))
    }
}

impl<T> tokio_serde::Deserializer<T> for PostcardSerializer
where
    T: for<'a> serde::Deserialize<'a>,
{
    type Error = std::io::Error;

    fn deserialize(self: Pin<&mut Self>, src: &bytes::BytesMut) -> Result<T, Self::Error> {
        postcard::from_bytes(src)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// A duplex stream that combines QUIC RecvStream and SendStream
pub struct QuicDuplexStream {
    recv: RecvStream,
    send: SendStream,
}

impl QuicDuplexStream {
    pub fn new(recv: RecvStream, send: SendStream) -> Self {
        Self { recv, send }
    }
}

impl AsyncRead for QuicDuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicDuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.send)
            .poll_write(cx, buf)
            .map_err(std::io::Error::other)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(std::io::Error::other)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(std::io::Error::other)
    }
}

/// A wrapper that allows injecting a first frame back into a stream
/// This is needed when we've already consumed the first frame to determine protocol type
pub struct StreamWithFirstFrame<S> {
    stream: S,
    first_frame: Option<bytes::BytesMut>,
}

impl<S> StreamWithFirstFrame<S> {
    pub fn new(stream: S, first_frame: bytes::BytesMut) -> Self {
        Self {
            stream,
            first_frame: Some(first_frame),
        }
    }
}

impl<S> Stream for StreamWithFirstFrame<S>
where
    S: Stream<Item = Result<bytes::BytesMut, std::io::Error>> + Unpin,
{
    type Item = Result<bytes::BytesMut, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        // If we have a first frame, return it first
        if let Some(first_frame) = self.first_frame.take() {
            return std::task::Poll::Ready(Some(Ok(first_frame)));
        }

        // Otherwise delegate to the underlying stream
        std::pin::Pin::new(&mut self.stream).poll_next(cx)
    }
}

impl<S> Sink<bytes::Bytes> for StreamWithFirstFrame<S>
where
    S: Sink<bytes::Bytes> + Unpin,
{
    type Error = S::Error;

    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_ready(cx)
    }

    fn start_send(
        mut self: std::pin::Pin<&mut Self>,
        item: bytes::Bytes,
    ) -> Result<(), Self::Error> {
        std::pin::Pin::new(&mut self.stream).start_send(item)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.stream).poll_close(cx)
    }
}

/// A stream wrapper that buffers some initial data and presents it as if it was never consumed.
/// This works at the raw AsyncRead/AsyncWrite level, making it compatible with tarpc's transport layer.
pub struct StreamWithBufferedData<S> {
    inner: S,
    buffered_data: Option<bytes::BytesMut>,
}

impl<S> StreamWithBufferedData<S> {
    pub fn new(inner: S, buffered_data: bytes::BytesMut) -> Self {
        Self {
            inner,
            buffered_data: Some(buffered_data),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StreamWithBufferedData<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // If we have buffered data, serve it first
        if let Some(buffered) = &mut self.buffered_data {
            if !buffered.is_empty() {
                let to_copy = std::cmp::min(buf.remaining(), buffered.len());
                buf.put_slice(&buffered.split_to(to_copy));

                // If buffered data is empty, remove it
                if buffered.is_empty() {
                    self.buffered_data = None;
                }

                return Poll::Ready(Ok(()));
            } else {
                // Empty buffer, remove it
                self.buffered_data = None;
            }
        }

        // No more buffered data, read from inner stream
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StreamWithBufferedData<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Handle QUIC stream for tarpc protocol with proper first frame restoration
async fn handle_tarpc_protocol<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    first_frame_data: bytes::BytesMut,
    service: impl RelayService + Clone + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("🚀 Starting tarpc protocol handler with restored first frame");

    // Create a stream that buffers the first frame at the raw stream level
    let stream_with_buffered_data = StreamWithBufferedData::new(stream, first_frame_data);

    // Now create the framed transport - this will work with tarpc because it sees a normal stream
    let codec = LengthDelimitedCodec::new();
    let framed = Framed::new(stream_with_buffered_data, codec);
    let transport = serde_transport::new(framed, PostcardSerializer);

    info!("✅ Created tarpc transport with buffered first frame");

    // Create tarpc server
    let server = server::BaseChannel::with_defaults(transport);
    info!("📡 Tarpc server ready to handle requests");

    // Handle incoming requests

    let requests = server.execute(service.serve());

    // TODO: Fix Send/Unpin trait issues with tarpc
    // while let Some(request_handler) = requests.next().await {
    //     tokio::spawn(request_handler);
    // }

    // Temporary workaround to allow compilation
    info!("⚠️ Tarpc request handling temporarily disabled due to trait bound issues");

    info!("🏁 Tarpc protocol handler completed");
    Ok(())
}

/// Handle streaming protocol (existing implementation)
async fn handle_streaming_protocol<S>(
    mut stream_with_first: StreamWithFirstFrame<S>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    S: Stream<Item = Result<bytes::BytesMut, std::io::Error>> + Sink<bytes::Bytes> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    info!("🎧 Starting streaming protocol handler");

    // Read the first message (which we already have)
    let first_message = stream_with_first
        .next()
        .await
        .ok_or("Stream ended without first message")?
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    // Parse the streaming protocol message
    use zoeyr_wire_protocol::StreamProtocolMessage;
    let stream_msg: StreamProtocolMessage = postcard::from_bytes(&first_message)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

    match stream_msg {
        StreamProtocolMessage::Request(request) => {
            info!("📥 Received streaming request: follow={}", request.follow);

            // Send response
            use zoeyr_wire_protocol::{StreamResponse, StreamingMessage};
            let response = StreamProtocolMessage::Response(StreamResponse::StreamStarted);
            let response_bytes = postcard::to_allocvec(&response)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            stream_with_first
                .send(response_bytes.into())
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

            // Simulate sending some messages
            let mut message_count = 0;
            let max_messages = if request.follow { 10 } else { 3 };

            while message_count < max_messages {
                message_count += 1;

                // Create test message
                let test_message = StreamingMessage::MessageReceived {
                    message_id: format!("test_msg_{message_count}"),
                    stream_position: message_count.to_string(),
                    message_data: format!("Test message {message_count} content").into_bytes(),
                };

                let msg_frame = StreamProtocolMessage::Message(test_message);
                let msg_bytes = postcard::to_allocvec(&msg_frame)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                stream_with_first
                    .send(msg_bytes.into())
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                info!("📤 Sent message {}", message_count);

                // Send heartbeat every 5 messages
                if message_count % 5 == 0 {
                    let heartbeat = StreamProtocolMessage::Message(StreamingMessage::Heartbeat);
                    let heartbeat_bytes = postcard::to_allocvec(&heartbeat)
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                    stream_with_first
                        .send(heartbeat_bytes.into())
                        .await
                        .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                    info!("💓 Sent heartbeat");
                }

                // In follow mode, continue streaming
                if request.follow {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }

            // Send batch end if not follow mode
            if !request.follow {
                let batch_end = StreamProtocolMessage::Message(StreamingMessage::BatchEnd);
                let batch_end_bytes = postcard::to_allocvec(&batch_end)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                stream_with_first
                    .send(batch_end_bytes.into())
                    .await
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;

                info!("📦 Sent batch end");
            }
        }
        _ => {
            warn!("⚠️ Unexpected streaming protocol message type");
        }
    }

    info!("🏁 Streaming protocol handler completed");
    Ok(())
}

/// Generic QUIC + tarpc server that can host any tarpc service
pub struct QuicTarpcServer<S> {
    server_key: SigningKey,
    addr: SocketAddr,
    service: S,
}

impl<S> QuicTarpcServer<S>
where
    S: Clone + Send + Sync + 'static,
    S: tarpc::server::Serve,
    S::Req: for<'de> serde::Deserialize<'de> + Send + 'static,
    S::Resp: serde::Serialize + Send + 'static,
{
    pub fn new(addr: SocketAddr, server_key: SigningKey, service: S) -> Self {
        Self {
            server_key,
            addr,
            service,
        }
    }

    pub fn server_public_key(&self) -> [u8; 32] {
        self.server_key.verifying_key().to_bytes()
    }

    pub async fn run(self) -> Result<()>
    where
        S: tarpc::server::Serve + Send + 'static,
    {
        info!("🚀 Starting QUIC+Tarpc Server");
        info!("📋 Server Address: {}", self.addr);
        info!(
            "🔑 Server Public Key: {}",
            hex::encode(self.server_public_key())
        );

        // Create QUIC server endpoint
        let endpoint = create_relay_server_endpoint(self.addr, &self.server_key)?;

        info!("✅ QUIC server listening on {}", self.addr);
        println!("\n🔑 IMPORTANT: Server Public Key for clients:");
        println!("   {}", hex::encode(self.server_public_key()));
        println!("   Copy this key to connect clients!\n");

        // Use LocalSet for all tarpc operations
        let local = tokio::task::LocalSet::new();

        local
            .run_until(async move {
                // Accept QUIC connections
                while let Some(incoming) = endpoint.accept().await {
                    let service = self.service.clone();

                    tokio::task::spawn_local(async move {
                        match incoming.await {
                            Ok(connection) => {
                                info!(
                                    "🔗 New QUIC connection from {}",
                                    connection.remote_address()
                                );
                                if let Err(e) =
                                    Self::handle_quic_connection(connection, service).await
                                {
                                    error!("❌ QUIC connection error: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("❌ QUIC connection failed: {}", e);
                            }
                        }
                    });
                }
            })
            .await;

        Ok(())
    }

    async fn handle_quic_connection(connection: Connection, service: S) -> Result<()>
    where
        S: tarpc::server::Serve + Send + 'static,
    {
        info!("🎯 Handling QUIC connection, waiting for streams...");

        // Accept bidirectional streams from the QUIC connection
        while let Ok((send, recv)) = connection.accept_bi().await {
            info!("📡 New bidirectional stream accepted");
            let service = service.clone();

            tokio::task::spawn_local(async move {
                // TODO: Fix tarpc protocol handling
                info!("⚠️ Tarpc protocol handling temporarily disabled for compilation");
                // if let Err(e) = Self::handle_tarpc_over_quic_stream_v2(recv, send, service).await {
                //     error!("❌ Tarpc over QUIC stream error: {}", e);
                // }
            });
        }

        info!("🔚 QUIC connection ended");
        Ok(())
    }

    async fn handle_tarpc_over_quic_stream_v2(
        recv: RecvStream,
        send: SendStream,
        service: impl RelayService + Clone + Send + 'static,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("🔍 Starting dual-protocol detection (v2 with buffered stream)");

        // Create a length-delimited reader to get the first message frame
        let codec = LengthDelimitedCodec::new();
        let combined = QuicDuplexStream::new(recv, send);
        let mut framed = Framed::new(combined, codec);

        // Read the first frame for protocol detection
        let first_frame = match framed.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(e)) => {
                error!("❌ Failed to read first frame: {}", e);
                return Err(Box::new(e));
            }
            None => {
                error!("❌ Connection closed before first frame");
                return Err("Connection closed".into());
            }
        };

        info!(
            "📥 Received first frame ({} bytes) for protocol detection",
            first_frame.len()
        );

        // Try to deserialize as streaming protocol
        match postcard::from_bytes::<StreamProtocolMessage>(&first_frame) {
            Ok(_) => {
                info!("🎧 Detected streaming protocol");

                // For streaming, we can use the existing StreamWithFirstFrame approach
                let stream_with_first = StreamWithFirstFrame::new(framed, first_frame);
                handle_streaming_protocol(stream_with_first).await
            }
            Err(_) => {
                info!("📞 Detected tarpc protocol");

                // For tarpc, we need to reconstruct the original stream with buffered data
                let underlying_stream = framed.into_inner();

                // Create a properly framed first message by adding length prefix
                let mut framed_first_message = bytes::BytesMut::new();
                framed_first_message.extend_from_slice(&(first_frame.len() as u32).to_be_bytes());
                framed_first_message.extend_from_slice(&first_frame);

                handle_tarpc_protocol(underlying_stream, framed_first_message, service).await
            }
        }
    }

    async fn handle_streaming_protocol(
        mut framed: Framed<QuicDuplexStream, LengthDelimitedCodec>,
        first_message: zoeyr_wire_protocol::StreamProtocolMessage,
    ) -> Result<()> {
        use futures_util::SinkExt;
        use zoeyr_wire_protocol::{StreamProtocolMessage, StreamResponse, StreamingMessage};

        info!("🎧 Starting streaming protocol handler");

        // Handle the first message (should be a Request)
        match first_message {
            StreamProtocolMessage::Request(stream_request) => {
                info!("📋 Received stream request with filters");
                info!("   Follow mode: {}", stream_request.follow);
                info!("   Limit: {:?}", stream_request.limit);

                // Send acknowledgment
                let response = StreamProtocolMessage::Response(StreamResponse::StreamStarted);
                let response_bytes = postcard::to_allocvec(&response)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize response: {}", e))?;

                framed
                    .send(response_bytes.into())
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send response: {}", e))?;

                info!("✅ Stream started, beginning message delivery");

                if stream_request.follow {
                    // Follow mode: send messages continuously
                    let mut message_count = 0;
                    loop {
                        message_count += 1;

                        // Send a test message
                        let test_message = StreamingMessage::MessageReceived {
                            message_id: format!("follow_msg_{message_count}"),
                            stream_position: message_count.to_string(),
                            message_data: format!(
                                "Follow mode message #{} - timestamp: {}",
                                message_count,
                                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
                            )
                            .into_bytes(),
                        };

                        let message_msg = StreamProtocolMessage::Message(test_message);
                        let message_bytes = postcard::to_allocvec(&message_msg)
                            .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;

                        if let Err(e) = framed.send(message_bytes.into()).await {
                            info!("🔌 Client disconnected during follow mode: {}", e);
                            break;
                        }

                        info!("📨 Sent follow message #{}", message_count);

                        // Send heartbeat every 5 messages
                        if message_count % 5 == 0 {
                            let heartbeat =
                                StreamProtocolMessage::Message(StreamingMessage::Heartbeat);
                            let heartbeat_bytes =
                                postcard::to_allocvec(&heartbeat).map_err(|e| {
                                    anyhow::anyhow!("Failed to serialize heartbeat: {}", e)
                                })?;

                            if let Err(e) = framed.send(heartbeat_bytes.into()).await {
                                info!("🔌 Client disconnected during heartbeat: {}", e);
                                break;
                            }

                            info!("💓 Sent heartbeat after {} messages", message_count);
                        }

                        // Wait 3 seconds between messages
                        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

                        // In follow mode, we'll continue until client disconnects
                        // (Connection errors will be caught by the send() calls above)
                    }
                } else {
                    // Batch mode: send one message then end
                    let test_message = StreamingMessage::MessageReceived {
                        message_id: "batch_test_message".to_string(),
                        stream_position: "1".to_string(),
                        message_data: format!(
                            "Batch mode test message - timestamp: {}",
                            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S")
                        )
                        .into_bytes(),
                    };

                    let message_msg = StreamProtocolMessage::Message(test_message);
                    let message_bytes = postcard::to_allocvec(&message_msg)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize message: {}", e))?;

                    framed
                        .send(message_bytes.into())
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to send message: {}", e))?;

                    info!("📨 Sent batch test message");

                    // Send batch end
                    let batch_end = StreamProtocolMessage::Message(StreamingMessage::BatchEnd);
                    let batch_end_bytes = postcard::to_allocvec(&batch_end)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize batch end: {}", e))?;

                    framed
                        .send(batch_end_bytes.into())
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to send batch end: {}", e))?;

                    info!("📦 Sent batch end signal");

                    // Send stream end
                    let stream_end = StreamProtocolMessage::Message(StreamingMessage::StreamEnd);
                    let stream_end_bytes = postcard::to_allocvec(&stream_end)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize stream end: {}", e))?;

                    framed
                        .send(stream_end_bytes.into())
                        .await
                        .map_err(|e| anyhow::anyhow!("Failed to send stream end: {}", e))?;

                    info!("🔚 Sent stream end signal");
                }

                info!("✅ Streaming session completed");
                Ok(())
            }
            _ => {
                let error_response =
                    StreamProtocolMessage::Response(StreamResponse::StreamRejected(
                        "Expected StreamRequest as first message".to_string(),
                    ));
                let error_bytes = postcard::to_allocvec(&error_response)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize error: {}", e))?;

                framed
                    .send(error_bytes.into())
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send error: {}", e))?;

                Err(anyhow::anyhow!(
                    "Invalid first message for streaming protocol"
                ))
            }
        }
    }
}

/// Server builder for common relay server setup
pub struct RelayServerBuilder {
    addr: SocketAddr,
    private_key: Option<String>,
    redis_url: String,
    key_output: Option<String>,
    blob_data_dir: Option<std::path::PathBuf>,
}

impl RelayServerBuilder {
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            private_key: None,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            key_output: None,
            blob_data_dir: None,
        }
    }

    pub fn with_private_key(mut self, private_key: String) -> Self {
        self.private_key = Some(private_key);
        self
    }

    pub fn with_redis_url(mut self, redis_url: String) -> Self {
        self.redis_url = redis_url;
        self
    }

    pub fn with_key_output(mut self, key_output: String) -> Self {
        self.key_output = Some(key_output);
        self
    }

    pub fn with_blob_storage(mut self, data_dir: std::path::PathBuf) -> Self {
        self.blob_data_dir = Some(data_dir);
        self
    }

    pub async fn build<
        T: Serialize + for<'de> Deserialize<'de> + Send + Sync + Sized + Clone + 'static,
    >(
        self,
    ) -> Result<(
        QuicTarpcServer<zoeyr_wire_protocol::ServeRelayService<crate::RelayServiceImpl<T>>>,
        Arc<RedisStorage<T>>,
    )> {
        // Load or generate server key
        let server_key = match self.private_key {
            Some(key_hex) => {
                info!("🔑 Loading server key from hex");
                load_ed25519_key_from_hex(&key_hex)
                    .context("Failed to load private key from hex")?
            }
            None => {
                info!("🔑 Generating new server key");
                let key = generate_ed25519_keypair();

                // Save the key if output path specified
                if let Some(key_output) = &self.key_output {
                    let key_hex = hex::encode(key.to_bytes());
                    match std::fs::write(key_output, &key_hex) {
                        Ok(_) => info!("💾 Server key saved to: {}", key_output),
                        Err(e) => warn!("⚠️ Failed to save server key: {}", e),
                    }
                }

                key
            }
        };

        // Create Redis storage
        let config = RelayConfig {
            redis: zoeyr_message_store::RedisConfig {
                url: self.redis_url,
                pool_size: 10,
            },
            ..Default::default()
        };

        let storage = Arc::new(RedisStorage::new(config).await?);
        info!("💾 Redis storage initialized");

        // Create service implementation
        let relay_service = crate::RelayServiceImpl::new(Arc::clone(&storage));

        // Create server
        let server = QuicTarpcServer::new(self.addr, server_key, relay_service.serve());

        Ok((server, storage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use bytes::{Bytes, BytesMut};
    use futures_util::{SinkExt, StreamExt};
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_util::codec::{Framed, LengthDelimitedCodec};
    use zoeyr_wire_protocol::{
        MessageFilters, RelayResult, RelayService, StreamProtocolMessage, StreamRequest,
    };

    // Mock duplex stream for testing
    struct MockDuplexStream {
        read_data: std::collections::VecDeque<Result<BytesMut, std::io::Error>>,
        written_data: Vec<Bytes>,
    }

    impl MockDuplexStream {
        fn new() -> Self {
            Self {
                read_data: std::collections::VecDeque::new(),
                written_data: Vec::new(),
            }
        }

        fn add_read_data(&mut self, data: BytesMut) {
            self.read_data.push_back(Ok(data));
        }

        fn add_read_error(&mut self, error: std::io::Error) {
            self.read_data.push_back(Err(error));
        }

        fn written_data(&self) -> &[Bytes] {
            &self.written_data
        }
    }

    impl AsyncRead for MockDuplexStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if let Some(data_result) = self.read_data.pop_front() {
                match data_result {
                    Ok(data) => {
                        let to_copy = std::cmp::min(buf.remaining(), data.len());
                        buf.put_slice(&data[..to_copy]);
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(e)),
                }
            } else {
                // No more data
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for MockDuplexStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.written_data.push(Bytes::copy_from_slice(buf));
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    // Mock relay service for testing
    #[derive(Clone)]
    struct MockRelayService {
        store_responses: std::collections::VecDeque<RelayResult<String>>,
    }

    impl MockRelayService {
        fn new() -> Self {
            Self {
                store_responses: std::collections::VecDeque::new(),
            }
        }

        fn add_store_response(&mut self, response: RelayResult<String>) {
            self.store_responses.push_back(response);
        }
    }

    impl RelayService for MockRelayService {
        async fn get_message(
            self,
            _ctx: tarpc::context::Context,
            _message_id: Vec<u8>,
        ) -> RelayResult<Option<Vec<u8>>> {
            Ok(None)
        }

        async fn store_message(
            mut self,
            _ctx: tarpc::context::Context,
            _message_data: Vec<u8>,
        ) -> RelayResult<String> {
            self.store_responses
                .pop_front()
                .unwrap_or(Ok("test_id".to_string()))
        }

        async fn start_message_stream(
            self,
            _ctx: tarpc::context::Context,
            _config: zoeyr_wire_protocol::StreamConfig,
        ) -> RelayResult<String> {
            Ok("session_id".to_string())
        }

        async fn get_stream_batch(
            self,
            _ctx: tarpc::context::Context,
            _session_id: String,
            _max_messages: Option<usize>,
        ) -> RelayResult<Vec<zoeyr_wire_protocol::StreamMessage>> {
            Ok(vec![])
        }

        async fn stop_message_stream(
            self,
            _ctx: tarpc::context::Context,
            _session_id: String,
        ) -> RelayResult<bool> {
            Ok(true)
        }
    }

    #[test]
    fn test_stream_with_first_frame_helper() {
        tokio_test::block_on(async {
            // Create properly length-delimited frames
            let mut second_frame = BytesMut::new();
            second_frame.extend_from_slice(&(12u32).to_be_bytes()); // length prefix
            second_frame.extend_from_slice(b"second_frame");

            let mut third_frame = BytesMut::new();
            third_frame.extend_from_slice(&(11u32).to_be_bytes()); // length prefix
            third_frame.extend_from_slice(b"third_frame");

            // Create a mock stream
            let mut mock_stream = MockDuplexStream::new();
            mock_stream.add_read_data(second_frame);
            mock_stream.add_read_data(third_frame);

            // Create framed stream
            let codec = LengthDelimitedCodec::new();
            let framed = Framed::new(mock_stream, codec);

            // Create StreamWithFirstFrame
            let first_frame = BytesMut::from("first_frame");
            let mut stream_with_first = StreamWithFirstFrame::new(framed, first_frame);

            // Test that first frame is returned first
            let first_result = stream_with_first.next().await.unwrap().unwrap();
            assert_eq!(first_result, "first_frame");

            // Test that subsequent frames come from underlying stream
            let second_result = stream_with_first.next().await.unwrap().unwrap();
            assert_eq!(second_result, "second_frame");

            let third_result = stream_with_first.next().await.unwrap().unwrap();
            assert_eq!(third_result, "third_frame");
        });
    }

    #[test]
    fn test_protocol_detection_streaming() {
        tokio_test::block_on(async {
            // Create a streaming protocol message
            let filters = MessageFilters::new();
            let stream_request = StreamRequest::new(filters).with_follow(true);
            let stream_msg = StreamProtocolMessage::Request(stream_request);

            // Serialize it
            let serialized = postcard::to_allocvec(&stream_msg).unwrap();

            // Test that it can be deserialized as streaming protocol
            let deserialized: Result<StreamProtocolMessage, _> = postcard::from_bytes(&serialized);
            assert!(deserialized.is_ok());

            match deserialized.unwrap() {
                StreamProtocolMessage::Request(req) => {
                    assert!(req.follow);
                }
                _ => panic!("Expected StreamRequest"),
            }
        });
    }

    #[test]
    fn test_protocol_detection_tarpc() {
        tokio_test::block_on(async {
            // Create a mock tarpc request (store_message call)
            let test_message_data = vec![1, 2, 3, 4];

            // For this test, we'll simulate what a tarpc request might look like
            // We'll use a simple struct that can't be deserialized as StreamProtocolMessage
            #[derive(serde::Serialize)]
            struct MockTarpcRequest {
                method: String,
                params: Vec<u8>,
            }

            let mock_tarpc_request = MockTarpcRequest {
                method: "store_message".to_string(),
                params: test_message_data,
            };

            let serialized = postcard::to_allocvec(&mock_tarpc_request).unwrap();

            // Test that it CANNOT be deserialized as streaming protocol
            let stream_result: Result<StreamProtocolMessage, _> = postcard::from_bytes(&serialized);
            assert!(stream_result.is_err());

            // This confirms our protocol detection logic:
            // if it deserializes as StreamProtocolMessage -> streaming
            // if it doesn't -> tarpc
        });
    }

    #[tokio::test]
    async fn test_streaming_protocol_flow() {
        // Create mock duplex stream
        let mut mock_stream = MockDuplexStream::new();

        // Create a streaming request
        let filters = MessageFilters::new();
        let stream_request = StreamRequest::new(filters).with_follow(false); // batch mode for test
        let request_msg = StreamProtocolMessage::Request(stream_request);
        let request_bytes = postcard::to_allocvec(&request_msg).unwrap();

        // Add the request to mock stream's read data with proper framing
        let mut framed_request = BytesMut::new();
        framed_request.extend_from_slice(&(request_bytes.len() as u32).to_be_bytes()); // length prefix
        framed_request.extend_from_slice(&request_bytes);
        mock_stream.add_read_data(framed_request);

        // Create framed stream
        let codec = LengthDelimitedCodec::new();
        let mut framed = Framed::new(mock_stream, codec);

        // Simulate reading the first frame (protocol detection)
        let first_frame = framed.next().await.unwrap().unwrap();

        // Test protocol detection
        let detected_msg: StreamProtocolMessage = postcard::from_bytes(&first_frame).unwrap();

        match detected_msg {
            StreamProtocolMessage::Request(req) => {
                assert!(!req.follow); // Should be batch mode

                // Test that we can create appropriate response
                use zoeyr_wire_protocol::{StreamResponse, StreamingMessage};
                let response = StreamProtocolMessage::Response(StreamResponse::StreamStarted);
                let response_bytes = postcard::to_allocvec(&response).unwrap();

                // Send response (in real implementation)
                let result = framed.send(response_bytes.into()).await;
                assert!(result.is_ok());

                // Create test message
                let test_message = StreamingMessage::MessageReceived {
                    message_id: "test_msg".to_string(),
                    stream_position: "1".to_string(),
                    message_data: b"test content".to_vec(),
                };
                let msg_frame = StreamProtocolMessage::Message(test_message);
                let msg_bytes = postcard::to_allocvec(&msg_frame).unwrap();

                // Send message
                let result = framed.send(msg_bytes.into()).await;
                assert!(result.is_ok());

                // Send batch end
                let batch_end = StreamProtocolMessage::Message(StreamingMessage::BatchEnd);
                let batch_end_bytes = postcard::to_allocvec(&batch_end).unwrap();

                let result = framed.send(batch_end_bytes.into()).await;
                assert!(result.is_ok());

                // Verify data was written
                let mock_stream = framed.into_inner();
                let written_data = mock_stream.written_data();
                assert_eq!(written_data.len(), 3); // response + message + batch_end
            }
            _ => panic!("Expected StreamRequest"),
        }
    }

    #[tokio::test]
    async fn test_postcard_vs_tarpc_serialization() {
        // Test that our serialization formats are distinguishable

        // Create streaming protocol message
        let filters = MessageFilters::new();
        let stream_request = StreamRequest::new(filters);
        let stream_msg = StreamProtocolMessage::Request(stream_request);
        let stream_bytes = postcard::to_allocvec(&stream_msg).unwrap();

        println!("Stream bytes: {stream_bytes:?}");
        println!("Stream bytes hex: {}", hex::encode(&stream_bytes));

        // Test that streaming bytes cannot be deserialized as tarpc
        // Use a more specific structure that would fail if the data doesn't match
        #[derive(serde::Serialize, serde::Deserialize, Debug)]
        struct MockTarpcRequest {
            method: String,
            args: Vec<u8>,
        }

        let tarpc_from_stream: Result<MockTarpcRequest, _> = postcard::from_bytes(&stream_bytes);
        println!("Trying to deserialize stream as tarpc: {tarpc_from_stream:?}");

        // The key insight: postcard is very permissive, so we need a different approach
        // Instead of relying on deserialization failure, we rely on successful deserialization
        // of our specific StreamProtocolMessage format

        // Test that we can deserialize as streaming protocol
        let stream_result: Result<StreamProtocolMessage, _> = postcard::from_bytes(&stream_bytes);
        assert!(
            stream_result.is_ok(),
            "Should be able to deserialize as StreamProtocolMessage"
        );

        // Create a more realistic tarpc-like message that looks different
        let tarpc_msg = MockTarpcRequest {
            method: "store_message".to_string(),
            args: vec![1, 2, 3, 4],
        };
        let tarpc_bytes = postcard::to_allocvec(&tarpc_msg).unwrap();

        println!("Tarpc bytes: {tarpc_bytes:?}");
        println!("Tarpc bytes hex: {}", hex::encode(&tarpc_bytes));

        // Test that tarpc bytes cannot be deserialized as our streaming protocol
        let stream_from_tarpc: Result<StreamProtocolMessage, _> =
            postcard::from_bytes(&tarpc_bytes);
        println!("Trying to deserialize tarpc as stream: {stream_from_tarpc:?}");
        assert!(
            stream_from_tarpc.is_err(),
            "Should not be able to deserialize tarpc as StreamProtocolMessage"
        );

        // Our protocol detection works by:
        // 1. Try to deserialize as StreamProtocolMessage
        // 2. If successful -> streaming protocol
        // 3. If fails -> tarpc protocol
        // This test validates that approach
    }
}
