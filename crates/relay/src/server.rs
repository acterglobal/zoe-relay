use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use quinn::{Connection, RecvStream, SendStream};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tarpc::{serde_transport, server};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{error, info, warn};

use crate::create_relay_server_endpoint;
use tarpc::server::Channel;
use zoeyr_message_store::{RedisStorage, RelayConfig};
use zoeyr_wire_protocol::{generate_ed25519_keypair, load_ed25519_key_from_hex, RelayService};

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
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.send)
            .poll_shutdown(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
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
                if let Err(e) = Self::handle_tarpc_over_quic_stream(send, recv, service).await {
                    error!("❌ Tarpc over QUIC stream error: {}", e);
                }
            });
        }

        info!("🔚 QUIC connection ended");
        Ok(())
    }

    async fn handle_tarpc_over_quic_stream(
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        service: S,
    ) -> Result<()>
    where
        S: tarpc::server::Serve + Send + 'static,
        S::Req: for<'de> serde::Deserialize<'de> + Send + 'static,
        S::Resp: serde::Serialize + Send + 'static,
    {
        info!("🔧 Setting up tarpc transport over QUIC stream");

        // Create tarpc transport from QUIC streams
        use tokio_util::codec::{Framed, LengthDelimitedCodec};

        // Create a combined duplex stream from the QUIC streams
        let codec = LengthDelimitedCodec::new();
        let combined = QuicDuplexStream::new(recv, send);
        let framed = Framed::new(combined, codec);
        let transport = serde_transport::new(framed, PostcardSerializer::default());

        info!("📦 Created tarpc transport, starting to execute service requests");

        // Create and execute tarpc server
        use futures_util::StreamExt;

        let server = server::BaseChannel::with_defaults(transport);
        let responses = server.execute(service);

        info!("🔄 Processing tarpc responses...");

        // Process responses sequentially since they're not Send
        tokio::pin!(responses);
        while let Some(response) = responses.next().await {
            info!("📨 Processing tarpc response");
            response.await;
        }

        info!("✅ Tarpc stream processing completed");
        Ok(())
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

    pub async fn build(
        self,
    ) -> Result<(
        QuicTarpcServer<zoeyr_wire_protocol::ServeRelayService<crate::RelayServiceImpl>>,
        Arc<RedisStorage>,
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
