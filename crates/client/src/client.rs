// Remove unused clap imports since they're not needed in this file
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::{SinkExt, StreamExt};
use quinn::Connection;
use quinn::{ClientConfig, Endpoint, crypto::rustls::QuicClientConfig};
use rand::rngs::OsRng;
use rustls::ClientConfig as RustlsClientConfig;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tarpc::serde_transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Duration, timeout};
use tokio_util::codec::LengthDelimitedCodec;
use tracing::{error, info, warn};
use zoe_wire_protocol::{
    AcceptSpecificServerCertVerifier, Kind, Message, MessageFilters, MessageFull,
    MessagesServiceRequest, PostcardFormat, StreamMessage, StreamPair, SubscriptionConfig,
    generate_deterministic_cert_from_ed25519,
};

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("Generic error: {0}")]
    Generic(String),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Quinn connect error: {0}")]
    QuinnConnect(#[from] quinn::ConnectError),
    #[error("Quinn connection error: {0}")]
    QuinnConnection(#[from] quinn::ConnectionError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
}

type Result<T> = std::result::Result<T, ClientError>;

/// A Zoe Relay Client
pub struct Client {
    client_key: SigningKey,
}

impl Client {
    pub fn new() -> Self {
        Self {
            client_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_key(key: SigningKey) -> Self {
        Self { client_key: key }
    }

    /// Connect to relay server and return the connection
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_public_key: VerifyingKey,
    ) -> Result<Connection> {
        info!("🚀 Starting message client");
        info!(
            "🔑 Client public key: {}",
            hex::encode(self.client_key.verifying_key().to_bytes())
        );
        info!("🌐 Connecting to server: {}", server_addr);
        info!(
            "🔐 Server public key: {}",
            hex::encode(server_public_key.to_bytes())
        );

        // Create client endpoint
        let client_endpoint = self.create_client_endpoint(&server_public_key)?;

        // Connect to server
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        info!("✅ Connected to relay server");
        Ok(connection)
    }

    fn create_client_endpoint(&self, server_public_key: &VerifyingKey) -> Result<Endpoint> {
        // Generate client certificate for mutual TLS
        let (client_certs, client_key) =
            generate_deterministic_cert_from_ed25519(&self.client_key, "client")
                .map_err(|e| ClientError::Crypto(e.to_string()))?;

        // Create custom certificate verifier that accepts our server
        let verifier = AcceptSpecificServerCertVerifier::new(*server_public_key);

        // Create client config with client certificate for mutual TLS
        let crypto = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(client_certs, client_key)?;

        let client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).map_err(|e| ClientError::Generic(e.to_string()))?,
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(endpoint)
    }

    /// Run the complete message echo test
    pub async fn run_echo_test(
        &self,
        server_addr: SocketAddr,
        server_public_key: VerifyingKey,
    ) -> Result<()> {
        // Connect to server
        let connection = self.connect(server_addr, server_public_key).await?;

        // Open bidirectional stream
        let (mut send, mut recv) = connection.open_bi().await?;

        // Send service ID (10 for Messages service)
        const MESSAGES_SERVICE_ID: u8 = 10;
        send.write_u8(MESSAGES_SERVICE_ID).await?;
        info!("📡 Selected Messages service (ID: {})", MESSAGES_SERVICE_ID);

        let service_ok = recv.read_u8().await?;
        if service_ok != 1 {
            return Err(ClientError::Generic(
                "Service ID not acknowledged".to_string(),
            ));
        }

        // Set up postcard transport for message communication
        let streams = StreamPair { recv, send };
        let framed = tokio_util::codec::Framed::new(streams, LengthDelimitedCodec::new());
        let transport = serde_transport::new(framed, PostcardFormat::default());
        let (mut sink, mut stream) = transport.split();

        info!("🔄 Transport established, starting message flow");

        // Step 1: Subscribe to messages from our own key
        let subscription_config = SubscriptionConfig {
            filters: MessageFilters {
                authors: Some(vec![self.client_key.verifying_key().to_bytes().to_vec()]),
                channels: None,
                events: None,
                users: None,
            },
            since: None,
            limit: None,
        };

        let subscribe_request = MessagesServiceRequest::Subscribe(subscription_config);
        sink.send(subscribe_request)
            .await
            .map_err(|e| ClientError::Generic(e.to_string()))?;
        sink.flush()
            .await
            .map_err(|e| ClientError::Generic(e.to_string()))?;
        info!("📬 Sent subscription request for our own messages");

        // Step 2: Create and publish an echo message
        let echo_content = "Hello from message client! 🚀".as_bytes().to_vec();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| ClientError::Generic(e.to_string()))?
            .as_secs();

        let message = Message::new_v0(
            echo_content.clone(),
            self.client_key.verifying_key(),
            timestamp,
            Kind::Regular,
            vec![], // no tags
        );

        let message_full = MessageFull::new(message, &self.client_key)
            .map_err(|e| ClientError::Generic(format!("Failed to create MessageFull: {}", e)))?;
        info!(
            "📝 Created message with ID: {}",
            hex::encode(message_full.id.as_bytes())
        );

        let publish_request = MessagesServiceRequest::Publish(message_full.clone());
        sink.send(publish_request)
            .await
            .map_err(|e| ClientError::Generic(e.to_string()))?;
        sink.flush()
            .await
            .map_err(|e| ClientError::Generic(e.to_string()))?;
        info!("📤 Published echo message to relay server");

        // Give a small delay to ensure the message is fully processed by the server
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Step 3: Wait for the message to come back via the stream
        info!("👂 Listening for messages...");

        let receive_timeout = Duration::from_secs(2);
        let mut message_received = false;
        let max_attempts = 15;
        let mut count = 0;

        loop {
            if count >= max_attempts || message_received {
                break;
            }
            count += 1;

            match timeout(receive_timeout, stream.next()).await {
                Ok(Some(Ok(stream_message))) => {
                    match stream_message {
                        StreamMessage::MessageReceived {
                            message,
                            stream_height,
                        } => {
                            info!("🎉 Received message via stream!");
                            info!("   Stream height: {}", stream_height);
                            info!("   Message ID: {}", hex::encode(message.id.as_bytes()));
                            info!("   Author: {}", hex::encode(message.author().to_bytes()));
                            info!(
                                "   Content: {:?}",
                                String::from_utf8_lossy(message.content())
                            );

                            // Verify it's our message
                            if message.id.as_bytes() == message_full.id.as_bytes() {
                                info!("✅ SUCCESS: Received our own echo message!");
                                info!(
                                    "   Original content: {:?}",
                                    String::from_utf8_lossy(&echo_content)
                                );
                                info!(
                                    "   Received content: {:?}",
                                    String::from_utf8_lossy(message.content())
                                );
                                message_received = true;
                            } else {
                                warn!("⚠️  Received different message than expected");
                            }
                        }
                        StreamMessage::StreamHeightUpdate(height) => {
                            info!("📊 Stream height update: {}", height);
                            // Continue listening
                        }
                    }
                }
                Ok(Some(Err(e))) => {
                    error!("❌ Error receiving stream message: {}", e);
                }
                Ok(None) => {
                    warn!("🔚 Stream ended without receiving message");
                }
                Err(_) => {
                    warn!(
                        "⏰ Timeout waiting for message ({}s) - attempt {}/{}",
                        receive_timeout.as_secs(),
                        count,
                        max_attempts
                    );
                }
            }
        }

        // Give the server a moment to process any remaining messages before closing
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Clean shutdown
        connection.close(0u32.into(), b"test complete");
        info!("🔌 Disconnected from server");

        if message_received {
            info!("🎊 Message client test completed successfully!");
            Ok(())
        } else {
            Err(ClientError::Generic(
                "Message was not received via stream".to_string(),
            ))
        }
    }

    /// Get the client's public key
    pub fn public_key(&self) -> VerifyingKey {
        self.client_key.verifying_key()
    }
}
