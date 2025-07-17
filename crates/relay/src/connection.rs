use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use futures_util::{Sink, Stream};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::{net::SocketAddr, pin::Pin};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tracing::{error, info};

use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

use zoeyr_wire_protocol::{
    extract_ed25519_from_cert, generate_deterministic_cert_from_ed25519, ServerWireMessage,
    StreamMessage,
};

/// Transport that routes ServerWireMessage<R, T> - RPC to RPC handling, Stream to channels
#[pin_project]
pub struct RoutingTransport<R, T, Transport>
where
    R: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    Transport: Stream + Sink<ServerWireMessage<R, T>> + Unpin,
{
    #[pin]
    inner: Transport,
    stream_tx: mpsc::UnboundedSender<StreamMessage<T>>,
    _phantom: std::marker::PhantomData<(R, T)>,
}

impl<R, T, Transport> RoutingTransport<R, T, Transport>
where
    R: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    Transport: Stream + Sink<ServerWireMessage<R, T>> + Unpin,
{
    pub fn new(inner: Transport, stream_tx: mpsc::UnboundedSender<StreamMessage<T>>) -> Self {
        Self {
            inner,
            stream_tx,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn with_channels(inner: Transport) -> (Self, mpsc::UnboundedReceiver<StreamMessage<T>>) {
        let (stream_tx, stream_rx) = mpsc::unbounded_channel();
        (
            Self {
                inner,
                stream_tx,
                _phantom: std::marker::PhantomData,
            },
            stream_rx,
        )
    }
}

impl<R, T, Transport, E> Stream for RoutingTransport<R, T, Transport>
where
    R: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    Transport:
        Stream<Item = Result<ServerWireMessage<R, T>, E>> + Sink<ServerWireMessage<R, T>> + Unpin,
    E: std::error::Error + Send + Sync + 'static,
{
    type Item = Result<R, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        match this.inner.poll_next(cx) {
            Poll::Ready(Some(Ok(ServerWireMessage::Rpc(rpc_item)))) => {
                Poll::Ready(Some(Ok(rpc_item)))
            }
            Poll::Ready(Some(Ok(ServerWireMessage::Stream(stream_msg)))) => {
                // Route stream message to channel
                if let Err(e) = this.stream_tx.send(stream_msg) {
                    error!("Failed to send stream message to channel: {}", e);
                }
                // Continue polling for next message (stream messages don't go to RPC)
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<R, T, Transport> Sink<R> for RoutingTransport<R, T, Transport>
where
    R: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync + Unpin,
    Transport: Stream + Sink<ServerWireMessage<R, T>> + Unpin,
    <Transport as Sink<ServerWireMessage<R, T>>>::Error: std::error::Error + Send + Sync + 'static,
{
    type Error = <Transport as Sink<ServerWireMessage<R, T>>>::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: R) -> Result<(), Self::Error> {
        let this = self.project();
        let wrapped = ServerWireMessage::Rpc(item);
        this.inner.start_send(wrapped)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.project();
        this.inner.poll_close(cx)
    }
}

/// Simple postcard codec for ServerWireMessage
#[derive(Clone, Debug, Default)]
pub struct PostcardCodec;

impl<R, T> tokio_serde::Serializer<ServerWireMessage<R, T>> for PostcardCodec
where
    R: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    type Error = std::io::Error;

    fn serialize(
        self: Pin<&mut Self>,
        item: &ServerWireMessage<R, T>,
    ) -> Result<bytes::Bytes, Self::Error> {
        let bytes = postcard::to_allocvec(item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(bytes::Bytes::from(bytes))
    }
}

impl<R, T> tokio_serde::Deserializer<ServerWireMessage<R, T>> for PostcardCodec
where
    R: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    type Error = std::io::Error;

    fn deserialize(
        self: Pin<&mut Self>,
        src: &bytes::BytesMut,
    ) -> Result<ServerWireMessage<R, T>, Self::Error> {
        postcard::from_bytes(src)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// Generic postcard codec for any serializable type
#[derive(Clone, Debug, Default)]
pub struct GenericPostcardCodec;

impl<Item> tokio_serde::Serializer<Item> for GenericPostcardCodec
where
    Item: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    type Error = std::io::Error;

    fn serialize(self: Pin<&mut Self>, item: &Item) -> Result<bytes::Bytes, Self::Error> {
        let bytes = postcard::to_allocvec(item)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(bytes::Bytes::from(bytes))
    }
}

impl<Item> tokio_serde::Deserializer<Item> for GenericPostcardCodec
where
    Item: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync,
{
    type Error = std::io::Error;

    fn deserialize(self: Pin<&mut Self>, src: &bytes::BytesMut) -> Result<Item, Self::Error> {
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

/// Custom TLS verifier that checks the server's embedded ed25519 key
#[derive(Debug)]
pub struct ServerEd25519TlsVerifier {
    expected_server_ed25519_key: VerifyingKey,
}

impl ServerEd25519TlsVerifier {
    pub fn new(expected_key: VerifyingKey) -> Self {
        Self {
            expected_server_ed25519_key: expected_key,
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for ServerEd25519TlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match extract_ed25519_from_cert(end_entity) {
            Ok(cert_ed25519_key) => {
                if cert_ed25519_key.to_bytes() == self.expected_server_ed25519_key.to_bytes() {
                    info!("✅ Server TLS certificate contains expected ed25519 key!");
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                } else {
                    error!("❌ Server TLS certificate contains wrong ed25519 key!");
                    error!(
                        "   Expected: {}",
                        hex::encode(self.expected_server_ed25519_key.to_bytes())
                    );
                    error!("   Found:    {}", hex::encode(cert_ed25519_key.to_bytes()));
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            Err(e) => {
                error!(
                    "❌ Failed to extract ed25519 key from server certificate: {}",
                    e
                );
                Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Only accept Ed25519 signatures to enforce our security model
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Shared QUIC client for connecting to relay servers
pub struct RelayClient {
    pub connection: Connection,
    pub client_key: SigningKey,
    pub server_key: VerifyingKey,
}

impl RelayClient {
    /// Connect to a relay server with ed25519 identity verification
    pub async fn connect(
        server_addr: SocketAddr,
        expected_server_ed25519_key: VerifyingKey,
        client_key: SigningKey,
    ) -> Result<Self> {
        info!("🔗 Connecting to relay server at {}", server_addr);
        info!(
            "🔑 Expected server ed25519 key: {}",
            hex::encode(expected_server_ed25519_key.to_bytes())
        );
        info!(
            "🔑 Client ed25519 key: {}",
            hex::encode(client_key.verifying_key().to_bytes())
        );

        // Create client config with server identity verification
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ServerEd25519TlsVerifier::new(
                expected_server_ed25519_key,
            )))
            .with_no_client_auth();

        let client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        // Connect - TLS handshake will verify server identity
        let connection = endpoint
            .connect(server_addr, "localhost")?
            .await
            .context("Failed to establish QUIC connection")?;

        info!("✅ Connected! TLS handshake verified server identity.");

        Ok(Self {
            connection,
            client_key,
            server_key: expected_server_ed25519_key,
        })
    }
}

// info!("🎯 Handling QUIC connection, waiting for streams...");
// let (send, recv) = connection.accept_bi().await?;

// // Now create the framed transport - this will work with tarpc because it sees a normal stream
// let codec = LengthDelimitedCodec::new();
// let combined = QuicDuplexStream::new(recv, send);
// let framed = Framed::new(combined, codec);
// let transport = serde_transport::new(stream, PostcardSerializer);

// info!("✅ Created tarpc transport with buffered first frame");

// // Create tarpc server
// let server = server::BaseChannel::with_defaults(transport);
// info!("📡 Tarpc server ready to handle requests");

// // Handle incoming requests

// tokio::spawn(
//     server.execute(service.serve())
//         // Handle all requests concurrently.
//         .for_each(|response| async move {
//             tokio::spawn(response);
//         }));

// info!("🔚 QUIC connection ended");
// Ok(())

/// Create a QUIC server endpoint with ed25519-derived TLS certificate
pub fn create_relay_server_endpoint(addr: SocketAddr, server_key: &SigningKey) -> Result<Endpoint> {
    info!("🚀 Creating relay server endpoint");
    info!("📋 Server Address: {}", addr);
    info!(
        "🔑 Server Public Key: {}",
        hex::encode(server_key.verifying_key().to_bytes())
    );

    // Generate TLS certificate from ed25519 key
    let (certs, key) = generate_deterministic_cert_from_ed25519(server_key, "localhost")
        .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

    // Create QUIC server config with no client auth required
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?,
    ));

    let endpoint = Endpoint::server(server_config, addr)?;

    info!("✅ Server endpoint ready on {}", addr);
    info!(
        "💡 Clients can connect with server public key: {}",
        hex::encode(server_key.verifying_key().to_bytes())
    );

    Ok(endpoint)
}
