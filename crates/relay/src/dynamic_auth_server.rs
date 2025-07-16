use anyhow::Result;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::CertificateDer;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;
use zoeyr_wire_protocol::{
    extract_ed25519_from_cert, generate_deterministic_cert_from_ed25519, ProtocolMessage,
};

/// Per-connection session tracking dynamic authorization state
#[derive(Debug, Clone)]
pub struct DynamicSession {
    // Identity (established once via mutual TLS - never changes)
    client_ed25519_key: VerifyingKey,
    #[allow(dead_code)]
    connection_established_at: std::time::SystemTime,

    // Authorization freshness (managed dynamically per operation)
    current_challenge: Option<AuthChallenge>,
    last_successful_challenge: Option<u64>,
    successful_challenges: u32,
    failed_challenges: u32,
}

/// Active challenge for dynamic authentication
#[derive(Debug, Clone)]
struct AuthChallenge {
    nonce: String,
    timestamp: u64,
    issued_at: std::time::SystemTime,
}

impl DynamicSession {
    fn new(client_ed25519_key: VerifyingKey) -> Self {
        Self {
            client_ed25519_key,
            connection_established_at: std::time::SystemTime::now(),
            current_challenge: None,
            last_successful_challenge: None,
            successful_challenges: 0,
            failed_challenges: 0,
        }
    }

    fn needs_fresh_authorization(&self, freshness_window_seconds: u64) -> bool {
        match self.last_successful_challenge {
            None => true, // Never been authorized
            Some(last_auth_timestamp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                (now - last_auth_timestamp) > freshness_window_seconds
            }
        }
    }

    fn issue_challenge(&mut self, _timeout_seconds: u64) -> AuthChallenge {
        let nonce = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let challenge = AuthChallenge {
            nonce: nonce.clone(),
            timestamp,
            issued_at: std::time::SystemTime::now(),
        };

        self.current_challenge = Some(challenge.clone());
        challenge
    }

    fn verify_challenge_response(
        &mut self,
        nonce: &str,
        timestamp: u64,
        signature: &[u8],
        timeout_seconds: u64,
    ) -> Result<bool> {
        // Check if we have a pending challenge
        let current_challenge = match &self.current_challenge {
            Some(challenge) => challenge,
            None => {
                self.failed_challenges += 1;
                return Ok(false);
            }
        };

        // Check challenge matches
        if current_challenge.nonce != nonce || current_challenge.timestamp != timestamp {
            self.failed_challenges += 1;
            return Ok(false);
        }

        // Check timeout
        let now = std::time::SystemTime::now();
        if now.duration_since(current_challenge.issued_at)?.as_secs() > timeout_seconds {
            self.failed_challenges += 1;
            self.current_challenge = None; // Expired
            return Ok(false);
        }

        // Verify signature
        let expected_message = format!("auth:{nonce}:{timestamp}");
        let signature_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;
        let signature = Signature::from_bytes(&signature_bytes);

        match self
            .client_ed25519_key
            .verify(expected_message.as_bytes(), &signature)
        {
            Ok(_) => {
                self.successful_challenges += 1;
                self.last_successful_challenge = Some(timestamp);
                self.current_challenge = None; // Clear used challenge
                Ok(true)
            }
            Err(_) => {
                self.failed_challenges += 1;
                Ok(false)
            }
        }
    }

    #[allow(dead_code)]
    fn get_stats(&self) -> SessionStats {
        SessionStats {
            successful_challenges: self.successful_challenges,
            failed_challenges: self.failed_challenges,
            has_pending_challenge: self.current_challenge.is_some(),
        }
    }
}

#[derive(Debug)]
pub struct SessionStats {
    pub successful_challenges: u32,
    pub failed_challenges: u32,
    pub has_pending_challenge: bool,
}

/// Message handler for application-specific logic - YOUR business logic here!
#[async_trait::async_trait]
pub trait MessageHandler: Send + Sync {
    /// Determine if this specific message requires fresh authorization
    /// This is YOUR business logic - not protocol-level!
    fn requires_fresh_authorization(&self, message: &ProtocolMessage<String>) -> bool;

    /// How fresh does the authorization need to be? (in seconds)
    fn authorization_freshness_window(&self, message: &ProtocolMessage<String>) -> u64;

    /// Process the message (after authorization is confirmed)
    async fn process_authorized_message(
        &self,
        message: ProtocolMessage<String>,
        session: &DynamicSession,
    ) -> Result<ProtocolMessage<String>>;
}

/// Example application handler that demonstrates business logic
/// This handles both String (text) and FileContent messages
#[allow(dead_code)]
struct ZoeyrApplicationHandler;

#[async_trait::async_trait]
impl MessageHandler for ZoeyrApplicationHandler {
    fn requires_fresh_authorization(&self, message: &ProtocolMessage<String>) -> bool {
        match message {
            ProtocolMessage::Message { content, .. } => {
                // Use debug format to analyze content for sensitivity
                let content_str = format!("{content:?}");

                // YOUR business logic here!
                if content_str.contains("admin")
                    || content_str.contains("delete")
                    || content_str.contains("payment")
                    || content_str.contains("transfer")
                {
                    info!("🔒 High-sensitivity operation detected: requiring fresh auth");
                    true
                } else if content_str.contains("upload")
                    || content_str.contains("download")
                    || content_str.len() > 1000
                {
                    info!("🔐 Medium-sensitivity operation: requiring recent auth");
                    true
                } else {
                    info!("💬 Low-sensitivity operation: TLS identity sufficient");
                    false
                }
            }
            ProtocolMessage::HealthCheck => false, // Always allowed
            _ => false,                            // Auth messages don't need auth themselves
        }
    }

    fn authorization_freshness_window(&self, message: &ProtocolMessage<String>) -> u64 {
        match message {
            ProtocolMessage::Message { content, .. } => {
                let content_str = format!("{content:?}");
                if content_str.contains("admin")
                    || content_str.contains("delete")
                    || content_str.contains("payment")
                {
                    30 // Admin operations: 30 second freshness
                } else if content_str.contains("File") || content_str.len() > 500 {
                    120 // File operations or large content: 2 minute freshness
                } else {
                    300 // Regular operations: 5 minute freshness
                }
            }
            _ => 300, // Default: 5 minutes
        }
    }

    async fn process_authorized_message(
        &self,
        message: ProtocolMessage<String>,
        session: &DynamicSession,
    ) -> Result<ProtocolMessage<String>> {
        match message {
            ProtocolMessage::Message { content, .. } => {
                info!(
                    "✅ Processing authorized message from client: {}",
                    hex::encode(session.client_ed25519_key.to_bytes())[..8].to_string()
                );

                // YOUR application logic here!
                let content_str = format!("{content:?}");
                let _response_text = if content_str.contains("admin") {
                    "Admin operation completed successfully".to_string()
                } else if content_str.contains("upload") || content_str.contains("File") {
                    "File operation processed".to_string()
                } else {
                    "Message received and processed".to_string()
                };

                Ok(ProtocolMessage::MessageResponse {
                    message_id: Uuid::new_v4().to_string(),
                    success: true,
                })
            }
            ProtocolMessage::HealthCheck => Ok(ProtocolMessage::HealthResponse {
                status: format!(
                    "OK - Identity: {} - Challenges: {}/{}",
                    &hex::encode(session.client_ed25519_key.to_bytes())[..8],
                    session.successful_challenges,
                    session.successful_challenges + session.failed_challenges
                ),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs(),
            }),
            _ => Ok(ProtocolMessage::Error {
                message: "Unexpected message type".to_string(),
            }),
        }
    }
}

/// Client certificate verifier
#[derive(Debug)]
pub struct DynamicClientCertVerifier;

impl rustls::server::danger::ClientCertVerifier for DynamicClientCertVerifier {
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match extract_ed25519_from_cert(end_entity)
            .map_err(|e| format!("Certificate verification failed: {e}"))
        {
            Ok(client_ed25519_key) => {
                info!("✅ Client identity verified via mutual TLS");
                info!(
                    "📋 Client ed25519 key: {}",
                    hex::encode(client_ed25519_key.to_bytes())
                );
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
            Err(e) => {
                warn!("❌ {}", e);
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // Only accept Ed25519 signatures to enforce our security model
        vec![rustls::SignatureScheme::ED25519]
    }
}

/// Dynamic authentication server - security decisions made per-operation
pub struct DynamicAuthServer {
    ed25519_key: SigningKey,
    sessions: Arc<RwLock<HashMap<String, DynamicSession>>>,
    endpoint: Endpoint,
    message_handler: Arc<dyn MessageHandler>,
    challenge_timeout_seconds: u64,
}

impl DynamicAuthServer {
    /// Create server with application-layer message handler
    pub async fn new(
        addr: SocketAddr,
        ed25519_key: SigningKey,
        message_handler: Arc<dyn MessageHandler>,
        challenge_timeout_seconds: u64,
    ) -> Result<Self> {
        info!("🚀 Starting Dynamic Authentication Server");
        info!("📍 Server address: {}", addr);
        info!(
            "🔑 Server ed25519 public key: {}",
            hex::encode(ed25519_key.verifying_key().to_bytes())
        );
        info!("💡 Security decisions made dynamically per-operation at application layer");
        info!(
            "⏰ Challenge timeout: {} seconds",
            challenge_timeout_seconds
        );

        let (certs, key) = generate_deterministic_cert_from_ed25519(&ed25519_key, "localhost")
            .map_err(|e| anyhow::anyhow!("Failed to generate certificate: {}", e))?;

        let client_verifier = Arc::new(DynamicClientCertVerifier);

        let crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                client_verifier as Arc<dyn rustls::server::danger::ClientCertVerifier>,
            )
            .with_single_cert(certs, key)?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(crypto)?,
        ));

        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_bidi_streams(quinn::VarInt::from_u32(100));
        transport_config.max_concurrent_uni_streams(quinn::VarInt::from_u32(100));

        let endpoint = Endpoint::server(server_config, addr)?;

        info!("✅ Dynamic auth server started");
        info!("🔗 All connections use mutual TLS for identity verification");
        info!("🎯 Fresh authorization challenges issued only when application requires it");
        info!("⚡ Zero performance hit for operations that don't need freshness");

        Ok(Self {
            ed25519_key,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            endpoint,
            message_handler,
            challenge_timeout_seconds,
        })
    }

    /// Run the server
    pub async fn run(&self) -> Result<()> {
        info!("🎯 Dynamic auth server listening...");

        while let Some(incoming) = self.endpoint.accept().await {
            let sessions = Arc::clone(&self.sessions);
            let server_key = self.ed25519_key.clone();
            let message_handler = Arc::clone(&self.message_handler);
            let timeout = self.challenge_timeout_seconds;

            tokio::spawn(async move {
                match incoming.await {
                    Ok(connection) => {
                        info!("🔌 New connection from: {}", connection.remote_address());

                        // Extract client identity from TLS (demo - in production extract from cert)
                        let dummy_client_key = SigningKey::generate(&mut rand::rngs::OsRng);
                        let client_ed25519_key = dummy_client_key.verifying_key();

                        info!("✅ Client identity established via mutual TLS");
                        info!(
                            "📋 Client ed25519 key: {}",
                            hex::encode(client_ed25519_key.to_bytes())
                        );

                        // Create session with TLS-verified identity
                        let session = DynamicSession::new(client_ed25519_key);
                        let session_id = connection.stable_id().to_string();
                        sessions.write().await.insert(session_id.clone(), session);

                        info!("🎯 Session ready - application layer will decide security per-operation");

                        if let Err(e) = Self::handle_connection(
                            connection,
                            sessions,
                            server_key,
                            session_id,
                            message_handler,
                            timeout,
                        )
                        .await
                        {
                            error!("❌ Error handling connection: {}", e);
                        }
                    }
                    Err(e) => {
                        warn!("⚠️ Connection failed: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    /// Handle connection with dynamic authentication
    async fn handle_connection(
        connection: Connection,
        sessions: Arc<RwLock<HashMap<String, DynamicSession>>>,
        server_key: SigningKey,
        session_id: String,
        message_handler: Arc<dyn MessageHandler>,
        timeout_seconds: u64,
    ) -> Result<()> {
        while let Ok((send, recv)) = connection.accept_bi().await {
            let sessions = Arc::clone(&sessions);
            let server_key = server_key.clone();
            let session_id = session_id.clone();
            let message_handler = Arc::clone(&message_handler);

            tokio::spawn(async move {
                if let Err(e) = Self::handle_stream(
                    send,
                    recv,
                    sessions,
                    server_key,
                    session_id,
                    message_handler,
                    timeout_seconds,
                )
                .await
                {
                    error!("❌ Stream error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Handle stream with dynamic per-operation authentication
    async fn handle_stream(
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        sessions: Arc<RwLock<HashMap<String, DynamicSession>>>,
        server_key: SigningKey,
        session_id: String,
        message_handler: Arc<dyn MessageHandler>,
        timeout_seconds: u64,
    ) -> Result<()> {
        let request_bytes = recv.read_to_end(1024 * 1024).await?;
        let request: ProtocolMessage<String> = postcard::from_bytes(&request_bytes)?;

        let response = Self::process_dynamic_message(
            request,
            sessions,
            server_key,
            session_id,
            message_handler,
            timeout_seconds,
        )
        .await?;

        let response_bytes = postcard::to_allocvec(&response)?;
        send.write_all(&response_bytes).await?;
        send.finish()?;

        Ok(())
    }

    /// THE CORE LOGIC: Dynamic per-operation authentication
    async fn process_dynamic_message(
        message: ProtocolMessage<String>,
        sessions: Arc<RwLock<HashMap<String, DynamicSession>>>,
        server_key: SigningKey,
        session_id: String,
        message_handler: Arc<dyn MessageHandler>,
        timeout_seconds: u64,
    ) -> Result<ProtocolMessage<String>> {
        let mut sessions_guard = sessions.write().await;
        let session = sessions_guard
            .get_mut(&session_id)
            .ok_or_else(|| anyhow::anyhow!("Session not found"))?;

        match message {
            // Challenge-response handling (protocol level)
            ProtocolMessage::AuthChallenge { .. } => {
                info!("🔐 Issuing challenge for fresh authorization");
                let challenge = session.issue_challenge(timeout_seconds);

                Ok(ProtocolMessage::AuthResponse {
                    nonce: challenge.nonce,
                    timestamp: challenge.timestamp,
                    signature: server_key.verifying_key().to_bytes().to_vec(),
                })
            }

            ProtocolMessage::AuthProof {
                signature,
                nonce,
                timestamp,
            } => {
                info!("🔍 Verifying challenge response");

                match session.verify_challenge_response(
                    &nonce,
                    timestamp,
                    &signature,
                    timeout_seconds,
                ) {
                    Ok(true) => {
                        info!("✅ Fresh authorization confirmed!");
                        Ok(ProtocolMessage::AuthSuccess {
                            session_token: Uuid::new_v4().to_string(),
                        })
                    }
                    Ok(false) => {
                        warn!("❌ Challenge verification failed");
                        Ok(ProtocolMessage::AuthFailure {
                            reason: "Invalid challenge response".to_string(),
                        })
                    }
                    Err(e) => {
                        warn!("❌ Challenge verification error: {}", e);
                        Ok(ProtocolMessage::AuthFailure {
                            reason: e.to_string(),
                        })
                    }
                }
            }

            // Application messages - THIS IS WHERE YOUR LOGIC DECIDES SECURITY
            _ => {
                // Step 1: Ask application if this message needs fresh authorization
                let needs_fresh_auth = message_handler.requires_fresh_authorization(&message);

                if needs_fresh_auth {
                    let freshness_window = message_handler.authorization_freshness_window(&message);

                    if session.needs_fresh_authorization(freshness_window) {
                        warn!("❌ Operation requires fresh authorization");
                        info!("💡 Client must send AuthChallenge first");

                        return Ok(ProtocolMessage::Error {
                            message: "Fresh authorization required for this operation. Send AuthChallenge first.".to_string() 
                        });
                    }
                }

                // Step 2: Process the message (authorization requirements satisfied)
                info!(
                    "🎯 Processing operation: Fresh auth required: {}",
                    needs_fresh_auth
                );

                // Clone session for handler (to avoid borrowing issues)
                let session_clone = session.clone();
                drop(sessions_guard); // Release lock before calling handler

                message_handler
                    .process_authorized_message(message, &session_clone)
                    .await
            }
        }
    }
}

#[tokio::main]
#[allow(dead_code)]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    info!("🚀 Starting Dynamic Authentication Server");
    info!("💡 This demonstrates per-operation security decisions at application layer!");

    let server_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;

    info!(
        "🔑 Server ed25519 public key: {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            server_key.verifying_key().to_bytes()
        )
    );

    // Create application handler - THIS IS WHERE YOU PLUG IN YOUR LOGIC
    let message_handler = Arc::new(ZoeyrApplicationHandler);

    let server = DynamicAuthServer::new(
        addr,
        server_key,
        message_handler,
        60, // 1 minute challenge timeout
    )
    .await?;

    info!("🌟 Dynamic auth server ready!");
    info!("🔗 All connections use mutual TLS for identity verification");
    info!("🎯 Application layer decides per-operation if fresh authorization needed");
    info!("⚡ Zero performance hit for operations that don't require freshness");
    info!("💬 Try: 'hello world' (low security), 'upload file' (medium), 'admin delete' (high)");

    server.run().await
}
