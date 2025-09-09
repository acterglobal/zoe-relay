use anyhow::Result;
use futures::StreamExt;
use std::{collections::BTreeMap, sync::Arc};
use tarpc::server::{BaseChannel, Channel};
use tokio::sync::RwLock;
use tokio_stream::{Stream, StreamExt as TokioStreamExt};
use tracing::{error, info, trace, warn};
use whatsmeow::{ConnectionStatus, WhatsAppBot};
use zoe_app_primitives::extra::rpc::whatsappbot::{
    CURRENT_WA_BOT_PROTOCOL_VERSION, CURRENT_WA_BOT_PROTOCOL_VERSION_REQ,
    WhatsAppBot as WhatsAppBotService, WhatsAppBotSessionInit, WhatsAppBotSessionInitFailure,
    WhatsAppBotSessionInitResponse,
};
use zoe_client::{Client, pqxdh::PqxdhProtocolHandler};
use zoe_wire_protocol::{
    Tag, VerifyingKey,
    version::{Version, VersionReq},
};

mod rpc_service;
mod session;

pub use rpc_service::WhatsAppBotServiceImpl;
pub use session::WhatsAppBotSession;

use crate::{bridge_event::BridgeEvent, connectable::WhatsAppBotExt};

/// Full bridge bot with both WhatsApp and PQXDH capabilities
pub struct ZoeBridgeBot {
    bot: Arc<WhatsAppBot>,
    zoe_client: Arc<Client>,
    pqxdh_handler: Arc<PqxdhProtocolHandler<zoe_client::services::MessagePersistenceManager>>,
    public_key: VerifyingKey,
    /// Active WhatsApp bot sessions (session_id -> session info)
    active_sessions: Arc<RwLock<BTreeMap<[u8; 32], WhatsAppBotSession>>>,
}

impl std::ops::Deref for ZoeBridgeBot {
    type Target = WhatsAppBot;

    fn deref(&self) -> &Self::Target {
        &self.bot
    }
}

impl ZoeBridgeBot {
    pub fn new(
        bot: WhatsAppBot,
        zoe_client: Arc<Client>,
        pqxdh_handler: Arc<PqxdhProtocolHandler<zoe_client::services::MessagePersistenceManager>>,
        public_key: VerifyingKey,
    ) -> Self {
        Self {
            bot: Arc::new(bot),
            zoe_client,
            pqxdh_handler,
            public_key,
            active_sessions: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    /// Get the bot's public key for PQXDH connections
    pub fn public_key(&self) -> VerifyingKey {
        self.public_key.clone()
    }

    /// Publish PQXDH inbox
    pub async fn publish_pqxdh_inbox(&self, force_overwrite: bool) -> Result<Tag> {
        info!("📢 Publishing PQXDH inbox for WhatsApp bot");

        let inbox_tag = self
            .pqxdh_handler
            .publish_service(force_overwrite)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to publish PQXDH inbox: {}", e))?;

        info!("✅ PQXDH inbox published with tag: {:?}", inbox_tag);
        Ok(inbox_tag)
    }

    /// Create a PQXDH connection stream
    pub async fn pqxdh_connection_stream<T>(&self) -> Result<impl Stream<Item = ([u8; 32], T)>>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    {
        info!("👂 Starting PQXDH connection listener");

        let stream = self
            .pqxdh_handler
            .inbox_stream::<T>()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create PQXDH connection stream: {e}"))?;
        info!("✅ PQXDH connection listener started");
        Ok(stream)
    }

    /// Send a message via PQXDH
    pub async fn send_pqxdh_message<T>(&self, session_id: &[u8; 32], message: &T) -> Result<()>
    where
        T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone,
    {
        self.pqxdh_handler
            .send_message(session_id, message)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send PQXDH message: {}", e))?;

        Ok(())
    }

    /// Handle a PQXDH connection by performing session initialization and version negotiation
    pub async fn setup_pqxdh_connection(
        &self,
        session_id: [u8; 32],
        raw_data: Vec<u8>,
    ) -> Result<()> {
        info!("🔐 New PQXDH connection: {:?}", hex::encode(session_id));
        info!("📦 Received data: {} bytes", raw_data.len());

        // Try to deserialize the session initialization message directly
        let session_init: WhatsAppBotSessionInit = match postcard::from_bytes(&raw_data) {
            Ok(init) => {
                info!("✅ Successfully parsed WhatsAppBotSessionInit");
                init
            }
            Err(e) => {
                error!("❌ Failed to parse session init message: {}", e);
                let response = WhatsAppBotSessionInitResponse::Failure(
                    WhatsAppBotSessionInitFailure::BotError(
                        "Invalid session initialization message format".to_string(),
                    ),
                );

                // Send response directly
                let _ = self.send_pqxdh_message(&session_id, &response).await;
                // TODO: drop the session and burn the code.

                return Err(anyhow::anyhow!("Invalid session initialization message"));
            }
        };

        trace!(
            "📋 Client supports {} versions",
            session_init.versions.len()
        );

        // Parse the bot's protocol version requirement
        let version_req = match VersionReq::parse(CURRENT_WA_BOT_PROTOCOL_VERSION_REQ) {
            Ok(req) => req,
            Err(e) => {
                error!("❌ Failed to parse bot version requirement: {}", e);
                let response = WhatsAppBotSessionInitResponse::Failure(
                    WhatsAppBotSessionInitFailure::BotError("Bot configuration error".to_string()),
                );

                // Send response directly
                let _ = self.send_pqxdh_message(&session_id, &response).await;

                return Err(anyhow::anyhow!("Failed to parse version requirement"));
            }
        };

        // Find the first compatible version
        let compatible_version = session_init
            .versions
            .iter()
            .find(|version| version_req.matches(version))
            .cloned();

        let response = match compatible_version {
            Some(version) => {
                info!("✅ Found compatible version: {}", version);

                // Start the tarpc service for this session
                if let Err(e) = self.start_tarpc_service(session_id, version.clone()).await {
                    error!("❌ Failed to start tarpc service: {}", e);
                    WhatsAppBotSessionInitResponse::Failure(
                        WhatsAppBotSessionInitFailure::BotError(
                            "Failed to start service".to_string(),
                        ),
                    )
                } else {
                    WhatsAppBotSessionInitResponse::Success(version)
                }
            }
            None => {
                warn!("⚠️ No compatible version found");
                info!("Bot requires: {}", CURRENT_WA_BOT_PROTOCOL_VERSION_REQ);
                info!("Client offered: {:?}", session_init.versions);

                let bot_version = match Version::parse(CURRENT_WA_BOT_PROTOCOL_VERSION) {
                    Ok(v) => vec![v],
                    Err(_) => vec![],
                };

                WhatsAppBotSessionInitResponse::Failure(
                    WhatsAppBotSessionInitFailure::NoCompatibleVersion(bot_version),
                )
            }
        };

        // Send the response directly
        self.send_pqxdh_message(&session_id, &response).await?;

        match response {
            WhatsAppBotSessionInitResponse::Success(_) => {
                info!("✅ Session initialization successful");
                Ok(())
            }
            WhatsAppBotSessionInitResponse::Failure(_) => {
                // Clean up any partially initialized session
                warn!("❌ Session initialization failed, performing cleanup");
                let _ = self.cleanup_session(&session_id).await;
                Err(anyhow::anyhow!("Session initialization failed"))
            }
        }
    }

    /// Start a tarpc service for the given session
    async fn start_tarpc_service(&self, session_id: [u8; 32], version: Version) -> Result<()> {
        info!(
            "🚀 Starting tarpc service for session: {}",
            hex::encode(session_id)
        );
        info!("📌 Using protocol version: {}", version);

        // Create a WhatsApp bot service implementation
        let bot_service = WhatsAppBotServiceImpl::new(
            Arc::clone(&self.bot),
            Arc::clone(&self.zoe_client),
            Arc::clone(&self.pqxdh_handler),
            session_id,
        );

        let transport = self.pqxdh_handler.tarpc_transport(session_id).await?;

        // Spawn the tarpc server
        let server_task = tokio::spawn(async move {
            let channel = BaseChannel::with_defaults(transport);
            channel
                .execute(bot_service.serve())
                .for_each(|response| async move {
                    tokio::spawn(response);
                })
                .await;
        });

        // Store the session information for cleanup
        let session = WhatsAppBotSession::new(session_id, version.clone(), server_task);
        {
            let mut sessions = self.active_sessions.write().await;
            sessions.insert(session_id, session);
        }

        info!(
            "✅ Tarpc service started successfully for session: {}",
            hex::encode(session_id)
        );
        info!(
            "📊 Total active sessions: {}",
            self.active_sessions.read().await.len()
        );
        Ok(())
    }

    /// Clean up a specific session
    pub async fn cleanup_session(&self, session_id: &[u8; 32]) -> Result<()> {
        info!("🧹 Cleaning up session: {}", hex::encode(session_id));

        let session = {
            let mut sessions = self.active_sessions.write().await;
            sessions.remove(session_id)
        };

        if let Some(session) = session {
            session.cleanup().await;
            info!(
                "📊 Remaining active sessions: {}",
                self.active_sessions.read().await.len()
            );
            Ok(())
        } else {
            warn!(
                "⚠️ Attempted to clean up non-existent session: {}",
                hex::encode(session_id)
            );
            Err(anyhow::anyhow!("Session not found"))
        }
    }

    /// Clean up all active sessions
    pub async fn cleanup_all_sessions(&self) -> Result<()> {
        info!("🧹 Cleaning up all active sessions");

        let sessions = {
            let mut sessions_lock = self.active_sessions.write().await;

            std::mem::take(&mut *sessions_lock)
        };

        info!("📊 Cleaning up {} sessions", sessions.len());

        // Clean up all sessions in parallel
        let cleanup_tasks: Vec<_> = sessions
            .into_iter()
            .map(|(session_id, session)| {
                tokio::spawn(async move {
                    session.cleanup().await;
                    session_id
                })
            })
            .collect();

        // Wait for all cleanup tasks to complete
        for task in cleanup_tasks {
            let session_id = task
                .await
                .map_err(|e| anyhow::anyhow!("Task join error: {}", e))?;
            info!("✅ Cleaned up session: {}", hex::encode(session_id));
        }

        info!("✅ All sessions cleaned up");
        Ok(())
    }

    /// Get count of active sessions
    pub async fn active_session_count(&self) -> usize {
        self.active_sessions.read().await.len()
    }

    /// Check if a specific session is active
    pub async fn is_session_active(&self, session_id: &[u8; 32]) -> bool {
        self.active_sessions.read().await.contains_key(session_id)
    }

    /// Handle PQXDH connection loss by cleaning up the associated session
    pub async fn handle_pqxdh_connection_loss(&self, session_id: &[u8; 32]) -> Result<()> {
        warn!(
            "🔌 PQXDH connection lost for session: {}",
            hex::encode(session_id)
        );
        self.cleanup_session(session_id).await
    }

    /// Run the full bridge mode - handles both WhatsApp messages and PQXDH connections internally
    /// Returns a stream that the main loop can poll for events
    pub async fn run_bridge(&self) -> Result<impl Stream<Item = BridgeEvent>> {
        info!("🌉 Starting Bridge Mode - WhatsApp ↔ PQXDH");

        // Publish PQXDH inbox (without force overwrite)
        info!("📢 Publishing PQXDH inbox...");
        let inbox_tag = self.publish_pqxdh_inbox(false).await?;
        info!("✅ PQXDH inbox published with tag: {:?}", inbox_tag);

        // Display bot's public key for clients to connect
        let public_key = self.public_key();
        match public_key.to_bytes() {
            Ok(bytes) => {
                info!("🔑 Bot Public Key: {}", hex::encode(bytes));
                info!("💡 Clients can use this key to establish PQXDH connections");
            }
            Err(e) => {
                error!("❌ Failed to serialize public key: {}", e);
            }
        }

        // Start WhatsApp message stream
        let message_stream = self.message_stream()?;
        info!("✅ WhatsApp message stream started");

        // Start PQXDH connection stream with raw bytes
        let pqxdh_stream = Box::pin(self.pqxdh_connection_stream::<Vec<u8>>().await?);
        info!("✅ PQXDH connection stream started");

        // Convert WhatsApp messages to events - filtering will be done in main.rs
        let whatsapp_events = TokioStreamExt::map(message_stream, BridgeEvent::WhatsAppMessage);

        let pqxdh_events = TokioStreamExt::map(pqxdh_stream, |(session_id, raw_data)| {
            BridgeEvent::PqxdhConnection {
                session_id,
                raw_data,
            }
        });

        // Merge the streams
        let combined_stream = TokioStreamExt::merge(whatsapp_events, pqxdh_events);

        info!("🔄 Bridge active - ready to handle events");
        Ok(combined_stream)
    }
}

#[async_trait::async_trait]
impl WhatsAppBotExt for ZoeBridgeBot {
    async fn connect(&self) -> Result<()> {
        self.bot.connect().await
    }

    async fn is_connected(&self) -> Result<bool> {
        self.bot.is_connected().await
    }

    async fn status(&self) -> Result<ConnectionStatus> {
        self.bot.get_connection_status().await
    }

    async fn qr_code(&self) -> Result<String> {
        self.bot.get_qr_code().await
    }

    async fn show_qr_code_if_needed(&self) -> Result<bool> {
        self.bot.show_qr_code_if_needed().await
    }

    async fn display_qr_code(&self) -> Result<()> {
        self.bot.display_qr_code().await
    }

    async fn wait_for_connection(&self, max_attempts: u32) -> Result<bool> {
        self.bot.wait_for_connection(max_attempts).await
    }

    async fn run_listen(&self) -> Result<impl Stream<Item = BridgeEvent>> {
        self.run_bridge().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{bot::WhatsAppBotSession, connectable::WhatsAppBotExt};

    use super::*;
    use whatsmeow::WhatsAppBot;

    #[tokio::test]
    async fn test_bot_creation() {
        let bot = WhatsAppBot::new("test.db");
        assert!(bot.is_ok());
    }

    #[tokio::test]
    async fn test_connection_status_check() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let status = bot.get_connection_status().await;
        assert!(status.is_ok());
    }

    #[tokio::test]
    async fn test_is_connected() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let connected = bot.is_connected().await;
        assert!(connected.is_ok());
        // In test mode with mocks, should be disconnected by default
        assert!(!connected.unwrap());
    }

    #[tokio::test]
    async fn test_qr_code_display() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let result = bot.show_qr_code_if_needed().await;
        assert!(result.is_ok());
        // Should return true since mock bot is disconnected by default
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_send_message() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        let result = bot
            .send_message("test@s.whatsapp.net", "Hello, World!")
            .await;
        assert!(result.is_ok());
        // Mock should return a message ID
        assert_eq!(result.unwrap(), "msg_mock_123");
    }

    #[tokio::test]
    async fn test_inner_access() {
        let bot = WhatsAppBot::new("test.db").unwrap();
        // WhatsAppBot is now used directly, no inner() method needed
        // Should be able to access bot methods directly
        let status = bot.get_connection_status().await;
        assert!(status.is_ok());
    }

    #[tokio::test]
    async fn test_whatsapp_only_functionality() {
        let bot = WhatsAppBot::new("test.db").unwrap();

        // ZoeWhatsAppBot should only have WhatsApp functionality
        // Test that basic WhatsApp methods are available
        assert!(bot.get_connection_status().await.is_ok());

        // Test that we can create message streams
        assert!(bot.message_stream().is_ok());
    }

    #[tokio::test]
    async fn test_session_init_serialization() {
        use zoe_wire_protocol::version::Version;

        let versions = vec![
            Version::parse("0.1.0").unwrap(),
            Version::parse("0.2.0").unwrap(),
        ];

        let session_init = WhatsAppBotSessionInit { versions };

        // Test postcard serialization
        let serialized = postcard::to_stdvec(&session_init).unwrap();
        let deserialized: WhatsAppBotSessionInit = postcard::from_bytes(&serialized).unwrap();

        assert_eq!(deserialized.versions.len(), 2);
        assert_eq!(deserialized.versions[0].to_string(), "0.1.0");
        assert_eq!(deserialized.versions[1].to_string(), "0.2.0");
    }

    #[tokio::test]
    async fn test_session_init_response_serialization() {
        use zoe_wire_protocol::version::Version;

        let version = Version::parse("0.1.0").unwrap();
        let response = WhatsAppBotSessionInitResponse::Success(version.clone());

        // Test postcard serialization
        let serialized = postcard::to_stdvec(&response).unwrap();
        let deserialized: WhatsAppBotSessionInitResponse =
            postcard::from_bytes(&serialized).unwrap();

        match deserialized {
            WhatsAppBotSessionInitResponse::Success(v) => {
                assert_eq!(v.to_string(), "0.1.0");
            }
            _ => panic!("Expected Success response"),
        }
    }

    #[tokio::test]
    async fn test_version_negotiation_logic() {
        use zoe_wire_protocol::version::{Version, VersionReq};

        let version_req = VersionReq::parse(CURRENT_WA_BOT_PROTOCOL_VERSION_REQ).unwrap();

        // Test compatible version
        let compatible_version = Version::parse("0.1.0").unwrap();
        assert!(version_req.matches(&compatible_version));

        // Test incompatible version (if it exists)
        // Note: This test depends on the actual version requirements
        let old_version = Version::parse("0.0.1").unwrap();
        // This assertion depends on the actual requirement string
        // For ">=0.1.0-dev.0", version 0.0.1 should not match
        assert!(!version_req.matches(&old_version));
    }

    #[tokio::test]
    async fn test_whatsapp_bot_session_lifecycle() {
        use zoe_wire_protocol::version::Version;

        let session_id = [1u8; 32];

        // Create dummy tasks for testing
        let dummy_server_task = tokio::spawn(async {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        });

        // Create a test session
        let version = Version::parse("0.1.0-dev.0").unwrap();
        let session = WhatsAppBotSession::new(session_id, version, dummy_server_task);

        // Verify session properties
        assert_eq!(session.session_id, session_id);

        // Test cleanup - this will abort the tasks and wait for them
        session.cleanup().await;

        // Tasks should be finished now
        // No assertions needed - if cleanup() completes without hanging, the test passes
    }

    #[tokio::test]
    async fn test_session_data_structures() {
        use std::collections::BTreeMap;
        use zoe_wire_protocol::version::Version;

        let mut sessions = BTreeMap::new();

        // Create multiple test sessions
        for i in 0..3 {
            let session_id = [i; 32];
            let dummy_server_task = tokio::spawn(async {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            });

            let version = Version::parse("0.1.0-dev.0").unwrap();
            let session = WhatsAppBotSession::new(session_id, version, dummy_server_task);

            sessions.insert(session_id, session);
        }

        // Should have 3 sessions
        assert_eq!(sessions.len(), 3);

        // Test that we can check for specific sessions
        assert!(sessions.contains_key(&[0; 32]));
        assert!(sessions.contains_key(&[1; 32]));
        assert!(sessions.contains_key(&[2; 32]));
        assert!(!sessions.contains_key(&[99; 32]));

        // Clean up all sessions
        for (_session_id, session) in sessions {
            session.cleanup().await;
        }
    }

    #[tokio::test]
    async fn test_session_init_and_response_serialization() {
        use zoe_app_primitives::extra::rpc::whatsappbot::{
            WhatsAppBotSessionInit, WhatsAppBotSessionInitFailure, WhatsAppBotSessionInitResponse,
        };
        use zoe_wire_protocol::version::Version;

        // Test session init serialization
        let versions = vec![Version::parse("0.1.0-dev.0").unwrap()];
        let session_init = WhatsAppBotSessionInit { versions };

        let serialized =
            postcard::to_stdvec(&session_init).expect("Failed to serialize session init");
        let deserialized: WhatsAppBotSessionInit =
            postcard::from_bytes(&serialized).expect("Failed to deserialize session init");

        assert_eq!(deserialized.versions.len(), 1);

        // Test success response
        let success_response =
            WhatsAppBotSessionInitResponse::Success(Version::parse("0.1.0-dev.0").unwrap());
        let serialized =
            postcard::to_stdvec(&success_response).expect("Failed to serialize success response");
        let _deserialized: WhatsAppBotSessionInitResponse =
            postcard::from_bytes(&serialized).expect("Failed to deserialize success response");

        // Test failure response
        let failure_response = WhatsAppBotSessionInitResponse::Failure(
            WhatsAppBotSessionInitFailure::BotError("Test error".to_string()),
        );
        let serialized =
            postcard::to_stdvec(&failure_response).expect("Failed to serialize failure response");
        let _deserialized: WhatsAppBotSessionInitResponse =
            postcard::from_bytes(&serialized).expect("Failed to deserialize failure response");
    }
}
