/// Information about an active WhatsApp bot session
/// WhatsApp bot functionality
use tokio::task::JoinHandle;
use tracing::info;
use zoe_wire_protocol::version::Version;

#[derive(Debug)]
pub struct WhatsAppBotSession {
    pub(crate) session_id: [u8; 32],
    #[allow(unused)]
    pub(crate) protocol_version: Version,
    pub(crate) server_task: JoinHandle<()>,
}

impl WhatsAppBotSession {
    /// Create a new session
    pub(crate) fn new(
        session_id: [u8; 32],
        protocol_version: Version,
        server_task: JoinHandle<()>,
    ) -> Self {
        Self {
            session_id,
            protocol_version,
            server_task,
        }
    }

    /// Clean up the session by aborting all tasks
    pub(crate) async fn cleanup(self) {
        info!("🧹 Cleaning up session: {}", hex::encode(self.session_id));

        // Abort both tasks
        self.server_task.abort();

        info!(
            "✅ Session cleanup completed: {}",
            hex::encode(self.session_id)
        );
    }
}
