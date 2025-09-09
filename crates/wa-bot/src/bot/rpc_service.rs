/// WhatsApp bot functionality
use std::sync::Arc;
use tracing::info;
use whatsmeow::WhatsAppBot;
use zoe_app_primitives::extra::rpc::whatsappbot::{
    CURRENT_WA_BOT_PROTOCOL_VERSION, WhatsAppBot as WhatsAppBotService,
};
use zoe_client::{Client, pqxdh::PqxdhProtocolHandler};

/// Implementation of the WhatsAppBot tarpc service
#[derive(Clone)]
#[allow(unused)]
pub struct WhatsAppBotServiceImpl {
    whatsapp_bot: Arc<WhatsAppBot>,
    zoe_client: Arc<Client>,
    pqxdh_handler: Arc<PqxdhProtocolHandler<zoe_client::services::MessagePersistenceManager>>,
    session_id: [u8; 32],
}

impl WhatsAppBotServiceImpl {
    pub(crate) fn new(
        whatsapp_bot: Arc<WhatsAppBot>,
        zoe_client: Arc<Client>,
        pqxdh_handler: Arc<PqxdhProtocolHandler<zoe_client::services::MessagePersistenceManager>>,
        session_id: [u8; 32],
    ) -> Self {
        Self {
            whatsapp_bot,
            zoe_client,
            pqxdh_handler,
            session_id,
        }
    }
}

impl WhatsAppBotService for WhatsAppBotServiceImpl {
    async fn ping(self, _context: tarpc::context::Context) -> String {
        info!(
            "🏓 Ping received from session: {}",
            hex::encode(self.session_id)
        );
        format!(
            "Pong from WhatsApp Bot! Session: {}, Protocol: {}",
            hex::encode(&self.session_id[..8]), // Show first 8 bytes
            CURRENT_WA_BOT_PROTOCOL_VERSION
        )
    }
}
