use serde::{Deserialize, Serialize};
use zoe_wire_protocol::version::Version;

pub static CURRENT_WA_BOT_PROTOCOL_VERSION: &str = "0.1.0-dev.0";
pub static CURRENT_WA_BOT_PROTOCOL_VERSION_REQ: &str = ">=0.1.0-dev.0";

/// WhatsApp bot service for remote procedure calls
#[tarpc::service]
pub trait WhatsAppBot {
    /// Check if the whatsapp bot is responding
    async fn ping() -> String;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhatsAppBotError {
    /// You need to upgrade your client to at least the version provided
    PleaseUpgrade(Version),
    /// There was some error within the communication to the bot,
    /// please create a new session
    ReEstablishSession,
    /// I can't let you do that, dave.
    RequiresAuthentication,
    /// The bot error in general, check the string for more details
    BotError(String),
}

/// Message expected when trying to connect to a whatsapp bot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhatsAppBotSessionInit {
    /// the protocol versions the client supports
    pub versions: Vec<Version>,
}

/// Why the session init failed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhatsAppBotSessionInitFailure {
    /// The bot error in general, check the string for more details
    BotError(String),
    /// The client has no compatible version with the bot, the vector is the
    /// list of supported versions by the bot
    NoCompatibleVersion(Vec<Version>),
}

/// What is being responded by the whatsapp bot when trying to
/// establish a session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WhatsAppBotSessionInitResponse {
    /// The version the bot agreed to use from the list of supported versions
    /// sent by the client
    Success(Version),
    Failure(WhatsAppBotSessionInitFailure),
}
