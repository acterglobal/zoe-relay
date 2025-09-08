use whatsmeow::MessageEvent;

/// Events that can occur in the bridge
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    /// A WhatsApp message was received
    WhatsAppMessage(MessageEvent),
    /// A PQXDH connection was established with raw message data
    PqxdhConnection {
        session_id: [u8; 32],
        raw_data: Vec<u8>,
    },
    /// An error occurred
    Error(String),
}
