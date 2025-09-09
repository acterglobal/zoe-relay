use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use super::PqxdhSession;
use zoe_wire_protocol::{KeyId, PqxdhInboxProtocol, Tag, inbox::pqxdh::PqxdhInbox};

/// Serializable state for a PQXDH protocol handler
///
/// This structure contains all the persistent state needed to restore a
/// `PqxdhProtocolHandler` across application restarts. It excludes runtime
/// dependencies like the messages manager and client keypair, focusing only
/// on the cryptographic and session state that needs to be preserved.
///
/// ## Persistence Strategy
/// This state can be serialized with `postcard` and stored in a database or file
/// system. When the application restarts, this state can be loaded and used to
/// reconstruct a fully functional protocol handler.
///
/// ## State Components
/// - **Protocol**: The specific PQXDH protocol variant being used
/// - **Sessions**: Active sessions keyed by target user ID
/// - **Inbox Tag**: The published inbox tag (for service providers)
/// - **Private Keys**: Cryptographic keys for responding to initial messages
#[derive(Serialize, Deserialize, Clone)]
pub struct PqxdhProtocolState {
    /// The PQXDH protocol variant being used
    pub(super) protocol: PqxdhInboxProtocol,
    /// Active sessions keyed by target user ID
    pub(super) sessions: BTreeMap<KeyId, PqxdhSession>,
    pub(super) inbox_tag: Option<Tag>,
    pub(super) inbox: Option<PqxdhInbox>,
    /// Private keys for responding to initial messages (if we're a service provider)
    pub(super) private_keys: Option<zoe_wire_protocol::inbox::pqxdh::PqxdhPrivateKeys>,
}

impl PqxdhProtocolState {
    /// Creates a new empty protocol state
    ///
    /// Initializes a new protocol state with the specified protocol variant.
    /// All other fields are set to their default empty values.
    ///
    /// # Arguments
    /// * `protocol` - The PQXDH protocol variant to use
    pub fn new(protocol: PqxdhInboxProtocol) -> Self {
        Self {
            protocol,
            sessions: BTreeMap::new(),
            inbox_tag: None,
            private_keys: None,
            inbox: None,
        }
    }
}
