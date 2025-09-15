use serde::{Deserialize, Serialize};

use super::GroupInfo;
use crate::group::events::key_info::GroupKeyInfo;
use crate::{metadata::Metadata, relay::RelayEndpoint};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(opaque, ignore_all))]
/// Complete information needed for a participant to join an encrypted group
///
/// This structure contains everything a new participant needs to join and
/// participate in an encrypted group, including the group metadata, encryption
/// keys, channel information, and relay endpoints for communication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupJoinInfo {
    /// Hash ID of the initial CreateGroup message
    ///
    /// This serves as the unique channel ID for the group and is derived
    /// from the Blake3 hash of the initial CreateGroup message.
    pub channel_id: String,

    /// Group information from the CreateGroup event
    ///
    /// Contains the group name, description, metadata, settings, and other
    /// information that was specified when the group was created.
    pub group_info: GroupInfo,

    /// Encryption key for the group
    ///
    /// The shared AES key used to encrypt and decrypt group messages.
    /// This is the raw key bytes that participants need to encrypt/decrypt
    /// group communications.
    pub encryption_key: [u8; 32],

    /// Key derivation information
    ///
    /// Contains metadata about how the encryption key was derived,
    /// including key ID and derivation parameters. This helps participants
    /// identify and manage the correct encryption keys.
    pub key_info: GroupKeyInfo,

    /// List of relay endpoints (ordered by priority)
    ///
    /// Contains the relay servers that participants can use to communicate
    /// within the group. The list is ordered by priority, with the first
    /// endpoint being the preferred relay. Participants should try relays
    /// in order until they find one that works.
    pub relay_endpoints: Vec<RelayEndpoint>,

    /// Optional invitation metadata
    ///
    /// Additional information about the invitation, such as who sent it,
    /// when it was created, expiration time, or invitation-specific settings.
    pub invitation_metadata: Vec<Metadata>,
}

impl GroupJoinInfo {
    /// Create new group join information
    pub fn new(
        channel_id: String,
        group_info: GroupInfo,
        encryption_key: [u8; 32],
        key_info: GroupKeyInfo,
        relay_endpoints: Vec<RelayEndpoint>,
    ) -> Self {
        Self {
            channel_id,
            group_info,
            encryption_key,
            key_info,
            relay_endpoints,
            invitation_metadata: Vec::new(),
        }
    }

    /// Add metadata to the invitation
    pub fn with_invitation_metadata(mut self, metadata: Metadata) -> Self {
        self.invitation_metadata.push(metadata);
        self
    }

    /// Add a relay endpoint to the list
    pub fn add_relay(mut self, endpoint: RelayEndpoint) -> Self {
        self.relay_endpoints.push(endpoint);
        self
    }

    /// Get the primary (first priority) relay endpoint
    pub fn primary_relay(&self) -> Option<RelayEndpoint> {
        self.relay_endpoints.first().cloned()
    }

    /// Get all relay endpoints ordered by priority
    pub fn relays_by_priority(&self) -> &[RelayEndpoint] {
        &self.relay_endpoints
    }

    /// Check if this invitation has any relay endpoints
    pub fn has_relays(&self) -> bool {
        !self.relay_endpoints.is_empty()
    }
}
