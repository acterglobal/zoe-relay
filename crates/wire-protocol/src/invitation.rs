//! Group invitation message types for PQXDH-based secure invitations
//!
//! This module defines the message types used in the group invitation flow,
//! providing type-safe structures for the multi-step verification process.

use crate::{Tag, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Protocol version for invitation messages
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum InboxHandshakeProtocolVersion {
    V1,
}

/// Purpose of the PQXDH handshake session
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HandshakePurpose {
    GroupInvitation,
    DirectMessage,
    FileTransfer,
    // Future purposes can be added here
}

/// Initial handshake request sent in PqxdhInitialMessage payload
///
/// This message establishes the PQXDH session and requests verification.
/// It contains NO sensitive group information for security.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VerificationHandshakeRequest {
    pub protocol_version: InboxHandshakeProtocolVersion,
    pub purpose: HandshakePurpose,
    pub timestamp: u64,
}

/// Response sent after emoji verification by the invitee
///
/// This message indicates whether the user accepted or rejected the invitation
/// after verifying the emoji sequence derived from the shared PQXDH secret.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HandshakeResponse {
    pub accepted: bool,
    pub timestamp: u64,
}

/// User profile information
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UserProfile {
    pub display_name: String,
    pub avatar: Option<Vec<u8>>, // Optional avatar data
    pub public_key: VerifyingKey,
}

/// Group metadata shared during invitation
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GroupMetadata {
    pub name: String,
    pub description: Option<String>,
    pub member_count: u32,
    pub created_at: u64,
}

/// Sensitive group data sent only after successful verification
///
/// This message contains all the information needed for the invitee to join
/// the group. It is only sent after the handshake has been confirmed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct GroupInvitationData {
    pub group_tag: Tag,
    pub shared_aes_key: [u8; 32],
    pub inviter_profile: UserProfile,
    pub group_metadata: GroupMetadata,
    pub timestamp: u64,
}

/// Generate a random ephemeral group invite protocol ID
///
/// Returns a random value in the range 0-999 for use with
/// PqxdhInboxProtocol::EphemeralGroupInvite(id).
/// This provides unlinkability between different invitation sessions.
pub fn generate_ephemeral_group_invite_id() -> u32 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen_range(0..1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ephemeral_id_range() {
        for _ in 0..100 {
            let id = generate_ephemeral_group_invite_id();
            assert!(id < 1000, "Generated ID {id} should be less than 1000");
        }
    }

    #[test]
    fn test_message_serialization() {
        let request = VerificationHandshakeRequest {
            protocol_version: InboxHandshakeProtocolVersion::V1,
            purpose: HandshakePurpose::GroupInvitation,
            timestamp: 1234567890,
        };

        let serialized = postcard::to_allocvec(&request).unwrap();
        let deserialized: VerificationHandshakeRequest = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_handshake_response() {
        let response = HandshakeResponse {
            accepted: true,
            timestamp: 1234567890,
        };

        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: HandshakeResponse = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(response, deserialized);
    }
}
