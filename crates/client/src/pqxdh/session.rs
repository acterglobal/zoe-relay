use serde::{Deserialize, Serialize};

use std::{
    ops::Deref,
    time::{SystemTime, UNIX_EPOCH},
};
use zoe_wire_protocol::{
    ChannelId, Content, KeyId, Kind, Message, MessageFull, Tag, VerifyingKey,
    inbox::pqxdh::{PqxdhSharedSecret, encrypt_pqxdh_session_message},
};

use super::{PqxdhError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq, Hash)]
pub struct PqxdhSessionId([u8; 32]);

impl PqxdhSessionId {
    /// Create a new PqxdhSessionId from a 32-byte array
    pub fn new(id: [u8; 32]) -> Self {
        Self(id)
    }

    pub fn random(rng: &mut impl rand::Rng) -> Self {
        let mut id = [0u8; 32];
        rng.fill_bytes(&mut id);
        Self(id)
    }
}

impl Deref for PqxdhSessionId {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<blake3::Hash> for PqxdhSessionId {
    fn from(hash: blake3::Hash) -> Self {
        Self(hash.into())
    }
}

impl From<&PqxdhSessionId> for ChannelId {
    fn from(val: &PqxdhSessionId) -> Self {
        ChannelId::from(val.0)
    }
}

impl From<PqxdhSessionId> for ChannelId {
    fn from(val: PqxdhSessionId) -> Self {
        ChannelId::from(val.0)
    }
}

impl From<&PqxdhSessionId> for KeyId {
    fn from(val: &PqxdhSessionId) -> Self {
        KeyId::from(val.0)
    }
}

impl From<PqxdhSessionId> for KeyId {
    fn from(val: PqxdhSessionId) -> Self {
        KeyId::from(val.0)
    }
}

impl From<&PqxdhSessionId> for [u8; 32] {
    fn from(val: &PqxdhSessionId) -> Self {
        val.0
    }
}

impl From<PqxdhSessionId> for [u8; 32] {
    fn from(val: PqxdhSessionId) -> Self {
        val.0
    }
}

/// A PQXDH session for secure communication
///
/// This struct represents an established PQXDH session between two parties.
/// It contains the shared cryptographic material and state needed to encrypt
/// and decrypt messages within the session.
///
/// ## Key Features
/// - **Shared Secret**: Cryptographic material derived from PQXDH key exchange
/// - **Sequence Numbers**: Monotonic counter for replay protection
/// - **Session Channel IDs**: A hash of the session channel id prefix and the target key, provides unlinkability
/// - **Serializable**: Can be persisted and restored across application restarts
///
/// ## Security Properties
/// - Forward secrecy through ephemeral key material
/// - Replay protection via sequence numbering
/// - Unlinkability through randomized channel identifiers
/// - Post-quantum resistance via CRYSTALS-Kyber
#[derive(Serialize, Deserialize, Clone)]
pub(super) struct PqxdhSession {
    pub(super) shared_secret: PqxdhSharedSecret,
    /// Current sequence number for this session (stored as u64 for serialization)
    pub(super) sequence_number: u64,
    /// The channel Id we are listening for, derived from the session channel id prefix
    pub(super) my_session_channel_id: PqxdhSessionId,
    /// The session id channel they will be listening to, derived from the session channel id prefix
    pub(super) their_session_channel_id: PqxdhSessionId,
    /// The key of the sender of the messages
    pub(super) their_key: VerifyingKey,
}

impl PqxdhSession {
    /// Get the channel they are listening for
    pub fn publish_channel_tag(&self) -> Tag {
        Tag::Channel {
            id: (&self.their_session_channel_id).into(),
            relays: vec![],
        }
    }

    /// Get the channel tag we want to be listening for
    pub fn listening_channel_tag(&self) -> Tag {
        Tag::Channel {
            id: (&self.my_session_channel_id).into(),
            relays: vec![],
        }
    }

    /// Get the next sequence number and increment the internal counter
    pub fn next_sequence_number(&mut self) -> u64 {
        let current = self.sequence_number;
        self.sequence_number += 1;
        current
    }

    /// Sends a message in an established PQXDH session
    ///
    /// This method encrypts and sends a message over an already established PQXDH session.
    /// The message is encrypted using the session's shared secret and includes sequence
    /// numbering for replay protection.
    ///
    /// # Arguments
    /// * `messages_service` - The messages service for publishing the encrypted message
    /// * `client_keypair` - The sender's keypair for message authentication
    /// * `payload` - The user data to encrypt and send
    ///
    /// # Security Features
    /// - Messages are encrypted with the session's shared secret
    /// - Sequence numbers prevent replay attacks
    /// - Messages are sent to the session's private channel ID
    /// - Each message uses fresh randomness for encryption
    pub fn gen_next_message<T: Serialize>(
        &mut self,
        client_keypair: &zoe_wire_protocol::KeyPair,
        payload: &T,
        kind: Kind,
    ) -> Result<MessageFull> {
        // Serialize the payload
        let payload_bytes = postcard::to_stdvec(payload)?;

        // Encrypt as session message
        let sequence = self.next_sequence_number();
        let mut rng = rand::thread_rng();
        let session_message =
            encrypt_pqxdh_session_message(&self.shared_secret, &payload_bytes, sequence, &mut rng)
                .map_err(|e| PqxdhError::Crypto(e.to_string()))?;

        // Send the session message
        let pqxdh_content = zoe_wire_protocol::PqxdhEncryptedContent::Session(session_message);

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let message = Message::new_v0(
            Content::PqxdhEncrypted(pqxdh_content),
            client_keypair.public_key(),
            timestamp,
            kind,
            vec![self.publish_channel_tag()],
        );

        MessageFull::new(message, client_keypair).map_err(|e| {
            PqxdhError::MessageCreation(format!("Failed to create session message: {e}"))
        })
    }

    /// Creates a PQXDH session from an established shared secret and channel ID (for responders)
    ///
    /// This constructor is used by service providers to create a session after successfully
    /// processing an initial PQXDH message. It initializes the session with the derived
    /// shared secret and the channel ID extracted from the initial message.
    ///
    /// # Arguments
    /// * `shared_secret` - The cryptographic material derived from PQXDH key exchange
    /// * `my_session_channel_id` - The channel ID we are listening for
    /// * `their_session_channel_id` - The channel ID they are listening for
    /// * `sender_key` - The public key of the sender of the initial message
    ///
    /// # Returns
    /// Returns a new `PqxdhSession` ready for encrypting and decrypting messages
    ///
    /// # Usage
    /// Typically called after `extract_initial_payload()` to create a session
    /// that can be used for ongoing communication with the client.
    pub fn from_shared_secret(
        shared_secret: PqxdhSharedSecret,
        my_session_channel_id: PqxdhSessionId,
        their_session_channel_id: PqxdhSessionId,
        their_key: VerifyingKey,
    ) -> Self {
        Self {
            shared_secret,
            sequence_number: 1,
            my_session_channel_id,
            their_session_channel_id,
            their_key,
        }
    }
}
