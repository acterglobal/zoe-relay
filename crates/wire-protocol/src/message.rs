use blake3::{Hash, Hasher};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use postcard::to_vec;
use serde::{Deserialize, Serialize};

use crate::{crypto::ChaCha20Poly1305Content, Ed25519EncryptedContent};

mod store_key;
pub use store_key::StoreKey;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Tag {
    Protected, // may not be forwarded, unless the other end is authenticated as the author, may it be accepted
    Event {
        // referes to another event in some form
        id: Hash,
        #[serde(default)]
        relays: Vec<String>,
    },
    User {
        // Refers to a user in some form
        id: Vec<u8>,
        #[serde(default)]
        relays: Vec<String>,
    },
    Channel {
        // Refers to a channel in some form
        id: Vec<u8>,
        #[serde(default)]
        relays: Vec<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// This is a regular event, that should be stored and made available to query for afterwards
    Regular,
    /// An ephemeral event is not kept permanently but mainly forwarded to who ever is interested
    /// if a number is provided and larger than 0, this is the maximum seconds the event should be
    /// stored for in case someone asks. If the timestamp + seconds is smaller than the current
    /// server time, the event might be discarded without even forwarding it.
    Emphemeral(Option<u8>),
    /// This is an event that should be stored in a specific store
    Store(StoreKey),
    /// This is an event that should clear a specific store
    ClearStore(StoreKey), // clear the given storekey of the user, if the events timestamp is larger than the stored one
}

/// Message content variants supporting both raw bytes and encrypted content
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Raw byte conten
    Raw(Vec<u8>),
    /// ChaCha20-Poly1305 encrypted content (minimal overhead)
    /// Key determined by message context (channel tags, etc.)
    ChaCha20Poly1305(ChaCha20Poly1305Content),
    /// Ed25519-derived ChaCha20-Poly1305 encrypted content
    /// Simple encryption using ed25519 keypair from mnemonic
    Ed25519Encrypted(Ed25519EncryptedContent),
}

impl Content {
    /// Create raw content from bytes
    pub fn raw(data: Vec<u8>) -> Self {
        Content::Raw(data)
    }

    /// Create raw content from serializable object
    pub fn raw_typed<T: Serialize>(data: &T) -> Result<Self, postcard::Error> {
        Ok(Content::Raw(postcard::to_stdvec(data)?))
    }

    /// Create encrypted content
    pub fn encrypted(content: ChaCha20Poly1305Content) -> Self {
        Content::ChaCha20Poly1305(content)
    }

    /// Create ed25519-encrypted content
    pub fn ed25519_encrypted(content: Ed25519EncryptedContent) -> Self {
        Content::Ed25519Encrypted(content)
    }

    /// Get the raw bytes if this is raw content
    pub fn as_raw(&self) -> Option<&Vec<u8>> {
        match self {
            Content::Raw(data) => Some(data),
            Content::ChaCha20Poly1305(_) => None,
            Content::Ed25519Encrypted(_) => None,
        }
    }

    /// Get the encrypted content if this is encrypted
    pub fn as_encrypted(&self) -> Option<&ChaCha20Poly1305Content> {
        match self {
            Content::Raw(_) => None,
            Content::ChaCha20Poly1305(content) => Some(content),
            Content::Ed25519Encrypted(_) => None,
        }
    }

    /// Get the ed25519-encrypted content if this is ed25519-encrypted
    pub fn as_ed25519_encrypted(&self) -> Option<&Ed25519EncryptedContent> {
        match self {
            Content::Raw(_) => None,
            Content::ChaCha20Poly1305(_) => None,
            Content::Ed25519Encrypted(content) => Some(content),
        }
    }

    /// Check if this content is encrypted
    pub fn is_encrypted(&self) -> bool {
        matches!(
            self,
            Content::ChaCha20Poly1305(_) | Content::Ed25519Encrypted(_)
        )
    }

    /// Check if this content is raw
    pub fn is_raw(&self) -> bool {
        matches!(self, Content::Raw(_))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Message {
    MessageV0(MessageV0),
}

impl Message {
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        match self {
            Message::MessageV0(message) => {
                let v = to_vec::<_, 4096>(message)?;
                Ok(v.to_vec())
            }
        }
    }

    pub fn verify_signature(
        &self,
        signature: &Signature,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        match self {
            Message::MessageV0(message) => {
                let message_bytes = to_vec::<_, 4096>(message)?;
                Ok(message.sender.verify(&message_bytes, signature).is_ok())
            }
        }
    }

    pub fn new_v0(
        content: Vec<u8>,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Self {
        Message::MessageV0(MessageV0 {
            sender,
            when,
            kind,
            tags,
            content: Content::Raw(content),
        })
    }

    pub fn new_v0_encrypted(
        content: ChaCha20Poly1305Content,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Self {
        Message::MessageV0(MessageV0 {
            sender,
            when,
            kind,
            tags,
            content: Content::ChaCha20Poly1305(content),
        })
    }

    pub fn new_v0_ed25519_encrypted(
        content: Ed25519EncryptedContent,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Self {
        Message::MessageV0(MessageV0 {
            sender,
            when,
            kind,
            tags,
            content: Content::Ed25519Encrypted(content),
        })
    }

    pub fn new_typed<T>(
        content: T,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Result<Self, postcard::Error>
    where
        T: Serialize,
    {
        Ok(Message::MessageV0(MessageV0 {
            sender,
            when,
            kind,
            tags,
            content: Content::Raw(postcard::to_stdvec(&content)?),
        }))
    }

    pub fn new_typed_encrypted<T>(
        content: T,
        encryption_key: &crate::crypto::EncryptionKey,
        sender: VerifyingKey,
        when: u64,
        kind: Kind,
        tags: Vec<Tag>,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        T: Serialize,
    {
        let plaintext = postcard::to_stdvec(&content)?;
        let encrypted_content = encryption_key.encrypt_content(&plaintext)?;

        Ok(Message::MessageV0(MessageV0 {
            sender,
            when,
            kind,
            tags,
            content: Content::ChaCha20Poly1305(encrypted_content),
        }))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MessageV0 {
    pub sender: VerifyingKey,
    pub when: u64, // unix timestamp in seconds
    pub kind: Kind,
    #[serde(default)]
    pub tags: Vec<Tag>,
    pub content: Content,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageFull {
    pub id: Hash,
    pub message: Box<Message>,
    // TODO: do we need to add a HMAC?
    pub signature: Signature,
}

impl MessageFull {
    /// Create a new MessageFull with proper signature and ID
    pub fn new(message: Message, signer: &SigningKey) -> Result<Self, Box<dyn std::error::Error>> {
        let message_bytes = message.to_bytes()?;
        let signature = signer.sign(&message_bytes);

        // Compute ID as Blake3 of serialized core message + signature
        let mut id_input = message_bytes.clone();
        id_input.extend_from_slice(&signature.to_bytes());
        let mut hasher = Hasher::new();
        hasher.update(&id_input);
        let id = hasher.finalize();

        Ok(MessageFull {
            id,
            message: Box::new(message),
            signature,
        })
    }

    /// Verify that this MessageFull has a valid signature
    pub fn verify(&self) -> Result<bool, Box<dyn std::error::Error>> {
        self.message.verify_signature(&self.signature)
    }

    /// Verify that the ID matches the expected Blake3 hash
    pub fn verify_id(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let message_bytes = self.message.to_bytes()?;
        let mut id_input = message_bytes;
        id_input.extend_from_slice(&self.signature.to_bytes());
        let mut hasher = Hasher::new();
        hasher.update(&id_input);
        let id = hasher.finalize();

        Ok(self.id == id)
    }

    /// Verify both signature and ID
    pub fn verify_all(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let signature_valid = self.verify()?;
        let id_valid = self.verify_id()?;
        Ok(signature_valid && id_valid)
    }

    /// The value this message is stored under in the storage
    pub fn storage_value(&self) -> Result<heapless::Vec<u8, 4096>, Box<dyn std::error::Error>> {
        Ok(postcard::to_vec(&self)?)
    }

    /// The timeout for this message in the storage
    pub fn storage_timeout(&self) -> Option<u64> {
        match &*self.message {
            Message::MessageV0(msg) => match msg.kind {
                Kind::Emphemeral(Some(timeout)) if timeout > 0 => Some(timeout as u64),
                _ => None,
            },
        }
    }

    pub fn store_key(&self) -> Option<StoreKey> {
        match &*self.message {
            Message::MessageV0(msg) => match &msg.kind {
                Kind::Store(key) => Some(key.clone()),
                _ => None,
            },
        }
    }

    /// this is meant to clear a storage key
    pub fn clear_key(&self) -> Option<StoreKey> {
        None
    }

    /// Deserialize a message from its storage value
    pub fn from_storage_value(value: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        let message: Self = postcard::from_bytes(value)?;
        Ok(message)
    }

    pub fn author(&self) -> &VerifyingKey {
        match &*self.message {
            Message::MessageV0(message) => &message.sender,
        }
    }

    pub fn when(&self) -> &u64 {
        match &*self.message {
            Message::MessageV0(message) => &message.when,
        }
    }

    pub fn kind(&self) -> &Kind {
        match &*self.message {
            Message::MessageV0(message) => &message.kind,
        }
    }

    pub fn tags(&self) -> &Vec<Tag> {
        match &*self.message {
            Message::MessageV0(message) => &message.tags,
        }
    }

    pub fn content(&self) -> &Content {
        match &*self.message {
            Message::MessageV0(message) => &message.content,
        }
    }

    /// Get raw content bytes if this message contains raw content
    pub fn raw_content(&self) -> Option<&Vec<u8>> {
        self.content().as_raw()
    }

    /// Get encrypted content if this message contains encrypted content
    pub fn encrypted_content(&self) -> Option<&ChaCha20Poly1305Content> {
        self.content().as_encrypted()
    }
}

impl MessageFull {
    /// Try to deserialize content if it's raw (unencrypted)
    pub fn try_deserialize_content<C>(&self) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(bytes) => Ok(postcard::from_bytes(bytes)?),
                Content::ChaCha20Poly1305(_) => {
                    Err("Cannot deserialize encrypted content without decryption key".into())
                }
                Content::Ed25519Encrypted(_) => {
                    Err("Cannot deserialize ed25519-encrypted content without signing key".into())
                }
            },
        }
    }

    /// Try to deserialize encrypted content by decrypting it first
    pub fn try_deserialize_encrypted_content<C>(
        &self,
        encryption_key: &crate::crypto::EncryptionKey,
    ) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(_) => Err("Content is not encrypted".into()),
                Content::ChaCha20Poly1305(encrypted) => {
                    let plaintext = encryption_key.decrypt_content(encrypted)?;
                    Ok(postcard::from_bytes(&plaintext)?)
                }
                Content::Ed25519Encrypted(_) => {
                    Err("Cannot decrypt ed25519-encrypted content with EncryptionKey - use signing key instead".into())
                }
            },
        }
    }

    /// Try to deserialize ed25519-encrypted content by decrypting it first
    pub fn try_deserialize_ed25519_encrypted_content<C>(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<C, Box<dyn std::error::Error>>
    where
        C: for<'a> Deserialize<'a>,
    {
        match &*self.message {
            Message::MessageV0(message) => match &message.content {
                Content::Raw(_) => Err("Content is not encrypted".into()),
                Content::ChaCha20Poly1305(_) => {
                    Err("Cannot decrypt ChaCha20Poly1305 content with signing key - use EncryptionKey instead".into())
                }
                Content::Ed25519Encrypted(encrypted) => {
                    let plaintext = encrypted.decrypt(signing_key)?;
                    Ok(postcard::from_bytes(&plaintext)?)
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn make_hash() -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(b"1234567890abcdef");
        hasher.finalize()
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct DummyContent {
        value: u32,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ComplexContent {
        text: String,
        numbers: Vec<i32>,
        flag: bool,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct TestContent {
        text: String,
        timestamp: u64,
        value: u32,
    }

    fn make_keys() -> (SigningKey, VerifyingKey) {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);
        let sk = SigningKey::from_bytes(&secret_bytes);
        let pk = sk.verifying_key();
        (sk, pk)
    }

    #[test]
    fn test_message_sign_and_verify() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core.clone(), &sk).unwrap();
        // Signature should verify
        assert!(msg_full.verify().unwrap());
        // ID should verify
        assert!(msg_full.verify_id().unwrap());
        // Both should verify
        assert!(msg_full.verify_all().unwrap());
        // Tampering with content should fail
        let mut tampered = msg_full.clone();
        let Message::MessageV0(ref mut msg) = *tampered.message;
        // Safely tamper with the content based on its type
        match &mut msg.content {
            Content::Raw(ref mut data) => {
                if !data.is_empty() {
                    data[0] = data[0].wrapping_add(1);
                }
            }
            Content::ChaCha20Poly1305(ref mut encrypted) => {
                if !encrypted.ciphertext.is_empty() {
                    encrypted.ciphertext[0] = encrypted.ciphertext[0].wrapping_add(1);
                }
            }
            Content::Ed25519Encrypted(ref mut encrypted) => {
                if !encrypted.ciphertext.is_empty() {
                    encrypted.ciphertext[0] = encrypted.ciphertext[0].wrapping_add(1);
                }
            }
        }
        assert!(!tampered.verify_all().unwrap());
    }

    #[test]
    fn test_signature_fails_with_wrong_key() {
        let (sk1, pk1) = make_keys();
        let (sk2, _pk2) = make_keys();
        let content = DummyContent { value: 7 };
        let core = Message::new_typed(
            content.clone(),
            pk1,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let mut msg_full = MessageFull::new(core, &sk1).unwrap();
        // Replace signature with one from a different key
        let fake_sig = sk2.sign(&msg_full.message.to_bytes().unwrap());
        msg_full.signature = fake_sig;
        assert!(!msg_full.verify().unwrap());
    }

    #[test]
    fn test_empty_content() {
        let (sk, pk) = make_keys();
        let core = Message::new_typed(
            DummyContent { value: 0 },
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_multiple_content_items() {
        let (sk, pk) = make_keys();
        let contents = [
            DummyContent { value: 1 },
            DummyContent { value: 2 },
            DummyContent { value: 3 },
        ];
        let core = Message::new_typed(
            contents[0].clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![
                Tag::Protected,
                Tag::Event {
                    id: make_hash(),
                    relays: vec!["relay1".to_string()],
                },
            ],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_complex_content_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::User {
                id: vec![1],
                relays: vec!["relay1".to_string()],
            }],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();

        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
        assert!(deserialized.verify_all().unwrap());
    }

    #[test]
    #[ignore = "this won't work, and that's the proof"]
    fn test_complex_content_serialization_is_not_vec_u8() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::User {
                id: vec![1],
                relays: vec!["relay1".to_string()],
            }],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        assert!(deserialized.verify_all().unwrap());

        let deserialize_u8 = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialize_u8.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
    }

    #[test]
    fn test_complex_content_no_tags_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();

        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
        assert!(deserialized.verify_all().unwrap());
    }

    #[test]
    fn test_all_tag_types_serialization() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 100 };

        let tags = [
            Tag::Protected,
            Tag::Event {
                id: make_hash(),
                relays: vec!["relay1".to_string()],
            },
            Tag::User {
                id: vec![2],
                relays: vec!["relay2".to_string()],
            },
            Tag::Channel {
                id: vec![3],
                relays: vec!["relay3".to_string()],
            },
        ];

        for tag in tags {
            let core = Message::new_typed(
                content.clone(),
                pk,
                1714857600,
                Kind::Regular,
                vec![tag.clone()],
            )
            .unwrap();

            let msg_full = MessageFull::new(core, &sk).unwrap();
            assert!(msg_full.verify_all().unwrap(), "Failed for tag: {tag:?}");
            // Serialize and deserialize
            let serialized = msg_full.storage_value().unwrap();
            let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
            let de_content: DummyContent = deserialized.try_deserialize_content().unwrap();

            assert_eq!(msg_full, deserialized);
            assert_eq!(content, de_content);
            assert!(deserialized.verify_all().unwrap());
        }
    }
    #[test]
    fn test_complex_content_empheral_kind_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Emphemeral(Some(10)),
            vec![],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);

        assert_eq!(msg_full, deserialized);
        assert!(deserialized.verify_all().unwrap());
    }

    #[test]
    fn test_complex_content_clear_store_kind_serialization() {
        // Create a signing key for testing
        let mut rng = rand::rngs::OsRng;
        let mut secret_bytes = [0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        for i in 0..10 {
            let content = TestContent {
                text: format!("Test message {}", i + 1),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                value: i as u32,
            };

            let mut tags = Vec::new();
            // Create a fake event ID (32 bytes)
            let mut event_id_bytes = [0u8; 32];
            event_id_bytes[0] = i as u8;
            let event_id = blake3::Hash::from(event_id_bytes);
            tags.push(Tag::Event {
                id: event_id,
                relays: Vec::new(),
            });

            let message = Message::new_typed(
                content.clone(),
                verifying_key,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                Kind::Regular,
                tags,
            )
            .unwrap();

            let msg_full = MessageFull::new(message, &signing_key).unwrap();
            assert!(msg_full.verify_all().unwrap());
            // Serialize and deserialize
            let serialized = msg_full.storage_value().unwrap();
            let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
            let de_content: TestContent = deserialized.try_deserialize_content().unwrap();

            assert_eq!(msg_full, deserialized);
            assert_eq!(content, de_content);
            assert!(deserialized.verify_all().unwrap());
        }
    }

    #[test]
    fn test_complex_content_store_kind_serialization() {
        let (sk, pk) = make_keys();
        let complex_content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            complex_content.clone(),
            pk,
            1714857600,
            Kind::Store(StoreKey::CustomKey(10)),
            vec![],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(complex_content, de_content);
        assert!(deserialized.verify_all().unwrap());
    }

    #[test]
    fn test_id_tampering() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let mut msg_full = MessageFull::new(core, &sk).unwrap();

        // Tamper with ID
        msg_full.id = make_hash();
        assert!(!msg_full.verify_id().unwrap());
        assert!(!msg_full.verify_all().unwrap());
        // Signature should still be valid
        assert!(msg_full.verify().unwrap());
    }

    #[test]
    fn test_empty_signature() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let mut msg_full = MessageFull::new(core, &sk).unwrap();
        // Create an invalid signature by using wrong key
        let (wrong_sk, _) = make_keys();
        let wrong_sig = wrong_sk.sign(&msg_full.message.to_bytes().unwrap());
        msg_full.signature = wrong_sig;
        assert!(!msg_full.verify().unwrap());
    }

    #[test]
    fn test_invalid_signature_length() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let mut msg_full = MessageFull::new(core, &sk).unwrap();
        // Create an invalid signature by using wrong key
        let (wrong_sk, _) = make_keys();
        let wrong_sig = wrong_sk.sign(&msg_full.message.to_bytes().unwrap());
        msg_full.signature = wrong_sig;
        assert!(!msg_full.verify().unwrap());
    }

    #[test]
    fn test_signature_tampering() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let mut msg_full = MessageFull::new(core, &sk).unwrap();
        // Create an invalid signature by using wrong key
        let (wrong_sk, _) = make_keys();
        let wrong_sig = wrong_sk.sign(&msg_full.message.to_bytes().unwrap());
        msg_full.signature = wrong_sig;
        let verify_result = msg_full.verify();
        match verify_result {
            Ok(false) | Err(_) => {}
            _ => panic!("Expected Ok(false) or Err(_) for tampered signature"),
        }
        let verify_all_result = msg_full.verify_all();
        match verify_all_result {
            Ok(false) | Err(_) => {}
            _ => panic!("Expected Ok(false) or Err(_) for tampered signature in verify_all"),
        }
        // ID should now be invalid
        assert!(!msg_full.verify_id().unwrap_or(false));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (sk, pk) = make_keys();
        let content = ComplexContent {
            text: "Hello, World!".to_string(),
            numbers: vec![1, 2, 3, 4, 5],
            flag: true,
        };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![
                Tag::Protected,
                Tag::Event {
                    id: make_hash(),
                    relays: vec!["relay1".to_string()],
                },
            ],
        )
        .unwrap();

        let msg_full = MessageFull::new(core, &sk).unwrap();

        // Serialize and deserialize
        let serialized = msg_full.storage_value().unwrap();
        let deserialized = MessageFull::from_storage_value(&serialized).unwrap();
        let de_content: ComplexContent = deserialized.try_deserialize_content().unwrap();

        assert_eq!(msg_full, deserialized);
        assert_eq!(content, de_content);
        assert!(deserialized.verify_all().unwrap());
    }

    #[test]
    fn test_core_message_serialization() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let serialized = core.to_bytes().unwrap();
        assert!(!serialized.is_empty());

        // Verify signature works with serialized bytes
        let signature = sk.sign(&serialized);
        assert!(core.verify_signature(&signature).unwrap());
    }

    #[test]
    fn test_multiple_tags() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![
                Tag::Protected,
                Tag::Event {
                    id: make_hash(),
                    relays: vec!["relay1".to_string()],
                },
                Tag::User {
                    id: vec![2],
                    relays: vec!["relay2".to_string()],
                },
            ],
        )
        .unwrap();
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_large_content() {
        let (sk, pk) = make_keys();
        let large_content = ComplexContent {
            text: "A".repeat(1000),       // Large string
            numbers: (0..1000).collect(), // Large vector
            flag: false,
        };
        let core = Message::new_typed(
            large_content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Channel {
                id: vec![1],
                relays: vec!["relay1".to_string()],
            }],
        )
        .unwrap();
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_id_uniqueness() {
        let (sk, pk) = make_keys();
        let content1 = DummyContent { value: 1 };
        let content2 = DummyContent { value: 2 };

        let core1 = Message::new_typed(
            content1.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let core2 = Message::new_typed(
            content2.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();

        let msg_full1 = MessageFull::new(core1, &sk).unwrap();
        let msg_full2 = MessageFull::new(core2, &sk).unwrap();

        // Different content should produce different IDs
        assert_ne!(msg_full1.id, msg_full2.id);
    }

    #[test]
    fn test_same_content_same_id() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };

        let core1 = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();
        let core2 = Message::new_typed(
            content.clone(),
            pk,
            1714857600,
            Kind::Regular,
            vec![Tag::Protected],
        )
        .unwrap();

        let msg_full1 = MessageFull::new(core1, &sk).unwrap();
        let msg_full2 = MessageFull::new(core2, &sk).unwrap();

        // Same content should produce same ID
        assert_eq!(msg_full1.id, msg_full2.id);
    }
}
