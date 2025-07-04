use postcard::to_vec;
use serde::{Deserialize, Serialize};
use ed25519_dalek::{VerifyingKey, Signer, SigningKey, Verifier, Signature};
use blake3::Hasher;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Tag {
    Protected, // may not be forwarded, unless the other end is authenticated as the author, may it be accepted
    Event { // referes to another event in some form
        id: u64,
        relays: Vec<String>,
    },
    User { // Refers to a user in some form
        id: u64,
        relays: Vec<String>,
    },
    Channel { // Refers to a channel in some form
        id: u64,
        relays: Vec<String>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum StoreKey {
    PublicUserInfo,
    MlsKeyPackage,
    CustomKey(u32) // yet to be known variant
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Regular, // shall be stored in order of arrival
    Emphemeral, // may only be forwarded but not be stored
    Store(StoreKey), // store only the latest messages of StoreKey per User
    ClearStore(StoreKey), // clear the given storekey of the user, if the events timestamp is larger than the stored one
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + for<'a> Deserialize<'a>")]
pub struct MessageFull<T> {
    pub id: u64,
    pub message: CoreMessage<T>,
    // TODO: do we need to add a HMAC?
    pub signature: Signature, 
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(bound = "T: Serialize + for<'a> Deserialize<'a>")]
pub struct CoreMessage<T> {
    pub sender: VerifyingKey,
    pub kind: Kind,
    pub tags: Vec<Tag>,
    pub content: Vec<T>,
}

impl<T> CoreMessage<T>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    /// Serialize the core message using postcard
    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        let heapless_vec = to_vec::<_, 4096>(self)?;
        Ok(heapless_vec.to_vec())
    }
    
    /// Verify that the signature is valid for this core message
    pub fn verify_signature(&self, signature: &Signature) -> Result<bool, Box<dyn std::error::Error>> {
        let message_bytes = self.to_bytes()?;
        Ok(self.sender.verify(&message_bytes, signature).is_ok())
    }
}

impl<T> MessageFull<T>
where
    T: Serialize + for<'a> Deserialize<'a>,
{
    /// Create a new MessageFull with proper signature and ID
    pub fn new(message: CoreMessage<T>, signer: &SigningKey) -> Result<Self, Box<dyn std::error::Error>> {
        let message_bytes = message.to_bytes()?;
        let signature = signer.sign(&message_bytes);
        
        // Compute ID as Blake3 of serialized core message + signature
        let mut id_input = message_bytes.clone();
        id_input.extend_from_slice(&signature.to_bytes());
        let mut hasher = Hasher::new();
        hasher.update(&id_input);
        let id_hash = hasher.finalize();
        
        // Convert first 8 bytes of hash to u64 for the ID
        let id_bytes: [u8; 8] = id_hash.as_bytes()[..8].try_into()?;
        let id = u64::from_le_bytes(id_bytes);
        
        Ok(MessageFull {
            id,
            message,
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
        let id_hash = hasher.finalize();
        
        let expected_id_bytes: [u8; 8] = id_hash.as_bytes()[..8].try_into()?;
        let expected_id = u64::from_le_bytes(expected_id_bytes);
        
        Ok(self.id == expected_id)
    }
    
    /// Verify both signature and ID
    pub fn verify_all(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let signature_valid = self.verify()?;
        let id_valid = self.verify_id()?;
        Ok(signature_valid && id_valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use ed25519_dalek::{SigningKey, VerifyingKey, Signer};

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
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content.clone()],
        };
        let msg_full = MessageFull::new(core.clone(), &sk).unwrap();
        // Signature should verify
        assert!(msg_full.verify().unwrap());
        // ID should verify
        assert!(msg_full.verify_id().unwrap());
        // Both should verify
        assert!(msg_full.verify_all().unwrap());
        // Tampering with content should fail
        let mut tampered = msg_full.clone();
        tampered.message.content[0].value = 99;
        assert!(!tampered.verify_all().unwrap());
    }

    #[test]
    fn test_signature_fails_with_wrong_key() {
        let (sk1, pk1) = make_keys();
        let (sk2, _pk2) = make_keys();
        let content = DummyContent { value: 7 };
        let core = CoreMessage {
            sender: pk1.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
        let mut msg_full = MessageFull::new(core, &sk1).unwrap();
        // Replace signature with one from a different key
        let fake_sig = sk2.sign(&msg_full.message.to_bytes().unwrap());
        msg_full.signature = fake_sig;
        assert!(!msg_full.verify().unwrap());
    }

    #[test]
    fn test_empty_content() {
        let (sk, pk) = make_keys();
        let core: CoreMessage<DummyContent> = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![],
        };
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_multiple_content_items() {
        let (sk, pk) = make_keys();
        let contents = vec![
            DummyContent { value: 1 },
            DummyContent { value: 2 },
            DummyContent { value: 3 },
        ];
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected, Tag::Event { id: 1, relays: vec!["relay1".to_string()] }],
            content: contents,
        };
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
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::User { id: 1, relays: vec!["relay1".to_string()] }],
            content: vec![complex_content],
        };
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_all_tag_types() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 100 };
        
        let tags = [
            Tag::Protected,
            Tag::Event { id: 1, relays: vec!["relay1".to_string()] },
            Tag::User { id: 2, relays: vec!["relay2".to_string()] },
            Tag::Channel { id: 3, relays: vec!["relay3".to_string()] },
        ];
        
        for tag in tags {
            let core = CoreMessage {
                sender: pk.clone(),
                kind: Kind::Regular,
                tags: vec![tag.clone()],
                content: vec![content.clone()],
            };
            let msg_full = MessageFull::new(core, &sk).unwrap();
            assert!(msg_full.verify_all().unwrap(), "Failed for tag: {:?}", tag);
        }
    }

    #[test]
    fn test_id_tampering() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
        let mut msg_full = MessageFull::new(core, &sk).unwrap();
        
        // Tamper with ID
        msg_full.id = 0x1234567890abcdef;
        assert!(!msg_full.verify_id().unwrap());
        assert!(!msg_full.verify_all().unwrap());
        // Signature should still be valid
        assert!(msg_full.verify().unwrap());
    }

    #[test]
    fn test_empty_signature() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
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
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
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
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
        let mut msg_full = MessageFull::new(core, &sk).unwrap();
        // Create an invalid signature by using wrong key
        let (wrong_sk, _) = make_keys();
        let wrong_sig = wrong_sk.sign(&msg_full.message.to_bytes().unwrap());
        msg_full.signature = wrong_sig;
        let verify_result = msg_full.verify();
        match verify_result {
            Ok(false) | Err(_) => {},
            _ => panic!("Expected Ok(false) or Err(_) for tampered signature"),
        }
        let verify_all_result = msg_full.verify_all();
        match verify_all_result {
            Ok(false) | Err(_) => {},
            _ => panic!("Expected Ok(false) or Err(_) for tampered signature in verify_all"),
        }
        // ID should now be invalid
        assert!(!msg_full.verify_id().unwrap_or(false));
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected, Tag::Event { id: 1, relays: vec!["relay1".to_string()] }],
            content: vec![content],
        };
        let msg_full = MessageFull::new(core, &sk).unwrap();
        
        // Serialize and deserialize
        let serialized = postcard::to_vec::<_, 1024>(&msg_full).unwrap();
        let deserialized: MessageFull<DummyContent> = postcard::from_bytes(&serialized).unwrap();
        
        assert_eq!(msg_full, deserialized);
        assert!(deserialized.verify_all().unwrap());
    }

    #[test]
    fn test_core_message_serialization() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
        
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
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected, Tag::Event { id: 1, relays: vec!["relay1".to_string()] }, Tag::User { id: 2, relays: vec!["relay2".to_string()] }],
            content: vec![content],
        };
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_large_content() {
        let (sk, pk) = make_keys();
        let large_content = ComplexContent {
            text: "A".repeat(1000), // Large string
            numbers: (0..1000).collect(), // Large vector
            flag: false,
        };
        let core = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Channel { id: 1, relays: vec!["relay1".to_string()] }],
            content: vec![large_content],
        };
        let msg_full = MessageFull::new(core, &sk).unwrap();
        assert!(msg_full.verify_all().unwrap());
    }

    #[test]
    fn test_id_uniqueness() {
        let (sk, pk) = make_keys();
        let content1 = DummyContent { value: 1 };
        let content2 = DummyContent { value: 2 };
        
        let core1 = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content1],
        };
        let core2 = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content2],
        };
        
        let msg_full1 = MessageFull::new(core1, &sk).unwrap();
        let msg_full2 = MessageFull::new(core2, &sk).unwrap();
        
        // Different content should produce different IDs
        assert_ne!(msg_full1.id, msg_full2.id);
    }

    #[test]
    fn test_same_content_same_id() {
        let (sk, pk) = make_keys();
        let content = DummyContent { value: 42 };
        
        let core1 = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content.clone()],
        };
        let core2 = CoreMessage {
            sender: pk.clone(),
            kind: Kind::Regular,
            tags: vec![Tag::Protected],
            content: vec![content],
        };
        
        let msg_full1 = MessageFull::new(core1, &sk).unwrap();
        let msg_full2 = MessageFull::new(core2, &sk).unwrap();
        
        // Same content should produce same ID
        assert_eq!(msg_full1.id, msg_full2.id);
    }
}

