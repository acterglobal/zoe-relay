use crate::Hash;
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

/// A unique identifier for cryptographic keys
///
/// This is a Blake3 hash that uniquely identifies a key, typically computed
/// from the key's public bytes or other identifying information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub Hash);

impl KeyId {
    /// Create a new KeyId from a Hash
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Create a KeyId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash::from(bytes))
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl Deref for KeyId {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Hash> for KeyId {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Hash::from(bytes))
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PartialOrd for KeyId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::ToSql for KeyId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(
            self.as_bytes().as_slice(),
        ))
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::types::FromSql for KeyId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Blob(bytes) => {
                if bytes.len() != 32 {
                    return Err(rusqlite::types::FromSqlError::InvalidBlobSize {
                        expected_size: 32,
                        blob_size: bytes.len(),
                    });
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(bytes);
                Ok(KeyId::from_bytes(array))
            }
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

/// A unique identifier for blobs
///
/// This is a Blake3 hash that uniquely identifies blob content, computed
/// from the blob's raw bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlobId(pub Hash);

impl BlobId {
    /// Create a new BlobId from a Hash
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Create a BlobId by hashing the given content
    pub fn from_content(content: &[u8]) -> Self {
        Self(crate::hash(content))
    }

    /// Create a BlobId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash::from(bytes))
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl Deref for BlobId {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Hash> for BlobId {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<[u8; 32]> for BlobId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Hash::from(bytes))
    }
}

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for BlobId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PartialOrd for BlobId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlobId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::ToSql for BlobId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(
            self.as_bytes().as_slice(),
        ))
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::types::FromSql for BlobId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Blob(bytes) => {
                if bytes.len() != 32 {
                    return Err(rusqlite::types::FromSqlError::InvalidBlobSize {
                        expected_size: 32,
                        blob_size: bytes.len(),
                    });
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(bytes);
                Ok(BlobId::from_bytes(array))
            }
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

/// A unique identifier for messages
///
/// This is a Blake3 hash that uniquely identifies message content, computed
/// from the message's serialized bytes (excluding signature to handle ML-DSA randomness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "frb-api", frb(opaque))]
pub struct MessageId(pub Hash);

#[cfg_attr(feature = "frb-api", frb)]
impl MessageId {
    /// Create a new MessageId from a Hash
    pub fn new(hash: Hash) -> Self {
        Self(hash)
    }

    /// Create a MessageId by hashing the given content
    pub fn from_content(content: &[u8]) -> Self {
        Self(crate::hash(content))
    }

    /// Create a MessageId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash::from(bytes))
    }

    /// Get the underlying bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }
}

impl Deref for MessageId {
    type Target = Hash;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Hash> for MessageId {
    fn from(hash: Hash) -> Self {
        Self(hash)
    }
}

impl From<[u8; 32]> for MessageId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Hash::from(bytes))
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for MessageId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl PartialOrd for MessageId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MessageId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::ToSql for MessageId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(
            self.as_bytes().as_slice(),
        ))
    }
}

#[cfg(feature = "rusqlite")]
impl rusqlite::types::FromSql for MessageId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match value {
            rusqlite::types::ValueRef::Blob(bytes) => {
                if bytes.len() != 32 {
                    return Err(rusqlite::types::FromSqlError::InvalidBlobSize {
                        expected_size: 32,
                        blob_size: bytes.len(),
                    });
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(bytes);
                Ok(MessageId::from_bytes(array))
            }
            _ => Err(rusqlite::types::FromSqlError::InvalidType),
        }
    }
}

/// Legacy type alias for backward compatibility
#[deprecated(note = "Use KeyId instead")]
pub type Id = [u8; 32];
