//! File storage primitives for Zoe applications
//!
//! This module contains types for describing stored files that have been
//! encrypted and stored in blob storage systems.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
// Re-export encryption types from zoe-encrypted-storage for convenience
pub use zoe_encrypted_storage::{CompressionConfig, ConvergentEncryptionInfo};

pub mod image;

pub use image::Image;

/// Reference to a stored file, containing everything needed to retrieve it
///
/// This type represents metadata for files that have been encrypted using
/// convergent encryption and stored in a content-addressable blob store.
/// It contains all the information needed to retrieve and decrypt the file later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRef {
    /// Hash of the encrypted blob in storage
    ///
    /// This is the content-addressable hash used by the blob storage system
    /// to uniquely identify and retrieve the encrypted file data.
    pub blob_hash: String,

    /// Encryption metadata needed for decryption
    ///
    /// Contains the encryption key, compression settings, and other metadata
    /// required to decrypt the stored file back to its original form.
    pub encryption_info: ConvergentEncryptionInfo,

    /// Original filename (for reference)
    ///
    /// The name of the file when it was stored. This is kept for
    /// reference and display purposes and doesn't affect retrieval.
    /// This is optional to support cases where filename is not relevant.
    pub filename: Option<String>,

    /// MIME type or file extension for reference
    ///
    /// Optional content type information derived from the file extension
    /// or explicitly provided when storing the file.
    pub content_type: Option<String>,

    /// Additional metadata about the stored file
    ///
    /// Arbitrary key-value metadata that applications can use to store
    /// additional information about the file (e.g., original timestamps,
    /// user tags, categories, etc.).
    pub metadata: BTreeMap<String, String>,
}

impl FileRef {
    /// Create a new FileRef with minimal required fields
    pub fn new(
        blob_hash: String,
        encryption_info: ConvergentEncryptionInfo,
        filename: Option<String>,
    ) -> Self {
        Self {
            blob_hash,
            encryption_info,
            filename,
            content_type: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Add metadata to the stored file info
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set the content type
    pub fn with_content_type(mut self, content_type: String) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// Get the filename (if available)
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Get file extension from the filename (if available)
    pub fn file_extension(&self) -> Option<String> {
        self.filename.as_ref().and_then(|filename| {
            std::path::Path::new(filename)
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|s| s.to_string())
        })
    }

    /// Get the original file size (from encryption info)
    pub fn original_size(&self) -> usize {
        self.encryption_info.source_size
    }
}
