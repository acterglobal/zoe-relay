//! File storage primitives for Zoe applications
//!
//! This module contains types for describing stored files that have been
//! encrypted and stored in blob storage systems.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
// Re-export encryption types from zoe-encrypted-storage for convenience
pub use zoe_encrypted_storage::{CompressionConfig, ConvergentEncryptionInfo};

use crate::Metadata;

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
    /// Structured metadata that applications can use to store additional
    /// information about the file (e.g., original timestamps, user tags,
    /// categories, etc.) using typed metadata variants.
    pub metadata: Vec<Metadata>,
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
            metadata: vec![],
        }
    }

    /// Add generic metadata to the stored file info
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.push(Metadata::Generic(key, value));
        self
    }

    /// Add structured metadata to the stored file info
    pub fn with_structured_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata.push(metadata);
        self
    }

    /// Get all generic metadata as a key-value map for backward compatibility
    ///
    /// This method extracts only the `Metadata::Generic(key, value)` entries and returns them
    /// as a `BTreeMap<String, String>` for backward compatibility with APIs that expect
    /// key-value metadata.
    pub fn generic_metadata(&self) -> BTreeMap<String, String> {
        self.metadata
            .iter()
            .filter_map(|meta| match meta {
                Metadata::Generic(key, value) => Some((key.clone(), value.clone())),
                _ => None,
            })
            .collect()
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

#[cfg(test)]
mod tests {
    use super::*;

    use zoe_encrypted_storage::{CompressionConfig, ConvergentEncryptionInfo};

    fn create_test_encryption_info() -> ConvergentEncryptionInfo {
        ConvergentEncryptionInfo {
            key: [42u8; 32],
            was_compressed: false,
            source_size: 1024,
        }
    }

    fn create_test_file_ref() -> FileRef {
        FileRef::new(
            "test_blob_hash_123".to_string(),
            create_test_encryption_info(),
            Some("test_file.txt".to_string()),
        )
    }

    #[test]
    fn test_file_ref_new() {
        let blob_hash = "test_hash_123".to_string();
        let encryption_info = create_test_encryption_info();
        let filename = Some("document.pdf".to_string());

        let file_ref = FileRef::new(blob_hash.clone(), encryption_info.clone(), filename.clone());

        assert_eq!(file_ref.blob_hash, blob_hash);
        assert_eq!(file_ref.encryption_info, encryption_info);
        assert_eq!(file_ref.filename, filename);
        assert_eq!(file_ref.content_type, None);
        assert!(file_ref.metadata.is_empty());
    }

    #[test]
    fn test_file_ref_with_metadata() {
        let file_ref = create_test_file_ref()
            .with_metadata("author".to_string(), "alice".to_string())
            .with_metadata("category".to_string(), "documents".to_string());

        let generic_meta = file_ref.generic_metadata();
        assert_eq!(generic_meta.get("author"), Some(&"alice".to_string()));
        assert_eq!(generic_meta.get("category"), Some(&"documents".to_string()));
        assert_eq!(file_ref.metadata.len(), 2);
    }

    #[test]
    fn test_file_ref_with_content_type() {
        let file_ref = create_test_file_ref().with_content_type("application/pdf".to_string());

        assert_eq!(file_ref.content_type, Some("application/pdf".to_string()));
    }

    #[test]
    fn test_file_ref_filename() {
        // Test with filename
        let file_ref_with_name = create_test_file_ref();
        assert_eq!(file_ref_with_name.filename(), Some("test_file.txt"));

        // Test without filename
        let file_ref_no_name =
            FileRef::new("hash".to_string(), create_test_encryption_info(), None);
        assert_eq!(file_ref_no_name.filename(), None);
    }

    #[test]
    fn test_file_ref_file_extension() {
        // Test with extension
        let file_ref_txt = FileRef::new(
            "hash".to_string(),
            create_test_encryption_info(),
            Some("document.txt".to_string()),
        );
        assert_eq!(file_ref_txt.file_extension(), Some("txt".to_string()));

        // Test with multiple dots
        let file_ref_tar_gz = FileRef::new(
            "hash".to_string(),
            create_test_encryption_info(),
            Some("archive.tar.gz".to_string()),
        );
        assert_eq!(file_ref_tar_gz.file_extension(), Some("gz".to_string()));

        // Test without extension
        let file_ref_no_ext = FileRef::new(
            "hash".to_string(),
            create_test_encryption_info(),
            Some("README".to_string()),
        );
        assert_eq!(file_ref_no_ext.file_extension(), None);

        // Test with no filename
        let file_ref_no_name =
            FileRef::new("hash".to_string(), create_test_encryption_info(), None);
        assert_eq!(file_ref_no_name.file_extension(), None);

        // Test with hidden file (starts with dot - no extension)
        let file_ref_hidden = FileRef::new(
            "hash".to_string(),
            create_test_encryption_info(),
            Some(".hidden".to_string()),
        );
        assert_eq!(file_ref_hidden.file_extension(), None);

        // Test with hidden file that has extension
        let file_ref_hidden_with_ext = FileRef::new(
            "hash".to_string(),
            create_test_encryption_info(),
            Some(".hidden.txt".to_string()),
        );
        assert_eq!(
            file_ref_hidden_with_ext.file_extension(),
            Some("txt".to_string())
        );
    }

    #[test]
    fn test_file_ref_original_size() {
        let encryption_info = ConvergentEncryptionInfo {
            key: [0u8; 32],
            was_compressed: false,
            source_size: 2048,
        };

        let file_ref = FileRef::new(
            "hash".to_string(),
            encryption_info,
            Some("large_file.bin".to_string()),
        );

        assert_eq!(file_ref.original_size(), 2048);
    }

    #[test]
    fn test_file_ref_builder_pattern() {
        let file_ref = FileRef::new(
            "test_hash".to_string(),
            create_test_encryption_info(),
            Some("image.png".to_string()),
        )
        .with_content_type("image/png".to_string())
        .with_metadata("width".to_string(), "1920".to_string())
        .with_metadata("height".to_string(), "1080".to_string());

        assert_eq!(file_ref.content_type, Some("image/png".to_string()));
        let generic_meta = file_ref.generic_metadata();
        assert_eq!(generic_meta.get("width"), Some(&"1920".to_string()));
        assert_eq!(generic_meta.get("height"), Some(&"1080".to_string()));
    }

    #[test]
    fn test_postcard_serialization_file_ref() {
        let file_ref = create_test_file_ref()
            .with_content_type("text/plain".to_string())
            .with_metadata("test".to_string(), "value".to_string());

        let serialized = postcard::to_stdvec(&file_ref).expect("Failed to serialize");
        let deserialized: FileRef =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(file_ref, deserialized);
    }

    #[test]
    fn test_postcard_serialization_convergent_encryption_info() {
        let encryption_info = create_test_encryption_info();

        let serialized = postcard::to_stdvec(&encryption_info).expect("Failed to serialize");
        let deserialized: ConvergentEncryptionInfo =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(encryption_info, deserialized);
    }

    #[test]
    fn test_postcard_serialization_compression_config() {
        let configs = [
            CompressionConfig::default(),
            CompressionConfig {
                enabled: false,
                quality: 1,
                min_size: 0,
            },
            CompressionConfig {
                enabled: true,
                quality: 11,
                min_size: 1024,
            },
        ];

        for compression in configs {
            let serialized = postcard::to_stdvec(&compression).expect("Failed to serialize");
            let deserialized: CompressionConfig =
                postcard::from_bytes(&serialized).expect("Failed to deserialize");
            assert_eq!(compression.enabled, deserialized.enabled);
            assert_eq!(compression.quality, deserialized.quality);
            assert_eq!(compression.min_size, deserialized.min_size);
        }
    }

    #[test]
    fn test_file_ref_with_different_compression_states() {
        // Test with compressed file
        let encryption_info_compressed = ConvergentEncryptionInfo {
            key: [1u8; 32],
            was_compressed: true,
            source_size: 512,
        };

        let file_ref_compressed = FileRef::new(
            "compressed_hash".to_string(),
            encryption_info_compressed,
            Some("compressed.txt".to_string()),
        );

        assert_eq!(file_ref_compressed.original_size(), 512);
        assert!(file_ref_compressed.encryption_info.was_compressed);

        // Test with uncompressed file
        let encryption_info_uncompressed = ConvergentEncryptionInfo {
            key: [2u8; 32],
            was_compressed: false,
            source_size: 1024,
        };

        let file_ref_uncompressed = FileRef::new(
            "uncompressed_hash".to_string(),
            encryption_info_uncompressed,
            Some("uncompressed.bin".to_string()),
        );

        assert_eq!(file_ref_uncompressed.original_size(), 1024);
        assert!(!file_ref_uncompressed.encryption_info.was_compressed);
    }

    #[test]
    fn test_file_ref_metadata_operations() {
        use crate::Metadata;

        let metadata = vec![Metadata::Generic(
            "initial".to_string(),
            "value".to_string(),
        )];

        let file_ref = FileRef {
            blob_hash: "test".to_string(),
            encryption_info: create_test_encryption_info(),
            filename: None,
            content_type: None,
            metadata,
        };

        // Test existing metadata
        let generic_meta = file_ref.generic_metadata();
        assert_eq!(generic_meta.get("initial"), Some(&"value".to_string()));

        // Test adding more metadata via builder
        let updated_file_ref =
            file_ref.with_metadata("new_key".to_string(), "new_value".to_string());

        let updated_generic_meta = updated_file_ref.generic_metadata();
        assert_eq!(
            updated_generic_meta.get("initial"),
            Some(&"value".to_string())
        );
        assert_eq!(
            updated_generic_meta.get("new_key"),
            Some(&"new_value".to_string())
        );
    }
}
