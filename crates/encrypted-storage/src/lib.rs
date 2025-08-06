//! # Convergent Encryption with Brotli Compression
//!
//! This crate provides convergent encryption for self-encrypting files for untrusted storage.
//! It uses Blake3 for key derivation, AES-256-GCM for encryption, and optional Brotli compression.
//!
//! ## Key Features
//!
//! - **Convergent Encryption**: Same content always produces the same ciphertext
//! - **Content-Based Key Derivation**: Encryption key is derived from file content using Blake3
//! - **Optional Compression**: Brotli compression reduces storage requirements
//! - **Deterministic**: Perfect for deduplication and integrity verification
//! - **No Key Management**: No need to store or manage encryption keys separately
//!
//! ## How It Works
//!
//! 1. **Compression** (optional): Content is compressed with Brotli if it reduces size
//! 2. **Key Derivation**: File content is hashed with Blake3 to create a 32-byte encryption key
//! 3. **Encryption**: AES-256-GCM encrypts the data using the derived key as both key and nonce
//! 4. **Metadata**: Compression status, original size, and encryption key are tracked for decryption
//!
//! ## Usage Example
//!
//! ```rust
//! use zoey_encrypted_storage::{ConvergentEncryption, CompressionConfig};
//!
//! // Basic encryption with default settings
//! let content = b"Hello, world!";
//! let (encrypted, info) = ConvergentEncryption::encrypt(content).unwrap();
//! let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();
//! assert_eq!(content, decrypted.as_slice());
//!
//! // Custom compression settings
//! let config = CompressionConfig {
//!     enabled: true,
//!     quality: 8,      // Higher compression (0-11)
//!     min_size: 128,   // Only compress files > 128 bytes
//! };
//! let (encrypted, info) = ConvergentEncryption::encrypt_with_compression_config(content, config).unwrap();
//! ```
//!
//! ## Security Considerations
//!
//! - **Convergent encryption reveals when identical files are stored**
//! - **The encryption key is derived from content, so knowledge of content allows decryption**
//! - **AES-256-GCM provides authenticated encryption**
//! - **Blake3 provides cryptographically secure hashing**
//!
//! This approach is ideal for:
//! - File deduplication systems
//! - Content-addressable storage
//! - Integrity verification
//! - Untrusted storage where you control the content

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use blake3::Hasher;
use brotli::{CompressorWriter, Decompressor};
use serde::{Deserialize, Serialize};
use std::io::{Cursor, Read, Write};
use thiserror::Error;

/// Error types for convergent encryption operations
#[derive(Debug, Error)]
pub enum ConvergentEncryptionError {
    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(aes_gcm::Error),
    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(aes_gcm::Error),
    /// Brotli compression failed
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    /// Brotli decompression failed
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
    /// Invalid key length provided
    #[error("Invalid key length")]
    InvalidKeyLength,
    /// Invalid nonce length provided
    #[error("Invalid nonce length")]
    InvalidNonceLength,
}

/// Encryption key derived from source content for convergent encryption
///
/// This is a 32-byte Blake3 hash of the content, used as both the encryption key
/// and the first 12 bytes as the nonce for AES-256-GCM.
pub type ConvergentEncryptionKey = [u8; 32];

/// Metadata about the encryption operation
///
/// Contains information needed for decryption, including whether compression
/// was applied and the original file size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvergentEncryptionInfo {
    /// The encryption key derived from the content
    pub key: ConvergentEncryptionKey,
    /// Whether Brotli compression was applied
    pub was_compressed: bool,
    /// Original size of the content before encryption
    pub source_size: usize,
}

/// Configuration for Brotli compression settings
///
/// Controls when and how compression is applied during encryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Whether to enable compression
    pub enabled: bool,
    /// Brotli compression quality (0-11, higher = better compression but slower)
    pub quality: u32,
    /// Minimum size threshold for compression (bytes)
    pub min_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            quality: 6,   // Good balance between speed and compression
            min_size: 64, // Don't compress very small content
        }
    }
}

/// Convergent encryption using AES-256-GCM with Blake3 key derivation and Brotli compression
///
/// This implementation provides convergent encryption where the encryption key
/// is derived from the content itself using Blake3. This enables:
///
/// - **Deterministic encryption**: Same content always produces the same ciphertext
/// - **Content-based deduplication**: Identical files can be identified by their key
/// - **No key management**: No need to store or manage encryption keys separately
/// - **Integrity verification**: Can verify file integrity by re-deriving the key
/// - **Optional compression**: Brotli compression reduces storage requirements
///
/// ## Security Model
///
/// - The 32-byte Blake3 hash serves as both the encryption key and nonce (first 12 bytes)
/// - AES-256-GCM provides authenticated encryption with integrity protection
/// - Compression is applied before encryption to maximize storage efficiency
/// - The same content will always produce the same ciphertext, enabling deduplication
///
/// ## Limitations
///
/// - **Identical content detection**: Adversaries can determine when identical files are stored
/// - **No forward secrecy**: If the content is known, the encryption can be broken
///
/// This approach is ideal for scenarios where you control the content and want
/// to benefit from deduplication and integrity verification.
pub struct ConvergentEncryption;

impl ConvergentEncryption {
    /// Derive encryption key from source content using Blake3
    ///
    /// This function calculates a 32-byte encryption key from the content using Blake3.
    /// The same content will always produce the same key, enabling convergent encryption.
    ///
    /// The derived key is used as both the encryption key and nonce for AES-256-GCM.
    ///
    /// # Arguments
    ///
    /// * `content` - The source content to derive the key from
    ///
    /// # Returns
    ///
    /// A 32-byte encryption key derived from the content
    fn derive_key(content: &[u8]) -> ConvergentEncryptionKey {
        let mut hasher = Hasher::new();
        hasher.update(content);
        *hasher.finalize().as_bytes()
    }

    /// Compress content using Brotli if beneficial
    ///
    /// Attempts to compress the content using Brotli. Only applies compression if:
    /// - Compression is enabled in the config
    /// - Content size is above the minimum threshold
    /// - Compressed size is smaller than the original
    ///
    /// # Arguments
    ///
    /// * `content` - The content to potentially compress
    /// * `config` - Compression configuration settings
    ///
    /// # Returns
    ///
    /// A tuple containing the data to encrypt (compressed or original) and a flag
    /// indicating whether compression was applied.
    fn compress(
        content: &[u8],
        config: &CompressionConfig,
    ) -> Result<(Vec<u8>, bool), ConvergentEncryptionError> {
        if !config.enabled || content.len() < config.min_size {
            return Ok((content.to_vec(), false));
        }
        let mut compressed = Vec::new();
        {
            let mut compressor = CompressorWriter::new(&mut compressed, 4096, config.quality, 22);
            compressor
                .write_all(content)
                .map_err(|e| ConvergentEncryptionError::CompressionFailed(e.to_string()))?;
        }
        if compressed.len() < content.len() {
            Ok((compressed, true))
        } else {
            Ok((content.to_vec(), false))
        }
    }

    /// Decompress content using Brotli
    ///
    /// Attempts to decompress the content using Brotli. This function assumes
    /// the content was compressed and will return an error if decompression fails.
    ///
    /// # Arguments
    ///
    /// * `content` - The compressed content to decompress
    ///
    /// # Returns
    ///
    /// The decompressed content
    fn decompress(content: &[u8]) -> Result<Vec<u8>, ConvergentEncryptionError> {
        let mut decompressed = Vec::new();
        let mut decompressor = Decompressor::new(Cursor::new(content), 4096);
        decompressor
            .read_to_end(&mut decompressed)
            .map_err(|e| ConvergentEncryptionError::DecompressionFailed(e.to_string()))?;
        Ok(decompressed)
    }

    /// Encrypt plaintext using convergent encryption with custom compression settings
    ///
    /// This function performs the complete encryption process:
    /// 1. Derives the encryption key from the content using Blake3
    /// 2. Compresses the content if beneficial (based on config)
    /// 3. Encrypts the data using AES-256-GCM with the derived key
    /// 4. Returns both the ciphertext and metadata for decryption
    ///
    /// The same plaintext will always produce the same ciphertext,
    /// enabling convergent encryption and deduplication.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The content to encrypt
    /// * `config` - Compression configuration settings
    ///
    /// # Returns
    ///
    /// A tuple containing the encrypted ciphertext and metadata needed for decryption
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoey_encrypted_storage::{ConvergentEncryption, CompressionConfig};
    ///
    /// let content = b"Hello, world!";
    ///
    /// // Encrypt with custom compression
    /// let config = CompressionConfig {
    ///     enabled: true,
    ///     quality: 8,
    ///     min_size: 128,
    /// };
    /// let (encrypted, info) = ConvergentEncryption::encrypt_with_compression_config(content, config).unwrap();
    /// ```
    pub fn encrypt_with_compression_config(
        plaintext: &[u8],
        config: CompressionConfig,
    ) -> Result<(Vec<u8>, ConvergentEncryptionInfo), ConvergentEncryptionError> {
        let key = Self::derive_key(plaintext);
        let filesize = plaintext.len();

        // Step 1: Compress if beneficial
        let (data_to_encrypt, was_compressed) = Self::compress(plaintext, &config)?;

        // Step 2: Encrypt the data (compressed or original)
        let enc_key = Key::<Aes256Gcm>::from_slice(&key);
        let nonce = Nonce::from_slice(&key[..12]); // Use first 12 bytes as nonce

        let cipher = Aes256Gcm::new(enc_key);
        let ciphertext = cipher
            .encrypt(nonce, &*data_to_encrypt)
            .map_err(ConvergentEncryptionError::EncryptionFailed)?;

        Ok((
            ciphertext,
            ConvergentEncryptionInfo {
                key,
                was_compressed,
                source_size: filesize,
            },
        ))
    }

    /// Decrypt ciphertext using the provided metadata with automatic decompression
    ///
    /// This function performs the complete decryption process:
    /// 1. Decrypts the ciphertext using AES-256-GCM
    /// 2. Decompresses the data if it was compressed during encryption
    /// 3. Returns the original plaintext
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data to decrypt
    /// * `config` - Metadata containing the key and compression information
    ///
    /// # Returns
    ///
    /// The original plaintext content
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoey_encrypted_storage::ConvergentEncryption;
    ///
    /// let content = b"Hello, world!";
    /// let (encrypted, info) = ConvergentEncryption::encrypt(content).unwrap();
    /// let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();
    /// assert_eq!(content, decrypted.as_slice());
    /// ```
    pub fn decrypt(
        ciphertext: &[u8],
        config: &ConvergentEncryptionInfo,
    ) -> Result<Vec<u8>, ConvergentEncryptionError> {
        // Step 1: Decrypt
        let enc_key = Key::<Aes256Gcm>::from_slice(&config.key);
        let nonce = Nonce::from_slice(&config.key[..12]); // Use first 12 bytes as nonce
        let cipher = Aes256Gcm::new(enc_key);
        let decrypted_data = cipher
            .decrypt(nonce, ciphertext)
            .map_err(ConvergentEncryptionError::DecryptionFailed)?;
        // Step 2: Decompress if needed
        if config.was_compressed {
            return Self::decompress(&decrypted_data);
        }
        Ok(decrypted_data)
    }

    /// Convenience function: encrypt content with default compression settings
    ///
    /// This function combines key derivation, compression, and encryption in one step
    /// using the default compression configuration. It's the simplest way to encrypt
    /// content with convergent encryption.
    ///
    /// # Arguments
    ///
    /// * `content` - The content to encrypt
    ///
    /// # Returns
    ///
    /// A tuple containing the encrypted ciphertext and metadata needed for decryption
    ///
    /// # Example
    ///
    /// ```rust
    /// use zoey_encrypted_storage::ConvergentEncryption;
    ///
    /// let content = b"Hello, world!";
    /// let (encrypted, info) = ConvergentEncryption::encrypt(content).unwrap();
    /// let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();
    /// assert_eq!(content, decrypted.as_slice());
    /// ```
    pub fn encrypt(
        content: &[u8],
    ) -> Result<(Vec<u8>, ConvergentEncryptionInfo), ConvergentEncryptionError> {
        Self::encrypt_with_compression_config(content, CompressionConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let content = b"Hello, convergent encryption!";

        let key1 = ConvergentEncryption::derive_key(content);
        let key2 = ConvergentEncryption::derive_key(content);

        // Same content should produce identical keys
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let content = b"Test message for encryption/decryption";

        let (encrypted, info) = ConvergentEncryption::encrypt_with_compression_config(
            content,
            CompressionConfig::default(),
        )
        .unwrap();
        let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();

        assert_ne!(&encrypted[..], content);
        assert_eq!(content, decrypted.as_slice());
    }

    #[test]
    fn test_convergent_encryption_deterministic() {
        let plaintext = b"Hello, convergent encryption!";

        // Encrypt the same content twice using the convenience function
        let (encrypted1, _info1) = ConvergentEncryption::encrypt(plaintext).unwrap();
        let (encrypted2, _info2) = ConvergentEncryption::encrypt(plaintext).unwrap();

        // Should produce identical ciphertext (convergent property)
        assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_convergent_encryption_decrypt() {
        let plaintext = b"Test message for decryption";

        let (encrypted, info) = ConvergentEncryption::encrypt(plaintext).unwrap();
        let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_file_encryption() {
        let file_content = b"This is a test file content for convergent encryption";

        let (encrypted, info) = ConvergentEncryption::encrypt(file_content).unwrap();

        // Key should be consistent
        let expected_key = ConvergentEncryption::derive_key(file_content);
        assert_eq!(info.key, expected_key);

        // Should be able to decrypt
        let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();
        assert_eq!(file_content, decrypted.as_slice());
    }

    #[test]
    fn test_different_content_produces_different_ciphertext() {
        let content1 = b"First content";
        let content2 = b"Second content";

        let (encrypted1, info1) = ConvergentEncryption::encrypt(content1).unwrap();
        let (encrypted2, info2) = ConvergentEncryption::encrypt(content2).unwrap();

        // Different content should produce different ciphertext
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(encrypted1, content1);
        assert_ne!(encrypted2, content2);
        assert_ne!(info1.key, info2.key);
    }

    #[test]
    fn test_different_content_produces_different_keys() {
        let content1 = b"First content";
        let content2 = b"Second content";

        let key1 = ConvergentEncryption::derive_key(content1);
        let key2 = ConvergentEncryption::derive_key(content2);

        // Different content should produce different keys
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_key_can_be_used_for_deduplication() {
        let content1 = b"Same content";
        let content2 = b"Same content";
        let content3 = b"Different content";

        let key1 = ConvergentEncryption::derive_key(content1);
        let key2 = ConvergentEncryption::derive_key(content2);
        let key3 = ConvergentEncryption::derive_key(content3);

        // Same content should have same key (for deduplication)
        assert_eq!(key1, key2);

        // Different content should have different keys
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }

    #[test]
    fn test_compression_works() {
        // Create compressible content (repeating pattern)
        let compressible_content = b"Hello world! ".repeat(100);

        let config = CompressionConfig {
            enabled: true,
            quality: 6,
            min_size: 64,
        };

        let (encrypted, info) =
            ConvergentEncryption::encrypt_with_compression_config(&compressible_content, config)
                .unwrap();
        let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();

        assert_eq!(compressible_content, decrypted.as_slice());
    }

    #[test]
    fn test_compression_disabled() {
        let content = b"Test content";

        let config = CompressionConfig {
            enabled: false,
            quality: 6,
            min_size: 64,
        };

        let (encrypted, info) =
            ConvergentEncryption::encrypt_with_compression_config(content, config).unwrap();
        let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();

        assert_eq!(content, decrypted.as_slice());
    }

    #[test]
    fn test_compression_below_min_size() {
        let small_content = b"Small";

        let config = CompressionConfig {
            enabled: true,
            quality: 6,
            min_size: 100, // Larger than content
        };

        let (encrypted, info) =
            ConvergentEncryption::encrypt_with_compression_config(small_content, config).unwrap();
        let decrypted = ConvergentEncryption::decrypt(&encrypted, &info).unwrap();

        assert_eq!(small_content, decrypted.as_slice());
    }

    #[test]
    fn test_compression_deterministic() {
        let compressible_content = b"Repeating pattern ".repeat(50);

        let config = CompressionConfig {
            enabled: true,
            quality: 6,
            min_size: 64,
        };

        let (encrypted1, _info1) = ConvergentEncryption::encrypt_with_compression_config(
            &compressible_content,
            config.clone(),
        )
        .unwrap();
        let (encrypted2, _info2) =
            ConvergentEncryption::encrypt_with_compression_config(&compressible_content, config)
                .unwrap();

        // Should produce identical ciphertext even with compression
        assert_eq!(encrypted1, encrypted2);
    }
}
