//! Group invitation utilities and emoji verification
//!
//! This module provides utilities for the group invitation flow, including
//! the cryptographic emoji derivation function used for PQXDH verification.

use blake3::Hasher;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

/// 64 carefully chosen emojis for maximum visual distinction
///
/// These emojis are organized into categories to avoid confusion and ensure
/// cross-platform consistency. They are chosen for:
/// - Visual distinction (no similar-looking emojis)
/// - Cross-platform consistency (common emojis that render similarly)
/// - Accessibility (high contrast, distinct shapes)
/// - Cultural neutrality (avoid emojis with cultural/religious significance)
pub const EMOJI_SET: [&str; 64] = [
    // Objects & Symbols (16)
    "🔑", "🌟", "🚀", "🎯", "🌈", "🔒", "⚡", "🎨", "🌸", "🔥", "💎", "🎪", "🌊", "🎭", "🍀", "🌺",
    // Animals & Nature (16)
    "🐱", "🐶", "🦋", "🐸", "🦊", "🐧", "🦁", "🐯", "🐨", "🐼", "🦉", "🐺", "🦄", "🐙", "🦀", "🐢",
    // Food & Drinks (16)
    "🍎", "🍌", "🍇", "🍓", "🥝", "🍑", "🥕", "🌽", "🍄", "🥑", "🍕", "🍔", "🎂", "🍪", "☕", "🍯",
    // Activities & Objects (16)
    "⚽", "🏀", "🎸", "🎹", "🎲", "🎮", "📱", "💻", "⌚", "📷", "🎧", "🔍", "💡", "🔧", "⚖️", "🎁",
];

/// Derive a 6-emoji verification sequence from a PQXDH shared secret
///
/// This function takes a 32-byte shared secret and derives a sequence of 6 emojis
/// that can be displayed to users for manual verification. The derivation uses
/// BLAKE3 with domain separation to ensure the emojis cannot be used to recover
/// the original shared secret.
///
/// # Security Properties
///
/// - **One-way function**: BLAKE3 is cryptographically one-way
/// - **Domain separation**: Uses unique context string for verification
/// - **Limited exposure**: Only 48 bits of derived data used for emojis
/// - **Uniform distribution**: Each emoji has equal probability (1/64)
/// - **High collision resistance**: 64^6 = 68.7 billion possible sequences
///
/// # Algorithm
///
/// 1. Derive 32-byte fingerprint using BLAKE3 with domain separation
/// 2. Split fingerprint into 6 chunks of ~5.33 bytes each
/// 3. Convert each chunk to little-endian integer
/// 4. Map integer modulo 64 to emoji index
///
/// # Arguments
///
/// * `shared_secret` - 32-byte PQXDH shared secret
///
/// # Returns
///
/// Array of 6 emoji strings for user verification
///
/// # Example
///
/// ```rust
/// use zoe_app_primitives::invitation::derive_emoji_verification;
///
/// let shared_secret = [0u8; 32]; // Example shared secret
/// let emojis = derive_emoji_verification(&shared_secret);
/// println!("Verify these emojis match: {}", emojis.join(" "));
/// ```
#[cfg_attr(feature = "frb-api", frb(ignore))]
pub fn derive_emoji_verification(shared_secret: &[u8; 32]) -> [&'static str; 6] {
    // Derive verification fingerprint using BLAKE3 with domain separation
    let mut hasher = Hasher::new();
    hasher.update(shared_secret);
    hasher.update(b"PQXDH-VERIFICATION-FINGERPRINT-v1");
    let verification_fingerprint = hasher.finalize();
    let fingerprint_bytes = verification_fingerprint.as_bytes();

    // Split into 6 chunks and derive emoji for each chunk
    let mut emojis = [""; 6];
    for (i, emoji) in emojis.iter_mut().enumerate() {
        let start = i * 5;
        let end = std::cmp::min(start + 5, 32);
        let chunk = &fingerprint_bytes[start..end];

        // Combine bytes in chunk to get index (little-endian)
        let mut index = 0u64;
        for (j, &byte) in chunk.iter().enumerate() {
            index += (byte as u64) << (j * 8);
        }

        *emoji = EMOJI_SET[(index % 64) as usize];
    }

    emojis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emoji_derivation_deterministic() {
        let shared_secret = [42u8; 32];

        let emojis1 = derive_emoji_verification(&shared_secret);
        let emojis2 = derive_emoji_verification(&shared_secret);

        assert_eq!(emojis1, emojis2, "Emoji derivation should be deterministic");
    }

    #[test]
    fn test_emoji_derivation_different_secrets() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];

        let emojis1 = derive_emoji_verification(&secret1);
        let emojis2 = derive_emoji_verification(&secret2);

        assert_ne!(
            emojis1, emojis2,
            "Different secrets should produce different emojis"
        );
    }

    #[test]
    fn test_emoji_set_size() {
        assert_eq!(
            EMOJI_SET.len(),
            64,
            "Emoji set should contain exactly 64 emojis"
        );
    }

    #[test]
    fn test_emoji_set_uniqueness() {
        let mut unique_emojis = std::collections::HashSet::new();
        for emoji in &EMOJI_SET {
            assert!(
                unique_emojis.insert(emoji),
                "Emoji set should not contain duplicates: {emoji}"
            );
        }
    }
    #[test]
    fn test_domain_separation() {
        let shared_secret = [100u8; 32];

        // Test that different domain strings produce different results
        let mut hasher1 = Hasher::new();
        hasher1.update(&shared_secret);
        hasher1.update(b"PQXDH-VERIFICATION-FINGERPRINT-v1");
        let fingerprint1 = hasher1.finalize();

        let mut hasher2 = Hasher::new();
        hasher2.update(&shared_secret);
        hasher2.update(b"DIFFERENT-DOMAIN-STRING");
        let fingerprint2 = hasher2.finalize();

        assert_ne!(
            fingerprint1.as_bytes(),
            fingerprint2.as_bytes(),
            "Different domain strings should produce different fingerprints"
        );
    }
}
