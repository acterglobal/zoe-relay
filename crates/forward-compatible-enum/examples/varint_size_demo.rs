//! Demonstration of varint encoding size differences between u8, u16, and u32
//!
//! This example shows that for most practical enum discriminants (< 1000 cases),
//! using u8, u16, or u32 makes NO difference in wire format size due to varint encoding.

use forward_compatible_enum::U32Discriminants;
use serde::{Deserialize, Serialize};

// Let's test with different integer types for discriminants

/// Same enum with u8 discriminants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u8", into = "u8")]
pub enum StatusU8 {
    Unknown,
    Active,
    Inactive,
    Pending,
    Banned,
}

impl From<u8> for StatusU8 {
    fn from(value: u8) -> Self {
        match value {
            0 => StatusU8::Unknown,
            1 => StatusU8::Active,
            2 => StatusU8::Inactive,
            3 => StatusU8::Pending,
            4 => StatusU8::Banned,
            _ => StatusU8::Unknown,
        }
    }
}

impl From<StatusU8> for u8 {
    fn from(value: StatusU8) -> Self {
        match value {
            StatusU8::Unknown => 0,
            StatusU8::Active => 1,
            StatusU8::Inactive => 2,
            StatusU8::Pending => 3,
            StatusU8::Banned => 4,
        }
    }
}

/// Same enum with u16 discriminants
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "u16", into = "u16")]
pub enum StatusU16 {
    Unknown,
    Active,
    Inactive,
    Pending,
    Banned,
}

impl From<u16> for StatusU16 {
    fn from(value: u16) -> Self {
        match value {
            0 => StatusU16::Unknown,
            1 => StatusU16::Active,
            2 => StatusU16::Inactive,
            3 => StatusU16::Pending,
            4 => StatusU16::Banned,
            _ => StatusU16::Unknown,
        }
    }
}

impl From<StatusU16> for u16 {
    fn from(value: StatusU16) -> Self {
        match value {
            StatusU16::Unknown => 0,
            StatusU16::Active => 1,
            StatusU16::Inactive => 2,
            StatusU16::Pending => 3,
            StatusU16::Banned => 4,
        }
    }
}

/// Same enum with our U32Discriminants derive macro
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, U32Discriminants)]
#[serde(from = "u32", into = "u32")]
pub enum StatusU32 {
    #[discriminant(0)]
    Unknown,

    #[discriminant(1)]
    Active,

    #[discriminant(2)]
    Inactive,

    #[discriminant(3)]
    Pending,

    #[discriminant(4)]
    Banned,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Varint Size Comparison: u8 vs u16 vs u32 ===\n");

    // Test discriminants from small to moderately large
    let test_discriminants = [
        0, 1, 2, 3, 4, // Tiny (< 5)
        127, 128, // 7-bit boundary
        255, 256, // 8-bit boundary
        16383, 16384, // 14-bit boundary
        65535, 65536, // 16-bit boundary
        127000, 130000, // Large but realistic
    ];

    println!("Testing discriminant values and their postcard serialization sizes:\n");
    println!(
        "{:>10} | {:>8} | {:>8} | {:>8} | {:>15}",
        "Value", "u8 size", "u16 size", "u32 size", "Wire Format"
    );
    println!(
        "{:-^10}|{:-^10}|{:-^10}|{:-^10}|{:-^17}",
        "", "", "", "", ""
    );

    for &discriminant in &test_discriminants {
        // Serialize u8 (if it fits)
        let u8_size = if discriminant <= u8::MAX as u32 {
            let bytes = postcard::to_stdvec(&(discriminant as u8))?;
            Some((bytes.len(), bytes))
        } else {
            None
        };

        // Serialize u16 (if it fits)
        let u16_size = if discriminant <= u16::MAX as u32 {
            let bytes = postcard::to_stdvec(&(discriminant as u16))?;
            Some((bytes.len(), bytes))
        } else {
            None
        };

        // Serialize u32
        let u32_bytes = postcard::to_stdvec(&discriminant)?;
        let u32_size = (u32_bytes.len(), u32_bytes.clone());

        // Format wire representation
        let wire_format = format!("{u32_bytes:?}");

        println!(
            "{:>10} | {:>8} | {:>8} | {:>8} | {:>15}",
            discriminant,
            u8_size
                .as_ref()
                .map(|s| s.0.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            u16_size
                .as_ref()
                .map(|s| s.0.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            u32_size.0,
            wire_format
        );

        // Verify they're all the same when they fit
        if let Some(u8_data) = u8_size
            && let Some(u16_data) = u16_size
        {
            assert_eq!(
                u8_data.1, u16_data.1,
                "u8 and u16 should serialize identically"
            );
            assert_eq!(
                u16_data.1, u32_size.1,
                "u16 and u32 should serialize identically"
            );
        }
    }

    println!("\n=== Key Insights ===\n");

    println!("1. 📏 **Wire size is IDENTICAL for small values regardless of integer type**");
    println!("   - Values 0-127: Always 1 byte on wire (regardless of u8/u16/u32)");
    println!("   - Values 128-16383: Always 2 bytes on wire");
    println!("   - Values 16384-2097151: Always 3 bytes on wire");

    println!("\n2. 🧮 **Varint encoding makes integer type irrelevant for small values**");
    println!("   - postcard uses variable-length encoding (LEB128-style)");
    println!("   - Only the VALUE matters, not the container type");
    println!("   - u8::MAX (255) and u32::from(255) encode identically");

    println!("\n3. 🎯 **For your use case (< 1000 enum variants):**");
    println!("   - All discriminants will be ≤ 1000, so always 1-2 bytes maximum");
    println!("   - u8 vs u16 vs u32 makes ZERO difference in wire size");
    println!("   - u32 is actually more convenient (no overflow concerns)");

    println!("\n4. 💡 **Performance comparison:**");

    // Test enum serialization sizes
    let status_u8 = StatusU8::Active;
    let status_u16 = StatusU16::Active;
    let status_u32 = StatusU32::Active;

    let bytes_u8 = postcard::to_stdvec(&status_u8)?;
    let bytes_u16 = postcard::to_stdvec(&status_u16)?;
    let bytes_u32 = postcard::to_stdvec(&status_u32)?;

    println!(
        "   - StatusU8::Active:  {} bytes {:?}",
        bytes_u8.len(),
        bytes_u8
    );
    println!(
        "   - StatusU16::Active: {} bytes {:?}",
        bytes_u16.len(),
        bytes_u16
    );
    println!(
        "   - StatusU32::Active: {} bytes {:?}",
        bytes_u32.len(),
        bytes_u32
    );

    assert_eq!(bytes_u8, bytes_u16);
    assert_eq!(bytes_u16, bytes_u32);

    println!("   ✅ All three produce identical wire format!");

    println!("\n=== Recommendation ===\n");

    println!("🏆 **Stick with u32 discriminants** because:");
    println!("   • No wire size penalty (thanks to varint encoding)");
    println!("   • No overflow concerns when adding new enum variants");
    println!("   • Simpler than managing u8/u16 boundaries");
    println!("   • Same performance characteristics");
    println!("   • More room for sparse discriminant numbering (e.g., 10, 20, 30...)");

    println!("\n🔬 **Technical details:**");
    println!("   • postcard uses LEB128 varint encoding");
    println!("   • Values 0-127: 1 byte (0xxxxxxx)");
    println!("   • Values 128-16383: 2 bytes (1xxxxxxx 0xxxxxxx)");
    println!("   • For enum discriminants < 1000: Always 1-2 bytes regardless of integer type");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identical_wire_formats() {
        // Test that all three integer types produce identical serialization
        let status_u8 = StatusU8::Pending;
        let status_u16 = StatusU16::Pending;
        let status_u32 = StatusU32::Pending;

        let bytes_u8 = postcard::to_stdvec(&status_u8).unwrap();
        let bytes_u16 = postcard::to_stdvec(&status_u16).unwrap();
        let bytes_u32 = postcard::to_stdvec(&status_u32).unwrap();

        assert_eq!(bytes_u8, bytes_u16);
        assert_eq!(bytes_u16, bytes_u32);
        assert_eq!(bytes_u8, vec![3]); // Discriminant 3 in 1 byte
    }

    #[test]
    fn test_varint_size_boundaries() {
        // Values that test varint encoding boundaries
        let test_cases = [
            (127u32, 1),   // Max 1-byte varint
            (128u32, 2),   // Min 2-byte varint
            (16383u32, 2), // Max 2-byte varint
            (16384u32, 3), // Min 3-byte varint
        ];

        for (value, expected_size) in test_cases {
            let bytes = postcard::to_stdvec(&value).unwrap();
            assert_eq!(
                bytes.len(),
                expected_size,
                "Value {} should encode to {} bytes, got {}",
                value,
                expected_size,
                bytes.len()
            );
        }
    }
}
