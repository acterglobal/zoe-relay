//! Simple test to understand postcard's varint behavior with different integer types

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Understanding Postcard's Varint Behavior ===\n");

    // Test the same numeric value serialized as different integer types
    let test_values = [0, 1, 127, 128, 255, 256, 16383, 16384];

    for value in test_values {
        println!("Value: {value}");

        // Test u8 (if it fits)
        if value <= u8::MAX as usize {
            let u8_bytes = postcard::to_stdvec(&(value as u8))?;
            println!("  u8:  {:?} ({} bytes)", u8_bytes, u8_bytes.len());
        }

        // Test u16 (if it fits)
        if value <= u16::MAX as usize {
            let u16_bytes = postcard::to_stdvec(&(value as u16))?;
            println!("  u16: {:?} ({} bytes)", u16_bytes, u16_bytes.len());
        }

        // Test u32
        let u32_bytes = postcard::to_stdvec(&(value as u32))?;
        println!("  u32: {:?} ({} bytes)", u32_bytes, u32_bytes.len());

        println!();
    }

    println!("=== Key Discovery ===");
    println!();
    println!("🔍 **Postcard serializes DIFFERENT integer types DIFFERENTLY!**");
    println!("   • u8 values use a simpler encoding");
    println!("   • u16/u32 values use varint encoding even for small numbers");
    println!("   • This explains why u8(128) ≠ u16(128) on the wire");

    println!("\n📋 **Implications for your enum discriminants:**");
    println!("   • u8 discriminants: More compact for values ≤ 255");
    println!("   • u16 discriminants: Varint overhead but more room");
    println!("   • u32 discriminants: Same varint overhead as u16 for small values");

    println!("\n💡 **Recommendation:**");
    println!("   • For enum discriminants < 256: u8 is most efficient");
    println!("   • For enum discriminants ≥ 256: u16 and u32 are equivalent");
    println!("   • If you ever need > 255 variants: stick with u32 for simplicity");

    // Test boundary cases more carefully
    println!("\n=== Detailed Analysis ===");

    // Compare u8 vs u16 for the same small values
    for value in [0, 1, 127, 128, 255] {
        let u8_bytes = postcard::to_stdvec(&(value as u8))?;
        let u16_bytes = postcard::to_stdvec(&(value as u16))?;
        let u32_bytes = postcard::to_stdvec(&(value as u32))?;

        println!(
            "Value {}: u8={} bytes, u16={} bytes, u32={} bytes",
            value,
            u8_bytes.len(),
            u16_bytes.len(),
            u32_bytes.len()
        );
    }

    Ok(())
}
