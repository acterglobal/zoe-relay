use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;
use whatsmeow::WhatsAppBot;
use tempfile::tempdir;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔍 QR Code Generation Test");
    println!("==========================");

    // Create bot
    println!("📱 Creating WhatsApp bot...");
    let temp_dir = tempdir().unwrap();
    let bot = WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap())?;
    println!("✅ Bot created successfully");

    // Test QR code generation
    println!("🔄 Requesting QR code from WhatsApp servers...");
    println!("   (This may take up to 45 seconds)");

    match bot.get_qr_code().await {
        Ok(qr_code) => {
            if qr_code.is_empty() {
                println!(
                    "✅ QR code generation successful (no code needed - already authenticated)"
                );
            } else {
                println!("✅ QR code generation successful!");
                println!("📋 QR Code length: {} characters", qr_code.len());

                // Generate and display visual QR code
                match QrCode::new(&qr_code) {
                    Ok(code) => {
                        let image = code
                            .render::<unicode::Dense1x2>()
                            .dark_color(unicode::Dense1x2::Light)
                            .light_color(unicode::Dense1x2::Dark)
                            .build();

                        println!("\n┌{}┐", "─".repeat(50));
                        println!("│{:^48}│", "📱 SCAN WITH WHATSAPP");
                        println!("├{}┤", "─".repeat(50));

                        // Display the QR code
                        for line in image.lines() {
                            let padded_line = format!("{line:^48}");
                            println!("│{padded_line}│");
                        }

                        println!("├{}┤", "─".repeat(50));
                        println!("│{:^48}│", "Ready to scan!");
                        println!("└{}┘", "─".repeat(50));
                    }
                    Err(e) => {
                        println!("❌ Failed to generate visual QR code: {e}");
                        println!("🔗 Raw QR data: {qr_code}");
                    }
                }
            }
        }
        Err(e) => {
            println!("❌ QR code generation failed: {e}");
        }
    }

    println!("\n✅ QR code test completed!");
    Ok(())
}
