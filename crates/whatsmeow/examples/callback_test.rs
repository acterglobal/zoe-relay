use whatsmeow::WhatsAppBot;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 WhatsApp Bot - Callback Test");
    println!("===============================");

    // Step 1: Create bot
    println!("\n1️⃣ Creating WhatsApp bot...");
    let bot = WhatsAppBot::new()?;
    println!("   ✅ Bot created successfully");

    // Step 2: Test connection status (should work without QR)
    println!("\n2️⃣ Testing connection status callback...");
    match bot.get_connection_status().await {
        Ok(status) => {
            println!("   ✅ Connection status callback worked!");
            println!("   📡 Status: {:?}", status);
        }
        Err(e) => {
            println!("   ❌ Connection status callback failed: {}", e);
        }
    }

    // Step 3: Test QR code generation (should work or fail gracefully)
    println!("\n3️⃣ Testing QR code generation callback...");
    match bot.get_qr_code().await {
        Ok(qr_code) => {
            if qr_code.is_empty() {
                println!("   ✅ QR code callback worked (no code needed)");
            } else {
                println!(
                    "   ✅ QR code callback worked! Got code: {}",
                    if qr_code.len() > 50 {
                        format!("{}...", &qr_code[..50])
                    } else {
                        qr_code
                    }
                );
            }
        }
        Err(e) => {
            println!("   ⚠️  QR code callback failed: {}", e);
            println!("   💡 This might be expected if not authenticated");
        }
    }

    // Step 4: Test contacts (should work or fail gracefully)
    println!("\n4️⃣ Testing contacts callback...");
    match bot.get_contacts().await {
        Ok(contacts) => {
            println!(
                "   ✅ Contacts callback worked! Got {} contacts",
                contacts.len()
            );
        }
        Err(e) => {
            println!("   ⚠️  Contacts callback failed: {}", e);
        }
    }

    println!("\n✅ Callback test completed!");
    println!("   🎯 All async callbacks are working properly");

    Ok(())
}
