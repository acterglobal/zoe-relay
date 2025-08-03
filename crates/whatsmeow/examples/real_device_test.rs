use qrcode::render::unicode;
use qrcode::QrCode;
use std::io::{self, Write};
use whatsmeow::{ConnectionStatus, WhatsAppBot};

/// Display a QR code in scannable ASCII format
fn display_qr_code(qr_data: &str) {
    println!("\n┌─────────────────────────────────────────────────────────────┐");
    println!("│                     📱 WHATSAPP QR CODE                      │");
    println!("├─────────────────────────────────────────────────────────────┤");
    println!("│                                                             │");
    println!("│  ⚠️  IMPORTANT: This QR code connects to YOUR WhatsApp!     │");
    println!("│                                                             │");
    println!("│  📱 TO SCAN:                                                │");
    println!("│  1. Open WhatsApp on your phone                            │");
    println!("│  2. Go to Settings > Linked Devices                        │");
    println!("│  3. Tap 'Link a Device'                                     │");
    println!("│  4. Scan this QR code with your phone's camera             │");
    println!("│                                                             │");
    println!("└─────────────────────────────────────────────────────────────┘");
    println!();

    // Generate actual QR code from the data
    match QrCode::new(qr_data) {
        Ok(code) => {
            let image = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .build();

            println!("┌{}┐", "─".repeat(50));
            println!("│{:^48}│", "📱 SCAN WITH WHATSAPP");
            println!("├{}┤", "─".repeat(50));

            // Display the QR code centered
            for line in image.lines() {
                // Center the QR code line within our box
                let padded_line = format!("{line:^48}");
                println!("│{padded_line}│");
            }

            println!("├{}┤", "─".repeat(50));
            println!("│{:^48}│", "⏰ Expires in ~20 seconds");
            println!("└{}┘", "─".repeat(50));
        }
        Err(e) => {
            println!("❌ Failed to generate QR code: {e}");
            println!("📋 Raw QR data: {qr_data}");
        }
    }

    println!();

    // Add visual separator and clear call to action
    println!("🎯 ACTION REQUIRED:");
    println!("   📱 Scan the QR code above with your WhatsApp mobile app");
    println!("   ⏳ You have about 20 seconds before the code expires");
    println!("   🔄 If it expires, just restart this example for a new code");
    println!();
}

fn wait_for_user_confirmation(message: &str) {
    println!("📋 {message}");
    println!("   ⏸️  Press Enter when ready to continue...");
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}

fn prompt_user(message: &str) -> String {
    print!("{message}");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 WhatsApp Bot - Real Device Test");
    println!("===================================");
    println!("🔥 This uses REAL WhatsApp servers and will generate scannable QR codes!");
    println!();

    println!("⚠️  This test requires:");
    println!("   • Real phone number");
    println!("   • WhatsApp mobile app");
    println!("   • User interaction for QR scanning");
    println!("   • Internet connection");
    println!("   • Good lighting for QR code scanning");
    println!("   • Stable network connection");

    wait_for_user_confirmation("Have your WhatsApp mobile app ready for QR scanning");

    // Step 1: Create bot
    println!("\n1️⃣ Creating WhatsApp bot...");
    let bot = WhatsAppBot::new()?;
    println!("   ✅ Bot created successfully");

    // Step 2: Get QR code for authentication
    println!("\n2️⃣ Getting QR code for authentication...");
    println!("   🔄 Requesting QR code from WhatsApp servers...");

    match bot.get_qr_code().await {
        Ok(qr_code) => {
            if !qr_code.is_empty() {
                println!("   ✅ Real QR Code received from WhatsApp servers!");

                // Display the QR code in a scannable format
                display_qr_code(&qr_code);

                println!("🚀 NEXT STEPS:");
                println!("   1. Use your phone's WhatsApp app to scan the QR code above");
                println!("   2. Follow the in-app instructions to link this device");
                println!("   3. Wait for 'Device linked' confirmation on your phone");

                wait_for_user_confirmation(
                    "After scanning the QR code and seeing 'Device linked' on your phone",
                );
            } else {
                println!("   ℹ️  No QR code needed (already authenticated)");
                println!("   📱 Your device is already linked to WhatsApp");
            }
        }
        Err(e) => {
            println!("   ⚠️  QR code generation failed: {e}");
            println!("   💡 This might be normal if already authenticated");
            println!("   🔄 Try disconnecting and reconnecting if issues persist");
        }
    }

    // Step 3: Wait for connection and check status
    println!("\n3️⃣ Waiting for WhatsApp connection...");

    // Try connecting
    match bot.connect().await {
        Ok(_) => println!("   ✅ Connection attempt initiated"),
        Err(e) => println!("   ⚠️  Connection failed: {e}"),
    }

    // Check connection status multiple times with better feedback
    println!("   🔄 Verifying connection status...");
    let mut connected = false;

    for attempt in 1..=10 {
        println!("   📡 Connection check {attempt}/10...");

        match bot.get_connection_status().await {
            Ok(status) => match status {
                ConnectionStatus::Connected => {
                    println!("   🎉 SUCCESS: Connected to WhatsApp!");
                    println!("   📱 Your device is now linked and ready to use");
                    connected = true;
                    break;
                }
                ConnectionStatus::Connecting => {
                    println!("   🔄 Status: Connecting... (please wait)");
                }
                ConnectionStatus::Disconnected => {
                    println!("   📴 Status: Disconnected");
                    if attempt > 5 {
                        println!("   💡 Try scanning the QR code again if connection fails");
                    }
                }
                ConnectionStatus::LoggedOut => {
                    println!("   🚪 Status: Logged out - QR code scan may be required");
                }
            },
            Err(e) => println!("   ❌ Status check error: {e}"),
        }

        if attempt < 10 {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    // Step 4: Test basic functionality
    if connected {
        println!("\n4️⃣ Testing basic functionality...");

        // Test contacts
        println!("   📞 Getting contacts...");
        match bot.get_contacts().await {
            Ok(contacts) => {
                println!("   ✅ Retrieved {} contacts", contacts.len());
                if !contacts.is_empty() {
                    println!("   👥 First few contacts:");
                    for (i, contact) in contacts.iter().take(3).enumerate() {
                        let name = contact.name.as_deref().unwrap_or("<No Name>");
                        println!("      {}. {} ({})", i + 1, name, contact.jid);
                    }
                    if contacts.len() > 3 {
                        println!("      ... and {} more", contacts.len() - 3);
                    }
                }
            }
            Err(e) => println!("   ⚠️  Contact retrieval failed: {e}"),
        }

        // Test groups
        println!("   👥 Getting groups...");
        match bot.get_groups().await {
            Ok(groups) => {
                println!("   ✅ Retrieved {} groups", groups.len());
                if !groups.is_empty() {
                    println!("   📋 Groups:");
                    for (i, group) in groups.iter().take(3).enumerate() {
                        println!(
                            "      {}. {} ({} members)",
                            i + 1,
                            group.name,
                            group.participants.len()
                        );
                    }
                    if groups.len() > 3 {
                        println!("      ... and {} more", groups.len() - 3);
                    }
                }
            }
            Err(e) => println!("   ⚠️  Group retrieval failed: {e}"),
        }

        // Optional: Send test message
        let send_test = prompt_user("\n💬 Would you like to send a test message? (y/N): ");
        if send_test.to_lowercase() == "y" {
            let recipient =
                prompt_user("   📱 Enter recipient (format: +1234567890@s.whatsapp.net): ");
            if !recipient.is_empty() && recipient.contains("@s.whatsapp.net") {
                let message = format!(
                    "🤖 Test message from Rust WhatsApp bot at {}",
                    chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
                );
                println!("   📝 Sending: {message}");

                match bot.send_message(&recipient, &message).await {
                    Ok(msg_id) => println!("   ✅ Message sent! ID: {msg_id}"),
                    Err(e) => println!("   ❌ Message failed: {e}"),
                }
            } else {
                println!("   ❌ Invalid recipient format");
            }
        }
    }

    // Final status summary
    if connected {
        println!("\n✅ Real device test completed successfully!");
        println!("   🎯 Result: WhatsApp connection established");
        println!("   📱 Device: Successfully linked to your WhatsApp account");
        println!("   🔗 Status: Ready for messaging and other operations");
        println!("   🚀 Your WhatsApp bot is now working with real servers!");
    } else {
        println!("\n⚠️ Real device test completed with warnings");
        println!("   📋 Check the status messages above for details");
        println!("   🔄 You may need to re-run this example with a fresh QR code");
        println!("   💡 Ensure your phone has a stable internet connection");
    }

    // Step 5: Cleanup
    println!("\n5️⃣ Cleanup");
    match bot.disconnect().await {
        Ok(_) => println!("   ✅ Disconnected successfully"),
        Err(e) => println!("   ⚠️  Disconnect failed: {e}"),
    }

    Ok(())
}
