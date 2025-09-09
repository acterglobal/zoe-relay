/// Integration tests for the WhatsApp bot
use anyhow::Result;
use zoe_wa_bot::{
    WhatsAppBot,
    connectable::WhatsAppBotExt,
    util::{extract_name_from_jid, should_display_message},
};

#[tokio::test]
async fn test_bot_initialization() -> Result<()> {
    let bot = WhatsAppBot::new("test.db")?;

    // Should be able to get connection status
    let _status = bot.get_connection_status().await?;

    // In test mode, should be disconnected by default
    assert!(!bot.is_connected().await?);

    Ok(())
}

#[tokio::test]
async fn test_qr_code_display_flow() -> Result<()> {
    let bot = WhatsAppBot::new("test.db")?;

    // Should show QR code since bot is disconnected in test mode
    let qr_displayed = bot.show_qr_code_if_needed().await?;
    assert!(
        qr_displayed,
        "QR code should be displayed for disconnected bot"
    );

    Ok(())
}

#[tokio::test]
async fn test_connection_operations() -> Result<()> {
    let bot = WhatsAppBot::new("test.db")?;

    // Test connection attempt
    bot.connect().await?;

    // Test wait for connection (should timeout quickly in test mode)
    let connected = bot.wait_for_connection(2).await?;
    assert!(!connected, "Should timeout in test mode");

    Ok(())
}

#[tokio::test]
async fn test_message_sending() -> Result<()> {
    let bot = WhatsAppBot::new("test.db")?;

    let message_id = bot
        .send_message("test@s.whatsapp.net", "Test message")
        .await?;

    // Mock should return a message ID
    assert_eq!(message_id, "msg_mock_123");

    Ok(())
}

#[tokio::test]
async fn test_inner_access() -> Result<()> {
    let bot = WhatsAppBot::new("test.db")?;
    // WhatsAppBot is now used directly, no inner() method needed

    // Should be able to access bot methods directly
    let _status = bot.get_connection_status().await?;

    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let bot = WhatsAppBot::new("test.db")?;

    // Test that multiple async operations can run concurrently
    let (status_result, qr_result, message_result) = tokio::join!(
        bot.get_connection_status(),
        bot.show_qr_code_if_needed(),
        bot.send_message("test@s.whatsapp.net", "Concurrent test")
    );

    // All operations should succeed
    assert!(status_result.is_ok());
    assert!(qr_result.is_ok());
    assert!(message_result.is_ok());

    // Message should return mock ID
    assert_eq!(message_result.unwrap(), "msg_mock_123");

    Ok(())
}

#[tokio::test]
async fn test_custom_db_path() -> Result<()> {
    // Test creating bot with custom database path
    let bot = WhatsAppBot::new("/tmp/test_whatsapp.db")?;

    // Should still work normally
    let _status = bot.get_connection_status().await?;

    Ok(())
}

#[tokio::test]
async fn test_message_stream_creation() -> Result<()> {
    // Test creating a message stream
    let bot = WhatsAppBot::new("test.db")?;

    // Should be able to create a message stream
    let _stream = bot.message_stream()?;

    // Should be able to stop the stream
    bot.stop_message_stream()?;

    Ok(())
}

#[tokio::test]
async fn test_message_stream_lifecycle() -> Result<()> {
    use tokio::time::{Duration, timeout};
    use tokio_stream::StreamExt;

    let bot = WhatsAppBot::new("test.db")?;

    // Create message stream
    let mut stream = bot.message_stream()?;

    // In test mode, the stream should not produce any messages immediately
    // Test with a short timeout to ensure it doesn't hang
    let result = timeout(Duration::from_millis(100), stream.next()).await;

    // Should timeout since no messages are being sent in test mode
    assert!(result.is_err(), "Stream should timeout in test mode");

    // Clean up
    bot.stop_message_stream()?;

    Ok(())
}

#[tokio::test]
async fn test_message_filtering() -> Result<()> {
    use whatsmeow::MessageEvent;

    // Create test messages
    let group_message = MessageEvent {
        id: "test1".to_string(),
        chat: "123456789-987654321@g.us".to_string(),
        sender: "1234567890@s.whatsapp.net".to_string(),
        timestamp: 1234567890,
        message_type: "text".to_string(),
        content: "Hello group!".to_string(),
        is_from_me: false,
    };

    let dm_message = MessageEvent {
        id: "test2".to_string(),
        chat: "1234567890@s.whatsapp.net".to_string(),
        sender: "1234567890@s.whatsapp.net".to_string(),
        timestamp: 1234567890,
        message_type: "text".to_string(),
        content: "Hello DM!".to_string(),
        is_from_me: false,
    };

    // Test group filter
    assert!(should_display_message(
        &group_message,
        &None,
        &None,
        true,
        false
    ));
    assert!(!should_display_message(
        &dm_message,
        &None,
        &None,
        true,
        false
    ));

    // Test DM filter
    assert!(!should_display_message(
        &group_message,
        &None,
        &None,
        false,
        true
    ));
    assert!(should_display_message(
        &dm_message,
        &None,
        &None,
        false,
        true
    ));

    // Test sender filter
    assert!(should_display_message(
        &group_message,
        &Some("1234".to_string()),
        &None,
        false,
        false
    ));
    assert!(!should_display_message(
        &group_message,
        &Some("9999".to_string()),
        &None,
        false,
        false
    ));

    Ok(())
}

#[test]
fn test_jid_name_extraction() {
    // Test phone number JID
    assert_eq!(
        extract_name_from_jid("1234567890@s.whatsapp.net"),
        "+1234567890"
    );

    // Test group JID
    assert!(extract_name_from_jid("123456789-987654321@g.us").starts_with("Group-"));

    // Test short JID
    assert_eq!(extract_name_from_jid("123@s.whatsapp.net"), "123");
}
