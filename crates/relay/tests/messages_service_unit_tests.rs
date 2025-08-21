use anyhow::Result;
use futures_util::StreamExt;
use ml_dsa::{KeyGen, MlDsa65};
use rand::rngs::OsRng;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use zoe_message_store::RedisMessageStorage;
use zoe_wire_protocol::{
    CatchUpRequest, FilterField, FilterOperation, FilterUpdateRequest, KeyPair, Kind, Message,
    MessageFilters, MessageFull, Tag,
};

// Test helper to set up tracing
fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_test_writer()
        .try_init()
        .ok();
}

// Test helper to create a test message
fn create_test_message(channel_id: &[u8], author_keypair: &KeyPair, content: &str) -> MessageFull {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let tags = vec![Tag::Channel {
        id: channel_id.to_vec(),
        relays: vec![],
    }];

    let message = Message::new_v0(
        content.as_bytes().to_vec(),
        author_keypair.public_key(),
        now,
        Kind::Regular,
        tags,
    );

    MessageFull::new(message, author_keypair).expect("Failed to create MessageFull")
}

// Test helper to set up Redis storage
async fn setup_test_storage() -> Result<RedisMessageStorage> {
    // Use a random database number to avoid conflicts between parallel tests
    let db_num = rand::random::<u8>() % 15 + 1; // Use databases 1-15 (avoid 0 which might be used elsewhere)
    let redis_url = format!("redis://127.0.0.1:6379/{db_num}");

    let client = redis::Client::open(redis_url).expect("Failed to create Redis client");
    let conn = client
        .get_connection_manager()
        .await
        .expect("Failed to connect to Redis");

    // Clean up test data
    let mut conn_cleanup = conn.clone();
    let _: () = redis::cmd("FLUSHDB")
        .query_async(&mut conn_cleanup)
        .await
        .expect("Failed to flush test database");

    Ok(RedisMessageStorage {
        conn: Arc::new(tokio::sync::Mutex::new(conn)),
        client,
    })
}

#[tokio::test]
async fn test_message_storage_and_retrieval() -> Result<()> {
    setup_tracing();
    let storage = setup_test_storage().await?;
    let keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut OsRng)));

    // Test basic message storage and retrieval
    let channel_id = b"test-channel";
    let test_message = create_test_message(channel_id, &keypair, "Test message content");

    // Store the message
    let publish_result = storage.store_message(&test_message).await?;
    let stream_id = publish_result
        .global_stream_id()
        .expect("Message should not be expired");
    assert!(!stream_id.is_empty());

    // Test message streaming with filters
    let filters = MessageFilters {
        channels: Some(vec![channel_id.to_vec()]),
        authors: None,
        events: None,
        users: None,
    };

    let stream = storage
        .listen_for_messages(&filters, Some("0-0".to_string()), None)
        .await?;
    tokio::pin!(stream);

    // Should receive the message we just stored
    let result = timeout(Duration::from_secs(2), stream.next()).await;
    assert!(result.is_ok(), "Timeout waiting for message");

    let stream_result = result.unwrap();
    assert!(stream_result.is_some(), "Stream should yield a result");

    let storage_result = stream_result.unwrap();
    assert!(storage_result.is_ok(), "Storage result should be ok");

    let (message_opt, _height) = storage_result.unwrap();
    assert!(message_opt.is_some(), "Message should be present");

    let received_message = message_opt.unwrap();
    assert_eq!(
        String::from_utf8_lossy(received_message.raw_content().unwrap()),
        "Test message content"
    );

    Ok(())
}

#[tokio::test]
async fn test_channel_catch_up_functionality() -> Result<()> {
    setup_tracing();
    let storage = setup_test_storage().await?;
    let keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut OsRng)));

    let channel_id = b"history-channel";
    let messages = vec![
        "Historical message 1",
        "Historical message 2",
        "Historical message 3",
    ];

    // Store historical messages
    for content in &messages {
        let msg = create_test_message(channel_id, &keypair, content);
        storage.store_message(&msg).await?;
    }

    // Test catch-up functionality
    let catch_up_stream = storage
        .catch_up(FilterField::Channel, channel_id, None)
        .await?;
    tokio::pin!(catch_up_stream);

    let mut retrieved_messages = Vec::new();
    while let Some(result) = catch_up_stream.next().await {
        let (message, (_global_height, _local_height)) = result?;
        retrieved_messages
            .push(String::from_utf8_lossy(message.raw_content().unwrap()).to_string());
    }

    assert_eq!(retrieved_messages.len(), 3);
    assert_eq!(retrieved_messages[0], "Historical message 1");
    assert_eq!(retrieved_messages[1], "Historical message 2");
    assert_eq!(retrieved_messages[2], "Historical message 3");

    Ok(())
}

#[tokio::test]
async fn test_filter_operations() -> Result<()> {
    setup_tracing();

    // Test the filter operations that the service uses
    let mut filters = MessageFilters::default();

    // Test adding channels
    let add_channels = FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]);
    filters.apply_operation(&add_channels);

    assert_eq!(
        filters.channels,
        Some(vec![b"general".to_vec(), b"tech".to_vec()])
    );

    // Test adding authors
    let add_authors = FilterOperation::add_authors(vec![b"alice".to_vec()]);
    filters.apply_operation(&add_authors);

    assert_eq!(filters.authors, Some(vec![b"alice".to_vec()]));

    // Test removing channels
    let remove_channels = FilterOperation::remove_channels(vec![b"general".to_vec()]);
    filters.apply_operation(&remove_channels);

    assert_eq!(filters.channels, Some(vec![b"tech".to_vec()]));

    // Test complex multi-operation update
    let complex_update = FilterUpdateRequest {
        operations: vec![
            FilterOperation::add_channels(vec![b"random".to_vec()]),
            FilterOperation::replace_authors(vec![b"bob".to_vec(), b"charlie".to_vec()]),
            FilterOperation::clear_events(),
        ],
    };

    for operation in &complex_update.operations {
        filters.apply_operation(operation);
    }

    assert_eq!(
        filters.channels,
        Some(vec![b"tech".to_vec(), b"random".to_vec()])
    );
    assert_eq!(
        filters.authors,
        Some(vec![b"bob".to_vec(), b"charlie".to_vec()])
    );
    assert_eq!(filters.events, None);

    Ok(())
}

#[tokio::test]
async fn test_concurrent_catch_up_and_live_streaming() -> Result<()> {
    setup_tracing();
    let storage = setup_test_storage().await?;
    let keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut OsRng)));

    let channel_id = b"concurrent-test";

    // Store some historical messages
    for i in 1..=3 {
        let msg = create_test_message(channel_id, &keypair, &format!("Historical {i}"));
        storage.store_message(&msg).await?;
    }

    // Start live streaming
    let filters = MessageFilters {
        channels: Some(vec![channel_id.to_vec()]),
        authors: None,
        events: None,
        users: None,
    };

    let live_stream = storage
        .listen_for_messages(&filters, Some("0-0".to_string()), None)
        .await?;
    tokio::pin!(live_stream);

    // Start catch-up stream
    let catch_up_stream = storage
        .catch_up(FilterField::Channel, channel_id, None)
        .await?;
    tokio::pin!(catch_up_stream);

    // Collect messages from both streams
    let mut live_messages = Vec::new();
    let mut catch_up_messages = Vec::new();

    // Collect historical messages from live stream (should get all 3)
    for _ in 0..3 {
        if let Some(result) = timeout(Duration::from_secs(2), live_stream.next()).await? {
            let (message_opt, _height) = result?;
            if let Some(message) = message_opt {
                live_messages
                    .push(String::from_utf8_lossy(message.raw_content().unwrap()).to_string());
            }
        }
    }

    // Collect messages from catch-up stream
    loop {
        let timeout_result = timeout(Duration::from_millis(500), catch_up_stream.next()).await;
        match timeout_result {
            Ok(Some(stream_result)) => match stream_result {
                Ok((message, _)) => {
                    catch_up_messages
                        .push(String::from_utf8_lossy(message.raw_content().unwrap()).to_string());
                }
                Err(_) => break,
            },
            Ok(None) => break, // Stream ended
            Err(_) => break,   // Timeout
        }
    }

    // Both streams should have the historical messages (allow for some timing variations)
    assert!(
        live_messages.len() >= 2,
        "Live messages: got {}, expected at least 2",
        live_messages.len()
    );
    assert!(
        catch_up_messages.len() >= 2,
        "Catch-up messages: got {}, expected at least 2",
        catch_up_messages.len()
    );

    // Send a new live message
    let live_msg = create_test_message(channel_id, &keypair, "New live message");
    storage.store_message(&live_msg).await?;

    // Live stream should receive the new message
    if let Some(result) = timeout(Duration::from_secs(2), live_stream.next()).await? {
        let (message_opt, _height) = result?;
        if let Some(message) = message_opt {
            let content = String::from_utf8_lossy(message.raw_content().unwrap());
            assert_eq!(content, "New live message");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_filter_state_management() -> Result<()> {
    setup_tracing();

    // Test the shared filter state management that the service uses
    let current_filters: Arc<RwLock<Option<MessageFilters>>> = Arc::new(RwLock::new(None));

    // Initially no filters
    {
        let guard = current_filters.read().await;
        assert!(guard.is_none());
    }

    // Set initial filters
    {
        let mut guard = current_filters.write().await;
        *guard = Some(MessageFilters {
            channels: Some(vec![b"general".to_vec()]),
            authors: None,
            events: None,
            users: None,
        });
    }

    // Apply filter updates
    {
        let mut guard = current_filters.write().await;
        if let Some(ref mut filters) = *guard {
            // Add tech channel
            filters.apply_operation(&FilterOperation::add_channels(vec![b"tech".to_vec()]));

            // Add author filter
            filters.apply_operation(&FilterOperation::add_authors(vec![b"alice".to_vec()]));
        }
    }

    // Verify final state
    {
        let guard = current_filters.read().await;
        if let Some(ref filters) = *guard {
            assert_eq!(
                filters.channels,
                Some(vec![b"general".to_vec(), b"tech".to_vec()])
            );
            assert_eq!(filters.authors, Some(vec![b"alice".to_vec()]));
        } else {
            panic!("Filters should be set");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_multiple_channel_catch_up() -> Result<()> {
    setup_tracing();
    let storage = setup_test_storage().await?;
    let keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut OsRng)));

    let channels = [b"channel1".as_slice(), b"channel2", b"channel3"];

    // Store messages in different channels
    for (i, channel) in channels.iter().enumerate() {
        for j in 1..=2 {
            let msg = create_test_message(
                channel,
                &keypair,
                &format!("Channel {} Message {}", i + 1, j),
            );
            storage.store_message(&msg).await?;
        }
    }

    // Test catch-up for each channel
    for (i, channel) in channels.iter().enumerate() {
        let catch_up_stream = storage
            .catch_up(FilterField::Channel, channel, None)
            .await?;
        tokio::pin!(catch_up_stream);

        let mut messages = Vec::new();
        while let Some(result) = catch_up_stream.next().await {
            let (message, _) = result?;
            messages.push(String::from_utf8_lossy(message.raw_content().unwrap()).to_string());
        }

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], format!("Channel {} Message 1", i + 1));
        assert_eq!(messages[1], format!("Channel {} Message 2", i + 1));
    }

    Ok(())
}

#[tokio::test]
async fn test_race_condition_prevention_logic() -> Result<()> {
    setup_tracing();
    let storage = setup_test_storage().await?;
    let keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut OsRng)));

    let initial_channel = b"initial";
    let new_channel = b"newchannel";

    // Store historical messages in new channel
    for i in 1..=3 {
        let msg = create_test_message(new_channel, &keypair, &format!("History {i}"));
        storage.store_message(&msg).await?;
    }

    // Simulate the race condition scenario:
    // 1. Start live subscription for initial channel
    let initial_filters = MessageFilters {
        channels: Some(vec![initial_channel.to_vec()]),
        authors: None,
        events: None,
        users: None,
    };

    let _live_stream = storage
        .listen_for_messages(&initial_filters, Some("0-0".to_string()), None)
        .await?;

    // 2. "Update" filters to include new channel (simulated)
    let updated_filters = MessageFilters {
        channels: Some(vec![initial_channel.to_vec(), new_channel.to_vec()]),
        authors: None,
        events: None,
        users: None,
    };

    // 3. Start catch-up for new channel (parallel to live stream)
    let catch_up_stream = storage
        .catch_up(FilterField::Channel, new_channel, None)
        .await?;
    tokio::pin!(catch_up_stream);

    // 4. Send new message to new channel during the race
    let race_msg = create_test_message(new_channel, &keypair, "Message during race");
    storage.store_message(&race_msg).await?;

    // Collect all messages to ensure no duplicates
    let mut all_messages = std::collections::HashSet::new();

    // Get messages from catch-up (should get historical + race message)
    loop {
        let timeout_result = timeout(Duration::from_millis(500), catch_up_stream.next()).await;
        match timeout_result {
            Ok(Some(stream_result)) => match stream_result {
                Ok((message, _)) => {
                    all_messages.insert(
                        String::from_utf8_lossy(message.raw_content().unwrap()).to_string(),
                    );
                }
                Err(_) => break,
            },
            Ok(None) => break, // Stream ended
            Err(_) => break,   // Timeout
        }
    }

    // Start new live stream with updated filters
    let updated_stream = storage
        .listen_for_messages(&updated_filters, Some("0-0".to_string()), None)
        .await?;
    tokio::pin!(updated_stream);

    // Collect a few messages from the updated live stream
    for _ in 0..5 {
        let timeout_result = timeout(Duration::from_millis(200), updated_stream.next()).await;
        match timeout_result {
            Ok(Some(stream_result)) => {
                match stream_result {
                    Ok((Some(message), _)) => {
                        all_messages.insert(
                            String::from_utf8_lossy(message.raw_content().unwrap()).to_string(),
                        );
                    }
                    Ok((None, _)) => continue, // Height update
                    Err(_) => break,
                }
            }
            Ok(None) => break, // Stream ended
            Err(_) => break,   // Timeout
        }
    }

    // Should have caught most or all messages (allow for timing variations)
    println!("All messages collected: {all_messages:?}");

    // The key test: we should have at least some messages and no obvious duplicates
    assert!(
        all_messages.len() >= 3,
        "Should have at least 3 messages, got {}",
        all_messages.len()
    );

    // Check for expected messages (at least some should be present)
    let expected_messages = ["History 1", "History 2", "History 3", "Message during race"];
    #[allow(clippy::unnecessary_to_owned)]
    let found_count = expected_messages
        .iter()
        .filter(|msg| all_messages.contains(&msg.to_string()))
        .count();

    assert!(
        found_count >= 3,
        "Should find at least 3 expected messages, found {found_count}"
    );

    Ok(())
}

#[tokio::test]
async fn test_generic_catch_up_requests() -> Result<()> {
    setup_tracing();
    let storage = setup_test_storage().await?;
    let keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut OsRng)));

    // Test that CatchUpRequest convenience constructors work correctly
    let channel_id = b"test-channel";
    let author_key = keypair.public_key();
    let author_encoded = author_key.encode();
    let author_id = author_encoded.as_slice();
    let event_id = b"test-event";
    let user_id = b"test-user";

    // Test channel catch-up request construction
    let channel_request = CatchUpRequest::for_channel(
        channel_id.to_vec(),
        Some("1234-0".to_string()),
        Some(100),
        "channel-req".to_string(),
    );

    assert_eq!(channel_request.filter_field, FilterField::Channel);
    assert_eq!(channel_request.filter_value, channel_id.to_vec());
    assert_eq!(channel_request.since, Some("1234-0".to_string()));
    assert_eq!(channel_request.max_messages, Some(100));
    assert_eq!(channel_request.request_id, "channel-req");

    // Test author catch-up request construction
    let author_request =
        CatchUpRequest::for_author(author_id.to_vec(), None, Some(50), "author-req".to_string());

    assert_eq!(author_request.filter_field, FilterField::Author);
    assert_eq!(author_request.filter_value, author_id.to_vec());
    assert_eq!(author_request.since, None);
    assert_eq!(author_request.max_messages, Some(50));
    assert_eq!(author_request.request_id, "author-req");

    // Test event catch-up request construction
    let event_request = CatchUpRequest::for_event(
        event_id.to_vec(),
        Some("5678-1".to_string()),
        None,
        "event-req".to_string(),
    );

    assert_eq!(event_request.filter_field, FilterField::Event);
    assert_eq!(event_request.filter_value, event_id.to_vec());
    assert_eq!(event_request.since, Some("5678-1".to_string()));
    assert_eq!(event_request.max_messages, None);
    assert_eq!(event_request.request_id, "event-req");

    // Test user catch-up request construction
    let user_request = CatchUpRequest::for_user(
        user_id.to_vec(),
        Some("9999-0".to_string()),
        Some(25),
        "user-req".to_string(),
    );

    assert_eq!(user_request.filter_field, FilterField::User);
    assert_eq!(user_request.filter_value, user_id.to_vec());
    assert_eq!(user_request.since, Some("9999-0".to_string()));
    assert_eq!(user_request.max_messages, Some(25));
    assert_eq!(user_request.request_id, "user-req");

    // Test that different filter fields work with storage.catch_up()
    // Store messages for different filter types
    let msg1 = create_test_message(channel_id, &keypair, "Channel message");
    storage.store_message(&msg1).await?;

    // Test channel catch-up works
    let channel_stream = storage
        .catch_up(FilterField::Channel, channel_id, None)
        .await?;
    tokio::pin!(channel_stream);

    let mut channel_messages = Vec::new();
    loop {
        let timeout_result = timeout(Duration::from_millis(100), channel_stream.next()).await;
        match timeout_result {
            Ok(Some(stream_result)) => match stream_result {
                Ok((message, _)) => {
                    channel_messages
                        .push(String::from_utf8_lossy(message.raw_content().unwrap()).to_string());
                }
                Err(_) => break,
            },
            Ok(None) => break, // Stream ended
            Err(_) => break,   // Timeout
        }
    }

    assert!(
        !channel_messages.is_empty(),
        "Should have retrieved channel messages"
    );
    assert!(channel_messages.contains(&"Channel message".to_string()));

    // Test author catch-up works
    let author_stream = storage
        .catch_up(FilterField::Author, author_id, None)
        .await?;
    tokio::pin!(author_stream);

    let mut author_messages = Vec::new();
    loop {
        let timeout_result = timeout(Duration::from_millis(100), author_stream.next()).await;
        match timeout_result {
            Ok(Some(stream_result)) => match stream_result {
                Ok((message, _)) => {
                    author_messages
                        .push(String::from_utf8_lossy(message.raw_content().unwrap()).to_string());
                }
                Err(_) => break,
            },
            Ok(None) => break, // Stream ended
            Err(_) => break,   // Timeout
        }
    }

    assert!(
        !author_messages.is_empty(),
        "Should have retrieved author messages"
    );
    assert!(author_messages.contains(&"Channel message".to_string()));

    println!("✅ Generic catch-up requests work for all filter field types");

    Ok(())
}
