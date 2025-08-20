use futures_util::StreamExt;
use ml_dsa::{KeyGen, MlDsa65};
use rand::rngs::OsRng;
use std::{sync::Arc, time::SystemTime};
use zoe_message_store::RedisMessageStorage;
use zoe_wire_protocol::{
    FilterField, FilterOperation, FilterUpdateRequest, KeyPair, Kind, Message, MessageFilters, MessageFull,
    Tag,
};

async fn setup_test_storage() -> RedisMessageStorage {
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

    RedisMessageStorage {
        conn: Arc::new(tokio::sync::Mutex::new(conn)),
        client,
    }
}

fn create_test_message(
    channel_id: &[u8],
    author_keypair: &KeyPair,
    content: &str,
) -> MessageFull {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
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

#[tokio::test]
async fn test_generic_filter_operations() {
    let mut filters = MessageFilters::default();

    // Test Add operation
    let add_channels = FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]);
    filters.apply_operation(&add_channels);

    assert_eq!(
        filters.channels,
        Some(vec![b"general".to_vec(), b"tech".to_vec()])
    );

    // Test Add authors
    let add_authors = FilterOperation::add_authors(vec![b"alice".to_vec(), b"bob".to_vec()]);
    filters.apply_operation(&add_authors);

    assert_eq!(
        filters.authors,
        Some(vec![b"alice".to_vec(), b"bob".to_vec()])
    );

    // Test Remove operation
    let remove_channel = FilterOperation::remove_channels(vec![b"general".to_vec()]);
    filters.apply_operation(&remove_channel);

    assert_eq!(filters.channels, Some(vec![b"tech".to_vec()]));

    // Test Replace operation
    let replace_events =
        FilterOperation::replace_events(vec![b"important".to_vec(), b"urgent".to_vec()]);
    filters.apply_operation(&replace_events);

    assert_eq!(
        filters.events,
        Some(vec![b"important".to_vec(), b"urgent".to_vec()])
    );

    // Test Clear operation
    let clear_authors = FilterOperation::clear_authors();
    filters.apply_operation(&clear_authors);

    assert_eq!(filters.authors, None);

    // Test convenience constructors
    let clear_channels = FilterOperation::clear_channels();
    filters.apply_operation(&clear_channels);
    assert_eq!(filters.channels, None);

    // Test ReplaceAll
    let new_filters = MessageFilters {
        channels: Some(vec![b"new-channel".to_vec()]),
        authors: Some(vec![b"new-author".to_vec()]),
        events: None,
        users: None,
    };
    let replace_all = FilterOperation::ReplaceAll(new_filters.clone());
    filters.apply_operation(&replace_all);

    assert_eq!(filters, new_filters);
}

#[tokio::test]
async fn test_atomic_multi_field_operations() {
    let mut filters = MessageFilters::default();

    let operations = vec![
        FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]),
        FilterOperation::add_authors(vec![b"alice".to_vec()]),
        FilterOperation::add_events(vec![b"important".to_vec()]),
        FilterOperation::add_users(vec![b"user1".to_vec()]),
    ];

    // Apply all operations atomically
    for operation in &operations {
        filters.apply_operation(operation);
    }

    assert_eq!(
        filters.channels,
        Some(vec![b"general".to_vec(), b"tech".to_vec()])
    );
    assert_eq!(filters.authors, Some(vec![b"alice".to_vec()]));
    assert_eq!(filters.events, Some(vec![b"important".to_vec()]));
    assert_eq!(filters.users, Some(vec![b"user1".to_vec()]));
}

#[tokio::test]
async fn test_channel_streams_storage_and_retrieval() {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut OsRng));

    let channel_a = b"channel-a";
    let channel_b = b"channel-b";

    // Create test messages for different channels
    let msg1 = create_test_message(channel_a, &keypair, "Message 1 in channel A");
    let msg2 = create_test_message(channel_b, &keypair, "Message 1 in channel B");
    let msg3 = create_test_message(channel_a, &keypair, "Message 2 in channel A");
    let msg4 = create_test_message(channel_a, &keypair, "Message 3 in channel A");

    // Store messages in order
    let publish_result1 = storage
        .store_message(&msg1)
        .await
        .expect("Failed to store msg1");
    let stream_id1 = publish_result1
        .global_stream_id()
        .expect("Message should not be expired");
    println!("Stored msg1 with stream ID: {stream_id1}");

    let publish_result2 = storage
        .store_message(&msg2)
        .await
        .expect("Failed to store msg2");
    let stream_id2 = publish_result2
        .global_stream_id()
        .expect("Message should not be expired");
    println!("Stored msg2 with stream ID: {stream_id2}");

    let publish_result3 = storage
        .store_message(&msg3)
        .await
        .expect("Failed to store msg3");
    let stream_id3 = publish_result3
        .global_stream_id()
        .expect("Message should not be expired");
    println!("Stored msg3 with stream ID: {stream_id3}");

    let publish_result4 = storage
        .store_message(&msg4)
        .await
        .expect("Failed to store msg4");
    let stream_id4 = publish_result4
        .global_stream_id()
        .expect("Message should not be expired");
    println!("Stored msg4 with stream ID: {stream_id4}");

    // Test channel catch-up retrieval - should maintain arrival order
    let channel_a_stream = storage
        .catch_up(FilterField::Channel, channel_a, None)
        .await
        .expect("Failed to get channel A catch-up stream");

    tokio::pin!(channel_a_stream);

    let mut channel_a_messages = Vec::new();
    while let Some(result) = channel_a_stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                channel_a_messages.push(message);
            }
            Err(e) => panic!("Error in channel A stream: {e:?}"),
        }
    }

    assert_eq!(channel_a_messages.len(), 3);

    // Verify messages are in correct order by content
    let content1 = String::from_utf8_lossy(
        channel_a_messages[0]
            .raw_content()
            .expect("Expected raw content"),
    );
    assert_eq!(content1, "Message 1 in channel A");

    let content2 = String::from_utf8_lossy(
        channel_a_messages[1]
            .raw_content()
            .expect("Expected raw content"),
    );
    assert_eq!(content2, "Message 2 in channel A");

    let content3 = String::from_utf8_lossy(
        channel_a_messages[2]
            .raw_content()
            .expect("Expected raw content"),
    );
    assert_eq!(content3, "Message 3 in channel A");

    // Test channel B catch-up
    let channel_b_stream = storage
        .catch_up(FilterField::Channel, channel_b, None)
        .await
        .expect("Failed to get channel B catch-up stream");

    tokio::pin!(channel_b_stream);

    let mut channel_b_messages = Vec::new();
    while let Some(result) = channel_b_stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                channel_b_messages.push(message);
            }
            Err(e) => panic!("Error in channel B stream: {e:?}"),
        }
    }

    assert_eq!(channel_b_messages.len(), 1);
    let content_b = String::from_utf8_lossy(
        channel_b_messages[0]
            .raw_content()
            .expect("Expected raw content"),
    );
    assert_eq!(content_b, "Message 1 in channel B");
}

#[tokio::test]
async fn test_filter_update_request() {
    // Test the FilterUpdateRequest structure
    let operations = vec![
        FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]),
        FilterOperation::remove_authors(vec![b"spammer".to_vec()]),
        FilterOperation::add_events(vec![b"important".to_vec()]),
    ];

    let filter_request = FilterUpdateRequest { operations };

    assert_eq!(filter_request.operations.len(), 3);

    // Test that we can apply all operations
    let mut filters = MessageFilters::default();
    for operation in &filter_request.operations {
        filters.apply_operation(operation);
    }

    assert_eq!(
        filters.channels,
        Some(vec![b"general".to_vec(), b"tech".to_vec()])
    );
    assert_eq!(filters.authors, None); // Nothing was added, so removing has no effect
    assert_eq!(filters.events, Some(vec![b"important".to_vec()]));
}

#[tokio::test]
async fn test_duplicate_prevention() {
    let mut filters = MessageFilters::default();

    // Add same channel twice
    let add_channels1 = FilterOperation::add_channels(vec![b"general".to_vec()]);
    let add_channels2 = FilterOperation::add_channels(vec![b"general".to_vec()]);

    filters.apply_operation(&add_channels1);
    filters.apply_operation(&add_channels2);

    // Should only have one instance
    assert_eq!(filters.channels, Some(vec![b"general".to_vec()]));
}

#[tokio::test]
async fn test_comprehensive_scenario() {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut OsRng));

    // Simulate a complex real-world scenario
    let general_channel = b"general";
    let tech_channel = b"tech";
    let urgent_channel = b"urgent";

    // Create initial filters (user starts with general channel)
    let mut filters = MessageFilters::default();
    filters.apply_operation(&FilterOperation::add_channels(vec![
        general_channel.to_vec()
    ]));

    // Store some messages in different channels
    let msg1 = create_test_message(general_channel, &keypair, "Welcome to general!");
    let msg2 = create_test_message(tech_channel, &keypair, "Tech discussion started");
    let msg3 = create_test_message(general_channel, &keypair, "General chat continues");
    let msg4 = create_test_message(urgent_channel, &keypair, "URGENT: Server down!");

    for msg in [&msg1, &msg2, &msg3, &msg4] {
        storage
            .store_message(msg)
            .await
            .expect("Failed to store message");
    }

    // User joins tech channel (this is the race condition scenario we're solving)
    let join_tech = FilterUpdateRequest {
        operations: vec![FilterOperation::add_channels(vec![tech_channel.to_vec()])],
    };

    // Apply the filter update (this would be atomic on server)
    for operation in &join_tech.operations {
        filters.apply_operation(operation);
    }

    // Now user is subscribed to both general and tech
    assert_eq!(
        filters.channels,
        Some(vec![general_channel.to_vec(), tech_channel.to_vec()])
    );

    // User can catch up on tech channel history
    let tech_stream = storage
        .catch_up(FilterField::Channel, tech_channel, None)
        .await
        .expect("Failed to get tech catch-up stream");

    tokio::pin!(tech_stream);

    let mut tech_messages = Vec::new();
    while let Some(result) = tech_stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                tech_messages.push(message);
            }
            Err(e) => panic!("Error in tech stream: {e:?}"),
        }
    }

    assert_eq!(tech_messages.len(), 1);
    let tech_content = String::from_utf8_lossy(
        tech_messages[0]
            .raw_content()
            .expect("Expected raw content"),
    );
    assert_eq!(tech_content, "Tech discussion started");

    // User joins urgent channel and blocks a user in one atomic operation
    let complex_update = FilterUpdateRequest {
        operations: vec![
            FilterOperation::add_channels(vec![urgent_channel.to_vec()]),
            FilterOperation::add_authors(vec![b"blocked_user".to_vec()]), // Block by adding to authors filter (inverted logic for demo)
        ],
    };

    for operation in &complex_update.operations {
        filters.apply_operation(operation);
    }

    // Verify complex update worked
    assert_eq!(
        filters.channels,
        Some(vec![
            general_channel.to_vec(),
            tech_channel.to_vec(),
            urgent_channel.to_vec()
        ])
    );
    assert_eq!(filters.authors, Some(vec![b"blocked_user".to_vec()]));

    // Get urgent channel history
    let urgent_stream = storage
        .catch_up(FilterField::Channel, urgent_channel, None)
        .await
        .expect("Failed to get urgent catch-up stream");

    tokio::pin!(urgent_stream);

    let mut urgent_messages = Vec::new();
    while let Some(result) = urgent_stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                urgent_messages.push(message);
            }
            Err(e) => panic!("Error in urgent stream: {e:?}"),
        }
    }

    assert_eq!(urgent_messages.len(), 1);
    let urgent_content = String::from_utf8_lossy(
        urgent_messages[0]
            .raw_content()
            .expect("Expected raw content"),
    );
    assert_eq!(urgent_content, "URGENT: Server down!");
}

#[tokio::test]
async fn test_expired_message_handling() -> Result<(), Box<dyn std::error::Error>> {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut OsRng));
    let channel_id = b"test-channel";

    // Create an expired message (expired 1 hour ago)
    let expired_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        - 3600; // 1 hour ago

    let mut message = create_test_message(channel_id, &keypair, "Expired message");
    // Manually set the message to be expired by setting when to past and timeout
    let Message::MessageV0(ref mut msg_v0) = message.message.as_mut();
    msg_v0.header.when = expired_time;
    msg_v0.header.kind = Kind::Emphemeral(Some(1)); // 1 second timeout, way past

    let publish_result = storage.store_message(&message).await?;

    // Should return Expired variant
    use zoe_wire_protocol::PublishResult;
    assert!(matches!(publish_result, PublishResult::Expired));
    assert!(publish_result.global_stream_id().is_none());
    assert!(!publish_result.was_stored());

    Ok(())
}

#[tokio::test]
async fn test_check_messages_bulk_sync() -> Result<(), Box<dyn std::error::Error>> {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::MlDsa65(MlDsa65::key_gen(&mut OsRng));
    let channel_id = b"test-channel";

    // Create some test messages
    let msg1 = create_test_message(channel_id, &keypair, "Message 1");
    let msg2 = create_test_message(channel_id, &keypair, "Message 2");
    let msg3 = create_test_message(channel_id, &keypair, "Message 3");

    // Store only msg1 and msg3, leave msg2 unstored
    let result1 = storage.store_message(&msg1).await?;
    let result3 = storage.store_message(&msg3).await?;

    let stream_id1 = result1
        .global_stream_id()
        .expect("Message should not be expired");
    let stream_id3 = result3
        .global_stream_id()
        .expect("Message should not be expired");

    // Check all three messages in bulk
    let message_ids = vec![msg1.id, msg2.id, msg3.id];
    let check_results = storage.check_messages(&message_ids).await?;

    // Verify results are in the correct order
    assert_eq!(check_results.len(), 3);
    assert_eq!(check_results[0], Some(stream_id1.to_string())); // msg1 should be found
    assert_eq!(check_results[1], None); // msg2 should not be found
    assert_eq!(check_results[2], Some(stream_id3.to_string())); // msg3 should be found

    // Test empty input
    let empty_results = storage.check_messages(&[]).await?;
    assert_eq!(empty_results, vec![]);

    // Test with only non-existent messages
    let msg4 = create_test_message(channel_id, &keypair, "Message 4");
    let msg5 = create_test_message(channel_id, &keypair, "Message 5");
    let nonexistent_ids = vec![msg4.id, msg5.id];
    let nonexistent_results = storage.check_messages(&nonexistent_ids).await?;
    assert_eq!(nonexistent_results, vec![None, None]);

    Ok(())
}
