use futures_util::StreamExt;
use rand::rngs::OsRng;
use std::{sync::Arc, time::SystemTime};
use zoe_message_store::RedisMessageStorage;
use zoe_wire_protocol::{
    Filter, FilterOperation, FilterUpdateRequest, KeyId, KeyPair, Kind, Message, MessageFilters,
    MessageFull, MessageId, Tag, VerifyingKey,
};

// Helper function to create test VerifyingKeys from byte arrays
fn create_test_verifying_key_id(bytes: &[u8]) -> KeyId {
    use rand::SeedableRng;

    // Create a simple hash from the input bytes for deterministic generation
    let mut seed = [0u8; 32];
    let len = std::cmp::min(bytes.len(), 32);
    seed[..len].copy_from_slice(&bytes[..len]);

    let mut seed_rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut seed_rng);
    let verifying_key = signing_key.verifying_key();

    KeyId::from(*VerifyingKey::Ed25519(Box::new(verifying_key)).id())
}

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

fn create_test_message(channel_id: &[u8], author_keypair: &KeyPair, content: &str) -> MessageFull {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let tags = vec![Tag::Channel {
        id: channel_id.to_vec(),
        relays: vec![],
    }];

    let message = Message::new_v0_raw(
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

    // Test Add operation for channels
    let add_channels = FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]);
    filters.apply_operation(&add_channels);

    // Check that channels were added
    let expected_filters = vec![
        Filter::Channel(b"general".to_vec()),
        Filter::Channel(b"tech".to_vec()),
    ];
    assert_eq!(filters.filters, Some(expected_filters));

    // Test Add authors
    let alice_key = create_test_verifying_key_id(b"alice");
    let bob_key = create_test_verifying_key_id(b"bob");
    let add_authors = FilterOperation::add_authors(vec![alice_key, bob_key]);
    filters.apply_operation(&add_authors);

    // Check that authors were added
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Author(alice_key)));
        assert!(filter_list.contains(&Filter::Author(bob_key)));
        assert!(filter_list.contains(&Filter::Channel(b"general".to_vec())));
        assert!(filter_list.contains(&Filter::Channel(b"tech".to_vec())));
    } else {
        panic!("Expected filters to be Some");
    }

    // Test Remove operation
    let remove_channel = FilterOperation::remove_channels(vec![b"general".to_vec()]);
    filters.apply_operation(&remove_channel);

    // Check that "general" was removed but "tech" remains
    if let Some(filter_list) = &filters.filters {
        assert!(!filter_list.contains(&Filter::Channel(b"general".to_vec())));
        assert!(filter_list.contains(&Filter::Channel(b"tech".to_vec())));
    }

    // Test Add events
    let add_events = FilterOperation::add_events(vec![
        MessageId::from_content(b"important"),
        MessageId::from_content(b"urgent"),
    ]);
    filters.apply_operation(&add_events);

    // Check that events were added
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Event(MessageId::from_content(b"important"))));
        assert!(filter_list.contains(&Filter::Event(MessageId::from_content(b"urgent"))));
    }

    // Test Clear operation
    let clear_op = FilterOperation::clear();
    filters.apply_operation(&clear_op);
    assert_eq!(filters.filters, None);

    // Test ReplaceAll with new filters
    let new_author = create_test_verifying_key_id(b"new-author");
    let new_filter_list = vec![
        Filter::Channel(b"new-channel".to_vec()),
        Filter::Author(new_author),
    ];
    let replace_all = FilterOperation::ReplaceAll(new_filter_list.clone());
    filters.apply_operation(&replace_all);

    assert_eq!(filters.filters, Some(new_filter_list));
}

#[tokio::test]
async fn test_atomic_multi_field_operations() {
    let mut filters = MessageFilters::default();

    let alice_key = create_test_verifying_key_id(b"alice");
    let user1_key = create_test_verifying_key_id(b"user1");

    let operations = vec![
        FilterOperation::add_channels(vec![b"general".to_vec(), b"tech".to_vec()]),
        FilterOperation::add_authors(vec![alice_key]),
        FilterOperation::add_events(vec![MessageId::from_content(b"important")]),
        FilterOperation::add_users(vec![user1_key]),
    ];

    // Apply all operations atomically
    for operation in &operations {
        filters.apply_operation(operation);
    }

    // Check that all filters were added
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Channel(b"general".to_vec())));
        assert!(filter_list.contains(&Filter::Channel(b"tech".to_vec())));
        assert!(filter_list.contains(&Filter::Author(alice_key)));
        assert!(filter_list.contains(&Filter::Event(MessageId::from_content(b"important"))));
        assert!(filter_list.contains(&Filter::User(user1_key)));
    } else {
        panic!("Expected filters to be Some");
    }
}

#[tokio::test]
async fn test_channel_streams_storage_and_retrieval() {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::generate_ml_dsa65(&mut OsRng);

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
    let channel_a_filter = Filter::Channel(channel_a.to_vec());
    let channel_a_stream = storage
        .catch_up(&channel_a_filter, None)
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
    let channel_b_filter = Filter::Channel(channel_b.to_vec());
    let channel_b_stream = storage
        .catch_up(&channel_b_filter, None)
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
        FilterOperation::remove_authors(vec![create_test_verifying_key_id(b"spammer")]),
        FilterOperation::add_events(vec![MessageId::from_content(b"important")]),
    ];

    let filter_request = FilterUpdateRequest { operations };

    assert_eq!(filter_request.operations.len(), 3);

    // Test that we can apply all operations
    let mut filters = MessageFilters::default();
    for operation in &filter_request.operations {
        filters.apply_operation(operation);
    }

    // Check that channels were added correctly
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Channel(b"general".to_vec())));
        assert!(filter_list.contains(&Filter::Channel(b"tech".to_vec())));
        assert!(filter_list.contains(&Filter::Event(MessageId::from_content(b"important"))));
        // Authors should not contain the "spammer" we tried to remove
        assert!(!filter_list.iter().any(|f| matches!(f, Filter::Author(_))));
    } else {
        panic!("Expected filters to be Some");
    }
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
    if let Some(filter_list) = &filters.filters {
        let channel_count = filter_list
            .iter()
            .filter(|f| matches!(f, Filter::Channel(ref c) if c == b"general"))
            .count();
        assert_eq!(channel_count, 1);
    } else {
        panic!("Expected filters to be Some");
    }
}

#[tokio::test]
async fn test_comprehensive_scenario() {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::generate_ml_dsa65(&mut OsRng);

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
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Channel(general_channel.to_vec())));
        assert!(filter_list.contains(&Filter::Channel(tech_channel.to_vec())));
    } else {
        panic!("Expected filters to be Some");
    }

    // User can catch up on tech channel history
    let tech_filter = Filter::Channel(tech_channel.to_vec());
    let tech_stream = storage
        .catch_up(&tech_filter, None)
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
            FilterOperation::add_authors(vec![create_test_verifying_key_id(b"blocked_user")]), // Block by adding to authors filter (inverted logic for demo)
        ],
    };

    for operation in &complex_update.operations {
        filters.apply_operation(operation);
    }

    // Verify complex update worked
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Channel(general_channel.to_vec())));
        assert!(filter_list.contains(&Filter::Channel(tech_channel.to_vec())));
        assert!(filter_list.contains(&Filter::Channel(urgent_channel.to_vec())));
        // Check that the blocked user author filter was added
        let blocked_user_key = create_test_verifying_key_id(b"blocked_user");
        assert!(filter_list.contains(&Filter::Author(blocked_user_key)));
    } else {
        panic!("Expected filters to be Some");
    }

    // Get urgent channel history
    let urgent_filter = Filter::Channel(urgent_channel.to_vec());
    let urgent_stream = storage
        .catch_up(&urgent_filter, None)
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

// #[tokio::test]
// async fn test_expired_message_handling() -> Result<(), Box<dyn std::error::Error>> {
//     let storage = setup_test_storage().await;
//     let keypair = KeyPair::generate_ml_dsa65(&mut OsRng);
//     let channel_id = b"test-channel";

//     // Create an expired message (expired 1 hour ago)
//     let expired_time = std::time::SystemTime::now()
//         .duration_since(std::time::UNIX_EPOCH)?
//         .as_secs()
//         - 3600; // 1 hour ago

//     let mut message = create_test_message(channel_id, &keypair, "Expired message");
//     // Manually set the message to be expired by setting when to past and timeout
//     let Message::MessageV0(ref mut msg_v0) = message.message().as_mut();
//     msg_v0.header.when = expired_time;
//     msg_v0.header.kind = Kind::Emphemeral(1); // 1 second timeout, way past

//     let publish_result = storage.store_message(&message).await?;

//     // Should return Expired variant
//     use zoe_wire_protocol::PublishResult;
//     assert!(matches!(publish_result, PublishResult::Expired));
//     assert!(publish_result.global_stream_id().is_none());
//     assert!(!publish_result.was_stored());

//     Ok(())
// }

#[tokio::test]
async fn test_check_messages_bulk_sync() -> Result<(), Box<dyn std::error::Error>> {
    let storage = setup_test_storage().await;
    let keypair = KeyPair::generate_ml_dsa65(&mut OsRng);
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
    let message_ids = vec![*msg1.id(), *msg2.id(), *msg3.id()];
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
    let nonexistent_ids = vec![*msg4.id(), *msg5.id()];
    let nonexistent_results = storage.check_messages(&nonexistent_ids).await?;
    assert_eq!(nonexistent_results, vec![None, None]);

    Ok(())
}

/// Comprehensive test for all supported signature types
/// Tests message storage, retrieval, and verification for Ed25519, MlDsa44, MlDsa65, and MlDsa87
#[tokio::test]
async fn test_all_signature_types_comprehensive() {
    let storage = setup_test_storage().await;

    // Generate keypairs for all supported signature types
    let ed25519_keypair = KeyPair::generate_ed25519(&mut OsRng);
    let ml_dsa_44_keypair = KeyPair::generate_ml_dsa44(&mut OsRng);
    let ml_dsa_65_keypair = KeyPair::generate_ml_dsa65(&mut OsRng);
    let ml_dsa_87_keypair = KeyPair::generate_ml_dsa87(&mut OsRng);

    let test_channel = b"signature_test_channel";

    // Create test messages with each signature type
    let ed25519_msg = create_test_message(
        test_channel,
        &ed25519_keypair,
        "Ed25519 signature test message",
    );
    let ml_dsa_44_msg = create_test_message(
        test_channel,
        &ml_dsa_44_keypair,
        "ML-DSA-44 signature test message",
    );
    let ml_dsa_65_msg = create_test_message(
        test_channel,
        &ml_dsa_65_keypair,
        "ML-DSA-65 signature test message",
    );
    let ml_dsa_87_msg = create_test_message(
        test_channel,
        &ml_dsa_87_keypair,
        "ML-DSA-87 signature test message",
    );

    // Store all messages
    println!(
        "🔍 Storing Ed25519 message with author ID: {}",
        hex::encode(ed25519_msg.author().id())
    );
    let ed25519_result = storage
        .store_message(&ed25519_msg)
        .await
        .expect("Failed to store Ed25519 message");
    let ed25519_stream_id = ed25519_result
        .global_stream_id()
        .expect("Ed25519 message should not be expired");

    let ml_dsa_44_result = storage
        .store_message(&ml_dsa_44_msg)
        .await
        .expect("Failed to store ML-DSA-44 message");
    let ml_dsa_44_stream_id = ml_dsa_44_result
        .global_stream_id()
        .expect("ML-DSA-44 message should not be expired");

    let ml_dsa_65_result = storage
        .store_message(&ml_dsa_65_msg)
        .await
        .expect("Failed to store ML-DSA-65 message");
    let ml_dsa_65_stream_id = ml_dsa_65_result
        .global_stream_id()
        .expect("ML-DSA-65 message should not be expired");

    let ml_dsa_87_result = storage
        .store_message(&ml_dsa_87_msg)
        .await
        .expect("Failed to store ML-DSA-87 message");
    let ml_dsa_87_stream_id = ml_dsa_87_result
        .global_stream_id()
        .expect("ML-DSA-87 message should not be expired");

    println!("✅ All signature types stored successfully:");
    println!("   📝 Ed25519 stream ID: {ed25519_stream_id}");
    println!("   📝 ML-DSA-44 stream ID: {ml_dsa_44_stream_id}");
    println!("   📝 ML-DSA-65 stream ID: {ml_dsa_65_stream_id}");
    println!("   📝 ML-DSA-87 stream ID: {ml_dsa_87_stream_id}");

    // Retrieve all messages by ID to verify storage integrity
    let retrieved_ed25519 = storage
        .get_message(ed25519_msg.id().as_bytes())
        .await
        .expect("Failed to retrieve Ed25519 message")
        .expect("Ed25519 message should exist");

    let retrieved_ml_dsa_44 = storage
        .get_message(ml_dsa_44_msg.id().as_bytes())
        .await
        .expect("Failed to retrieve ML-DSA-44 message")
        .expect("ML-DSA-44 message should exist");

    let retrieved_ml_dsa_65 = storage
        .get_message(ml_dsa_65_msg.id().as_bytes())
        .await
        .expect("Failed to retrieve ML-DSA-65 message")
        .expect("ML-DSA-65 message should exist");

    let retrieved_ml_dsa_87 = storage
        .get_message(ml_dsa_87_msg.id().as_bytes())
        .await
        .expect("Failed to retrieve ML-DSA-87 message")
        .expect("ML-DSA-87 message should exist");

    // Verify message content integrity
    assert_eq!(
        String::from_utf8_lossy(
            retrieved_ed25519
                .raw_content()
                .expect("Expected raw content")
        ),
        "Ed25519 signature test message"
    );
    assert_eq!(
        String::from_utf8_lossy(
            retrieved_ml_dsa_44
                .raw_content()
                .expect("Expected raw content")
        ),
        "ML-DSA-44 signature test message"
    );
    assert_eq!(
        String::from_utf8_lossy(
            retrieved_ml_dsa_65
                .raw_content()
                .expect("Expected raw content")
        ),
        "ML-DSA-65 signature test message"
    );
    assert_eq!(
        String::from_utf8_lossy(
            retrieved_ml_dsa_87
                .raw_content()
                .expect("Expected raw content")
        ),
        "ML-DSA-87 signature test message"
    );

    // Verify signature verification works for all types
    let ed25519_msg_bytes = postcard::to_stdvec(retrieved_ed25519.message())
        .expect("Failed to serialize Ed25519 message");
    assert_eq!(
        retrieved_ed25519
            .message()
            .verify_sender_signature(&ed25519_msg_bytes, retrieved_ed25519.signature())
            .expect("Ed25519 signature verification should succeed"),
        (),
        "Ed25519 signature should be valid"
    );

    let ml_dsa_44_msg_bytes = postcard::to_stdvec(retrieved_ml_dsa_44.message())
        .expect("Failed to serialize ML-DSA-44 message");
    assert_eq!(
        retrieved_ml_dsa_44
            .message()
            .verify_sender_signature(&ml_dsa_44_msg_bytes, retrieved_ml_dsa_44.signature())
            .expect("ML-DSA-44 signature verification should succeed"),
        (),
        "ML-DSA-44 signature should be valid"
    );

    let ml_dsa_65_msg_bytes = postcard::to_stdvec(retrieved_ml_dsa_65.message())
        .expect("Failed to serialize ML-DSA-65 message");
    assert_eq!(
        retrieved_ml_dsa_65
            .message()
            .verify_sender_signature(&ml_dsa_65_msg_bytes, retrieved_ml_dsa_65.signature())
            .expect("ML-DSA-65 signature verification should succeed"),
        (),
        "ML-DSA-65 signature should be valid"
    );

    let ml_dsa_87_msg_bytes = postcard::to_stdvec(retrieved_ml_dsa_87.message())
        .expect("Failed to serialize ML-DSA-87 message");
    assert_eq!(
        retrieved_ml_dsa_87
            .message()
            .verify_sender_signature(&ml_dsa_87_msg_bytes, retrieved_ml_dsa_87.signature())
            .expect("ML-DSA-87 signature verification should succeed"),
        (),
        "ML-DSA-87 signature should be valid"
    );

    // Test channel streaming with mixed signature types
    let channel_filter = Filter::Channel(test_channel.to_vec());
    let channel_stream = storage
        .catch_up(&channel_filter, None)
        .await
        .expect("Failed to get channel catch-up stream");

    tokio::pin!(channel_stream);

    let mut all_messages = Vec::new();
    while let Some(result) = channel_stream.next().await {
        match result {
            Ok((message, (_global_height, _local_height))) => {
                println!(
                    "🔍 Retrieved message ID: {}",
                    hex::encode(message.id().as_bytes())
                );
                all_messages.push(message);
            }
            Err(e) => panic!("Error in channel stream: {e:?}"),
        }
    }

    // Should have all 4 messages
    assert_eq!(
        all_messages.len(),
        4,
        "Should retrieve all 4 messages with different signature types"
    );

    // Verify all messages have valid signatures
    for (i, message) in all_messages.iter().enumerate() {
        let msg_bytes =
            postcard::to_stdvec(message.message()).expect("Failed to serialize message");
        assert_eq!(
            message
                .message()
                .verify_sender_signature(&msg_bytes, message.signature())
                .expect("Signature verification should succeed"),
            (),
            "Message {i} signature should be valid"
        );
    }

    // Test author filtering with different signature types
    let ed25519_author_id = ed25519_keypair.public_key().id();
    let ml_dsa_65_author_id = ml_dsa_65_keypair.public_key().id();

    println!(
        "🔍 Ed25519 author ID: {}",
        hex::encode(ed25519_author_id.as_bytes())
    );
    println!(
        "🔍 ML-DSA-65 author ID: {}",
        hex::encode(ml_dsa_65_author_id.as_bytes())
    );

    // Filter by Ed25519 author
    let ed25519_filter = Filter::Author(ed25519_author_id);
    let ed25519_author_stream = storage
        .catch_up(&ed25519_filter, None)
        .await
        .expect("Failed to get Ed25519 author stream");

    tokio::pin!(ed25519_author_stream);

    let mut ed25519_author_messages = Vec::new();
    while let Some(result) = ed25519_author_stream.next().await {
        match result {
            Ok((message, _)) => {
                ed25519_author_messages.push(message);
            }
            Err(e) => panic!("Error in Ed25519 author stream: {e:?}"),
        }
    }
    let found_len = ed25519_author_messages.len();
    assert_eq!(
        found_len, 1,
        "Should find exactly 1 Ed25519 message, found {found_len} messages",
    );
    assert_eq!(
        String::from_utf8_lossy(
            ed25519_author_messages[0]
                .raw_content()
                .expect("Expected raw content")
        ),
        "Ed25519 signature test message"
    );

    // Filter by ML-DSA-65 author
    let ml_dsa_65_filter = Filter::Author(ml_dsa_65_author_id);
    let ml_dsa_65_author_stream = storage
        .catch_up(&ml_dsa_65_filter, None)
        .await
        .expect("Failed to get ML-DSA-65 author stream");

    tokio::pin!(ml_dsa_65_author_stream);

    let mut ml_dsa_65_author_messages = Vec::new();
    while let Some(result) = ml_dsa_65_author_stream.next().await {
        match result {
            Ok((message, _)) => {
                ml_dsa_65_author_messages.push(message);
            }
            Err(e) => panic!("Error in ML-DSA-65 author stream: {e:?}"),
        }
    }

    assert_eq!(
        ml_dsa_65_author_messages.len(),
        1,
        "Should find exactly 1 ML-DSA-65 message"
    );
    assert_eq!(
        String::from_utf8_lossy(
            ml_dsa_65_author_messages[0]
                .raw_content()
                .expect("Expected raw content")
        ),
        "ML-DSA-65 signature test message"
    );

    println!("✅ **ALL SIGNATURE TYPES TEST RESULTS**:");
    println!("   🔑 Ed25519 signatures: ✅ Storage, retrieval, and verification working");
    println!("   🔑 ML-DSA-44 signatures: ✅ Storage, retrieval, and verification working");
    println!("   🔑 ML-DSA-65 signatures: ✅ Storage, retrieval, and verification working");
    println!("   🔑 ML-DSA-87 signatures: ✅ Storage, retrieval, and verification working");
    println!("   📡 Channel streaming with mixed signatures: ✅ Working");
    println!("   👤 Author filtering with different signature types: ✅ Working");
}

/// Test message storage ordering with different signature types
#[tokio::test]
async fn test_signature_type_ordering() {
    let storage = setup_test_storage().await;

    // Generate keypairs for all supported signature types
    let ed25519_keypair = KeyPair::generate_ed25519(&mut OsRng);
    let ml_dsa_44_keypair = KeyPair::generate_ml_dsa44(&mut OsRng);
    let ml_dsa_65_keypair = KeyPair::generate_ml_dsa65(&mut OsRng);
    let ml_dsa_87_keypair = KeyPair::generate_ml_dsa87(&mut OsRng);

    let test_channel = b"signature_ordering_test";

    // Create messages with the same timestamp to test signature-based ordering
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let tags = vec![Tag::Channel {
        id: test_channel.to_vec(),
        relays: vec![],
    }];

    // Create messages with identical timestamps but different signature types
    let ed25519_message = Message::new_v0_raw(
        b"Ed25519 message".to_vec(),
        ed25519_keypair.public_key(),
        timestamp,
        Kind::Regular,
        tags.clone(),
    );
    let ed25519_full = MessageFull::new(ed25519_message, &ed25519_keypair)
        .expect("Failed to create Ed25519 MessageFull");

    let ml_dsa_44_message = Message::new_v0_raw(
        b"ML-DSA-44 message".to_vec(),
        ml_dsa_44_keypair.public_key(),
        timestamp,
        Kind::Regular,
        tags.clone(),
    );
    let ml_dsa_44_full = MessageFull::new(ml_dsa_44_message, &ml_dsa_44_keypair)
        .expect("Failed to create ML-DSA-44 MessageFull");

    let ml_dsa_65_message = Message::new_v0_raw(
        b"ML-DSA-65 message".to_vec(),
        ml_dsa_65_keypair.public_key(),
        timestamp,
        Kind::Regular,
        tags.clone(),
    );
    let ml_dsa_65_full = MessageFull::new(ml_dsa_65_message, &ml_dsa_65_keypair)
        .expect("Failed to create ML-DSA-65 MessageFull");

    let ml_dsa_87_message = Message::new_v0_raw(
        b"ML-DSA-87 message".to_vec(),
        ml_dsa_87_keypair.public_key(),
        timestamp,
        Kind::Regular,
        tags,
    );
    let ml_dsa_87_full = MessageFull::new(ml_dsa_87_message, &ml_dsa_87_keypair)
        .expect("Failed to create ML-DSA-87 MessageFull");

    // Store messages in reverse signature type order to test ordering
    storage
        .store_message(&ml_dsa_87_full)
        .await
        .expect("Failed to store ML-DSA-87 message");
    storage
        .store_message(&ml_dsa_65_full)
        .await
        .expect("Failed to store ML-DSA-65 message");
    storage
        .store_message(&ml_dsa_44_full)
        .await
        .expect("Failed to store ML-DSA-44 message");
    storage
        .store_message(&ed25519_full)
        .await
        .expect("Failed to store Ed25519 message");

    // Retrieve messages and verify ordering
    let channel_filter = Filter::Channel(test_channel.to_vec());
    let channel_stream = storage
        .catch_up(&channel_filter, None)
        .await
        .expect("Failed to get channel catch-up stream");

    tokio::pin!(channel_stream);

    let mut ordered_messages = Vec::new();
    while let Some(result) = channel_stream.next().await {
        match result {
            Ok((message, _)) => {
                ordered_messages.push(message);
            }
            Err(e) => panic!("Error in channel stream: {e:?}"),
        }
    }

    assert_eq!(ordered_messages.len(), 4, "Should retrieve all 4 messages");

    // Messages are ordered by Redis stream insertion order (storage order)
    // We stored them in reverse signature type order: ML-DSA-87, ML-DSA-65, ML-DSA-44, Ed25519
    let expected_contents = [
        "ML-DSA-87 message",
        "ML-DSA-65 message",
        "ML-DSA-44 message",
        "Ed25519 message",
    ];

    for (i, (message, expected_content)) in ordered_messages
        .iter()
        .zip(expected_contents.iter())
        .enumerate()
    {
        let actual_content =
            String::from_utf8_lossy(message.raw_content().expect("Expected raw content"));
        assert_eq!(
            actual_content, *expected_content,
            "Message {i} should have content '{expected_content}' but got '{actual_content}'"
        );
    }

    println!("✅ **SIGNATURE TYPE STORAGE ORDERING TEST RESULTS**:");
    println!("   📊 Messages stored and retrieved in insertion order: ✅");
    println!("   🔢 All signature types work correctly in storage: ✅");
}
