use futures_util::StreamExt;
use rand::rngs::OsRng;
use zoe_wire_protocol::{
    CatchUpRequest, ChannelId, Filter, FilterOperation, FilterUpdateRequest, KeyId, KeyPair, Kind,
    Message, MessageFilters, MessageFull, Tag, VerifyingKey,
};

// Helper function to create test VerifyingKeys from byte arrays
fn create_test_verifying_key(bytes: &[u8]) -> VerifyingKey {
    use rand::SeedableRng;

    // Create a simple hash from the input bytes for deterministic generation
    let mut seed = [0u8; 32];
    let len = std::cmp::min(bytes.len(), 32);
    seed[..len].copy_from_slice(&bytes[..len]);

    let mut seed_rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let signing_key = ed25519_dalek::SigningKey::generate(&mut seed_rng);
    let verifying_key = signing_key.verifying_key();

    VerifyingKey::Ed25519(Box::new(verifying_key))
}

// Test helper to set up tracing
fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init()
        .ok(); // Ignore errors if already initialized
}

async fn setup_test_storage() -> zoe_message_store::storage::RedisMessageStorage {
    // Use a random database number to avoid conflicts between parallel tests
    let db_num = rand::random::<u8>() % 15 + 1; // Use databases 1-15 (avoid 0 which might be used elsewhere)
    let redis_url = format!("redis://127.0.0.1:6379/{db_num}");

    let storage = zoe_message_store::storage::RedisMessageStorage::new(redis_url)
        .await
        .expect("Failed to create storage");

    storage
}

#[tokio::test]
async fn test_filter_operations_with_new_types() {
    setup_tracing();

    let mut filters = MessageFilters::default();

    // Test adding channels
    let add_channels =
        FilterOperation::add_channels(vec![b"general".to_vec().into(), b"tech".to_vec().into()]);
    filters.apply_operation(&add_channels);

    // Check that channels were added
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Channel(b"general".to_vec().into())));
        assert!(filter_list.contains(&Filter::Channel(b"tech".to_vec().into())));
    } else {
        panic!("Expected filters to be Some");
    }

    // Test adding authors
    let alice_key = create_test_verifying_key(b"alice");
    let add_authors = FilterOperation::add_authors(vec![KeyId::from(*alice_key.id())]);
    filters.apply_operation(&add_authors);

    // Check that author was added
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Author(KeyId::from(*alice_key.id()))));
    }

    // Test clear
    let clear_op = FilterOperation::clear();
    filters.apply_operation(&clear_op);
    assert_eq!(filters.filters, None);
}

#[tokio::test]
async fn test_catch_up_with_new_api() {
    setup_tracing();

    let storage = setup_test_storage().await;
    let keypair = KeyPair::generate_ml_dsa65(&mut OsRng);

    let channel_id = b"test_channel";

    // Store a test message
    let tags = vec![Tag::Channel {
        id: channel_id.to_vec().into(),
        relays: vec![],
    }];

    let message = Message::new_v0_raw(
        b"Test message content".to_vec(),
        keypair.public_key(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        Kind::Regular,
        tags,
    );

    let message_full = MessageFull::new(message, &keypair).expect("Failed to create MessageFull");
    storage
        .store_message(&message_full)
        .await
        .expect("Failed to store message");

    // Test catch-up with new API
    let channel_filter = Filter::Channel(channel_id.to_vec().into());
    let catch_up_stream = storage
        .catch_up(&channel_filter, None)
        .await
        .expect("Failed to get catch-up stream");

    tokio::pin!(catch_up_stream);

    let mut messages = Vec::new();
    while let Some(result) = catch_up_stream.next().await {
        let (message, _) = result.expect("Failed to get message from stream");
        messages.push(message);
        if !messages.is_empty() {
            break; // We expect at least one message
        }
    }

    assert_eq!(messages.len(), 1);
    assert_eq!(
        String::from_utf8_lossy(messages[0].content().as_raw().unwrap()),
        "Test message content"
    );
}

#[tokio::test]
async fn test_catch_up_request_with_unified_filter() {
    setup_tracing();

    let channel_id: ChannelId = b"test_channel_123".to_vec().into();

    // Test CatchUpRequest with new unified Filter type
    let catch_up_request = CatchUpRequest {
        filter: Filter::Channel(channel_id.clone()),
        since: None,
        max_messages: Some(10),
        request_id: 123,
    };

    // Verify the request was created correctly
    assert_eq!(catch_up_request.request_id, 123);
    assert_eq!(catch_up_request.max_messages, Some(10));
    assert_eq!(catch_up_request.since, None);

    // Verify the filter is correct
    match &catch_up_request.filter {
        Filter::Channel(id) => assert_eq!(id, &channel_id),
        _ => panic!("Expected Channel filter"),
    }
}

#[tokio::test]
async fn test_filter_update_request() {
    setup_tracing();

    let alice_key = create_test_verifying_key(b"alice");

    // Test FilterUpdateRequest with new operations
    let operations = vec![
        FilterOperation::add_channels(vec![b"general".to_vec().into(), b"tech".to_vec().into()]),
        FilterOperation::add_authors(vec![KeyId::from(*alice_key.id())]),
        FilterOperation::add_events(vec![zoe_wire_protocol::MessageId::from_content(
            b"important",
        )]),
    ];

    let filter_request = FilterUpdateRequest { operations };

    let mut filters = MessageFilters::default();
    for operation in &filter_request.operations {
        filters.apply_operation(operation);
    }

    // Check that all filters were applied correctly
    if let Some(filter_list) = &filters.filters {
        assert!(filter_list.contains(&Filter::Channel(b"general".to_vec().into())));
        assert!(filter_list.contains(&Filter::Channel(b"tech".to_vec().into())));
        assert!(filter_list.contains(&Filter::Author(KeyId::from(*alice_key.id()))));
        assert!(
            filter_list.contains(&Filter::Event(zoe_wire_protocol::MessageId::from_content(
                b"important"
            )))
        );
    } else {
        panic!("Expected filters to be Some");
    }
}
