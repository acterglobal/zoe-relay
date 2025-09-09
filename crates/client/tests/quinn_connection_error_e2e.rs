use std::net::Ipv4Addr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use zoe_app_primitives::{NetworkAddress, RelayAddress};
use zoe_client::{Client, RelayConnectionStatus};
use zoe_wire_protocol::KeyPair;

/// Test that Quinn connection errors are properly captured and stored in relay status
#[tokio::test]
async fn test_quinn_connection_error_capture() {
    // Initialize logging for test debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Create temporary directories
    let media_dir = TempDir::new().expect("Failed to create temp media dir");
    let db_dir = TempDir::new().expect("Failed to create temp db dir");

    // Create client
    let mut builder = Client::builder();
    builder.media_storage_dir_pathbuf(media_dir.path().to_path_buf());
    builder.db_storage_dir_pathbuf(db_dir.path().to_path_buf());

    let client = builder.build().await.expect("Failed to build client");

    // Subscribe to relay status updates
    let mut relay_status_receiver = client.subscribe_to_relay_status();

    // Create a relay that will fail to connect (no server running)
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Quinn Error Relay".to_string());

    // Attempt to add the relay (will fail)
    let add_result = client.add_relay(relay_address.clone()).await;
    assert!(
        add_result.is_err(),
        "Connection should fail since no server is running"
    );

    // Should receive a "Connecting" status update
    let connecting_update = timeout(Duration::from_secs(5), relay_status_receiver.recv())
        .await
        .expect("Should receive connecting status")
        .expect("Channel should not be closed");

    assert_eq!(connecting_update.relay_address, relay_address);
    assert!(matches!(
        connecting_update.status,
        RelayConnectionStatus::Connecting
    ));

    // Should receive a "Failed" status update with error details
    let failed_update = timeout(Duration::from_secs(30), relay_status_receiver.recv())
        .await
        .expect("Should receive failed status")
        .expect("Channel should not be closed");

    assert_eq!(failed_update.relay_address, relay_address);
    if let RelayConnectionStatus::Failed { error } = &failed_update.status {
        assert!(!error.is_empty(), "Error message should not be empty");
        // The error should contain information about connection failure
        assert!(
            error.contains("connection") || error.contains("refused") || error.contains("timeout"),
            "Error should indicate connection issue: {}",
            error
        );
    } else {
        panic!("Expected Failed status, got: {:?}", failed_update.status);
    }

    // Verify the relay is tracked as failed with error details
    let relay_status = client
        .get_relay_status()
        .await
        .expect("Should get relay status");
    assert_eq!(relay_status.len(), 1);
    if let RelayConnectionStatus::Failed { error } = &relay_status[0].status {
        assert!(
            !error.is_empty(),
            "Stored error message should not be empty"
        );
    } else {
        panic!(
            "Expected Failed status in stored relay info, got: {:?}",
            relay_status[0].status
        );
    }

    client.close().await;
}

/// Test that manual disconnection doesn't include error information
#[tokio::test]
async fn test_manual_disconnection_no_error() {
    // Initialize logging for test debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Create temporary directories
    let media_dir = TempDir::new().expect("Failed to create temp media dir");
    let db_dir = TempDir::new().expect("Failed to create temp db dir");

    // Create client
    let mut builder = Client::builder();
    builder.media_storage_dir_pathbuf(media_dir.path().to_path_buf());
    builder.db_storage_dir_pathbuf(db_dir.path().to_path_buf());

    let client = builder.build().await.expect("Failed to build client");

    // Subscribe to relay status updates
    let mut relay_status_receiver = client.subscribe_to_relay_status();

    // Create a relay that will fail to connect
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Manual Disconnect Relay".to_string());

    // Attempt to add the relay (will fail but will be tracked)
    let _add_result = client.add_relay(relay_address.clone()).await;

    // Consume the initial status updates (Connecting -> Failed)
    let _connecting = timeout(Duration::from_secs(5), relay_status_receiver.recv()).await;
    let _failed = timeout(Duration::from_secs(30), relay_status_receiver.recv()).await;

    // Manually remove the relay
    let removed = client
        .remove_relay(relay_keypair.public_key())
        .await
        .expect("Should remove relay");
    assert!(removed, "Relay should have been removed");

    // Should receive a "Disconnected" status update without error (manual removal)
    let disconnected_update = timeout(Duration::from_secs(5), relay_status_receiver.recv())
        .await
        .expect("Should receive disconnected status")
        .expect("Channel should not be closed");

    assert_eq!(disconnected_update.relay_address, relay_address);
    if let RelayConnectionStatus::Disconnected { error } = &disconnected_update.status {
        assert!(
            error.is_none(),
            "Manual disconnection should not have error: {:?}",
            error
        );
    } else {
        panic!(
            "Expected Disconnected status, got: {:?}",
            disconnected_update.status
        );
    }

    client.close().await;
}

/// Test that connection error information is preserved in relay status
#[tokio::test]
async fn test_connection_error_preservation() {
    // Initialize logging for test debugging
    let _ = tracing_subscriber::fmt::try_init();

    // Create temporary directories
    let media_dir = TempDir::new().expect("Failed to create temp media dir");
    let db_dir = TempDir::new().expect("Failed to create temp db dir");

    // Create client
    let mut builder = Client::builder();
    builder.media_storage_dir_pathbuf(media_dir.path().to_path_buf());
    builder.db_storage_dir_pathbuf(db_dir.path().to_path_buf());

    let client = builder.build().await.expect("Failed to build client");

    // Create a relay that will fail to connect
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Error Preservation Relay".to_string());

    // Attempt to add the relay (will fail)
    let _add_result = client.add_relay(relay_address).await;

    // Wait a bit for the connection attempt to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check that the error information is preserved in the relay status
    let relay_status = client
        .get_relay_status()
        .await
        .expect("Should get relay status");
    assert_eq!(relay_status.len(), 1);

    // The relay should be marked as Failed with error details
    if let RelayConnectionStatus::Failed { error } = &relay_status[0].status {
        assert!(
            !error.is_empty(),
            "Error should be preserved in relay status"
        );
        println!("Captured connection error: {}", error);
    } else {
        panic!(
            "Expected Failed status with error, got: {:?}",
            relay_status[0].status
        );
    }

    client.close().await;
}
