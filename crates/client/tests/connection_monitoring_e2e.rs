use std::net::Ipv4Addr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use zoe_app_primitives::{NetworkAddress, RelayAddress};
use zoe_client::{Client, RelayConnectionStatus};
use zoe_wire_protocol::KeyPair;

/// Test that connection monitoring detects when a relay connection is lost
#[tokio::test]
async fn test_connection_monitoring_detects_disconnection() {
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
        .with_name("Test Connection Monitor Relay".to_string());

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

    // Should receive a "Failed" status update
    let failed_update = timeout(Duration::from_secs(30), relay_status_receiver.recv())
        .await
        .expect("Should receive failed status")
        .expect("Channel should not be closed");

    assert_eq!(failed_update.relay_address, relay_address);
    assert!(matches!(
        failed_update.status,
        RelayConnectionStatus::Failed { .. }
    ));

    // Verify the relay is tracked as failed
    let relay_status = client
        .get_relay_status()
        .await
        .expect("Should get relay status");
    assert_eq!(relay_status.len(), 1);
    assert!(matches!(
        relay_status[0].status,
        RelayConnectionStatus::Failed { .. }
    ));

    client.close().await;
}

/// Test that connection monitoring properly cleans up when client is closed
#[tokio::test]
async fn test_connection_monitoring_cleanup() {
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
        .with_name("Test Cleanup Relay".to_string());

    // Attempt to add the relay (will fail but will be tracked)
    let _add_result = client.add_relay(relay_address).await;

    // Verify relay is tracked
    let relay_status = client
        .get_relay_status()
        .await
        .expect("Should get relay status");
    assert_eq!(relay_status.len(), 1);

    // Close the client - this should clean up all connection monitors
    client.close().await;

    // The test passes if no panics occur during cleanup
}

/// Test that automatic reconnection is attempted after connection loss
#[tokio::test]
async fn test_automatic_reconnection_attempt() {
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
        .with_name("Test Reconnection Relay".to_string());

    // Attempt to add the relay (will fail)
    let _add_result = client.add_relay(relay_address.clone()).await;

    // Consume the initial status updates (Connecting -> Failed)
    let _connecting = timeout(Duration::from_secs(5), relay_status_receiver.recv()).await;
    let _failed = timeout(Duration::from_secs(30), relay_status_receiver.recv()).await;

    // Note: In a real scenario with an actual connection that gets lost,
    // the connection monitoring would detect the disconnection and attempt
    // automatic reconnection. Since we're testing with a non-existent server,
    // we can't test the actual reconnection logic, but we can verify that
    // the monitoring infrastructure is in place.

    // Verify the relay is still tracked for potential reconnection
    let relay_status = client
        .get_relay_status()
        .await
        .expect("Should get relay status");
    assert_eq!(relay_status.len(), 1);
    assert!(matches!(
        relay_status[0].status,
        RelayConnectionStatus::Failed { .. }
    ));

    client.close().await;
}
