use std::net::Ipv4Addr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use zoe_app_primitives::{NetworkAddress, RelayAddress};
use zoe_client::{Client, RelayConnectionStatus};
use zoe_wire_protocol::KeyPair;

/// Test that the broadcast channel properly delivers relay status updates to multiple subscribers
#[tokio::test]
async fn test_broadcast_channel_multiple_subscribers() {
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

    // Create multiple subscribers to the broadcast channel
    let mut subscriber1 = client.subscribe_to_relay_status();
    let mut subscriber2 = client.subscribe_to_relay_status();
    let mut subscriber3 = client.subscribe_to_relay_status();

    // Create a relay that will fail to connect
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Broadcast Relay".to_string());

    // Attempt to add the relay (will fail but will broadcast status updates)
    let _add_result = client.add_relay(relay_address.clone()).await;

    // All subscribers should receive the connecting status
    let update1 = timeout(Duration::from_secs(5), subscriber1.recv())
        .await
        .expect("Timeout waiting for subscriber1 connecting status")
        .expect("Failed to receive connecting status on subscriber1");

    let update2 = timeout(Duration::from_secs(5), subscriber2.recv())
        .await
        .expect("Timeout waiting for subscriber2 connecting status")
        .expect("Failed to receive connecting status on subscriber2");

    let update3 = timeout(Duration::from_secs(5), subscriber3.recv())
        .await
        .expect("Timeout waiting for subscriber3 connecting status")
        .expect("Failed to receive connecting status on subscriber3");

    // All updates should be identical
    assert_eq!(update1.relay_id, relay_address.id());
    assert_eq!(update2.relay_id, relay_address.id());
    assert_eq!(update3.relay_id, relay_address.id());

    assert_eq!(update1.status, RelayConnectionStatus::Connecting);
    assert_eq!(update2.status, RelayConnectionStatus::Connecting);
    assert_eq!(update3.status, RelayConnectionStatus::Connecting);

    // All subscribers should receive the failed status
    let failed1 = timeout(Duration::from_secs(15), subscriber1.recv())
        .await
        .expect("Timeout waiting for subscriber1 failed status")
        .expect("Failed to receive failed status on subscriber1");

    let failed2 = timeout(Duration::from_secs(15), subscriber2.recv())
        .await
        .expect("Timeout waiting for subscriber2 failed status")
        .expect("Failed to receive failed status on subscriber2");

    let failed3 = timeout(Duration::from_secs(15), subscriber3.recv())
        .await
        .expect("Timeout waiting for subscriber3 failed status")
        .expect("Failed to receive failed status on subscriber3");

    // All failed updates should be identical
    assert_eq!(failed1.relay_id, relay_address.id());
    assert_eq!(failed2.relay_id, relay_address.id());
    assert_eq!(failed3.relay_id, relay_address.id());

    // All should be failed status
    assert!(matches!(
        failed1.status,
        RelayConnectionStatus::Failed { .. }
    ));
    assert!(matches!(
        failed2.status,
        RelayConnectionStatus::Failed { .. }
    ));
    assert!(matches!(
        failed3.status,
        RelayConnectionStatus::Failed { .. }
    ));

    client.close().await;
}

/// Test that client secret observable works correctly
#[tokio::test]
async fn test_client_secret_observable() {
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

    // Subscribe to client secret updates
    let mut client_secret_subscriber = client.subscribe_to_client_secret();

    // Get initial client secret
    let initial_secret = client.client_secret();
    assert!(initial_secret.servers().is_empty());

    // The client secret observable should not emit updates for failed connections
    // since we only update the client secret on successful connections

    // Create a relay that will fail to connect
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Secret Relay".to_string());

    // Attempt to add the relay (will fail)
    let _add_result = client.add_relay(relay_address).await;

    // Should not receive any client secret updates since connection failed
    let secret_update_result =
        timeout(Duration::from_millis(500), client_secret_subscriber.next()).await;
    assert!(
        secret_update_result.is_err(),
        "Should not receive client secret update for failed connection"
    );

    // Verify client secret is unchanged
    let final_secret = client.client_secret();
    assert!(final_secret.servers().is_empty());

    client.close().await;
}

/// Test that overall connection status is computed correctly from relay states
#[tokio::test]
async fn test_overall_status_computation_accuracy() {
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

    // Initial status should be disconnected
    let initial_status = client.overall_status().await;
    assert!(!initial_status.is_connected);
    assert_eq!(initial_status.connected_count, 0);
    assert_eq!(initial_status.total_count, 0);

    // has_connected_relays should match overall status
    assert!(!client.has_connected_relays().await);

    // After failed connection attempts, status should remain disconnected
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Status Relay".to_string());

    let _add_result = client.add_relay(relay_address).await;

    // Wait a bit for connection attempt to complete
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Status should still be disconnected since connection failed
    let post_attempt_status = client.overall_status().await;
    assert!(!post_attempt_status.is_connected);
    assert_eq!(post_attempt_status.connected_count, 0);
    assert_eq!(post_attempt_status.total_count, 0); // No relays added since connection failed

    // has_connected_relays should still be false
    assert!(!client.has_connected_relays().await);

    client.close().await;
}
