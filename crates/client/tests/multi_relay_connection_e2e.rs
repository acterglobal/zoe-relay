use std::net::Ipv4Addr;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;
use zoe_app_primitives::connection::{NetworkAddress, RelayAddress};
use zoe_client::{Client, RelayConnectionStatus};
use zoe_wire_protocol::KeyPair;

/// Test that the client can handle multiple relay addresses and tries them in order
#[tokio::test]
async fn test_multi_address_relay_connection_attempts_max_30s() {
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

    // Create a relay with multiple addresses (all will fail but we can test the attempts)
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::dns_with_port(
            "nonexistent.example.com",
            8080,
        )) // Will fail DNS
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(192, 168, 1, 99),
            8080,
        )) // Will fail connection
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        )) // Will fail connection but is reachable
        .with_name("Test Multi-Address Relay".to_string());

    // Get initial overall status
    let initial_status = client.overall_status().await;
    assert!(!initial_status.is_connected);
    assert_eq!(initial_status.connected_count, 0);
    assert_eq!(initial_status.total_count, 0);

    // Attempt to add the relay (will fail but should try all addresses)
    let add_result = client.add_relay(relay_address.clone()).await;
    assert!(add_result.is_err(), "Expected connection to fail");

    // Verify the error contains information about all attempted addresses
    let error_msg = add_result.unwrap_err().to_string();
    assert!(error_msg.contains("Failed to connect to relay at any address"));
    assert!(error_msg.contains("nonexistent.example.com:8080"));
    assert!(error_msg.contains("192.168.1.99:8080"));
    assert!(error_msg.contains("127.0.0.1:8080"));

    // Wait for relay status updates
    let connecting_update = timeout(Duration::from_secs(5), relay_status_receiver.recv())
        .await
        .expect("Timeout waiting for connecting status")
        .expect("Failed to receive connecting status");

    assert_eq!(connecting_update.relay_id, relay_address.id());
    assert_eq!(connecting_update.relay_address.id(), relay_address.id());
    assert_eq!(connecting_update.status, RelayConnectionStatus::Connecting);

    let failed_update = timeout(Duration::from_secs(15), relay_status_receiver.recv())
        .await
        .expect("Timeout waiting for failed status")
        .expect("Failed to receive failed status");

    assert_eq!(failed_update.relay_id, relay_address.id());
    match failed_update.status {
        RelayConnectionStatus::Failed { error } => {
            assert!(error.contains("All connection attempts failed"));
            // Verify it tried multiple addresses
            assert!(
                error.contains("nonexistent.example.com:8080")
                    || error.contains("192.168.1.99:8080")
                    || error.contains("127.0.0.1:8080")
            );
        }
        other => panic!("Expected Failed status, got: {other:?}"),
    }

    // Verify overall status is still disconnected
    let final_status = client.overall_status().await;
    assert!(!final_status.is_connected);
    assert_eq!(final_status.connected_count, 0);
    assert_eq!(final_status.total_count, 0); // Should be 0 since connection failed

    // Verify relay info was stored with failed status for future reconnection attempts
    let relay_status = client
        .get_relay_status()
        .await
        .expect("Failed to get relay status");
    assert_eq!(
        relay_status.len(),
        1,
        "Failed relay should be tracked for reconnection"
    );
    assert!(
        matches!(relay_status[0].status, RelayConnectionStatus::Failed { .. }),
        "Relay status should be Failed"
    );

    client.close().await;
}

/// Test that client secret is only updated on successful connections
#[tokio::test]
async fn test_client_secret_only_updated_on_success() {
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

    // Create a relay that will fail to connect
    let relay_keypair = KeyPair::generate(&mut rand::thread_rng());
    let relay_address = RelayAddress::new(relay_keypair.public_key())
        .with_address(NetworkAddress::ipv4_with_port(
            Ipv4Addr::new(127, 0, 0, 1),
            8080,
        ))
        .with_name("Test Relay".to_string());

    // Attempt to add the relay (will fail)
    let add_result = client.add_relay(relay_address).await;
    assert!(add_result.is_err(), "Expected connection to fail");

    // Wait a bit to ensure no client secret update occurs
    let secret_update_result =
        timeout(Duration::from_millis(500), client_secret_subscriber.next()).await;
    assert!(
        secret_update_result.is_err(),
        "Client secret should not be updated on failed connection"
    );

    // Verify client secret is unchanged
    let final_secret = client.client_secret();
    assert!(final_secret.servers().is_empty());
    assert_eq!(initial_secret.servers().len(), final_secret.servers().len());

    client.close().await;
}

/// Test overall connection status computation
#[tokio::test]
async fn test_overall_connection_status_computation() {
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

    // Initial status should show no connections
    let status = client.overall_status().await;
    assert!(!status.is_connected);
    assert_eq!(status.connected_count, 0);
    assert_eq!(status.total_count, 0);

    // Verify has_connected_relays matches overall status
    assert!(!client.has_connected_relays().await);

    client.close().await;
}
