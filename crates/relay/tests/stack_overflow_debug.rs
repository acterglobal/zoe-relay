//! Debug test to isolate stack overflow in ML-DSA handshake
//!
//! This test creates a minimal reproduction case to identify where
//! the stack overflow is occurring in the ML-DSA challenge-response handshake.

use anyhow::Result;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;
use zoe_blob_store::BlobServiceImpl;
use zoe_message_store::RedisMessageStorage;
use zoe_relay::{RelayServer, RelayServiceRouter};
use zoe_wire_protocol::{
    KeyPair, Kind, Message, MessageFilters, MessageFull, Tag, VerifyingKey, generate_keypair,
};


/// Test challenge creation and key proof verification in isolation
#[tokio::test]
async fn test_challenge_verification_isolation() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing challenge verification in isolation");

    // Generate keys
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let client_keypair = generate_keypair(&mut rand::thread_rng());

    // Create challenge
    let challenge =
        zoe_relay::challenge::generate_ml_dsa_challenge(server_keypair.verifying_key())?;
    info!("✅ Generated ML-DSA challenge");

    // Create key proofs
    let response = zoe_client::challenge::create_ml_dsa_key_proofs(&challenge, &[&client_keypair])?;
    info!("✅ Created key proofs");

    // Verify key proofs - this is where the stack overflow might occur
    let (verified_keys, result) =
        zoe_relay::challenge::verify_ml_dsa_key_proofs(&response, &challenge)?;
    info!(
        "✅ Verified key proofs: {} keys, result: {:?}",
        verified_keys.len(),
        result
    );

    assert!(
        !verified_keys.is_empty(),
        "Should have verified at least one key"
    );

    Ok(())
}

/// Test multiple signature verifications to see if it's cumulative
#[tokio::test]
async fn test_multiple_signature_verifications() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing multiple signature verifications");

    // Generate keys
    let keypair = generate_keypair(&mut rand::thread_rng());
    let test_data = b"test signature data";

    // Test multiple signatures in a loop to see if stack usage accumulates
    for i in 0..10 {
        info!("🔄 Iteration {}", i);

        let signature = keypair.signing_key().sign(test_data);
        keypair
            .verifying_key()
            .verify(test_data, &signature)
            .map_err(|e| {
                anyhow::anyhow!("Signature verification failed at iteration {}: {}", i, e)
            })?;
    }

    info!("✅ Completed multiple signature verifications");

    Ok(())
}

/// Test large signature data to see if data size affects stack usage
#[tokio::test]
async fn test_large_signature_data() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing large signature data");

    // Generate keys
    let keypair = generate_keypair(&mut rand::thread_rng());

    // Test with increasingly large data sizes
    let sizes = [1, 100, 1000, 10000, 100000];

    for size in sizes {
        info!("📏 Testing with data size: {} bytes", size);

        let test_data = vec![0u8; size];
        let signature = keypair.signing_key().sign(&test_data);

        keypair
            .verifying_key()
            .verify(&test_data, &signature)
            .map_err(|e| {
                anyhow::anyhow!("Signature verification failed for size {}: {}", size, e)
            })?;

        info!("✅ Verified signature for {} bytes", size);
    }

    Ok(())
}

/// Test QUIC connection establishment using zoe-wire-protocol
/// This isolates whether the stack overflow is in the QUIC layer
#[tokio::test]
async fn test_quic_connection_establishment() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing QUIC connection establishment with zoe-wire-protocol");

    // Generate server keypair for TLS
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();

    // Create server config
    let server_config = create_ml_dsa_44_server_config(&server_keypair, "localhost")?;
    let server_config = ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
    ));

    // Create server endpoint
    let server_addr = "127.0.0.1:0".parse()?;
    let server_endpoint = Endpoint::server(server_config, server_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    info!("✅ Server endpoint created at {}", server_addr);

    // Accept connections in background
    let server_handle = tokio::spawn(async move {
        info!("🔄 Server waiting for connections...");
        if let Some(conn) = server_endpoint.accept().await {
            match conn.await {
                Ok(connection) => {
                    info!(
                        "✅ Server accepted connection from {}",
                        connection.remote_address()
                    );
                    // Just accept one stream and close
                    if let Ok((_send, _recv)) = connection.accept_bi().await {
                        info!("✅ Server accepted bidirectional stream");
                    }
                }
                Err(e) => {
                    info!("❌ Server connection failed: {}", e);
                }
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client config with proper certificate verifier for our self-signed certs
    let crypto_provider = ml_dsa_44_crypto_provider();
    let server_public_key = server_keypair.verifying_key().clone();
    let verifier = AcceptSpecificServerCertVerifier::new(server_public_key);

    let client_config =
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(crypto_provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
            .with_no_client_auth();

    let client_config = ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?,
    ));

    // Create client endpoint
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    client_endpoint.set_default_client_config(client_config);
    info!("✅ Client endpoint created");

    // Test connection establishment with timeout
    let connection_result = timeout(Duration::from_secs(5), async {
        info!("🔄 Client connecting to server...");
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        info!("✅ Client connected to server");

        // Open a stream
        let (send, recv) = connection.open_bi().await?;
        info!("✅ Client opened bidirectional stream");

        // Close the stream
        drop(send);
        drop(recv);

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match connection_result {
        Ok(Ok(())) => {
            info!("✅ QUIC connection establishment successful");
        }
        Ok(Err(e)) => {
            info!("❌ QUIC connection failed: {}", e);
            return Err(e);
        }
        Err(_) => {
            info!("❌ QUIC connection timed out");
            return Err(anyhow::anyhow!("Connection timed out"));
        }
    }

    // Clean up server
    server_handle.abort();

    info!("✅ QUIC connection test completed successfully");
    Ok(())
}

/// Test multiple QUIC connections to check for resource leaks
#[tokio::test]
async fn test_multiple_quic_connections() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing multiple QUIC connections for resource leaks");

    // Generate server keypair
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();

    // Create server config
    let server_config = create_ml_dsa_44_server_config(&server_keypair, "localhost")?;
    let server_config = ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
    ));

    // Create server endpoint
    let server_addr = "127.0.0.1:0".parse()?;
    let server_endpoint = Endpoint::server(server_config, server_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    // Accept connections in background
    let server_handle = tokio::spawn(async move {
        let mut connection_count = 0;
        while let Some(conn) = server_endpoint.accept().await {
            connection_count += 1;
            info!("🔄 Server accepting connection #{}", connection_count);

            if let Ok(connection) = conn.await {
                info!("✅ Server accepted connection #{}", connection_count);
                // Accept one stream per connection
                if let Ok((_send, _recv)) = connection.accept_bi().await {
                    info!(
                        "✅ Server accepted stream for connection #{}",
                        connection_count
                    );
                }
            }

            if connection_count >= 5 {
                break;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create client config once with proper certificate verifier
    let crypto_provider = ml_dsa_44_crypto_provider();
    let server_public_key = server_keypair.verifying_key().clone();
    let verifier = AcceptSpecificServerCertVerifier::new(server_public_key);

    let client_config =
        rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(crypto_provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
            .with_no_client_auth();

    let client_config = ClientConfig::new(std::sync::Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?,
    ));

    // Create multiple client connections
    for i in 1..=5 {
        info!("🔄 Creating client connection #{}", i);

        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config.clone());

        let connection_result = timeout(Duration::from_secs(2), async {
            let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
            let (_send, _recv) = connection.open_bi().await?;
            info!("✅ Client connection #{} successful", i);
            Ok::<(), anyhow::Error>(())
        })
        .await;

        match connection_result {
            Ok(Ok(())) => {
                info!("✅ Connection #{} completed", i);
            }
            Ok(Err(e)) => {
                info!("❌ Connection #{} failed: {}", i, e);
                return Err(e);
            }
            Err(_) => {
                info!("❌ Connection #{} timed out", i);
                return Err(anyhow::anyhow!("Connection {} timed out", i));
            }
        }

        // Small delay between connections
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    server_handle.abort();

    info!("✅ Multiple QUIC connections test completed successfully");
    Ok(())
}

/// Test client creation process to isolate stack overflow
/// This tests the actual client creation that's failing in the e2e tests
#[tokio::test]
async fn test_client_creation_process() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing client creation process to isolate stack overflow");

    // Start a relay server first (similar to the e2e test setup)
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_config = create_ml_dsa_44_server_config(&server_keypair, "localhost")?;
    let server_config = ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config)?,
    ));

    let server_addr = "127.0.0.1:0".parse()?;
    let server_endpoint = Endpoint::server(server_config, server_addr)?;
    let server_addr = server_endpoint.local_addr()?;

    info!("✅ Test relay server started at {}", server_addr);

    // Accept connections and perform handshake (simplified version)
    let server_handle = tokio::spawn(async move {
        info!("🔄 Test server waiting for connections...");
        if let Some(conn) = server_endpoint.accept().await {
            match conn.await {
                Ok(connection) => {
                    info!("✅ Test server accepted connection");
                    // Accept handshake stream
                    if let Ok((send, recv)) = connection.accept_bi().await {
                        info!("✅ Test server accepted handshake stream");
                        // For this test, just close the streams to simulate successful handshake
                        drop(send);
                        drop(recv);
                    }

                    // Accept service streams
                    while let Ok((send, recv)) = connection.accept_bi().await {
                        info!("✅ Test server accepted service stream");
                        drop(send);
                        drop(recv);
                    }
                }
                Err(e) => {
                    info!("❌ Test server connection failed: {}", e);
                }
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Now test the client creation process with timeout
    info!("🔄 Starting client creation process...");

    let client_creation_result = timeout(Duration::from_secs(10), async {
        info!("🔄 Step 1: Creating client keypair...");
        let client_keypair = generate_ml_dsa_44_keypair_for_tls();
        info!("✅ Step 1 completed");

        info!("🔄 Step 2: Creating client config...");
        let crypto_provider = ml_dsa_44_crypto_provider();
        let server_public_key = server_keypair.verifying_key().clone();
        let verifier = AcceptSpecificServerCertVerifier::new(server_public_key);

        let client_config =
            rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(crypto_provider))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .dangerous()
                .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
                .with_no_client_auth();

        let client_config = ClientConfig::new(std::sync::Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(client_config)?,
        ));
        info!("✅ Step 2 completed");

        info!("🔄 Step 3: Creating client endpoint...");
        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        client_endpoint.set_default_client_config(client_config);
        info!("✅ Step 3 completed");

        info!("🔄 Step 4: Connecting to server...");
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        info!("✅ Step 4 completed");

        info!("🔄 Step 5: Opening handshake stream...");
        let (send, recv) = connection.open_bi().await?;
        info!("✅ Step 5 completed");

        // Close streams
        drop(send);
        drop(recv);

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match client_creation_result {
        Ok(Ok(())) => {
            info!("✅ Client creation process completed successfully");
        }
        Ok(Err(e)) => {
            info!("❌ Client creation process failed: {}", e);
            return Err(e);
        }
        Err(_) => {
            info!("❌ Client creation process timed out - this indicates where the stack overflow occurs");
            return Err(anyhow::anyhow!("Client creation timed out"));
        }
    }

    server_handle.abort();

    info!("✅ Client creation test completed successfully");
    Ok(())
}

/// Test the specific steps in Client::build() to isolate stack overflow
/// This tests the actual client build process that's failing in the e2e tests
#[tokio::test]
async fn test_client_build_steps() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    info!("🧪 Testing Client::build() steps to isolate stack overflow");

    // SIMPLIFIED VERSION - Remove complex nested async structure
    info!("🔄 Step 0: Creating basic keypairs...");
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_public_key = server_keypair.verifying_key().clone();
    let mut rng = rand::thread_rng();
    let inner_keypair = generate_keypair(&mut rng);
    info!("✅ Step 0 completed");

    // Test just the RelayClient creation without server
    info!("🔄 Step 1: Testing RelayClient::new (will fail but shouldn't stack overflow)...");

    // Use a non-existent server address to avoid complex server setup
    let fake_server_addr = "127.0.0.1:9999".parse()?;

    // This should fail quickly with connection error, not stack overflow
    let result =
        zoe_client::RelayClient::new(inner_keypair, server_public_key, fake_server_addr).await;

    match result {
        Ok(_) => {
            info!("✅ RelayClient created (unexpected success)");
        }
        Err(e) => {
            info!("✅ RelayClient failed as expected: {}", e);
        }
    }

    info!("✅ Simple client build test completed - no stack overflow");
    Ok(())
}
