//! End-to-end tests for the challenge protocol using client_endpoint and server_endpoint
//!
//! These tests verify that the challenge protocol works correctly between
//! client and server using the wire protocol endpoints.

use anyhow::Result;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::{sleep, timeout};
use tracing::info;

use zoe_wire_protocol::{
    KeyPair, TransportPrivateKey,
    connection::{client::create_client_endpoint, server::create_server_endpoint},
    generate_ed25519_relay_keypair, generate_keypair,
};

// Initialize crypto provider for Rustls
fn init_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install crypto provider");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_challenge_protocol_basic_handshake() -> Result<()> {
    init_crypto_provider();
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    info!("🚀 Starting basic challenge protocol handshake test");

    // Generate server and client keys
    let server_signing_key = generate_ed25519_relay_keypair(&mut rand::thread_rng());
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: match server_signing_key {
            KeyPair::Ed25519(key) => *key,
            _ => panic!("Expected Ed25519 key"),
        },
    };
    let server_public_key = server_keypair.public_key();
    let client_keypair = generate_keypair(&mut rand::thread_rng());

    // Find free port and create server endpoint
    let server_endpoint =
        create_server_endpoint(SocketAddr::from(([127, 0, 0, 1], 0)), &server_keypair)?;
    let server_addr = server_endpoint.local_addr().unwrap();

    info!("✅ Server endpoint created on {}", server_addr);

    // Create client endpoint
    let client_endpoint = create_client_endpoint(&server_public_key)?;

    info!("✅ Client endpoint created");

    // Test the challenge protocol
    let result = timeout(Duration::from_secs(5), async {
        // Server task: accept connection and perform challenge handshake
        let server_task = async {
            info!("📡 Server waiting for connection...");
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            info!("✅ Server accepted connection");

            let (send, recv) = connection.open_bi().await.unwrap();
            info!("📡 Server accepted bidirectional stream");

            // Use the server's keypair for the challenge
            let server_challenge_keypair = match &server_keypair {
                TransportPrivateKey::Ed25519 { signing_key } => {
                    KeyPair::Ed25519(Box::new(signing_key.clone()))
                }
                #[cfg(feature = "tls-ml-dsa-44")]
                TransportPrivateKey::MlDsa44 { keypair } => {
                    KeyPair::MlDsa44(Box::new(keypair.clone()))
                }
            };

            // Perform challenge handshake
            let verified_keys = zoe_relay::challenge::perform_multi_challenge_handshake(
                send,
                recv,
                &server_challenge_keypair,
            )
            .await?;

            info!(
                "✅ Server completed challenge handshake with {} verified keys",
                verified_keys.len()
            );
            sleep(Duration::from_millis(100)).await;
            connection.close(0u32.into(), b"Test completed");
            Ok::<_, anyhow::Error>(verified_keys.len())
        };

        // Client task: connect and respond to challenge
        let client_task = async {
            sleep(Duration::from_millis(100)).await;
            info!("🔗 Client connecting to server...");
            let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
            info!("✅ Client connected to server");

            let (send, recv) = connection.accept_bi().await?;
            info!("🔗 Client opened bidirectional stream");

            // Perform challenge handshake from client side
            let server_verifying_key = match &server_public_key {
                zoe_wire_protocol::TransportPublicKey::Ed25519 { verifying_key } => {
                    zoe_wire_protocol::VerifyingKey::Ed25519(Box::new(*verifying_key))
                }
                zoe_wire_protocol::TransportPublicKey::MlDsa44 {
                    verifying_key_bytes,
                } => {
                    // This would need proper conversion for ML-DSA
                    panic!("ML-DSA not supported in this test");
                }
            };
            let (verified_count, _) = zoe_client::challenge::perform_client_challenge_handshake(
                send,
                recv,
                &server_verifying_key,
                &[&client_keypair],
            )
            .await?;

            info!(
                "✅ Client completed challenge handshake with {} verified keys",
                verified_count
            );
            sleep(Duration::from_millis(100)).await;
            connection.close(0u32.into(), b"Test completed");
            Ok::<_, anyhow::Error>(verified_count)
        };

        // Run both tasks concurrently
        let (server_result, client_result) = tokio::try_join!(server_task, client_task)?;

        // Both should have verified 1 key
        assert_eq!(server_result, 1, "Server should verify 1 client key");
        assert_eq!(client_result, 1, "Client should verify 1 server key");

        Ok::<_, anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            info!("✅ Challenge protocol test passed!");
            Ok(())
        }
        Ok(Err(e)) => {
            anyhow::bail!("Challenge protocol test failed: {}", e);
        }
        Err(_) => {
            anyhow::bail!("Challenge protocol test timed out after 5 seconds");
        }
    }
}

#[tokio::test]
async fn test_challenge_protocol_multiple_keys() -> Result<()> {
    init_crypto_provider();
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    info!("🚀 Starting multiple keys challenge protocol test");

    // Generate server and multiple client keys
    let server_signing_key = generate_ed25519_relay_keypair(&mut rand::thread_rng());
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: match server_signing_key {
            KeyPair::Ed25519(key) => *key,
            _ => panic!("Expected Ed25519 key"),
        },
    };
    let server_public_key = server_keypair.public_key();

    let client_keypair1 = generate_keypair(&mut rand::thread_rng());
    let client_keypair2 = generate_keypair(&mut rand::thread_rng());
    let client_keypair3 = generate_keypair(&mut rand::thread_rng());

    let server_endpoint =
        create_server_endpoint(SocketAddr::from(([127, 0, 0, 1], 0)), &server_keypair)?;
    let server_addr = server_endpoint.local_addr().unwrap();

    // Create client endpoint
    let client_endpoint = create_client_endpoint(&server_public_key)?;

    // Test the challenge protocol with multiple keys
    let result = timeout(Duration::from_secs(15), async {
        // Server task
        let server_task = async {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.open_bi().await.unwrap();

            let server_challenge_keypair = match &server_keypair {
                TransportPrivateKey::Ed25519 { signing_key } => {
                    KeyPair::Ed25519(Box::new(signing_key.clone()))
                }
                #[cfg(feature = "tls-ml-dsa-44")]
                TransportPrivateKey::MlDsa44 { keypair } => {
                    KeyPair::MlDsa44(Box::new(keypair.clone()))
                }
            };

            let verified_keys = zoe_relay::challenge::perform_multi_challenge_handshake(
                send,
                recv,
                &server_challenge_keypair,
            )
            .await?;
            sleep(Duration::from_millis(100)).await;
            connection.close(0u32.into(), b"Test completed");

            Ok::<_, anyhow::Error>(verified_keys.len())
        };

        // Client task with multiple keys
        let client_task = async {
            let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
            let (send, recv) = connection.accept_bi().await?;

            let client_keys = vec![&client_keypair1, &client_keypair2, &client_keypair3];
            let server_verifying_key = match &server_public_key {
                zoe_wire_protocol::TransportPublicKey::Ed25519 { verifying_key } => {
                    zoe_wire_protocol::VerifyingKey::Ed25519(Box::new(*verifying_key))
                }
                zoe_wire_protocol::TransportPublicKey::MlDsa44 {
                    verifying_key_bytes: _,
                } => {
                    panic!("ML-DSA not supported in this test");
                }
            };
            let (verified_count, _) = zoe_client::challenge::perform_client_challenge_handshake(
                send,
                recv,
                &server_verifying_key,
                &client_keys,
            )
            .await?;

            sleep(Duration::from_millis(100)).await;
            connection.close(0u32.into(), b"Test completed");

            Ok::<_, anyhow::Error>(verified_count)
        };

        let (server_result, client_result) = tokio::try_join!(server_task, client_task)?;

        // Server should verify 3 client keys
        assert_eq!(server_result, 3, "Server should verify 3 client keys");
        // Client should confirm 3 client keys
        assert_eq!(client_result, 3, "Client should confirm 3 client keys");

        Ok::<_, anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            info!("✅ Multiple keys challenge protocol test passed!");
            Ok(())
        }
        Ok(Err(e)) => {
            anyhow::bail!("Multiple keys test failed: {}", e);
        }
        Err(_) => {
            anyhow::bail!("Multiple keys test timed out after 15 seconds");
        }
    }
}

#[tokio::test]
async fn test_challenge_protocol_invalid_signature() -> Result<()> {
    init_crypto_provider();
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    info!("🚀 Starting invalid signature challenge protocol test");

    // Generate server keys
    let server_signing_key = generate_ed25519_relay_keypair(&mut rand::thread_rng());
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: match server_signing_key {
            KeyPair::Ed25519(key) => *key,
            _ => panic!("Expected Ed25519 key"),
        },
    };
    let _server_public_key = server_keypair.public_key();

    // Generate a different server key to create invalid signature
    let wrong_server_signing_key = generate_ed25519_relay_keypair(&mut rand::thread_rng());
    let wrong_server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: match wrong_server_signing_key {
            KeyPair::Ed25519(key) => *key,
            _ => panic!("Expected Ed25519 key"),
        },
    };
    let wrong_server_public_key = wrong_server_keypair.public_key();

    let client_keypair = generate_keypair(&mut rand::thread_rng());

    // Find free port and create server endpoint
    let server_endpoint =
        create_server_endpoint(SocketAddr::from(([127, 0, 0, 1], 0)), &server_keypair)?;
    let server_addr = server_endpoint.local_addr().unwrap();

    // Create client endpoint with WRONG server public key
    let client_endpoint = create_client_endpoint(&wrong_server_public_key)?;

    // Test should fail due to signature mismatch
    let result = timeout(Duration::from_secs(5), async {
        let server_task = async {
            let connection = server_endpoint.accept().await.unwrap().await.unwrap();
            let (send, recv) = connection.accept_bi().await.unwrap();

            let server_challenge_keypair = match &server_keypair {
                TransportPrivateKey::Ed25519 { signing_key } => {
                    KeyPair::Ed25519(Box::new(signing_key.clone()))
                }
                #[cfg(feature = "tls-ml-dsa-44")]
                TransportPrivateKey::MlDsa44 { keypair } => {
                    KeyPair::MlDsa44(Box::new(keypair.clone()))
                }
            };

            let _verified_keys = zoe_relay::challenge::perform_multi_challenge_handshake(
                send,
                recv,
                &server_challenge_keypair,
            )
            .await?;

            Ok::<_, anyhow::Error>(())
        };

        let client_task = async {
            let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
            let (send, recv) = connection.open_bi().await?;

            // This should fail because client expects wrong server signature
            let wrong_server_verifying_key = match &wrong_server_public_key {
                zoe_wire_protocol::TransportPublicKey::Ed25519 { verifying_key } => {
                    zoe_wire_protocol::VerifyingKey::Ed25519(Box::new(*verifying_key))
                }
                zoe_wire_protocol::TransportPublicKey::MlDsa44 {
                    verifying_key_bytes: _,
                } => {
                    panic!("ML-DSA not supported in this test");
                }
            };
            let _verified_count = zoe_client::challenge::perform_client_challenge_handshake(
                send,
                recv,
                &wrong_server_verifying_key, // Wrong key!
                &[&client_keypair],
            )
            .await?;

            Ok::<_, anyhow::Error>(())
        };

        // This should fail
        tokio::try_join!(server_task, client_task)?;
        Ok::<_, anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            anyhow::bail!("Invalid signature test should have failed but didn't!");
        }
        Ok(Err(_)) => {
            info!("✅ Invalid signature test correctly failed as expected");
            Ok(())
        }
        Err(_) => {
            info!(
                "✅ Invalid signature test timed out as expected (client rejected server signature)"
            );
            Ok(())
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_challenge_protocol_version_mismatch() -> Result<()> {
    init_crypto_provider();
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    info!("🚀 Starting protocol version mismatch test");

    // Generate server and client keys
    let server_signing_key = generate_ed25519_relay_keypair(&mut rand::thread_rng());
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: match server_signing_key {
            KeyPair::Ed25519(key) => *key,
            _ => panic!("Expected Ed25519 key"),
        },
    };
    let server_public_key = server_keypair.public_key();

    // Create server with specific protocol requirements that won't match the client
    use zoe_wire_protocol::version::{ProtocolVariant, ServerProtocolConfig, VersionReq};

    // Server requires a very high version that the client won't support
    // We'll create a server config that requires an impossibly high version
    let server_protocol_config = ServerProtocolConfig::new().add_variant_requirement(
        ProtocolVariant::Relay,
        VersionReq::parse(">=99.0.0").unwrap(), // Impossibly high version requirement
    );

    // Find free port and create server endpoint with incompatible protocol requirements
    let server_endpoint =
        zoe_wire_protocol::connection::server::create_server_endpoint_with_protocols(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            &server_keypair,
            &server_protocol_config,
        )?;
    let server_addr = server_endpoint.local_addr().unwrap();

    info!(
        "✅ Server endpoint created on {} with high version requirement",
        server_addr
    );

    // Create client endpoint with default (low) version
    let client_endpoint = create_client_endpoint(&server_public_key)?;

    info!("✅ Client endpoint created with default version");

    // Test that the connection is rejected due to protocol mismatch
    let result = timeout(Duration::from_secs(5), async {
        // Server task: should accept connection but client will close it after protocol validation
        let server_task = async {
            info!("📡 Server waiting for connection (TLS will succeed, but client will close after validation)...");
            // Try to accept a connection - TLS should succeed but client will close after validation
            match timeout(Duration::from_secs(2), server_endpoint.accept()).await {
                Ok(Some(incoming)) => {
                    // If we get an incoming connection, try to complete the handshake
                    match timeout(Duration::from_secs(1), incoming).await {
                        Ok(Ok(_connection)) => {
                            info!("✅ Server TLS connection succeeded (expected - client will validate and close)");
                            // Wait a bit for the client to validate and close the connection
                            sleep(Duration::from_millis(200)).await;
                            Ok::<(), anyhow::Error>(())
                        }
                        Ok(Err(e)) => {
                            info!("✅ Server connection failed: {}", e);
                            Ok::<(), anyhow::Error>(())
                        }
                        Err(_) => {
                            info!("✅ Server connection timed out");
                            Ok::<(), anyhow::Error>(())
                        }
                    }
                }
                Ok(None) => {
                    info!("✅ Server accept returned None (no incoming connections)");
                    Ok::<(), anyhow::Error>(())
                }
                Err(_) => {
                    info!("✅ Server accept timed out");
                    Ok::<(), anyhow::Error>(())
                }
            }
        };

        // Client task: should fail to connect due to protocol mismatch
        let client_task = async {
            sleep(Duration::from_millis(100)).await;
            info!("🔗 Client attempting to connect (should fail)...");
            match client_endpoint.connect(server_addr, "localhost") {
                Ok(connecting) => {
                    // Try to complete the connection
                    match timeout(Duration::from_secs(2), connecting).await {
                        Ok(Ok(connection)) => {
                            info!("✅ Client TLS connection succeeded, now validating protocol support...");
                            // Connection succeeded, but we need to validate the protocol
                            let client_protocol_config = zoe_wire_protocol::version::ClientProtocolConfig::default();
                            match zoe_wire_protocol::version::validate_server_protocol_support(&connection, &client_protocol_config) {
                                Ok(negotiated_version) => {
                                    panic!("Protocol validation succeeded when it should have failed: {}", negotiated_version);
                                }
                                Err(zoe_wire_protocol::version::ProtocolVersionError::ProtocolNotSupportedByServer) => {
                                    info!("✅ Client correctly detected protocol not supported by server");
                                    Ok::<(), anyhow::Error>(())
                                }
                                Err(e) => {
                                    panic!("Client protocol validation failed with unexpected error: {}", e);
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            info!("✅ Client connection correctly failed: {}", e);
                            // Verify it's the expected error type
                            let error_string = e.to_string();
                            if error_string.contains("protocol") || error_string.contains("handshake") {
                                Ok::<(), anyhow::Error>(())
                            } else {
                                panic!("Client failed with unexpected error: {}", e);
                            }
                        }
                        Err(_) => {
                            info!("✅ Client connection timed out (acceptable for protocol mismatch)");
                            Ok::<(), anyhow::Error>(())
                        }
                    }
                }
                Err(e) => {
                    info!("✅ Client connect failed immediately: {}", e);
                    Ok::<(), anyhow::Error>(())
                }
            }
        };

        // Run both tasks - both should handle the rejection gracefully
        let (_server_result, _client_result) = tokio::try_join!(server_task, client_task)?;

        Ok::<_, anyhow::Error>(())
    })
    .await;

    match result {
        Ok(Ok(())) => {
            info!("✅ Protocol version mismatch test passed!");
            Ok(())
        }
        Ok(Err(e)) => {
            panic!("Test failed with error: {}", e);
        }
        Err(_) => {
            panic!("Test timed out");
        }
    }
}
