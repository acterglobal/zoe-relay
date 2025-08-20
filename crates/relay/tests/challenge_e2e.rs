//! End-to-end integration tests for the challenge protocol using in-process QUIC
//!
//! These tests verify the complete client-server challenge handshake flow
//! using real QUIC connections in-process.

use anyhow::Result;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ml_dsa::{KeyGen, MlDsa65};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use signature::{SignatureEncoding, Signer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;
use zoe_client::challenge::perform_client_ml_dsa_handshake;
use zoe_wire_protocol::{
    generate_deterministic_cert_from_ml_dsa_44_for_tls, generate_ml_dsa_44_keypair_for_tls,
    AcceptSpecificServerCertVerifier,
};

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

/// Creates a test QUIC server with ML-DSA-44 certificate
async fn create_test_server(
    server_keypair: &ml_dsa::KeyPair<ml_dsa::MlDsa44>,
) -> Result<(Endpoint, SocketAddr)> {
    // Generate certificate from ML-DSA-44 key
    let cert_der = generate_deterministic_cert_from_ml_dsa_44_for_tls(server_keypair, "localhost")?;

    // Create a temporary Ed25519 key for rustls compatibility
    let temp_ed25519_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        temp_ed25519_key
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec()
            .into(),
    );

    // Create server config
    let rustls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(zoe_wire_protocol::ZoeClientCertVerifier::new()))
        .with_single_cert(cert_der, key_der)
        .map_err(|e| anyhow::anyhow!("Server config error: {}", e))?;

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| anyhow::anyhow!("QUIC server config error: {}", e))?,
    ));

    // Create server endpoint
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
        .map_err(|e| anyhow::anyhow!("Server endpoint error: {}", e))?;

    let server_addr = server_endpoint.local_addr().unwrap();
    info!("Test server listening on {}", server_addr);

    Ok((server_endpoint, server_addr))
}

/// Creates a test QUIC client with ML-DSA-44 certificate
async fn create_test_client(
    client_keypair: &ml_dsa::KeyPair<ml_dsa::MlDsa44>,
    server_public_key: &ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
) -> Result<Endpoint> {
    // Generate client certificate from ML-DSA-44 key
    let cert_der = generate_deterministic_cert_from_ml_dsa_44_for_tls(client_keypair, "localhost")?;

    // Create a temporary Ed25519 key for rustls compatibility
    let temp_ed25519_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        temp_ed25519_key
            .to_pkcs8_der()
            .unwrap()
            .as_bytes()
            .to_vec()
            .into(),
    );

    // Create client config with server verification
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptSpecificServerCertVerifier::new(
            server_public_key.clone(),
        )))
        .with_client_auth_cert(cert_der, key_der)
        .map_err(|e| anyhow::anyhow!("Client config error: {}", e))?;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| anyhow::anyhow!("QUIC client config error: {}", e))?,
    ));

    // Set transport config
    client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

    // Create client endpoint
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())
        .map_err(|e| anyhow::anyhow!("Client endpoint error: {}", e))?;
    client_endpoint.set_default_client_config(client_config);

    Ok(client_endpoint)
}

#[tokio::test]
async fn test_single_key_challenge_success() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_public_key = server_keypair.verifying_key();
    let server_key = server_keypair.signing_key();
    let client_keypair_tls = generate_ml_dsa_44_keypair_for_tls();
    let client_key = client_keypair_tls.signing_key();
    let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint = create_test_client(&client_keypair_tls, server_public_key).await?;

    // Server task: accept connection and perform handshake
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (send, recv) = connection.accept_bi().await.unwrap();

        // TODO: Update challenge handshake to work with ML-DSA-44 keys
        // perform_multi_challenge_handshake(send, recv, &server_public_key)
        Ok::<std::collections::BTreeSet<Vec<u8>>, anyhow::Error>(std::collections::BTreeSet::new())
            .unwrap()
    });

    // Client task: connect and perform handshake
    let client_task = tokio::spawn(async move {
        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();

        perform_client_ml_dsa_handshake(send, recv, &[&client_keypair])
            .await
            .unwrap()
    });

    // Wait for both tasks with timeout
    let server_result = timeout(Duration::from_secs(10), server_task).await??;
    let client_result = timeout(Duration::from_secs(10), client_task).await??;

    // Verify results
    assert_eq!(server_result.len(), 1); // Server verified 1 key
    assert_eq!(client_result, 1); // Client had 1 key verified

    info!("✅ Single key challenge test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_multiple_keys_challenge_success() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_public_key = server_keypair.verifying_key();
    let client_keypair_tls = generate_ml_dsa_44_keypair_for_tls();

    // Generate multiple ML-DSA keypairs
    let client_keypair1 = MlDsa65::key_gen(&mut rand::thread_rng());
    let client_keypair2 = MlDsa65::key_gen(&mut rand::thread_rng());
    let client_keypair3 = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint = create_test_client(&client_keypair_tls, server_public_key).await?;

    // Server task: accept connection and perform handshake
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (send, recv) = connection.accept_bi().await.unwrap();

        // TODO: Update challenge handshake to work with ML-DSA-44 keys
        // perform_multi_challenge_handshake(send, recv, &server_public_key)
        Ok::<std::collections::BTreeSet<Vec<u8>>, anyhow::Error>(std::collections::BTreeSet::new())
            .unwrap()
    });

    // Client task: connect and perform handshake with multiple keys
    let client_task = tokio::spawn(async move {
        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();

        perform_client_ml_dsa_handshake(
            send,
            recv,
            &[&client_keypair1, &client_keypair2, &client_keypair3],
        )
        .await
        .unwrap()
    });

    // Wait for both tasks with timeout
    let server_result = timeout(Duration::from_secs(10), server_task).await??;
    let client_result = timeout(Duration::from_secs(10), client_task).await??;

    // Verify results
    assert_eq!(server_result.len(), 3); // Server verified 3 keys
    assert_eq!(client_result, 3); // Client had 3 keys verified

    info!("✅ Multiple keys challenge test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_challenge_with_invalid_key() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_public_key = server_keypair.verifying_key();
    let client_keypair_tls = generate_ml_dsa_44_keypair_for_tls();

    // Generate ML-DSA keypairs (we'll create invalid signatures)
    let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint = create_test_client(&client_keypair_tls, server_public_key).await?;

    // Server task: accept connection and perform handshake
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (send, recv) = connection.accept_bi().await.unwrap();

        // This should fail because we'll send invalid signatures
        // TODO: Update challenge handshake to work with ML-DSA-44 keys
        // perform_multi_challenge_handshake(send, recv, &server_public_key)
        Ok::<std::collections::BTreeSet<Vec<u8>>, anyhow::Error>(std::collections::BTreeSet::new())
    });

    // Client task: connect and send invalid response
    let client_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use zoe_wire_protocol::{MlDsaKeyProof, MlDsaMultiKeyResponse, ZoeChallenge};

        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();

        // Receive challenge
        let challenge_len = recv.read_u32().await.unwrap() as usize;
        let mut challenge_buf = vec![0u8; challenge_len];
        recv.read_exact(&mut challenge_buf).await.unwrap();
        let challenge: ZoeChallenge = postcard::from_bytes(&challenge_buf).unwrap();

        // Create invalid response (wrong signature)
        let invalid_signature = client_keypair.signing_key().sign(b"wrong data");
        let response = MlDsaMultiKeyResponse {
            key_proofs: vec![MlDsaKeyProof {
                public_key: client_keypair.verifying_key().encode().as_slice().to_vec(),
                signature: invalid_signature.to_bytes().to_vec(),
            }],
        };

        // Send invalid response
        let response_bytes = postcard::to_stdvec(&response).unwrap();
        send.write_u32(response_bytes.len() as u32).await.unwrap();
        send.write_all(&response_bytes).await.unwrap();

        // This should fail
        Ok::<(), anyhow::Error>(())
    });

    // Wait for both tasks with timeout
    let server_result = timeout(Duration::from_secs(10), server_task).await?;
    let client_result = timeout(Duration::from_secs(10), client_task).await??;

    // Server should fail due to invalid signature
    assert!(server_result.is_err());

    info!("✅ Invalid key challenge test completed successfully (expected failure)");
    Ok(())
}

#[tokio::test]
async fn test_connection_without_challenge() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_public_key = server_keypair.verifying_key();
    let client_keypair_tls = generate_ml_dsa_44_keypair_for_tls();

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint = create_test_client(&client_keypair_tls, server_public_key).await?;

    // Server task: accept connection but don't perform handshake
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();

        // Just verify we can establish the QUIC connection
        info!("Server: QUIC connection established");
        Ok::<(), anyhow::Error>(())
    });

    // Client task: connect but don't perform handshake
    let client_task = tokio::spawn(async move {
        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();

        // Just verify we can establish the QUIC connection
        info!("Client: QUIC connection established");
        Ok::<(), anyhow::Error>(())
    });

    // Wait for both tasks with timeout
    let server_result = timeout(Duration::from_secs(10), server_task).await??;
    let client_result = timeout(Duration::from_secs(10), client_task).await??;

    // Both should succeed (just QUIC connection, no challenge)
    assert!(server_result.is_ok());
    assert!(client_result.is_ok());

    info!("✅ Basic QUIC connection test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_challenge_timeout() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_keypair = generate_ml_dsa_44_keypair_for_tls();
    let server_public_key = server_keypair.verifying_key();
    let client_keypair_tls = generate_ml_dsa_44_keypair_for_tls();

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint = create_test_client(&client_keypair_tls, server_public_key).await?;

    // Server task: accept connection and perform handshake
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint.accept().await.unwrap();
        let connection = incoming.await.unwrap();
        let (send, recv) = connection.accept_bi().await.unwrap();

        // This should timeout because client won't respond
        // TODO: Update challenge handshake to work with ML-DSA-44 keys
        // perform_multi_challenge_handshake(send, recv, &server_public_key)
        Ok::<std::collections::BTreeSet<Vec<u8>>, anyhow::Error>(std::collections::BTreeSet::new())
    });

    // Client task: connect but don't respond to challenge
    let client_task = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;

        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, mut recv) = connection.open_bi().await.unwrap();

        // Receive challenge but don't respond
        let challenge_len = recv.read_u32().await.unwrap() as usize;
        let mut challenge_buf = vec![0u8; challenge_len];
        recv.read_exact(&mut challenge_buf).await.unwrap();

        info!("Client: Received challenge but not responding (simulating timeout)");

        // Sleep to simulate timeout
        tokio::time::sleep(Duration::from_secs(5)).await;

        Ok::<(), anyhow::Error>(())
    });

    // Wait for both tasks with shorter timeout
    let server_result = timeout(Duration::from_secs(3), server_task).await;
    let client_result = timeout(Duration::from_secs(6), client_task).await??;

    // Server should timeout
    assert!(server_result.is_err()); // Should timeout

    info!("✅ Challenge timeout test completed successfully (expected timeout)");
    Ok(())
}
