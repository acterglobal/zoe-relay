//! End-to-end integration tests for the challenge protocol using in-process QUIC
//!
//! These tests verify the complete client-server challenge handshake flow
//! using real QUIC connections in-process.

use anyhow::Result;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ml_dsa::{KeyGen, MlDsa65};
use quinn::{Endpoint, ServerConfig};
use signature::{Signer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;
use zoe_client::challenge::perform_client_ml_dsa_handshake;
use zoe_wire_protocol::{
    connection::client::create_client_endpoint,
    generate_ed25519_cert_for_tls,
    KeyPair, 
    TransportPrivateKey, 
    TransportPublicKey,
    VerifyingKey
};

#[cfg(feature = "tls-ml-dsa-44")]
use zoe_wire_protocol::generate_ml_dsa_44_cert_for_tls;

/// Initialize tracing for tests
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();
}

/// Creates a test QUIC server with ML-DSA-44 certificate
async fn create_test_server(
    server_keypair: &TransportPrivateKey,
) -> Result<(Endpoint, SocketAddr)> {
    // Generate certificate from transport key (Ed25519 only for tests)
    let (cert_der, key_der) = match server_keypair {
        TransportPrivateKey::Ed25519 { signing_key } => {
            let cert_chain = generate_ed25519_cert_for_tls(signing_key, "localhost")?;
            let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
                signing_key
                    .to_pkcs8_der()
                    .unwrap()
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
            (cert_chain, key_der)
        }
        #[cfg(feature = "tls-ml-dsa-44")]
        TransportPrivateKey::MlDsa44 { keypair } => {
            let cert_chain = generate_ml_dsa_44_cert_for_tls(keypair, "localhost")?;
            // For ML-DSA-44, we need to create a compatible key format
            // This is a simplified approach - in production you'd want proper ML-DSA key handling
            let temp_ed25519_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
                temp_ed25519_key
                    .to_pkcs8_der()
                    .unwrap()
                    .as_bytes()
                    .to_vec()
                    .into(),
            );
            (cert_chain, key_der)
        }
    };

    // Create server config with no client cert verification for tests
    let rustls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
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

#[tokio::test]
async fn test_single_key_challenge_success() -> Result<()> {
    init_tracing();

    // Generate test keys
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let server_public_key = server_keypair.public_key();
    let client_keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint =
        create_client_endpoint(&server_public_key)?;

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

    // Convert TransportPublicKey to VerifyingKey for challenge
    let server_verifying_key = match &server_public_key {
        TransportPublicKey::Ed25519 { verifying_key } => {
            VerifyingKey::Ed25519(Box::new(*verifying_key))
        }
        TransportPublicKey::MlDsa44 { verifying_key_bytes } => {
            let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(
                verifying_key_bytes.as_slice(),
            ).unwrap();
            VerifyingKey::MlDsa44(Box::new(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded)))
        }
    };

    // Client task: connect and perform handshake
    let client_task = tokio::spawn(async move {
        let connection = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = connection.open_bi().await.unwrap();

        perform_client_ml_dsa_handshake(send, recv, &server_verifying_key, &[&client_keypair])
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
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let server_public_key = server_keypair.public_key();

    // Generate multiple ML-DSA keypairs
    let client_keypair1 = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));
    let client_keypair2 = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));
    let client_keypair3 = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint =
        create_client_endpoint(&server_public_key)?;

    // Convert TransportPublicKey to VerifyingKey for challenge
    let server_verifying_key = match &server_public_key {
        TransportPublicKey::Ed25519 { verifying_key } => {
            VerifyingKey::Ed25519(Box::new(*verifying_key))
        }
        TransportPublicKey::MlDsa44 { verifying_key_bytes } => {
            let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(
                verifying_key_bytes.as_slice(),
            ).unwrap();
            VerifyingKey::MlDsa44(Box::new(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded)))
        }
    };

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
            &server_verifying_key,
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
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let server_public_key = server_keypair.public_key();

    // Generate ML-DSA keypairs (we'll create invalid signatures)
    let client_keypair = KeyPair::MlDsa65(Box::new(MlDsa65::key_gen(&mut rand::thread_rng())));

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint =
        create_client_endpoint(&server_public_key)?;

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
        let invalid_signature = client_keypair.sign(b"wrong data");
        let response = MlDsaMultiKeyResponse {
            key_proofs: vec![MlDsaKeyProof {
                public_key: client_keypair.public_key().encode(),
                signature: match invalid_signature {
                    zoe_wire_protocol::Signature::MlDsa65(sig) => sig.encode().to_vec(),
                    _ => panic!("Expected MlDsa65 signature"),
                },
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
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let server_public_key = server_keypair.public_key();

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint =
        create_client_endpoint(&server_public_key)?;

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
    let server_keypair = TransportPrivateKey::Ed25519 {
        signing_key: ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng),
    };
    let server_public_key = server_keypair.public_key();

    // Create server
    let (server_endpoint, server_addr) = create_test_server(&server_keypair).await?;

    // Create client
    let client_endpoint =
        create_client_endpoint(&server_public_key)?;

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
