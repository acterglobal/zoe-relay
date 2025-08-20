//! End-to-end integration tests for the challenge protocol using in-process QUIC
//!
//! These tests verify the complete client-server challenge handshake flow
//! using real QUIC connections in-process with ML-DSA-44 keys for TLS authentication.

#![allow(dead_code, unused_imports, unused_variables)]

use anyhow::Result;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ml_dsa::{KeyGen, MlDsa44, MlDsa65};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use signature::{SignatureEncoding, Signer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;
use tracing::{info, warn};
use zoe_client::challenge::perform_client_ml_dsa_handshake;
use zoe_relay::challenge::{
    create_key_proofs, generate_ml_dsa_challenge, verify_ml_dsa_key_proofs,
};
use zoe_wire_protocol::MlDsaMultiKeyResult;
use zoe_wire_protocol::{
    generate_deterministic_cert_from_ml_dsa_44_for_tls, generate_ml_dsa_44_keypair_for_tls,
    AcceptSpecificServerCertVerifier, MlDsaKeyProof, MlDsaMultiKeyChallenge, MlDsaMultiKeyResponse,
    ZoeChallenge, ZoeChallengeRejection, ZoeChallengeResult,
};

/// Test certificate verifier that accepts any certificate (for testing only)
#[derive(Debug)]
struct AcceptAnyCertVerifier;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
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
    let server_config = ServerConfig::with_single_cert(cert_der, key_der)
        .map_err(|e| anyhow::anyhow!("Server config error: {}", e))?;

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
    let crypto_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptSpecificServerCertVerifier::new(
            server_public_key.clone(),
        )))
        .with_client_auth_cert(cert_der, key_der)
        .map_err(|e| anyhow::anyhow!("Client config error: {}", e))?;

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)
            .map_err(|e| anyhow::anyhow!("QUIC config error: {}", e))?,
    ));

    // Set transport config
    client_config.transport_config(Arc::new(quinn::TransportConfig::default()));

    // Create client endpoint
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())
        .map_err(|e| anyhow::anyhow!("Client endpoint error: {}", e))?;
    client_endpoint.set_default_client_config(client_config);

    Ok(client_endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Initialize tracing for tests
    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();
    }

    #[tokio::test]
    async fn test_single_key_challenge_success() -> Result<()> {
        // Generate test keys
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();
        let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

        // Generate challenge
        let challenge = generate_ml_dsa_challenge(&server_public_key)?;

        // Create response
        let response = create_key_proofs(&challenge, &[&client_keypair])?;

        // Verify the response
        let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &challenge)?;

        // Should have one verified key
        assert_eq!(verified_keys.len(), 1);
        assert!(
            verified_keys.contains(&client_keypair.verifying_key().encode().as_slice().to_vec())
        );

        // Result should be AllValid
        match result {
            MlDsaMultiKeyResult::AllValid => {}
            _ => panic!("Expected AllValid result, got: {:?}", result),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_keys_challenge_success() -> Result<()> {
        // Generate test keys
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();

        let client_keypair1 = MlDsa65::key_gen(&mut rand::thread_rng());
        let client_keypair2 = MlDsa65::key_gen(&mut rand::thread_rng());
        let client_keypair3 = MlDsa65::key_gen(&mut rand::thread_rng());

        // Generate challenge
        let challenge = generate_ml_dsa_challenge(&server_public_key)?;

        // Create response with multiple keys
        let keypairs = [&client_keypair1, &client_keypair2, &client_keypair3];
        let response = create_key_proofs(&challenge, &keypairs)?;

        // Verify the response
        let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &challenge)?;

        // Should have three verified keys
        assert_eq!(verified_keys.len(), 3);

        // Check each key is verified
        for keypair in &keypairs {
            assert!(verified_keys.contains(&keypair.verifying_key().encode().as_slice().to_vec()));
        }

        // Result should be AllValid
        match result {
            MlDsaMultiKeyResult::AllValid => {}
            _ => panic!("Expected AllValid result, got: {:?}", result),
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_partial_failure_challenge() -> Result<()> {
        // Generate test keys
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();

        let client_keypair1 = MlDsa65::key_gen(&mut rand::thread_rng());
        let client_keypair2 = MlDsa65::key_gen(&mut rand::thread_rng());

        // Generate challenge
        let challenge = generate_ml_dsa_challenge(&server_public_key)?;

        // Create one valid and one invalid response
        let signature_data = [&challenge.nonce[..], &challenge.server_public_key[..]].concat();
        let valid_signature = client_keypair1.signing_key().sign(&signature_data);
        let invalid_signature = client_keypair2.signing_key().sign(b"wrong data");

        let response = MlDsaMultiKeyResponse {
            key_proofs: vec![
                MlDsaKeyProof {
                    public_key: client_keypair1.verifying_key().encode().as_slice().to_vec(),
                    signature: valid_signature.encode().to_vec(),
                },
                MlDsaKeyProof {
                    public_key: client_keypair2.verifying_key().encode().as_slice().to_vec(),
                    signature: invalid_signature.encode().to_vec(),
                },
            ],
        };

        // Verify the response
        let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &challenge)?;

        // Should have one verified key (the valid one)
        assert_eq!(verified_keys.len(), 1);
        assert!(
            verified_keys.contains(&client_keypair1.verifying_key().encode().as_slice().to_vec())
        );

        // Result should be PartialFailure
        match result {
            MlDsaMultiKeyResult::PartialFailure { failed_indices } => {
                assert_eq!(failed_indices, vec![1]); // Second key failed
            }
            _ => panic!("Expected PartialFailure result, got: {:?}", result),
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_all_failed_challenge() -> Result<()> {
        // Generate test keys
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();

        let client_keypair1 = MlDsa65::key_gen(&mut rand::thread_rng());
        let client_keypair2 = MlDsa65::key_gen(&mut rand::thread_rng());

        // Generate challenge
        let challenge = generate_ml_dsa_challenge(&server_public_key)?;

        // Create invalid responses (wrong signature data)
        let invalid_signature1 = client_keypair1.signing_key().sign(b"wrong data 1");
        let invalid_signature2 = client_keypair2.signing_key().sign(b"wrong data 2");

        let response = MlDsaMultiKeyResponse {
            key_proofs: vec![
                MlDsaKeyProof {
                    public_key: client_keypair1.verifying_key().encode().as_slice().to_vec(),
                    signature: invalid_signature1.encode().to_vec(),
                },
                MlDsaKeyProof {
                    public_key: client_keypair2.verifying_key().encode().as_slice().to_vec(),
                    signature: invalid_signature2.encode().to_vec(),
                },
            ],
        };

        // Verify the response
        let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &challenge)?;

        // Should have no verified keys
        assert_eq!(verified_keys.len(), 0);

        // Result should be AllFailed
        match result {
            MlDsaMultiKeyResult::AllFailed => {}
            _ => panic!("Expected AllFailed result, got: {:?}", result),
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_expired_challenge() -> Result<()> {
        // Generate test keys
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();
        let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

        // Create expired challenge
        let expired_challenge = MlDsaMultiKeyChallenge {
            nonce: [42u8; 32],
            server_public_key: server_public_key.encode().to_vec(),
            expires_at: 1000000000, // Way in the past
        };

        // Create valid response (but challenge is expired)
        let response = create_key_proofs(&expired_challenge, &[&client_keypair])?;

        // Verify the response
        let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &expired_challenge)?;

        // Should have no verified keys due to expiration
        assert_eq!(verified_keys.len(), 0);

        // Result should be AllFailed
        match result {
            MlDsaMultiKeyResult::AllFailed => {}
            _ => panic!(
                "Expected AllFailed result for expired challenge, got: {:?}",
                result
            ),
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_challenge_serialization_roundtrip() -> Result<()> {
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();

        // Create challenge
        let original_challenge = ZoeChallenge::MlDsaMultiKey(MlDsaMultiKeyChallenge {
            nonce: [123u8; 32],
            server_public_key: server_public_key.encode().to_vec(),
            expires_at: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 30,
        });

        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&original_challenge)?;
        let deserialized: ZoeChallenge = postcard::from_bytes(&serialized)?;

        // Verify they match
        match (original_challenge, deserialized) {
            (ZoeChallenge::MlDsaMultiKey(orig), ZoeChallenge::MlDsaMultiKey(deser)) => {
                assert_eq!(orig.nonce, deser.nonce);
                assert_eq!(orig.server_public_key, deser.server_public_key);
                assert_eq!(orig.expires_at, deser.expires_at);
            }
            _ => panic!("Challenge type mismatch after serialization"),
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_response_serialization_roundtrip() -> Result<()> {
        let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());
        let signature = client_keypair.signing_key().sign(b"test data");

        // Create response
        let original_response = MlDsaMultiKeyResponse {
            key_proofs: vec![MlDsaKeyProof {
                public_key: client_keypair.verifying_key().encode().as_slice().to_vec(),
                signature: signature.encode().to_vec(),
            }],
        };

        // Serialize and deserialize
        let serialized = postcard::to_stdvec(&original_response)?;
        let deserialized: MlDsaMultiKeyResponse = postcard::from_bytes(&serialized)?;

        // Verify they match
        assert_eq!(
            original_response.key_proofs.len(),
            deserialized.key_proofs.len()
        );
        assert_eq!(
            original_response.key_proofs[0].public_key,
            deserialized.key_proofs[0].public_key
        );
        assert_eq!(
            original_response.key_proofs[0].signature,
            deserialized.key_proofs[0].signature
        );

        Ok(())
    }

    #[tokio::test]

    async fn test_challenge_result_serialization() -> Result<()> {
        let results = vec![
            ZoeChallengeResult::Accepted,
            ZoeChallengeResult::Next,
            ZoeChallengeResult::Rejected(ZoeChallengeRejection::ChallengeFailed),
            ZoeChallengeResult::Error("Test error".to_string()),
        ];

        for original_result in results {
            // Serialize and deserialize
            let serialized = postcard::to_stdvec(&original_result)?;
            let deserialized: ZoeChallengeResult = postcard::from_bytes(&serialized)?;

            // Verify they match (simplified comparison)
            match (&original_result, &deserialized) {
                (ZoeChallengeResult::Accepted, ZoeChallengeResult::Accepted) => {}
                (ZoeChallengeResult::Next, ZoeChallengeResult::Next) => {}
                (ZoeChallengeResult::Rejected(_), ZoeChallengeResult::Rejected(_)) => {}
                (ZoeChallengeResult::Error(orig), ZoeChallengeResult::Error(deser)) => {
                    assert_eq!(orig, deser);
                }
                _ => panic!(
                    "Result type mismatch: {:?} != {:?}",
                    original_result, deserialized
                ),
            }
        }

        Ok(())
    }

    #[tokio::test]

    async fn test_stream_communication() -> Result<()> {
        // Create in-memory duplex streams for testing
        let (client_stream, server_stream) = duplex(1024 * 1024); // 1MB buffer
        let (mut server_read, mut server_write) = tokio::io::split(server_stream);
        let (mut client_read, mut client_write) = tokio::io::split(client_stream);

        // Generate test data
        let server_keypair = generate_ml_dsa_44_keypair_for_tls();
        let server_public_key = server_keypair.verifying_key().clone();
        let client_keypair = MlDsa65::key_gen(&mut rand::thread_rng());

        // Test challenge sending and receiving
        let server_task = tokio::spawn(async move {
            // Server: Generate and send challenge
            let challenge = generate_ml_dsa_challenge(&server_public_key).unwrap();
            let challenge_enum = ZoeChallenge::MlDsaMultiKey(challenge.clone());

            // Send challenge
            let challenge_bytes = postcard::to_stdvec(&challenge_enum).unwrap();
            server_write
                .write_u32(challenge_bytes.len() as u32)
                .await
                .unwrap();
            server_write.write_all(&challenge_bytes).await.unwrap();

            // Receive response
            let response_len = server_read.read_u32().await.unwrap() as usize;
            let mut response_buf = vec![0u8; response_len];
            server_read.read_exact(&mut response_buf).await.unwrap();
            let response: MlDsaMultiKeyResponse = postcard::from_bytes(&response_buf).unwrap();

            // Verify response
            let (verified_keys, result) = verify_ml_dsa_key_proofs(&response, &challenge).unwrap();

            // Send result
            let result_enum = if verified_keys.is_empty() {
                ZoeChallengeResult::Rejected(ZoeChallengeRejection::ChallengeFailed)
            } else {
                ZoeChallengeResult::Accepted
            };
            let result_bytes = postcard::to_stdvec(&result_enum).unwrap();
            server_write
                .write_u32(result_bytes.len() as u32)
                .await
                .unwrap();
            server_write.write_all(&result_bytes).await.unwrap();

            verified_keys.len()
        });

        let client_task = tokio::spawn(async move {
            // Client: Receive challenge
            let challenge_len = client_read.read_u32().await.unwrap() as usize;
            let mut challenge_buf = vec![0u8; challenge_len];
            client_read.read_exact(&mut challenge_buf).await.unwrap();
            let challenge: ZoeChallenge = postcard::from_bytes(&challenge_buf).unwrap();

            // Create response
            let response = match challenge {
                ZoeChallenge::MlDsaMultiKey(ml_dsa_challenge) => {
                    create_key_proofs(&ml_dsa_challenge, &[&client_keypair]).unwrap()
                }
                _ => panic!("Unexpected challenge type"),
            };

            // Send response
            let response_bytes = postcard::to_stdvec(&response).unwrap();
            client_write
                .write_u32(response_bytes.len() as u32)
                .await
                .unwrap();
            client_write.write_all(&response_bytes).await.unwrap();

            // Receive result
            let result_len = client_read.read_u32().await.unwrap() as usize;
            let mut result_buf = vec![0u8; result_len];
            client_read.read_exact(&mut result_buf).await.unwrap();
            let result: ZoeChallengeResult = postcard::from_bytes(&result_buf).unwrap();

            match result {
                ZoeChallengeResult::Accepted => true,
                _ => false,
            }
        });

        // Wait for both tasks
        let (server_verified_count, client_success) = tokio::try_join!(server_task, client_task)?;

        // Verify results
        assert_eq!(server_verified_count, 1);
        assert!(client_success);

        Ok(())
    }

    #[tokio::test]

    async fn test_forward_compatibility() -> Result<()> {
        // Test unknown challenge type
        let unknown_challenge = ZoeChallenge::Unknown {
            discriminant: 999,
            data: vec![1, 2, 3, 4],
        };

        let serialized = postcard::to_stdvec(&unknown_challenge)?;
        let deserialized: ZoeChallenge = postcard::from_bytes(&serialized)?;

        match deserialized {
            ZoeChallenge::Unknown { discriminant, data } => {
                assert_eq!(discriminant, 999);
                assert_eq!(data, vec![1, 2, 3, 4]);
            }
            _ => panic!("Expected Unknown challenge type"),
        }

        // Test unknown result type
        let unknown_result = ZoeChallengeResult::Unknown {
            discriminant: 888,
            data: vec![5, 6, 7, 8],
        };

        let serialized = postcard::to_stdvec(&unknown_result)?;
        let deserialized: ZoeChallengeResult = postcard::from_bytes(&serialized)?;

        match deserialized {
            ZoeChallengeResult::Unknown { discriminant, data } => {
                assert_eq!(discriminant, 888);
                assert_eq!(data, vec![5, 6, 7, 8]);
            }
            _ => panic!("Expected Unknown result type"),
        }

        Ok(())
    }
}
