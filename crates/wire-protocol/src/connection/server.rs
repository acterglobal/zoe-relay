use crate::crypto::{CryptoError, Result};
use crate::version::ServerProtocolConfig;
use crate::KeyPair;
use quinn::Endpoint;
use std::net::SocketAddr;
use tracing::info;

use quinn::ServerConfig;
use std::sync::Arc;

#[cfg(feature = "tls-ml-dsa-44")]
use super::ml_dsa::{create_ml_dsa_44_server_config, create_ml_dsa_44_server_config_with_alpn};

/// Create a QUIC server endpoint with TLS certificate (Ed25519 or ML-DSA-44)
pub fn create_server_endpoint(addr: SocketAddr, server_keypair: &KeyPair) -> Result<Endpoint> {
    create_server_endpoint_with_protocols(addr, server_keypair, &ServerProtocolConfig::default())
}

/// Create a QUIC server endpoint with protocol version negotiation support
pub fn create_server_endpoint_with_protocols(
    addr: SocketAddr,
    server_keypair: &KeyPair,
    protocol_negotiation: &ServerProtocolConfig,
) -> Result<Endpoint> {
    info!("🚀 Creating relay server endpoint on {}", addr);

    let rustls_config = match server_keypair {
        KeyPair::Ed25519(signing_key) => {
            info!(
                "🔑 Server Ed25519 public key: {}",
                hex::encode(signing_key.verifying_key().to_bytes())
            );

            // Create Ed25519 server configuration with ALPN
            super::ed25519::create_ed25519_server_config_with_alpn(
                signing_key.as_ref(),
                "localhost",
                protocol_negotiation.clone(),
            )
            .map_err(|e| {
                CryptoError::TlsError(format!("Failed to create Ed25519 server config: {e}"))
            })?
        }

        #[cfg(feature = "tls-ml-dsa-44")]
        KeyPair::MlDsa44(keypair, _) => {
            info!(
                "🔑 Server ML-DSA-44 public key: {}",
                hex::encode(keypair.verifying_key().encode())
            );

            // Create ML-DSA-44 server configuration with ALPN
            create_ml_dsa_44_server_config_with_alpn(
                keypair,
                "localhost",
                protocol_negotiation.clone(),
            )
            .map_err(|e| {
                CryptoError::TlsError(format!("Failed to create ML-DSA-44 server config: {e}"))
            })?
        }

        // ML-DSA-65 and ML-DSA-87 are not supported for TLS yet
        KeyPair::MlDsa65(_, _) => {
            return Err(CryptoError::TlsError(
                "ML-DSA-65 is not supported for TLS transport security yet. Use Ed25519 or ML-DSA-44.".to_string(),
            ));
        }
        KeyPair::MlDsa87(_, _) => {
            return Err(CryptoError::TlsError(
                "ML-DSA-87 is not supported for TLS transport security yet. Use Ed25519 or ML-DSA-44.".to_string(),
            ));
        }

        #[cfg(not(feature = "tls-ml-dsa-44"))]
        KeyPair::MlDsa44(_, _) => {
            return Err(CryptoError::TlsError(
                "ML-DSA-44 TLS support is not enabled. Enable the 'tls-ml-dsa-44' feature or use Ed25519.".to_string(),
            ));
        }
    };

    let server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .map_err(|e| CryptoError::TlsError(format!("Failed to create server config: {e}")))?,
    ));

    let endpoint = Endpoint::server(server_config, addr)
        .map_err(|e| CryptoError::TlsError(format!("Failed to create server endpoint: {e}")))?;
    info!("✅ Server endpoint ready on {}", addr);

    Ok(endpoint)
}
