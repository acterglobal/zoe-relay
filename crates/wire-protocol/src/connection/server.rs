use crate::crypto::{CryptoError, Result};
use crate::version::ServerProtocolConfig;
use crate::TransportPrivateKey;
use quinn::Endpoint;
use std::net::SocketAddr;
use tracing::info;

use quinn::ServerConfig;
use std::sync::Arc;

#[cfg(feature = "tls-ml-dsa-44")]
use super::ml_dsa::{create_ml_dsa_44_server_config, create_ml_dsa_44_server_config_with_alpn};

/// Create a QUIC server endpoint with TLS certificate (Ed25519 or ML-DSA-44)
pub fn create_server_endpoint(
    addr: SocketAddr,
    server_keypair: &TransportPrivateKey,
) -> Result<Endpoint> {
    create_server_endpoint_with_protocols(addr, server_keypair, &ServerProtocolConfig::default())
}

/// Create a QUIC server endpoint with protocol version negotiation support
pub fn create_server_endpoint_with_protocols(
    addr: SocketAddr,
    server_keypair: &TransportPrivateKey,
    protocol_negotiation: &ServerProtocolConfig,
) -> Result<Endpoint> {
    info!("🚀 Creating relay server endpoint on {}", addr);

    let rustls_config = match server_keypair {
        TransportPrivateKey::Ed25519 { signing_key } => {
            info!(
                "🔑 Server Ed25519 public key: {}",
                hex::encode(signing_key.verifying_key().to_bytes())
            );

            // Create Ed25519 server configuration with ALPN
            super::ed25519::create_ed25519_server_config_with_alpn(
                signing_key,
                "localhost",
                protocol_negotiation.clone(),
            )
            .map_err(|e| {
                CryptoError::TlsError(format!("Failed to create Ed25519 server config: {e}"))
            })?
        }

        #[cfg(feature = "tls-ml-dsa-44")]
        TransportPrivateKey::MlDsa44 { keypair } => {
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
