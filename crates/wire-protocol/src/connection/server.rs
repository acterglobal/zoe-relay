use crate::crypto::{CryptoError, Result};
use crate::TransportPrivateKey;
use quinn::Endpoint;
use std::net::SocketAddr;
use tracing::info;

use quinn::ServerConfig;
use std::sync::Arc;

#[cfg(feature = "tls-ml-dsa-44")]
use super::ml_dsa::create_ml_dsa_44_server_config;

use super::ed25519::create_ed25519_server_config;

/// Create a QUIC server endpoint with TLS certificate (Ed25519 or ML-DSA-44)
pub fn create_server_endpoint(
    addr: SocketAddr,
    server_keypair: &TransportPrivateKey,
) -> Result<Endpoint> {
    info!("🚀 Creating relay server endpoint on {}", addr);

    let rustls_config = match server_keypair {
        TransportPrivateKey::Ed25519 { signing_key } => {
            info!(
                "🔑 Server Ed25519 public key: {}",
                hex::encode(signing_key.verifying_key().to_bytes())
            );

            // Create Ed25519 server configuration
            create_ed25519_server_config(signing_key, "localhost").map_err(|e| {
                CryptoError::TlsError(format!("Failed to create Ed25519 server config: {e}"))
            })?
        }

        #[cfg(feature = "tls-ml-dsa-44")]
        TransportPrivateKey::MlDsa44 { keypair } => {
            info!(
                "🔑 Server ML-DSA-44 public key: {}",
                hex::encode(keypair.verifying_key().encode())
            );

            // Create ML-DSA-44 server configuration using the wire protocol wrapper
            create_ml_dsa_44_server_config(keypair, "localhost").map_err(|e| {
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
