use crate::ClientError;
use crate::error::Result;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::SocketAddr;
use std::sync::Arc;
use zoe_app_primitives::RelayAddress;
use zoe_wire_protocol::{KeyPair, VerifyingKey};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb(opaque))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSecret {
    #[serde(
        serialize_with = "serialize_key_pair",
        deserialize_with = "deserialize_key_pair"
    )]
    pub(crate) inner_keypair: Arc<KeyPair>, // inner protocol
    pub(crate) servers: Vec<RelayAddress>,
    pub(crate) encryption_key: [u8; 32],
}

impl PartialEq for ClientSecret {
    fn eq(&self, other: &Self) -> bool {
        // Compare servers and encryption key, but not keypair (since KeyPair doesn't implement Eq)
        self.servers == other.servers && self.encryption_key == other.encryption_key
    }
}

impl Eq for ClientSecret {}

impl ClientSecret {
    /// Get the list of configured servers
    pub fn servers(&self) -> &[RelayAddress] {
        &self.servers
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyClientSecret {
    #[serde(
        serialize_with = "serialize_key_pair",
        deserialize_with = "deserialize_key_pair"
    )]
    inner_keypair: Arc<KeyPair>, // inner protocol
    server_public_key: VerifyingKey, // TLS server key
    server_addr: SocketAddr,
    encryption_key: [u8; 32],
}

impl PartialEq for LegacyClientSecret {
    fn eq(&self, other: &Self) -> bool {
        // Compare all fields except keypair (since KeyPair doesn't implement Eq)
        self.server_public_key == other.server_public_key
            && self.server_addr == other.server_addr
            && self.encryption_key == other.encryption_key
    }
}

impl Eq for LegacyClientSecret {}

fn serialize_key_pair<S>(
    key_pair: &Arc<KeyPair>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&key_pair.to_pem().map_err(serde::ser::Error::custom)?)
}
fn deserialize_key_pair<'de, D>(deserializer: D) -> std::result::Result<Arc<KeyPair>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Ok(Arc::new(
        KeyPair::from_pem(&s).map_err(serde::de::Error::custom)?,
    ))
}

impl ClientSecret {
    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex).map_err(|e| {
            ClientError::BuildError(format!("Failed to decode hex for client secret: {}", e))
        })?;
        let secret = match postcard::from_bytes(&bytes) {
            Ok(secret) => secret,
            Err(e) => {
                tracing::warn!(
                    "Failed to deserialize client secret: {}. Trying with legacy format.",
                    e
                );
                let legacy_secret: LegacyClientSecret =
                    postcard::from_bytes(&bytes).map_err(|e| {
                        ClientError::BuildError(format!(
                            "Failed to deserialize legacy client secret: {}",
                            e
                        ))
                    })?;
                ClientSecret {
                    inner_keypair: legacy_secret.inner_keypair,
                    servers: vec![
                        RelayAddress::new(legacy_secret.server_public_key)
                            .with_address(legacy_secret.server_addr.into()),
                    ],
                    encryption_key: legacy_secret.encryption_key,
                }
            }
        };
        Ok(secret)
    }

    pub fn to_hex(&self) -> Result<String> {
        let bytes = postcard::to_stdvec(&self).map_err(|e| {
            ClientError::BuildError(format!("Failed to serialize client secret: {}", e))
        })?;
        Ok(hex::encode(bytes))
    }
}
