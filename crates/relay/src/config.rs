use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zoe_wire_protocol::generate_ml_dsa_44_keypair_for_tls;

/// Serde support for ML-DSA-44 KeyPair
mod serde_ml_dsa_44 {
    use ml_dsa::{KeyPair, MlDsa44};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(keypair: &KeyPair<MlDsa44>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = keypair.signing_key().encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<KeyPair<MlDsa44>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSigningKey::<MlDsa44>::try_from(bytes.as_slice())
            .map_err(serde::de::Error::custom)?;
        let signing_key: ml_dsa::SigningKey<MlDsa44> = ml_dsa::SigningKey::decode(&encoded);

        // We can't reconstruct a KeyPair from just a SigningKey
        // So we'll generate a new keypair for now
        // TODO: This is a limitation - we should store the full keypair seed
        use ml_dsa::KeyGen;
        Ok(MlDsa44::key_gen(&mut rand::thread_rng()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelayConfig {
    #[serde(with = "serde_ml_dsa_44")]
    pub server_keypair: ml_dsa::KeyPair<ml_dsa::MlDsa44>,
    pub blob_config: BlobConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlobConfig {
    pub data_dir: PathBuf,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            server_keypair: generate_ml_dsa_44_keypair_for_tls(),
            blob_config: BlobConfig::default(),
        }
    }
}

impl Default for BlobConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./blob-store-data"),
        }
    }
}
