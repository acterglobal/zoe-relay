use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use ml_dsa;

// Remote serde definitions for ML-DSA types
use super::{MlDsaParams, Signature, SigningKey, VerifyingKey};

/// Remote serde definition for ML-DSA VerifyingKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef")]
pub struct VerifyingKeyDef;

impl VerifyingKeyDef {
    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsaParams>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::VerifyingKey::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA SigningKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::SigningKeyDef")]
pub struct SigningKeyDef;

impl SigningKeyDef {
    pub fn serialize<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSigningKey::<MlDsaParams>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::SigningKey::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA Signature
/// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef")]
pub struct SignatureDef;

impl SignatureDef {
    pub fn serialize<S>(sig: &Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSignature::<MlDsaParams>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        ml_dsa::Signature::decode(&encoded)
            .ok_or_else(|| ::serde::de::Error::custom("Invalid signature encoding"))
    }
}
