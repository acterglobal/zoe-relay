use ::serde::{Deserialize, Deserializer, Serialize, Serializer};
use ml_dsa;

/// Remote serde definition for ML-DSA-44 VerifyingKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef44")]
pub struct VerifyingKeyDef44;

impl VerifyingKeyDef44 {
    pub fn serialize<S>(
        key: &ml_dsa::VerifyingKey<ml_dsa::MlDsa44>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::VerifyingKey<ml_dsa::MlDsa44>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa44>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA-65 VerifyingKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef65")]
pub struct VerifyingKeyDef65;

impl VerifyingKeyDef65 {
    pub fn serialize<S>(
        key: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA-87 VerifyingKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::VerifyingKeyDef87")]
pub struct VerifyingKeyDef87;

impl VerifyingKeyDef87 {
    pub fn serialize<S>(
        key: &ml_dsa::VerifyingKey<ml_dsa::MlDsa87>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::VerifyingKey<ml_dsa::MlDsa87>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::VerifyingKey::<ml_dsa::MlDsa87>::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA-44 SigningKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::SigningKeyDef44")]
pub struct SigningKeyDef44;

impl SigningKeyDef44 {
    pub fn serialize<S>(
        key: &ml_dsa::SigningKey<ml_dsa::MlDsa44>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa44>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSigningKey::<ml_dsa::MlDsa44>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::SigningKey::<ml_dsa::MlDsa44>::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA-65 SigningKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::SigningKeyDef65")]
pub struct SigningKeyDef65;

impl SigningKeyDef65 {
    pub fn serialize<S>(
        key: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSigningKey::<ml_dsa::MlDsa65>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::SigningKey::<ml_dsa::MlDsa65>::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA-87 SigningKey
/// Use with #[serde(with = "zoe_wire_protocol::serde::SigningKeyDef87")]
pub struct SigningKeyDef87;

impl SigningKeyDef87 {
    pub fn serialize<S>(
        key: &ml_dsa::SigningKey<ml_dsa::MlDsa87>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa87>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSigningKey::<ml_dsa::MlDsa87>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        Ok(ml_dsa::SigningKey::<ml_dsa::MlDsa87>::decode(&encoded))
    }
}

/// Remote serde definition for ML-DSA-44 Signature
/// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef44")]
pub struct SignatureDef44;

impl SignatureDef44 {
    pub fn serialize<S>(
        sig: &ml_dsa::Signature<ml_dsa::MlDsa44>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::Signature<ml_dsa::MlDsa44>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSignature::<ml_dsa::MlDsa44>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        ml_dsa::Signature::<ml_dsa::MlDsa44>::decode(&encoded)
            .ok_or_else(|| ::serde::de::Error::custom("Invalid signature encoding"))
    }
}

/// Remote serde definition for ML-DSA-65 Signature
/// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef65")]
pub struct SignatureDef65;

impl SignatureDef65 {
    pub fn serialize<S>(
        sig: &ml_dsa::Signature<ml_dsa::MlDsa65>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::Signature<ml_dsa::MlDsa65>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&encoded)
            .ok_or_else(|| ::serde::de::Error::custom("Invalid signature encoding"))
    }
}

/// Remote serde definition for ML-DSA-87 Signature
/// Use with #[serde(with = "zoe_wire_protocol::serde::SignatureDef87")]
pub struct SignatureDef87;

impl SignatureDef87 {
    pub fn serialize<S>(
        sig: &ml_dsa::Signature<ml_dsa::MlDsa87>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = sig.encode().as_slice().to_vec();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<ml_dsa::Signature<ml_dsa::MlDsa87>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let encoded = ml_dsa::EncodedSignature::<ml_dsa::MlDsa87>::try_from(bytes.as_slice())
            .map_err(::serde::de::Error::custom)?;
        ml_dsa::Signature::<ml_dsa::MlDsa87>::decode(&encoded)
            .ok_or_else(|| ::serde::de::Error::custom("Invalid signature encoding"))
    }
}
