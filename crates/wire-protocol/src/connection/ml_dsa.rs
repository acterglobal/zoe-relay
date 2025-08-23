//! ML-DSA-44-based TLS certificate and connection utilities
//!
//! This module provides ML-DSA-44-based TLS certificate generation and verification
//! for post-quantum transport security in the Zoe wire protocol.
//!
//! This module is only available when the `ml-dsa-44` feature is enabled.

#[cfg(feature = "tls-ml-dsa-44")]
pub mod ml_dsa_44 {
    use der::{asn1::*, Encode};
    use ml_dsa::{KeyPair, MlDsa44, VerifyingKey as MlDsaVerifyingKey};
    use rustls::pki_types::CertificateDer;
    use signature::{SignatureEncoding, Signer};
    use x509_cert::{
        attr::{AttributeTypeAndValue, AttributeValue},
        certificate::{Certificate, TbsCertificate, Version},
        name::{Name, RelativeDistinguishedName},
        serial_number::SerialNumber,
        spki::{AlgorithmIdentifier, SubjectPublicKeyInfo},
        time::{Time, Validity},
    };
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::prelude::*;

    use crate::crypto::CryptoError;

    /// ML-DSA-44 public key extracted from certificates
    pub type PublicKey = MlDsaVerifyingKey<MlDsa44>;

    /// Generate a deterministic TLS certificate using ML-DSA-44
    ///
    /// This creates a proper ML-DSA-44 certificate where the ML-DSA-44 public key
    /// is stored directly in the SubjectPublicKeyInfo field according to FIPS 204.
    pub fn generate_ml_dsa_44_cert_for_tls(
        ml_dsa_key_pair: &KeyPair<MlDsa44>,
        subject_name: &str,
    ) -> std::result::Result<Vec<CertificateDer<'static>>, CryptoError> {
        tracing::debug!(
            "🔧 Creating proper ML-DSA-44 certificate for subject: {}",
            subject_name
        );

        let verifying_key = ml_dsa_key_pair.verifying_key();
        let public_key_bytes = verifying_key.encode();

        tracing::debug!(
            "🔧 ML-DSA-44 public key length: {} bytes",
            public_key_bytes.len()
        );

        // ML-DSA-44 algorithm identifier OID (from FIPS 204)
        let ml_dsa_44_oid = ObjectIdentifier::new("2.16.840.1.101.3.4.3.17")
            .map_err(|e| CryptoError::ParseError(format!("Invalid ML-DSA-44 OID: {e}")))?;

        // Create SubjectPublicKeyInfo with ML-DSA-44 public key
        let algorithm = AlgorithmIdentifier {
            oid: ml_dsa_44_oid,
            parameters: None,
        };

        let subject_public_key_info = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: BitString::from_bytes(&public_key_bytes)
                .map_err(|e| CryptoError::ParseError(format!("Failed to create BitString: {e}")))?,
        };

        // Create subject name (CN=subject_name)
        let cn_oid = const_oid::db::rfc4519::CN;
        let cn_value = AttributeValue::new(der::Tag::Utf8String, subject_name.as_bytes())
            .map_err(|e| CryptoError::ParseError(format!("Failed to create CN value: {e}")))?;

        let cn_attribute = AttributeTypeAndValue {
            oid: cn_oid,
            value: cn_value,
        };

        let rdn = RelativeDistinguishedName::from(
            SetOfVec::try_from(vec![cn_attribute])
                .map_err(|e| CryptoError::ParseError(format!("Failed to create RDN: {e}")))?,
        );

        let subject = Name::try_from(vec![rdn])
            .map_err(|e| CryptoError::ParseError(format!("Failed to create subject: {e}")))?;

        // Set validity period (1 year from now)
        let now = std::time::SystemTime::now();
        let not_before = Time::GeneralTime(
            GeneralizedTime::from_system_time(now)
                .map_err(|e| CryptoError::ParseError(format!("Time conversion error: {e}")))?,
        );
        let not_after = Time::GeneralTime(
            GeneralizedTime::from_system_time(
                now + std::time::Duration::from_secs(365 * 24 * 3600),
            )
            .map_err(|e| CryptoError::ParseError(format!("Time conversion error: {e}")))?,
        );

        let validity = Validity {
            not_before,
            not_after,
        };

        // Create TBS certificate
        let tbs_certificate = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::from(1u32),
            signature: AlgorithmIdentifier {
                oid: ml_dsa_44_oid,
                parameters: None,
            },
            issuer: subject.clone(), // Self-signed
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };

        // Encode TBS certificate for signing
        let tbs_der = tbs_certificate.to_der().map_err(|e| {
            CryptoError::ParseError(format!("Failed to encode TBS certificate: {e}"))
        })?;

        // Sign the TBS certificate with ML-DSA-44
        let signature = ml_dsa_key_pair.sign(&tbs_der);

        // Create final certificate
        let certificate = Certificate {
            tbs_certificate,
            signature_algorithm: AlgorithmIdentifier {
                oid: ml_dsa_44_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(signature.to_bytes().as_ref()).map_err(|e| {
                CryptoError::ParseError(format!("Failed to create signature BitString: {e}"))
            })?,
        };

        // Encode certificate to DER
        let cert_der = certificate
            .to_der()
            .map_err(|e| CryptoError::ParseError(format!("Failed to encode certificate: {e}")))?;

        tracing::debug!("✅ Generated proper ML-DSA-44 certificate successfully");

        Ok(vec![CertificateDer::from(cert_der)])
    }

    /// Extract ML-DSA-44 public key from a certificate
    ///
    /// This function extracts the ML-DSA-44 public key directly from the certificate's
    /// SubjectPublicKeyInfo field when the certificate uses the ML-DSA-44 algorithm identifier.
    pub fn extract_ml_dsa_44_public_key_from_cert(
        cert_der: &CertificateDer,
    ) -> std::result::Result<PublicKey, CryptoError> {
        // Parse the certificate
        let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
            .map_err(|e| CryptoError::ParseError(format!("Failed to parse certificate: {e:?}")))?;

        // Get the subject public key info
        let spki = cert.public_key();
        let algorithm_oid = &spki.algorithm.algorithm;

        // ML-DSA-44 algorithm identifier: 2.16.840.1.101.3.4.3.17
        let ml_dsa_44_oid = oid!(2.16.840 .1 .101 .3 .4 .3 .17);

        tracing::debug!("🔍 Certificate algorithm OID: {}", algorithm_oid);

        if algorithm_oid != &ml_dsa_44_oid {
            return Err(CryptoError::ParseError(format!(
                "Certificate is not using ML-DSA-44 algorithm. Found OID: {algorithm_oid}"
            )));
        }

        tracing::debug!("🔍 Found ML-DSA-44 certificate");
        let public_key_bits = &spki.subject_public_key;

        // The BIT STRING contains the raw 1312-byte ML-DSA-44 public key
        // Note: BIT STRING may have unused bits indicator as first byte
        let key_bytes = if public_key_bits.data.len() == 1313 && public_key_bits.data[0] == 0 {
            // Skip the unused bits indicator (should be 0 for ML-DSA-44)
            &public_key_bits.data[1..]
        } else if public_key_bits.data.len() == 1312 {
            // Direct 1312-byte key
            &public_key_bits.data
        } else {
            return Err(CryptoError::ParseError(format!(
                "Invalid ML-DSA-44 public key length: {} bytes",
                public_key_bits.data.len()
            )));
        };

        tracing::debug!(
            "🔍 Extracted ML-DSA-44 public key: {} bytes",
            key_bytes.len()
        );

        // Validate key length
        if key_bytes.len() != 1312 {
            return Err(CryptoError::ParseError(format!(
                "Invalid ML-DSA-44 public key length: {} bytes (expected 1312)",
                key_bytes.len()
            )));
        }

        // Convert to ML-DSA-44 VerifyingKey
        let encoded_key: &ml_dsa::EncodedVerifyingKey<MlDsa44> =
            key_bytes.try_into().map_err(|_| {
                CryptoError::ParseError("Invalid ML-DSA-44 verifying key length".to_string())
            })?;

        let verifying_key = MlDsaVerifyingKey::<MlDsa44>::decode(encoded_key);

        tracing::debug!("✅ Successfully extracted ML-DSA-44 public key from certificate");
        Ok(verifying_key)
    }

    /// Create a complete rustls ServerConfig for ML-DSA-44 certificates
    pub fn create_ml_dsa_44_server_config(
        ml_dsa_keypair: &KeyPair<MlDsa44>,
        hostname: &str,
    ) -> std::result::Result<rustls::ServerConfig, CryptoError> {
        create_ml_dsa_44_server_config_with_alpn(
            ml_dsa_keypair,
            hostname,
            crate::version::ServerProtocolConfig::default(),
        )
    }

    /// Create a complete rustls ServerConfig for ML-DSA-44 certificates with ALPN support
    pub fn create_ml_dsa_44_server_config_with_alpn(
        ml_dsa_keypair: &KeyPair<MlDsa44>,
        hostname: &str,
        server_protocol_config: crate::version::ServerProtocolConfig,
    ) -> std::result::Result<rustls::ServerConfig, CryptoError> {
        let alpn_protocols = server_protocol_config.alpn_protocols();
        // Generate TLS certificate from ML-DSA-44 key
        let certs = generate_ml_dsa_44_cert_for_tls(ml_dsa_keypair, hostname)?;

        // Use the default crypto provider
        let crypto_provider = rustls::crypto::aws_lc_rs::default_provider();

        // Create certificate resolver with ML-DSA-44 signing key
        let private_key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(ml_dsa_keypair.encode().to_vec()),
        );

        // Create a simple certificate resolver
        #[derive(Debug)]
        struct MlDsaCertResolver {
            certs: Vec<rustls::pki_types::CertificateDer<'static>>,
            key: rustls::pki_types::PrivateKeyDer<'static>,
        }

        impl rustls::server::ResolvesServerCert for MlDsaCertResolver {
            fn resolve(
                &self,
                _client_hello: rustls::server::ClientHello,
            ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
                let signing_key =
                    rustls::crypto::aws_lc_rs::sign::any_supported_type(&self.key).ok()?;
                Some(std::sync::Arc::new(rustls::sign::CertifiedKey::new(
                    self.certs.clone(),
                    signing_key,
                )))
            }
        }

        let cert_resolver = MlDsaCertResolver {
            certs,
            key: private_key,
        };

        // Create rustls server config
        let mut rustls_config =
            rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(crypto_provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| CryptoError::TlsError(format!("Failed to set TLS version: {}", e)))?
                .with_no_client_auth() // we accept any client
                .with_cert_resolver(std::sync::Arc::new(cert_resolver));

        // Set ALPN protocols
        rustls_config.alpn_protocols = alpn_protocols;

        Ok(rustls_config)
    }
}

#[cfg(feature = "tls-ml-dsa-44")]
pub use ml_dsa_44::*;
