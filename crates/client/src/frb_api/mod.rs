use crate::Client;
use flutter_rust_bridge::frb;
use zoe_app_primitives::connection::RelayAddress;
use zoe_wire_protocol::VerifyingKey;

mod for_std;
#[allow(unused_imports)]
pub use for_std::*;

// initialize for frb
pub fn frb_init() {
    // Initialize Rustls crypto provider before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");
}

// Key conversion utilities - work with hex strings instead of raw types
#[frb]
pub fn create_signing_key_random() -> String {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let key = SigningKey::generate(&mut OsRng);
    hex::encode(key.to_bytes())
}

#[frb]
pub fn signing_key_from_hex(hex: String) -> Result<String, String> {
    use ed25519_dalek::SigningKey;
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("SigningKey must be exactly 32 bytes".to_string());
    }
    let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid byte array")?;
    let _key = SigningKey::from_bytes(&array);
    Ok(hex::encode(array)) // Return the validated hex
}

#[frb]
pub fn signing_key_to_verifying_key(signing_key_hex: String) -> Result<String, String> {
    use ed25519_dalek::SigningKey;
    let bytes = hex::decode(signing_key_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("SigningKey must be exactly 32 bytes".to_string());
    }
    let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid byte array")?;
    let signing_key = SigningKey::from_bytes(&array);
    let verifying_key = signing_key.verifying_key();
    Ok(hex::encode(verifying_key.to_bytes()))
}

#[frb]
pub fn verifying_key_from_hex(hex: String) -> Result<VerifyingKey, String> {
    VerifyingKey::from_hex(hex)
}

// Relay management functions
#[frb]
pub async fn prepare_client_for_systems_test(
    client: &Client,
    server_address: String,
    server_key_hex: String,
) -> Result<bool, String> {
    // Parse server key
    let server_key =
        VerifyingKey::from_hex(server_key_hex).map_err(|e| format!("Invalid server key: {}", e))?;

    let relay_address = RelayAddress::new(server_key).with_address_str(server_address);

    client.close().await;

    client
        .add_relay(relay_address)
        .await
        .map_err(|e| format!("Failed to add relay: {}", e))?;

    Ok(true)
}

// RelayAddress creation helper
#[frb]
pub fn create_relay_address_with_hostname(
    server_key_hex: String,
    hostname: String,
) -> Result<RelayAddress, String> {
    // Parse server key
    let server_key =
        VerifyingKey::from_hex(server_key_hex).map_err(|e| format!("Invalid server key: {}", e))?;
    // Create RelayAddress
    let relay_address = RelayAddress::new(server_key)
        .with_address_str(hostname)
        .with_name("Default Server".to_string());

    Ok(relay_address)
}
