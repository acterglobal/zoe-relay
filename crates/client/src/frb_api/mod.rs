use flutter_rust_bridge::frb;
use std::net::SocketAddr;

// Socket address utilities
#[frb]
pub fn create_socket_addr(ip: String, port: u16) -> Result<SocketAddr, String> {
    format!("{}:{}", ip, port)
        .parse()
        .map_err(|e| format!("Invalid socket address: {}", e))
}

#[frb]
pub fn socket_addr_to_string(addr: &SocketAddr) -> String {
    addr.to_string()
}

#[frb]
pub fn socket_addr_ip(addr: &SocketAddr) -> String {
    addr.ip().to_string()
}

#[frb]
pub fn socket_addr_port(addr: &SocketAddr) -> u16 {
    addr.port()
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
pub fn verifying_key_from_hex(hex: String) -> Result<String, String> {
    use ed25519_dalek::VerifyingKey;
    let bytes = hex::decode(hex).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err("VerifyingKey must be exactly 32 bytes".to_string());
    }
    let array: [u8; 32] = bytes.try_into().map_err(|_| "Invalid byte array")?;
    let _key =
        VerifyingKey::from_bytes(&array).map_err(|e| format!("Invalid verifying key: {}", e))?;
    Ok(hex::encode(array)) // Return the validated hex
}
