use flutter_rust_bridge::frb;
use zoe_wire_protocol::VerifyingKey;
use crate::Client;
use crate::system_check::{SystemCheck, SystemCheckConfig};

mod for_std;
#[allow(unused_imports)]
pub use for_std::*;

// initialize for frb
pub fn frb_init() {
    // Initialize Rustls crypto provider before any TLS operations
    rustls::crypto::aws_lc_rs::default_provider()
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

// SystemCheck API - simplified interface for Flutter
#[frb]
pub async fn run_systems_check(client: &Client) -> Result<SystemsCheckResult, String> {
    let system_check = SystemCheck::with_defaults(client.clone());
    let results = system_check.run_all().await
        .map_err(|e| format!("Systems check failed: {}", e))?;
    
    let success = results.is_success();
    let total_count = results.total_count().to_string();
    let passed_count = results.passed_count().to_string();
    let failed_count = results.failed_count().to_string();
    let duration_ms = results.total_duration.as_millis() as u64;
    
    // Get category results
    let mut categories = Vec::new();
    let test_categories = [
        crate::system_check::TestCategory::Connectivity,
        crate::system_check::TestCategory::Storage,
        crate::system_check::TestCategory::BlobService,
        crate::system_check::TestCategory::OfflineStorage,
        crate::system_check::TestCategory::OfflineBlob,
        crate::system_check::TestCategory::Synchronization,
    ];
    
    for category in test_categories {
        if results.get_category_results(category).is_some() {
            let has_failures = results.category_has_failures(category);
            let category_name = format!("{:?}", category);
            categories.push(SystemsCheckCategory {
                name: category_name,
                has_failures,
            });
        }
    }
    
    Ok(SystemsCheckResult {
        success,
        total_count,
        passed_count,
        failed_count,
        duration_ms,
        categories,
    })
}

#[frb]
pub async fn run_systems_check_category(client: &Client, category_name: String) -> Result<SystemsCheckResult, String> {
    let category = match category_name.as_str() {
        "Connectivity" => crate::system_check::TestCategory::Connectivity,
        "Storage" => crate::system_check::TestCategory::Storage,
        "BlobService" => crate::system_check::TestCategory::BlobService,
        "OfflineStorage" => crate::system_check::TestCategory::OfflineStorage,
        "OfflineBlob" => crate::system_check::TestCategory::OfflineBlob,
        "Synchronization" => crate::system_check::TestCategory::Synchronization,
        _ => return Err(format!("Unknown category: {}", category_name)),
    };
    
    let system_check = SystemCheck::with_defaults(client.clone());
    let test_infos = system_check.run_category_tests(category).await
        .map_err(|e| format!("Category test failed: {}", e))?;
    
    // Create minimal results for single category
    let config = SystemCheckConfig::default();
    let mut results = crate::system_check::SystemCheckResults::new(config);
    
    for test_info in test_infos {
        results.add_test(category, test_info);
    }
    results.finalize();
    
    let success = results.is_success();
    let total_count = results.total_count().to_string();
    let passed_count = results.passed_count().to_string();
    let failed_count = results.failed_count().to_string();
    let duration_ms = results.total_duration.as_millis() as u64;
    
    let has_failures = results.category_has_failures(category);
    let categories = vec![SystemsCheckCategory {
        name: category_name,
        has_failures,
    }];
    
    Ok(SystemsCheckResult {
        success,
        total_count,
        passed_count,
        failed_count,
        duration_ms,
        categories,
    })
}

// Simple data structures for Flutter - avoiding complex opaque types
#[frb]
pub struct SystemsCheckResult {
    pub success: bool,
    pub total_count: String,
    pub passed_count: String,
    pub failed_count: String,
    pub duration_ms: u64,
    pub categories: Vec<SystemsCheckCategory>,
}

#[frb]
pub struct SystemsCheckCategory {
    pub name: String,
    pub has_failures: bool,
}
