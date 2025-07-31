//! # Blob Client Example
//!
//! Demonstrates connecting to a Zoe Relay Server and using the Blob service
//! to upload files to and download files from the remote blob store.
//!
//! ## Usage
//!
//! ```bash
//! # Start the relay server first
//! cargo run --bin zoe-relay
//!
//! # In another terminal, run the client to upload a file
//! cargo run --example blob_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY> --upload ./README.md
//!
//! # Or download a file by hash
//! cargo run --example blob_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY> --download <BLOB_HASH> --output ./downloaded_file.md
//!
//! # Or do a round-trip test (upload then download)
//! cargo run --example blob_client -- --address 127.0.0.1:4433 --server-key <HEX_PUBLIC_KEY> --test ./test_file.txt
//! ```

use anyhow::Result;
use clap::{Arg, Command};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{
    fs,
    net::SocketAddr,
    path::Path,
};
use tracing::{info, warn, error};
use zoe_client::{BlobService, RelayClient};

/// Upload a file to the blob store
async fn upload_file(blob_service: &BlobService, file_path: &Path) -> Result<String> {
    info!("📁 Reading file: {}", file_path.display());
    
    let file_data = fs::read(file_path)?;
    let file_size = file_data.len();
    info!("📊 File size: {} bytes", file_size);

    info!("📤 Uploading file to blob store...");
    let hash = blob_service.upload_blob(&file_data).await?;
    
    info!("✅ File uploaded successfully!");
    info!("🔗 Blob hash: {}", hash);
    info!("📏 Uploaded {} bytes", file_size);
    
    Ok(hash)
}

/// Download a blob from the store
async fn download_blob(blob_service: &BlobService, hash: &str, output_path: Option<&Path>) -> Result<()> {
    info!("📥 Downloading blob with hash: {}", hash);
    
    let blob_data = blob_service.get_blob(hash).await?;
    let data_size = blob_data.len();
    info!("📊 Downloaded {} bytes", data_size);

    if let Some(output_path) = output_path {
        info!("💾 Writing to file: {}", output_path.display());
        fs::write(output_path, &blob_data)?;
        info!("✅ File saved successfully!");
    } else {
        info!("📄 Blob content preview (first 200 bytes):");
        let preview = if blob_data.len() > 200 {
            &blob_data[..200]
        } else {
            &blob_data
        };
        
        // Try to display as text if it's valid UTF-8
        match std::str::from_utf8(preview) {
            Ok(text) => {
                info!("📝 Text content:\n{}", text);
                if blob_data.len() > 200 {
                    info!("... (truncated, {} more bytes)", blob_data.len() - 200);
                }
            }
            Err(_) => {
                info!("🔢 Binary content (hex): {}", hex::encode(preview));
                if blob_data.len() > 200 {
                    info!("... (truncated, {} more bytes)", blob_data.len() - 200);
                }
            }
        }
    }
    
    Ok(())
}

/// Run a round-trip test: upload a file, then download it back
async fn run_roundtrip_test(blob_service: &BlobService, file_path: &Path) -> Result<()> {
    info!("🔄 Starting round-trip test with file: {}", file_path.display());
    
    // Read original file
    let original_data = fs::read(file_path)?;
    info!("📖 Original file size: {} bytes", original_data.len());
    
    // Upload file
    let hash = upload_file(blob_service, file_path).await?;
    
    // Download the same blob
    info!("🔄 Now downloading the uploaded blob...");
    let downloaded_data = blob_service.get_blob(&hash).await?;
    info!("📥 Downloaded {} bytes", downloaded_data.len());
    
    // Compare data
    if original_data == downloaded_data {
        info!("🎉 SUCCESS: Round-trip test passed!");
        info!("✅ Original and downloaded data match perfectly");
        info!("🔗 Blob hash: {}", hash);
    } else {
        error!("❌ FAILURE: Data mismatch!");
        error!("   Original size: {} bytes", original_data.len());
        error!("   Downloaded size: {} bytes", downloaded_data.len());
        return Err(anyhow::anyhow!("Round-trip test failed: data mismatch"));
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse command line arguments
    let matches = Command::new("blob_client")
        .about("Blob store client for testing Zoe Relay Blob service")
        .arg(
            Arg::new("address")
                .short('a')
                .long("address")
                .value_name("ADDRESS")
                .help("Server address to connect to")
                .default_value("127.0.0.1:4433"),
        )
        .arg(
            Arg::new("server-key")
                .short('k')
                .long("server-key")
                .value_name("HEX_PUBLIC_KEY")
                .help("Server's ed25519 public key (hex encoded)")
                .required(true),
        )
        .arg(
            Arg::new("client-key")
                .short('c')
                .long("client-key")
                .value_name("HEX_PRIVATE_KEY")
                .help("Client's ed25519 private key (hex encoded, optional - generates random if not provided)"),
        )
        .arg(
            Arg::new("upload")
                .short('u')
                .long("upload")
                .value_name("FILE_PATH")
                .help("Upload a file to the blob store")
                .conflicts_with_all(&["download", "test"]),
        )
        .arg(
            Arg::new("download")
                .short('d')
                .long("download")
                .value_name("BLOB_HASH")
                .help("Download a blob by its hash")
                .conflicts_with_all(&["upload", "test"]),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("OUTPUT_PATH")
                .help("Output file path for downloaded blob (only used with --download)"),
        )
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .value_name("FILE_PATH")
                .help("Run round-trip test: upload file then download it back")
                .conflicts_with_all(&["upload", "download"]),
        )
        .get_matches();

    // Parse server address
    let address: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

    // Parse server public key
    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes = hex::decode(server_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid server key hex: {}", e))?;

    if server_key_bytes.len() != 32 {
        anyhow::bail!("Server key must be 32 bytes (64 hex characters)");
    }

    let server_public_key = VerifyingKey::from_bytes(&server_key_bytes.try_into().unwrap())
        .map_err(|e| anyhow::anyhow!("Invalid ed25519 public key: {}", e))?;

    // Create client (with optional private key)
    let client = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let client_key_bytes = hex::decode(client_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid client key hex: {}", e))?;

        if client_key_bytes.len() != 32 {
            anyhow::bail!("Client key must be 32 bytes (64 hex characters)");
        }

        let client_key = SigningKey::from_bytes(&client_key_bytes.try_into().unwrap());
        RelayClient::new(client_key, server_public_key, address).await?
    } else {
        RelayClient::new_with_random_key(server_public_key, address).await?
    };

    info!("🔗 Connected to relay server at {}", address);
    info!("🔑 Client public key: {}", hex::encode(client.public_key().to_bytes()));

    // Connect to blob service
    let blob_service = client.connect_blob_service().await?;
    info!("🗃️  Connected to blob service");

    // Execute the requested operation  
    if let Some(file_path_str) = matches.get_one::<String>("upload") {
        let file_path = Path::new(file_path_str);
        if !file_path.exists() {
            anyhow::bail!("File does not exist: {}", file_path.display());
        }
        upload_file(&blob_service, file_path).await?;
    } else if let Some(hash) = matches.get_one::<String>("download") {
        let output_path = matches.get_one::<String>("output").map(|s| Path::new(s));
        download_blob(&blob_service, hash, output_path).await?;
    } else if let Some(file_path_str) = matches.get_one::<String>("test") {
        let file_path = Path::new(file_path_str);
        if !file_path.exists() {
            anyhow::bail!("File does not exist: {}", file_path.display());
        }
        run_roundtrip_test(&blob_service, file_path).await?;
    } else {
        warn!("⚠️  No operation specified. Use --upload, --download, or --test");
        warn!("   Run with --help for usage information");
        return Ok(());
    }

    info!("🔌 Disconnected from server");
    info!("🎊 Blob client operation completed successfully!");
    
    Ok(())
}