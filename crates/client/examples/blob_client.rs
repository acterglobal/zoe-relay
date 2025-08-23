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
//! # Upload a file
//! cargo run --example blob_client -- --server-key <HEX_PUBLIC_KEY> upload ./README.md
//!
//! # Download a file by hash
//! cargo run --example blob_client -- --server-key <HEX_PUBLIC_KEY> download <BLOB_HASH> --output ./downloaded_file.md
//!
//! # Run a round-trip test (upload then download)
//! cargo run --example blob_client -- --server-key <HEX_PUBLIC_KEY> test ./test_file.txt
//! ```

use anyhow::Result;
use clap::{Arg, Command};
use std::{fs, net::SocketAddr, path::Path};
use tracing::{error, info};
use zoe_client::{BlobService, RelayClient};
use zoe_wire_protocol::KeyPair;

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
async fn download_blob(
    blob_service: &BlobService,
    hash: &str,
    output_path: Option<&Path>,
) -> Result<()> {
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
    info!(
        "🔄 Starting round-trip test with file: {}",
        file_path.display()
    );

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

/// Blob client commands
#[derive(Debug, Clone)]
enum BlobCommand {
    Upload {
        file_path: String,
    },
    Download {
        hash: String,
        output_path: Option<String>,
    },
    Test {
        file_path: String,
    },
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

    // Parse command line arguments using subcommands
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
        .subcommand(
            Command::new("upload")
                .about("Upload a file to the blob store")
                .arg(
                    Arg::new("file")
                        .value_name("FILE_PATH")
                        .help("Path to the file to upload")
                        .required(true),
                )
        )
        .subcommand(
            Command::new("download")
                .about("Download a blob by its hash")
                .arg(
                    Arg::new("hash")
                        .value_name("BLOB_HASH")
                        .help("Hash of the blob to download")
                        .required(true),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("OUTPUT_PATH")
                        .help("Output file path for downloaded blob"),
                )
        )
        .subcommand(
            Command::new("test")
                .about("Run round-trip test: upload file then download it back")
                .arg(
                    Arg::new("file")
                        .value_name("FILE_PATH")
                        .help("Path to the file to test with")
                        .required(true),
                )
        )
        .subcommand_required(true)
        .get_matches();

    // Parse global arguments
    let address: SocketAddr = matches
        .get_one::<String>("address")
        .unwrap()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid address: {}", e))?;

    let server_key_hex = matches.get_one::<String>("server-key").unwrap();
    let server_key_bytes = hex::decode(server_key_hex)
        .map_err(|e| anyhow::anyhow!("Invalid server key hex: {}", e))?;

    // Try to decode as Ed25519 first (default), then ML-DSA-44
    let server_public_key = if server_key_bytes.len() == 32 {
        // Ed25519 public key (32 bytes)
        let ed25519_key = ed25519_dalek::VerifyingKey::from_bytes(
            server_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid Ed25519 public key length"))?,
        )
        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;
        zoe_wire_protocol::VerifyingKey::Ed25519(Box::new(ed25519_key))
    } else if server_key_bytes.len() == 1312 {
        // ML-DSA-44 public key (1312 bytes)
        let ml_dsa_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa44>::decode(
            server_key_bytes
                .as_slice()
                .try_into()
                .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-44 public key length: {}", e))?,
        );
        zoe_wire_protocol::VerifyingKey::MlDsa44((Box::new(ml_dsa_key), blake3::hash(b"")))
    } else {
        anyhow::bail!("Server key must be either 32 bytes (Ed25519) or 1312 bytes (ML-DSA-44)");
    };

    // Parse subcommand
    let command = match matches.subcommand() {
        Some(("upload", sub_matches)) => {
            let file_path = sub_matches.get_one::<String>("file").unwrap().clone();
            BlobCommand::Upload { file_path }
        }
        Some(("download", sub_matches)) => {
            let hash = sub_matches.get_one::<String>("hash").unwrap().clone();
            let output_path = sub_matches.get_one::<String>("output").cloned();
            BlobCommand::Download { hash, output_path }
        }
        Some(("test", sub_matches)) => {
            let file_path = sub_matches.get_one::<String>("file").unwrap().clone();
            BlobCommand::Test { file_path }
        }
        _ => anyhow::bail!("Invalid subcommand"),
    };

    // Create client (with optional private key)
    let client = if let Some(client_key_hex) = matches.get_one::<String>("client-key") {
        let _client_key_bytes = hex::decode(client_key_hex)
            .map_err(|e| anyhow::anyhow!("Invalid client key hex: {}", e))?;

        // For now, just generate a random key since ML-DSA key loading is complex
        // TODO: Implement proper ML-DSA key loading from bytes
        let client_keypair = KeyPair::generate(&mut rand::thread_rng());
        RelayClient::new(client_keypair, server_public_key, address).await?
    } else {
        RelayClient::new_with_random_key(server_public_key, address).await?
    };

    info!("🔗 Connected to relay server at {}", address);
    info!(
        "🔑 Client public key: {}",
        hex::encode(client.public_key().encode())
    );

    // Connect to blob service
    let blob_service = client.connect_blob_service().await?;
    info!("🗃️  Connected to blob service");

    // Execute the requested operation
    match command {
        BlobCommand::Upload { file_path } => {
            let file_path = Path::new(&file_path);
            if !file_path.exists() {
                anyhow::bail!("File does not exist: {}", file_path.display());
            }
            upload_file(&blob_service, file_path).await?;
        }
        BlobCommand::Download { hash, output_path } => {
            let output_path = output_path.as_ref().map(Path::new);
            download_blob(&blob_service, &hash, output_path).await?;
        }
        BlobCommand::Test { file_path } => {
            let file_path = Path::new(&file_path);
            if !file_path.exists() {
                anyhow::bail!("File does not exist: {}", file_path.display());
            }
            run_roundtrip_test(&blob_service, file_path).await?;
        }
    }

    info!("🔌 Disconnected from server");
    info!("🎊 Blob client operation completed successfully!");

    Ok(())
}
