//! Example demonstrating the higher-level file storage abstraction
//!
//! This example shows how to use the FileStorage client to:
//! 1. Store files with encryption
//! 2. Retrieve files and decrypt them
//! 3. Work with the stored file metadata
//!
//! Run with: `cargo run --example file_storage_example`

use tempfile::tempdir;
use tokio::fs;
use zoe_client::FileStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("file_storage_example=info,zoe_client=info,zoe_blob_store=info")
        .init();

    println!("🔐 File Storage Example");
    println!("======================");

    // Create a temporary directory for our blob storage
    let temp_dir = tempdir()?;
    let storage_path = temp_dir.path().join("file_storage");

    // Create the file storage client
    println!("\n📁 Creating file storage at: {}", storage_path.display());
    let file_storage = FileStorage::new(&storage_path).await?;

    // Example 1: Store and retrieve a text file
    println!("\n📝 Example 1: Text File Storage");
    println!("------------------------------");

    // Create a sample text file
    let text_content =
        "Hello, World!\nThis is a test file for encrypted storage.\n🔒 Encryption rocks!";
    let text_file_path = temp_dir.path().join("sample.txt");
    fs::write(&text_file_path, text_content).await?;

    // Store the file
    println!("📤 Storing file: {}", text_file_path.display());
    let stored_info = file_storage.store_file(&text_file_path).await?;

    println!("✅ File stored successfully!");
    println!("   📋 Blob hash: {}", stored_info.blob_hash);
    println!("   📦 Original size: {} bytes", stored_info.original_size());
    println!(
        "   🗜️  Compressed: {}",
        stored_info.encryption_info.was_compressed
    );

    // Retrieve the file
    println!("\n📥 Retrieving file...");
    let retrieved_content = file_storage.retrieve_file(&stored_info).await?;
    let retrieved_text = String::from_utf8(retrieved_content)?;

    println!("✅ File retrieved successfully!");
    println!("📄 Content:\n{retrieved_text}");

    // Verify content matches
    assert_eq!(text_content, retrieved_text);
    println!("✓ Content verification passed!");

    // Example 2: Store raw data without a file
    println!("\n📊 Example 2: Raw Data Storage");
    println!("----------------------------");

    let raw_data = b"This is raw binary data that doesn't come from a file";

    println!("📤 Storing raw data ({} bytes)...", raw_data.len());
    let raw_stored_info = file_storage
        .store_data(
            raw_data,
            "raw_data_example",
            Some("application/octet-stream".to_string()),
        )
        .await?;

    println!("✅ Raw data stored!");
    println!("   📋 Blob hash: {}", raw_stored_info.blob_hash);
    println!(
        "   📦 Original size: {} bytes",
        raw_stored_info.original_size()
    );
    println!("   🏷️  Content type: {:?}", raw_stored_info.content_type);

    // Retrieve the raw data
    let retrieved_raw_data = file_storage.retrieve_file(&raw_stored_info).await?;

    println!("📥 Raw data retrieved: {} bytes", retrieved_raw_data.len());
    assert_eq!(raw_data.as_slice(), retrieved_raw_data.as_slice());
    println!("✓ Raw data verification passed!");

    // Example 3: Demonstrate convergent encryption
    println!("\n🔄 Example 3: Convergent Encryption");
    println!("----------------------------------");

    let duplicate_content = "This is the same content stored twice";

    // Store the same content twice
    let stored1 = file_storage
        .store_data(duplicate_content.as_bytes(), "content1", None)
        .await?;
    let stored2 = file_storage
        .store_data(duplicate_content.as_bytes(), "content2", None)
        .await?;

    println!("📤 Stored same content twice:");
    println!("   📋 Hash 1: {}", stored1.blob_hash);
    println!("   📋 Hash 2: {}", stored2.blob_hash);

    if stored1.blob_hash == stored2.blob_hash {
        println!("✅ Convergent encryption working! Same content = same hash");
    } else {
        println!("❌ Unexpected: different hashes for same content");
    }

    // Example 4: Check if files exist
    println!("\n🔍 Example 4: File Existence Check");
    println!("---------------------------------");

    let exists = file_storage.has_file(&stored_info).await?;
    println!("📋 File {} exists: {}", stored_info.blob_hash, exists);
    assert!(exists);

    // Example 5: Retrieve file to disk
    println!("\n💾 Example 5: Retrieve to Disk");
    println!("-----------------------------");

    let output_file = temp_dir.path().join("retrieved_file.txt");
    file_storage
        .retrieve_file_to_disk(&stored_info, &output_file)
        .await?;

    println!("📁 File saved to: {}", output_file.display());

    // Verify the saved file
    let saved_content = fs::read_to_string(&output_file).await?;
    assert_eq!(text_content, saved_content);
    println!("✓ Saved file verification passed!");

    // Example 6: Storage statistics
    println!("\n📈 Example 6: Storage Information");
    println!("-------------------------------");

    println!("🏪 Storage location: {}", storage_path.display());

    // Get underlying blob client for advanced operations
    let blob_client = file_storage.blob_client();
    let blob_list = blob_client.list_local_blobs().await?;
    println!("📦 Total blobs stored: {}", blob_list.len());

    println!("\n🎉 File Storage Example Complete!");
    println!("All examples ran successfully. The file storage provides:");
    println!("  ✅ Transparent encryption/decryption");
    println!("  ✅ Content-based deduplication");
    println!("  ✅ Compression for efficiency");
    println!("  ✅ Secure blob storage");
    println!("  ✅ Flexible API for files and raw data");

    Ok(())
}
