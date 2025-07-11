use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tracing::{info, warn};

/// Configuration for the example client
#[derive(Debug, Clone)]
struct ExampleConfig {
    server_url: String,
    test_file_path: PathBuf,
    temp_download_path: PathBuf,
}

impl Default for ExampleConfig {
    fn default() -> Self {
        Self {
            server_url: "http://127.0.0.1:9091".to_string(),
            test_file_path: PathBuf::from("test_data.txt"),
            temp_download_path: PathBuf::from("downloaded_data.txt"),
        }
    }
}

/// Example client for interacting with the blob store
struct ExampleClient {
    config: ExampleConfig,
    client: Client,
}

impl ExampleClient {
    fn new(config: ExampleConfig) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { config, client }
    }

    /// Check if the blob store server is healthy
    async fn health_check(&self) -> Result<bool> {
        let response = self
            .client
            .get(&format!("{}/health", self.config.server_url))
            .send()
            .await?;

        if response.status().is_success() {
            let health: Value = response.json().await?;
            info!("Server health: {:?}", health);
            Ok(true)
        } else {
            warn!("Server health check failed: {}", response.status());
            Ok(false)
        }
    }

    /// Upload a file to the blob store
    async fn upload_file(&self) -> Result<String> {
        // Read the test file
        let file_content = fs::read(&self.config.test_file_path)
            .await
            .context("Failed to read test file")?;

        info!(
            "Uploading file: {} ({} bytes)",
            self.config.test_file_path.display(),
            file_content.len()
        );

        // Upload to blob store
        let response = self
            .client
            .post(&format!("{}/upload", self.config.server_url))
            .body(file_content.clone())
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Upload failed: {}", response.status());
        }

        let upload_response: Value = response.json().await?;
        let hash = upload_response["hash"]
            .as_str()
            .context("No hash in response")?
            .to_string();

        info!("Upload successful, hash: {}", hash);
        Ok(hash)
    }

    /// Download a file from the blob store by hash
    async fn download_file(&self, hash: &str) -> Result<Vec<u8>> {
        info!("Downloading file with hash: {}", hash);

        let response = self
            .client
            .get(&format!("{}/blob/{}", self.config.server_url, hash))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Download failed: {}", response.status());
        }

        let data = response.bytes().await?;
        info!("Download successful: {} bytes", data.len());

        Ok(data.to_vec())
    }

    /// Get information about a blob
    async fn get_blob_info(&self, hash: &str) -> Result<Value> {
        let response = self
            .client
            .get(&format!("{}/blob/{}/info", self.config.server_url, hash))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("Get blob info failed: {}", response.status());
        }

        let info: Value = response.json().await?;
        info!("Blob info: {:?}", info);
        Ok(info)
    }

    /// Save downloaded data to a file
    async fn save_downloaded_data(&self, data: &[u8]) -> Result<()> {
        fs::write(&self.config.temp_download_path, data)
            .await
            .context("Failed to write downloaded data")?;

        info!(
            "Saved downloaded data to: {}",
            self.config.temp_download_path.display()
        );
        Ok(())
    }

    /// Compare original and downloaded data
    async fn compare_data(&self) -> Result<bool> {
        let original_data = fs::read(&self.config.test_file_path)
            .await
            .context("Failed to read original file")?;

        let downloaded_data = fs::read(&self.config.temp_download_path)
            .await
            .context("Failed to read downloaded file")?;

        let matches = original_data == downloaded_data;

        if matches {
            info!("✅ Data integrity check passed! Original and downloaded data match.");
        } else {
            warn!("❌ Data integrity check failed! Original and downloaded data differ.");
            warn!("Original size: {} bytes", original_data.len());
            warn!("Downloaded size: {} bytes", downloaded_data.len());
        }

        Ok(matches)
    }

    /// Clean up temporary files
    async fn cleanup(&self) -> Result<()> {
        if self.config.temp_download_path.exists() {
            fs::remove_file(&self.config.temp_download_path)
                .await
                .context("Failed to remove temporary file")?;
            info!(
                "Cleaned up temporary file: {}",
                self.config.temp_download_path.display()
            );
        }
        Ok(())
    }

    /// Run the complete upload/download example
    async fn run_example(&self) -> Result<()> {
        info!("🚀 Starting blob store upload/download example");

        // Step 1: Health check
        info!("Step 1: Checking server health...");
        if !self.health_check().await? {
            anyhow::bail!("Server is not healthy");
        }

        // Step 2: Create test data if it doesn't exist
        if !self.config.test_file_path.exists() {
            info!("Step 2: Creating test data file...");
            let test_content = "Hello, World! This is test data for the blob store.\n".repeat(100);
            fs::write(&self.config.test_file_path, test_content)
                .await
                .context("Failed to create test file")?;
            info!(
                "Created test file: {}",
                self.config.test_file_path.display()
            );
        }

        // Step 3: Upload file
        info!("Step 3: Uploading file to blob store...");
        let hash = self.upload_file().await?;

        // Step 4: Get blob info
        info!("Step 4: Getting blob information...");
        self.get_blob_info(&hash).await?;

        // Step 5: Download file
        info!("Step 5: Downloading file from blob store...");
        let downloaded_data = self.download_file(&hash).await?;

        // Step 6: Save downloaded data
        info!("Step 6: Saving downloaded data...");
        self.save_downloaded_data(&downloaded_data).await?;

        // Step 7: Compare data
        info!("Step 7: Comparing original and downloaded data...");
        let data_matches = self.compare_data().await?;

        // Step 8: Cleanup
        info!("Step 8: Cleaning up...");
        self.cleanup().await?;

        if data_matches {
            info!("🎉 Example completed successfully!");
        } else {
            anyhow::bail!("Example failed: data integrity check failed");
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create configuration
    let config = ExampleConfig::default();

    // Create client
    let client = ExampleClient::new(config);

    // Run the example
    match client.run_example().await {
        Ok(()) => {
            info!("Example completed successfully");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("Example failed: {}", e);
            std::process::exit(1);
        }
    }
}
