use zoeyr_blob_store::server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run the server with command line arguments
    server::run_with_args().await?;
    Ok(())
}
