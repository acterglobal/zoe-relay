# Blob Store Examples

This directory contains example applications that demonstrate how to use the Zoeyr blob store.

## Upload/Download Example

The `upload_download` example demonstrates a complete workflow of uploading a file to the blob store and downloading it back to verify data integrity.

### Features

- **Health Check**: Verifies the blob store server is running and healthy
- **Test Data Creation**: Automatically creates test data if it doesn't exist
- **File Upload**: Uploads a file to the blob store and receives a content hash
- **Blob Information**: Retrieves metadata about the uploaded blob
- **File Download**: Downloads the file using the content hash
- **Data Integrity Check**: Compares the original and downloaded data to ensure they match
- **Cleanup**: Removes temporary files after the test

### Usage

1. **Start the blob store server** (in a separate terminal):
   ```bash
   cd zoeyr/crates/blob-store
   cargo run
   ```

2. **Run the example** (in another terminal):
   ```bash
   cd zoeyr/crates/blob-store
   cargo run --example upload_download
   ```

### Expected Output

The example will output detailed logs showing each step of the process:

```
🚀 Starting blob store upload/download example
Step 1: Checking server health...
Server health: {"service":"zoeyr-blob-store","status":"healthy"}
Step 2: Creating test data file...
Created test file: test_data.txt
Step 3: Uploading file to blob store...
Uploading file: test_data.txt (2800 bytes)
Upload successful, hash: bafybeihvj3axxqjytthc2s36ek7l2blbkf6x4yrlqkjqnm33w5eqjbofdm
Step 4: Getting blob information...
Blob info: {"exists":true,"hash":"bafybeihvj3axxqjytthc2s36ek7l2blbkf6x4yrlqkjqnm33w5eqjbofdm","size":2800}
Step 5: Downloading file from blob store...
Downloading file with hash: bafybeihvj3axxqjytthc2s36ek7l2blbkf6x4yrlqkjqnm33w5eqjbofdm
Download successful: 2800 bytes
Step 6: Saving downloaded data...
Saved downloaded data to: downloaded_data.txt
Step 7: Comparing original and downloaded data...
✅ Data integrity check passed! Original and downloaded data match.
Step 8: Cleaning up...
Cleaned up temporary file: downloaded_data.txt
🎉 Example completed successfully!
```

### Configuration

The example uses the following default configuration:

- **Server URL**: `http://127.0.0.1:9091` (matches the default blob store server port)
- **Test File**: `test_data.txt` (created automatically if it doesn't exist)
- **Download File**: `downloaded_data.txt` (temporary file, cleaned up after test)

### Customization

You can modify the `ExampleConfig` struct in the example to change:
- Server URL and port
- Test file path
- Download file path
- HTTP client timeout settings

### Error Handling

The example includes comprehensive error handling for:
- Server connectivity issues
- File I/O operations
- HTTP request failures
- Data integrity mismatches

If any step fails, the example will exit with a non-zero status code and display an error message. 