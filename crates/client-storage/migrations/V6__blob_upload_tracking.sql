-- Blob upload tracking table
-- Tracks which blobs have been uploaded to which relay servers
CREATE TABLE IF NOT EXISTS blob_upload_status (
    blob_hash BLOB NOT NULL,                        -- Hash of the blob content (32 bytes)
    relay_id BLOB NOT NULL,                         -- Hash of the relay server's Ed25519 public key (32 bytes)
    uploaded_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when upload was confirmed
    blob_size INTEGER NOT NULL,                     -- Size of the blob in bytes
    PRIMARY KEY (blob_hash, relay_id)
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_blob_upload_relay_id ON blob_upload_status(relay_id);
CREATE INDEX IF NOT EXISTS idx_blob_upload_uploaded_at ON blob_upload_status(uploaded_at);
CREATE INDEX IF NOT EXISTS idx_blob_upload_blob_hash ON blob_upload_status(blob_hash);

-- Update schema version
UPDATE storage_metadata SET value = '6', updated_at = strftime('%s', 'now') WHERE key = 'schema_version';