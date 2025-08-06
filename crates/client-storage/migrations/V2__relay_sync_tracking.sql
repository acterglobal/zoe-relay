-- Relay sync tracking table
-- Tracks which messages have been confirmed synced to which relay servers
CREATE TABLE IF NOT EXISTS relay_sync_status (
    message_id BLOB NOT NULL,                   -- Blake3 hash of the message (32 bytes)
    relay_pubkey BLOB NOT NULL,                 -- Ed25519 public key of the relay server (32 bytes)
    global_stream_id TEXT NOT NULL,             -- Global stream ID confirmation from relay (String)
    synced_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when sync was confirmed
    PRIMARY KEY (message_id, relay_pubkey),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_relay_sync_relay_pubkey ON relay_sync_status(relay_pubkey);
CREATE INDEX IF NOT EXISTS idx_relay_sync_global_stream_id ON relay_sync_status(global_stream_id);
CREATE INDEX IF NOT EXISTS idx_relay_sync_synced_at ON relay_sync_status(synced_at);

-- Update schema version
UPDATE storage_metadata SET value = '2', updated_at = strftime('%s', 'now') WHERE key = 'schema_version';