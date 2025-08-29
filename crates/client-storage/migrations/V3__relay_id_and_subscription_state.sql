-- Migration V3: Change relay references to use relay_id (hash) and add subscription state storage
-- This migration:
-- 1. Updates relay_sync_status table to use relay_id instead of relay_pubkey
-- 2. Adds subscription_states table for storing subscription state per relay
-- 3. Updates indexes accordingly

-- Create new relay_sync_status table with relay_id
CREATE TABLE IF NOT EXISTS relay_sync_status_new (
    message_id BLOB NOT NULL,                   -- Blake3 hash of the message (32 bytes)
    relay_id BLOB NOT NULL,                     -- Blake3 hash of relay's Ed25519 public key (32 bytes)
    global_stream_id TEXT NOT NULL,             -- Global stream ID confirmation from relay (String)
    synced_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when sync was confirmed
    PRIMARY KEY (message_id, relay_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Copy existing data from old table (this will be empty for most users since we're changing the key format)
-- Note: We cannot migrate existing data since relay_pubkey != relay_id, so we start fresh
-- INSERT INTO relay_sync_status_new (message_id, relay_id, global_stream_id, synced_at)
-- SELECT message_id, relay_pubkey, global_stream_id, synced_at FROM relay_sync_status;
-- (Commented out because relay_pubkey is not the same as relay_id)

-- Drop old table and rename new one
DROP TABLE IF EXISTS relay_sync_status;
ALTER TABLE relay_sync_status_new RENAME TO relay_sync_status;

-- Create indexes for the new relay_sync_status table
CREATE INDEX IF NOT EXISTS idx_relay_sync_relay_id ON relay_sync_status(relay_id);
CREATE INDEX IF NOT EXISTS idx_relay_sync_global_stream_id ON relay_sync_status(global_stream_id);
CREATE INDEX IF NOT EXISTS idx_relay_sync_synced_at ON relay_sync_status(synced_at);

-- Create subscription_states table
CREATE TABLE IF NOT EXISTS subscription_states (
    relay_id BLOB PRIMARY KEY,                  -- Blake3 hash of relay's Ed25519 public key (32 bytes)
    state_data BLOB NOT NULL,                   -- Serialized SubscriptionState (postcard format)
    updated_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when state was last updated
    created_at INTEGER DEFAULT (strftime('%s', 'now'))  -- Unix timestamp when state was first created
);

-- Index for efficient queries by update time
CREATE INDEX IF NOT EXISTS idx_subscription_states_updated_at ON subscription_states(updated_at);

-- Update schema version
UPDATE storage_metadata SET value = '3', updated_at = strftime('%s', 'now') WHERE key = 'schema_version';