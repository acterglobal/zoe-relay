-- Migration V4: Add state storage table for key-value state persistence
-- This migration adds a generic key-value store for application state using postcard serialization

-- Create state_storage table
CREATE TABLE IF NOT EXISTS state_storage (
    key TEXT PRIMARY KEY,                       -- String key for the state entry
    value_data BLOB NOT NULL,                   -- Serialized state value (postcard format)
    updated_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when state was last updated
    created_at INTEGER DEFAULT (strftime('%s', 'now'))  -- Unix timestamp when state was first created
);

-- Index for efficient queries by update time
CREATE INDEX IF NOT EXISTS idx_state_storage_updated_at ON state_storage(updated_at);

-- Index for efficient queries by creation time
CREATE INDEX IF NOT EXISTS idx_state_storage_created_at ON state_storage(created_at);

-- Update schema version
UPDATE storage_metadata SET value = '4', updated_at = strftime('%s', 'now') WHERE key = 'schema_version';