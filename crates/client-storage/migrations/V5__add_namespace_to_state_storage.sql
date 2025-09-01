-- Migration V5: Add namespace column to state_storage table for efficient categorization
-- This migration adds a namespace column to organize state data by type

-- Add namespace column to existing state_storage table
ALTER TABLE state_storage ADD COLUMN namespace BLOB NOT NULL DEFAULT 'config';

-- Create index for efficient namespace queries
CREATE INDEX IF NOT EXISTS idx_state_storage_namespace ON state_storage(namespace);

-- Create composite index for namespace + key lookups
CREATE INDEX IF NOT EXISTS idx_state_storage_namespace_key ON state_storage(namespace, key);

-- Update schema version
UPDATE storage_metadata SET value = '5', updated_at = strftime('%s', 'now') WHERE key = 'schema_version';