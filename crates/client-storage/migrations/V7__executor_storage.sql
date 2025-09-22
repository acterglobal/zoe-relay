-- Executor storage tables for generic model and index storage
-- These tables support the ExecutorStore trait for persistent model storage

-- Generic model storage table
-- Stores any serializable model data using postcard serialization
CREATE TABLE IF NOT EXISTS executor_models (
    model_id BLOB NOT NULL PRIMARY KEY,                -- Serialized model ID (using postcard)
    model_data BLOB NOT NULL,                          -- Serialized model data (using postcard)
    created_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when model was created
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))  -- Unix timestamp when model was last updated
);

-- Generic index storage table  
-- Stores index data for efficient querying and references
CREATE TABLE IF NOT EXISTS executor_indexes (
    index_id BLOB NOT NULL PRIMARY KEY,               -- Serialized index ID (using postcard)
    index_data BLOB NOT NULL,                         -- Serialized index data (using postcard)
    created_at INTEGER DEFAULT (strftime('%s', 'now')), -- Unix timestamp when index was created
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))  -- Unix timestamp when index was last updated
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_executor_models_created_at ON executor_models(created_at);
CREATE INDEX IF NOT EXISTS idx_executor_models_updated_at ON executor_models(updated_at);
CREATE INDEX IF NOT EXISTS idx_executor_indexes_created_at ON executor_indexes(created_at);
CREATE INDEX IF NOT EXISTS idx_executor_indexes_updated_at ON executor_indexes(updated_at);

-- Update schema version
UPDATE storage_metadata SET value = '7', updated_at = strftime('%s', 'now') WHERE key = 'schema_version';
