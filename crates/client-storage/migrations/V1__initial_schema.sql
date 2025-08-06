-- Simple key-value storage for messages with extracted common fields
-- Main messages table with extracted author and timestamp for efficient querying
CREATE TABLE IF NOT EXISTS messages (
    id BLOB PRIMARY KEY,                    -- Blake3 hash of the message (32 bytes)
    data BLOB NOT NULL,                     -- Postcard-serialized MessageFull
    author BLOB NOT NULL,                   -- Ed25519 public key of the author (32 bytes)
    timestamp INTEGER NOT NULL             -- Unix timestamp from message
);

-- Tag tables for efficient queries by tag type
-- Event tags (references to other events)
CREATE TABLE IF NOT EXISTS tag_events (
    message_id BLOB NOT NULL,               -- Message that has this tag
    event_id BLOB NOT NULL,                 -- Referenced event ID (32 bytes)
    PRIMARY KEY (message_id, event_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- User tags (references to users)
CREATE TABLE IF NOT EXISTS tag_users (
    message_id BLOB NOT NULL,               -- Message that has this tag
    user_id BLOB NOT NULL,                  -- Referenced user ID
    PRIMARY KEY (message_id, user_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Channel tags (references to channels)
CREATE TABLE IF NOT EXISTS tag_channels (
    message_id BLOB NOT NULL,               -- Message that has this tag
    channel_id BLOB NOT NULL,               -- Referenced channel ID
    PRIMARY KEY (message_id, channel_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
);

-- Indexes for efficient queries on main table
CREATE INDEX IF NOT EXISTS idx_messages_author ON messages(author);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_author_timestamp ON messages(author, timestamp);

-- Indexes for tag tables
CREATE INDEX IF NOT EXISTS idx_tag_events_event_id ON tag_events(event_id);
CREATE INDEX IF NOT EXISTS idx_tag_users_user_id ON tag_users(user_id);
CREATE INDEX IF NOT EXISTS idx_tag_channels_channel_id ON tag_channels(channel_id);

-- Store metadata about the storage system
CREATE TABLE IF NOT EXISTS storage_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER DEFAULT (strftime('%s', 'now'))
);

-- Initialize metadata
INSERT INTO storage_metadata (key, value) VALUES ('schema_version', '1');
INSERT INTO storage_metadata (key, value) VALUES ('encryption_version', '1');
INSERT INTO storage_metadata (key, value) VALUES ('created_at', strftime('%s', 'now'));