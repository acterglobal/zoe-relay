use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayConfig {
    /// Redis connection configuration
    pub redis: RedisConfig,

    /// Service configuration
    pub service: ServiceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    /// Redis connection URL
    pub url: String,

    /// Connection pool size
    pub pool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Maximum message size in bytes
    pub max_message_size: usize,

    /// Message retention period for ephemeral messages (seconds)
    pub ephemeral_retention: u64,

    /// Enable debug logging
    pub debug: bool,

    /// Bind address for the service
    pub bind_address: String,

    /// Port for the service
    pub port: u16,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            pool_size: 10,
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024, // 1MB
            ephemeral_retention: 3600,     // 1 hour
            debug: false,
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
        }
    }
}
