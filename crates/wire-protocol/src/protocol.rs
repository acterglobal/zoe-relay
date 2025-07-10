use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::{ProtocolMessage, DynamicSession};

/// Error type for protocol operations
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),
    
    #[error("Authorization required")]
    AuthorizationRequired,
    
    #[error("Transport error: {0}")]
    Transport(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Cryptography error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// Trait for handling application messages with custom business logic
#[async_trait]
pub trait MessageHandler<T>: Send + Sync 
where 
    T: Serialize + for<'a> Deserialize<'a> + Clone + PartialEq + Send + Sync
{
    /// Determine if this specific message requires fresh authorization
    /// This is YOUR business logic - not protocol-level!
    fn requires_fresh_authorization(&self, message: &ProtocolMessage<T>) -> bool;
    
    /// How fresh does the authorization need to be? (in seconds)
    fn authorization_freshness_window(&self, message: &ProtocolMessage<T>) -> u64;
    
    /// Process the message (after authorization is confirmed)
    async fn process_authorized_message(
        &self, 
        message: ProtocolMessage<T>, 
        session: &DynamicSession
    ) -> Result<ProtocolMessage<T>>;
}

/// Connection metadata for tracking client state
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub remote_addr: std::net::SocketAddr,
    pub established_at: std::time::SystemTime,
    pub connection_id: String,
}

/// Session configuration parameters
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Default challenge timeout in seconds
    pub challenge_timeout: u64,
    
    /// Maximum allowed clock skew in seconds
    pub max_clock_skew: u64,
    
    /// Session cleanup interval in seconds
    pub cleanup_interval: u64,
    
    /// Maximum number of failed authentication attempts
    pub max_failed_attempts: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            challenge_timeout: 300,      // 5 minutes
            max_clock_skew: 60,          // 1 minute
            cleanup_interval: 3600,      // 1 hour
            max_failed_attempts: 10,
        }
    }
}

/// Configuration for transport-level settings
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Maximum message size in bytes
    pub max_message_size: usize,
    
    /// Keep-alive interval in seconds
    pub keep_alive_interval: u64,
    
    /// Maximum number of concurrent streams per connection
    pub max_concurrent_streams: u64,
    
    /// Idle timeout for connections in seconds
    pub idle_timeout: u64,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            max_message_size: 1024 * 1024 * 10,  // 10MB
            keep_alive_interval: 30,             // 30 seconds
            max_concurrent_streams: 100,
            idle_timeout: 600,                   // 10 minutes
        }
    }
}

/// Statistics about protocol usage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProtocolStats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub total_messages: u64,
    pub authentication_challenges: u64,
    pub successful_authentications: u64,
    pub failed_authentications: u64,
    pub messages_requiring_auth: u64,
    pub messages_using_cached_auth: u64,
}

impl ProtocolStats {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn authentication_success_rate(&self) -> f64 {
        if self.authentication_challenges == 0 {
            0.0
        } else {
            self.successful_authentications as f64 / self.authentication_challenges as f64
        }
    }
    
    pub fn auth_cache_hit_rate(&self) -> f64 {
        let total_auth_required = self.messages_requiring_auth;
        if total_auth_required == 0 {
            0.0
        } else {
            self.messages_using_cached_auth as f64 / total_auth_required as f64
        }
    }
} 