use crate::protocol::{ProtocolError, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Session state for dynamic authentication
#[derive(Debug, Clone)]
pub struct DynamicSession {
    // Identity (established once via mutual TLS - never changes)
    pub client_ed25519_key: VerifyingKey,
    pub connection_established_at: std::time::SystemTime,

    // Authorization freshness (managed dynamically per operation)
    pub current_challenge: Option<AuthChallenge>,
    pub last_successful_challenge: Option<u64>,
    pub successful_challenges: u32,
    pub failed_challenges: u32,
}

/// Authentication challenge for dynamic authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub nonce: String,
    pub timestamp: u64,
    pub issued_at: std::time::SystemTime,
}

impl DynamicSession {
    /// Create new session for verified client identity
    pub fn new(client_ed25519_key: VerifyingKey) -> Self {
        Self {
            client_ed25519_key,
            connection_established_at: std::time::SystemTime::now(),
            current_challenge: None,
            last_successful_challenge: None,
            successful_challenges: 0,
            failed_challenges: 0,
        }
    }

    /// Check if this session needs fresh authorization
    pub fn needs_fresh_authorization(&self, freshness_window_seconds: u64) -> bool {
        match self.last_successful_challenge {
            None => true, // Never authenticated
            Some(last_auth_timestamp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                (now - last_auth_timestamp) > freshness_window_seconds
            }
        }
    }

    /// Issue a new authentication challenge
    pub fn issue_challenge(&mut self, _timeout_seconds: u64) -> AuthChallenge {
        let nonce = uuid::Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let challenge = AuthChallenge {
            nonce: nonce.clone(),
            timestamp,
            issued_at: std::time::SystemTime::now(),
        };

        self.current_challenge = Some(challenge.clone());
        challenge
    }

    /// Verify challenge response and update session state
    pub fn verify_challenge_response(
        &mut self,
        nonce: &str,
        timestamp: u64,
        signature: &[u8],
        timeout_seconds: u64,
    ) -> Result<bool> {
        // Check if we have a pending challenge
        let challenge = match &self.current_challenge {
            Some(challenge) => challenge,
            None => {
                self.failed_challenges += 1;
                return Err(ProtocolError::AuthenticationFailed(
                    "No challenge issued".to_string(),
                ));
            }
        };

        // Verify nonce matches
        if challenge.nonce != nonce || challenge.timestamp != timestamp {
            self.failed_challenges += 1;
            return Err(ProtocolError::AuthenticationFailed(
                "Challenge mismatch".to_string(),
            ));
        }

        // Check challenge timeout
        let elapsed = challenge
            .issued_at
            .elapsed()
            .map_err(|_| ProtocolError::AuthenticationFailed("Time error".to_string()))?;

        if elapsed.as_secs() > timeout_seconds {
            self.failed_challenges += 1;
            self.current_challenge = None;
            return Err(ProtocolError::AuthenticationFailed(
                "Challenge expired".to_string(),
            ));
        }

        // Verify signature
        let message_to_verify = format!("auth:{}:{}", nonce, timestamp);
        let signature = Signature::from_slice(signature)
            .map_err(|e| ProtocolError::Crypto(format!("Invalid signature: {}", e)))?;

        match self
            .client_ed25519_key
            .verify(message_to_verify.as_bytes(), &signature)
        {
            Ok(_) => {
                // Success! Update session state
                self.successful_challenges += 1;
                self.last_successful_challenge = Some(timestamp);
                self.current_challenge = None;
                Ok(true)
            }
            Err(_) => {
                self.failed_challenges += 1;
                self.current_challenge = None;
                Err(ProtocolError::AuthenticationFailed(
                    "Signature verification failed".to_string(),
                ))
            }
        }
    }

    /// Get session statistics
    pub fn get_stats(&self) -> SessionStats {
        SessionStats {
            client_key: hex::encode(self.client_ed25519_key.to_bytes()),
            connection_established_at: self.connection_established_at,
            successful_challenges: self.successful_challenges,
            failed_challenges: self.failed_challenges,
            last_successful_challenge: self.last_successful_challenge,
            has_pending_challenge: self.current_challenge.is_some(),
        }
    }
}

/// Session statistics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub client_key: String,
    pub connection_established_at: std::time::SystemTime,
    pub successful_challenges: u32,
    pub failed_challenges: u32,
    pub last_successful_challenge: Option<u64>,
    pub has_pending_challenge: bool,
}

/// Authentication challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallengeResponse {
    pub nonce: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl AuthChallengeResponse {
    pub fn new(nonce: String, timestamp: u64, signature: Vec<u8>, public_key: Vec<u8>) -> Self {
        Self {
            nonce,
            timestamp,
            signature,
            public_key,
        }
    }
}

/// Authentication context for verified users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub authenticated_at: u64,
    pub expires_at: u64,
    pub permissions: Vec<String>,
}

impl AuthContext {
    pub fn new(
        user_id: String,
        public_key: Vec<u8>,
        authenticated_at: u64,
        expires_at: u64,
        permissions: Vec<String>,
    ) -> Self {
        Self {
            user_id,
            public_key,
            authenticated_at,
            expires_at,
            permissions,
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
            || self.permissions.contains(&"*".to_string())
    }
}

/// Session manager for tracking multiple client sessions
#[derive(Debug)]
pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, DynamicSession>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new session for a client
    pub fn create_session(&self, session_id: String, client_key: VerifyingKey) -> Result<()> {
        let session = DynamicSession::new(client_key);
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ProtocolError::Transport("Lock error".to_string()))?;
        sessions.insert(session_id, session);
        Ok(())
    }

    /// Get a session for modification
    pub fn with_session<F, R>(&self, session_id: &str, f: F) -> Result<R>
    where
        F: FnOnce(&mut DynamicSession) -> Result<R>,
    {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ProtocolError::Transport("Lock error".to_string()))?;

        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| ProtocolError::SessionExpired)?;

        f(session)
    }

    /// Get session statistics
    pub fn get_session_stats(&self, session_id: &str) -> Result<SessionStats> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| ProtocolError::Transport("Lock error".to_string()))?;

        let session = sessions
            .get(session_id)
            .ok_or_else(|| ProtocolError::SessionExpired)?;

        Ok(session.get_stats())
    }

    /// Remove expired sessions
    pub fn cleanup_sessions(&self, max_idle_seconds: u64) -> Result<usize> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| ProtocolError::Transport("Lock error".to_string()))?;

        let now = std::time::SystemTime::now();
        let initial_count = sessions.len();

        sessions.retain(|_, session| {
            match now.duration_since(session.connection_established_at) {
                Ok(duration) => duration.as_secs() <= max_idle_seconds,
                Err(_) => false, // Remove sessions with invalid timestamps
            }
        });

        Ok(initial_count - sessions.len())
    }

    /// Get all session statistics
    pub fn get_all_stats(&self) -> Result<Vec<(String, SessionStats)>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| ProtocolError::Transport("Lock error".to_string()))?;

        Ok(sessions
            .iter()
            .map(|(id, session)| (id.clone(), session.get_stats()))
            .collect())
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility for creating and verifying authentication challenges
pub struct AuthChallengeManager {
    server_key: SigningKey,
}

impl AuthChallengeManager {
    pub fn new(server_key: SigningKey) -> Self {
        Self { server_key }
    }

    /// Create a client-side challenge response
    pub fn create_response(
        &self,
        challenge_nonce: &str,
        challenge_timestamp: u64,
    ) -> Result<Vec<u8>> {
        let message_to_sign = format!("auth:{}:{}", challenge_nonce, challenge_timestamp);
        let signature = self.server_key.sign(message_to_sign.as_bytes());
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify a challenge response from a client
    pub fn verify_response(
        client_key: &VerifyingKey,
        challenge_nonce: &str,
        challenge_timestamp: u64,
        signature: &[u8],
    ) -> Result<bool> {
        let message_to_verify = format!("auth:{}:{}", challenge_nonce, challenge_timestamp);
        let signature = Signature::from_slice(signature)
            .map_err(|e| ProtocolError::Crypto(format!("Invalid signature: {}", e)))?;

        match client_key.verify(message_to_verify.as_bytes(), &signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
