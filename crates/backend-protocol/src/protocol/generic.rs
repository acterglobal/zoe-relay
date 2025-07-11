use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum GenericError<T: Serialize + Deserialize> {
    Internal(String),
    InvalidRequest(String),
    Unauthorized(String),
    NotFound(String),
    Conflict(String),
    TooManyRequests(String),
    Custom(T),
}
