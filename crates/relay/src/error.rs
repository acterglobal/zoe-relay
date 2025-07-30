/// Standard service error types
///
/// Send over the wire as u8. Inspired by HTTP status codes.
#[derive(Debug, thiserror::Error)]
#[repr(u8)]
pub enum ServiceError {
    // 40-49 are for client errors
    #[error("Authentication failed")]
    AuthenticationFailed = 41, // 401 unauthorized in HTTP

    #[error("Resource not found")]
    ResourceNotFound = 44, // 404 not found in HTTP

    #[error("Invalid service ID: {0}")]
    InvalidServiceId(u8) = 40, // 400 bad request in HTTP

    // 50-59 are for server errors
    #[error("Unknown service")]
    UnknownService = 51, // the service is not known

    #[error("Service unavailable")]
    ServiceUnavailable = 52, // the service is known but unavailable at this point
}

impl ServiceError {
    /// Get the u8 discriminant value for this error
    pub fn as_u8(&self) -> u8 {
        match self {
            ServiceError::InvalidServiceId(_) => 40,
            ServiceError::AuthenticationFailed => 41,
            ServiceError::ResourceNotFound => 44,
            ServiceError::UnknownService => 51,
            ServiceError::ServiceUnavailable => 52,
        }
    }
}
