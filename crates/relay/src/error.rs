/// Standard service error types
///
/// Send over the wire as u8. Inspired by HTTP status codes.
pub enum ServiceError {
    // 40-49 are for client errors
    AuthenticationFailed = 41, // 401 unauthorized in HTTP
    ResourceNotFound = 44,     // 404 not found in HTTP
    // 50-59 are for server errors
    UnknownService = 51,     // the service is not known
    ServiceUnavailable = 52, // the service is known but unavailable at this point
}
