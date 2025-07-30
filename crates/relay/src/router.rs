//! Service Router Abstractions
//!
//! This module provides the core abstractions for routing incoming connections
//! to different services based on a service identifier sent by the client.
//!
//! ## Core Traits
//!
//! - [`ServiceRouter`]: Routes connections to services based on service IDs
//! - [`Service`]: Handles individual service connections
//!
//! ## Service Routing Flow
//!
//! 1. Client connects and sends a `u8` service identifier
//! 2. [`ServiceRouter::parse_service_id`] converts the `u8` to a typed service ID
//! 3. [`ServiceRouter::create_service`] creates the appropriate service instance
//! 4. The service's [`Service::run`] method handles the connection
//!
//! ## Example
//!
//! ```rust
//! use zoeyr_relay::{ServiceRouter, Service, ConnectionInfo, StreamPair};
//! use async_trait::async_trait;
//!
//! #[derive(Debug, Clone, PartialEq)]
//! enum ServiceType {
//!     MessageService,
//!     BlobService,
//! }
//!
//! impl TryFrom<u8> for ServiceType {
//!     type Error = MyError;
//!     
//!     fn try_from(value: u8) -> Result<Self, Self::Error> {
//!         match value {
//!             1 => Ok(ServiceType::MessageService),
//!             2 => Ok(ServiceType::BlobService),
//!             _ => Err(MyError::UnknownService(value)),
//!         }
//!     }
//! }
//!
//! impl std::fmt::Display for ServiceType {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         match self {
//!             ServiceType::MessageService => write!(f, "MessageService"),
//!             ServiceType::BlobService => write!(f, "BlobService"),
//!         }
//!     }
//! }
//!
//! #[derive(Debug, thiserror::Error)]
//! enum MyError {
//!     #[error("Unknown service ID: {0}")]
//!     UnknownService(u8),
//! }
//!
//! struct MyRouter;
//! struct MyService { /* service fields */ }
//!
//! #[async_trait]
//! impl Service for MyService {
//!     type Error = MyError;
//!     async fn run(self) -> Result<(), Self::Error> {
//!         // Service implementation
//!         Ok(())
//!     }
//! }
//!
//! #[async_trait]
//! impl ServiceRouter for MyRouter {
//!     type Error = MyError;
//!     type ServiceId = ServiceType;
//!     type Service = MyService;
//!
//!     async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error> {
//!         ServiceType::try_from(service_id)
//!     }
//!
//!     async fn create_service(
//!         &self,
//!         service_id: &Self::ServiceId,
//!         connection_info: &ConnectionInfo,
//!         streams: StreamPair,
//!     ) -> Result<Self::Service, Self::Error> {
//!         Ok(MyService { /* initialize service */ })
//!     }
//! }
//! ```

use async_trait::async_trait;

use crate::{ConnectionInfo, StreamPair};

/// A service that handles a specific type of connection
///
/// Services are created by a [`ServiceRouter`] and run independently
/// to handle bi-directional streams from authenticated clients.
#[async_trait]
pub trait Service: Send + Sync {
    /// The error type returned by this service
    type Error: std::error::Error + Send + Sync + 'static;

    /// Run the service with the provided streams
    ///
    /// This method will be called in its own task and should handle
    /// the bi-directional communication with the client.
    async fn run(self) -> Result<(), Self::Error>;
}

/// Routes incoming connections to appropriate services
///
/// The router is responsible for parsing service identifiers and
/// creating service instances to handle connections.
#[async_trait]
pub trait ServiceRouter: Send + Sync {
    /// The error type returned by routing operations
    type Error: std::error::Error + Send + Sync + 'static;

    /// The typed service identifier (e.g., an enum)
    type ServiceId: std::fmt::Debug + Send + Sync;

    /// The service type that handles connections
    type Service: Service;

    /// Parse a raw service ID byte into a typed service identifier
    ///
    /// # Arguments
    /// * `service_id` - The raw service ID byte sent by the client
    ///
    /// # Returns
    /// A typed service identifier or an error if the ID is invalid
    async fn parse_service_id(&self, service_id: u8) -> Result<Self::ServiceId, Self::Error>;

    /// Create a service instance for the given service ID
    ///
    /// # Arguments
    /// * `service_id` - The parsed service identifier
    /// * `connection_info` - Information about the authenticated client
    /// * `streams` - The bi-directional streams for communication
    ///
    /// # Returns
    /// A service instance ready to handle the connection
    async fn create_service(
        &self,
        service_id: &Self::ServiceId,
        connection_info: &ConnectionInfo,
        streams: StreamPair,
    ) -> Result<Self::Service, Self::Error>;
}
