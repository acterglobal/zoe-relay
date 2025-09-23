//! Unified generic executor for event-sourced models
//!
//! This module provides a unified executor that works with the new GroupStateModel trait,
//! supporting both synchronous and asynchronous execution patterns with flexible
//! permission context handling.

use thiserror::Error;

/// Errors that can occur during execution
#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("Storage error: {0}")]
    StorageError(String),
    #[error("Permission error: {0}")]
    PermissionError(String),
    #[error("Event execution failed: {0}")]
    EventExecutionFailed(String),
    #[error("Model creation failed: {0}")]
    ModelCreationFailed(String),
}

/// Result type for executor operations
pub type ExecutorResult<T> = Result<T, ExecutorError>;
