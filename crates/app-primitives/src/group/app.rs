//! Unified traits and types for group applications and executors
//!
//! This module defines the core traits that all group application models and events
//! must implement, providing a unified interface for both simple and complex
//! execution patterns with flexible permission context handling.

use crate::digital_groups_organizer::models::core::ActivityMeta;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zoe_wire_protocol::MessageId;

/// Trait for app events that require group state reference for permission validation
///
/// App events operate within a group context and must reference a specific group state
/// to determine what permissions were active when validating the event. This enables
/// cross-channel validation where app events are validated against the group permissions
/// that were active at a specific point in time.
pub trait ExecutorEvent:
    Debug + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
    /// Returns all model IDs that this event will potentially affect
    ///
    /// The executor uses this to determine which models to load before
    /// applying the event. Models that don't exist will be skipped.
    fn applies_to(&self) -> Option<Vec<MessageId>> {
        None
    }
    /// Returns the group state reference for permission validation
    ///
    /// This is required for all app events to enable cross-channel validation.
    ///
    /// # Returns
    ///
    /// The group message ID to use for permission context
    fn group_state_reference(&self) -> MessageId;
}

/// The state of permissions for a particular app,
pub trait AppPermissionState:
    Debug + Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de>
{
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Event not applicable: {0}")]
    EventNotApplicable(String),
}

pub struct ExecutionUpdateInfo<M, E> {
    pub updated_models: Vec<M>,
    pub updated_references: Vec<E>,
}

impl<M, E> Default for ExecutionUpdateInfo<M, E> {
    fn default() -> Self {
        Self {
            updated_models: Vec::new(),
            updated_references: Vec::new(),
        }
    }
}

impl<M, E> ExecutionUpdateInfo<M, E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_model(mut self, model: M) -> Self {
        self.updated_models.push(model);
        self
    }

    pub fn add_reference(mut self, reference: E) -> Self {
        self.updated_references.push(reference);
        self
    }
}

impl<M, E> From<(Vec<M>, Vec<E>)> for ExecutionUpdateInfo<M, E> {
    fn from((updated_models, updated_references): (Vec<M>, Vec<E>)) -> Self {
        Self {
            updated_models,
            updated_references,
        }
    }
}

/// Unified trait for all executable models in the group system
///
/// This trait defines a clean, simple interface for event-sourced models.
/// All storage and async operations are handled by the executor, keeping
/// the model trait focused on pure business logic.
pub trait GroupStateModel:
    Debug + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de>
{
    /// The type of events this model can process
    type Event: ExecutorEvent;

    /// The type of permission context this model uses
    type PermissionState: AppPermissionState;

    type Error: Into<ExecuteError>;

    type ExecutiveKey: serde::Serialize
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + Clone
        + std::fmt::Debug
        + PartialEq
        + Eq
        + Ord;

    /// if an event doesn't return anything in "applies_to", this model will be created and
    /// the event will be exected on the default model
    fn default_model(group_meta: ActivityMeta) -> Self;

    /// Get the activity metadata for this model
    fn activity_meta(&self) -> &ActivityMeta;

    /// Execute an event with permission context (for permission-sensitive operations)
    ///
    /// This method should be used when the event requires permission checking.
    /// The default implementation calls `execute_event` and ignores the context.
    fn execute(
        &mut self,
        event: &Self::Event,
        context: &Self::PermissionState,
    ) -> Result<Vec<ExecutionUpdateInfo<Self, Self::ExecutiveKey>>, Self::Error>;

    /// Handle redaction of this model
    ///
    /// This method is called when the model needs to be redacted (deleted/hidden).
    /// It should return appropriate ExecuteReferences for cleanup.
    fn redact(&self, context: &Self::PermissionState) -> Result<Vec<Self>, Self::Error>;
}
