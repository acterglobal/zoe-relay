//! Unified traits and types for group applications and executors
//!
//! This module defines the core traits that all group application models and events
//! must implement, providing a unified interface for both simple and complex
//! execution patterns with flexible permission context handling.

use crate::{digital_groups_organizer::models::core::ActivityMeta, identity::IdentityRef};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zoe_wire_protocol::MessageId;

/// A wrapper type that ensures a value is properly acknowledged in the dual-acknowledgment system.
///
/// This type encapsulates both the actual value and the required acknowledgments for permission-changing
/// operations. It ensures that all permission-changing events properly acknowledge previous state changes
/// to prevent timestamp manipulation attacks.
///
/// # Type Parameters
/// * `T` - The inner type being acknowledged (e.g., `GroupRole`, `GroupSettings`)
///
/// # Example
/// ```rust
/// use zoe_app_primitives::group::app::Acknowledged;
/// use zoe_wire_protocol::MessageId;
///
/// let acknowledged_value = Acknowledged::new(
///     "some_data".to_string(),
///     MessageId::from_bytes([1; 32]), // own_ack
///     MessageId::from_bytes([2; 32]), // others_ack
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Acknowledgment {
    /// Last state-changing message from THIS sender that they acknowledge
    ///
    /// This prevents the sender from backdating this event before their own
    /// previously acknowledged state changes. Creates a "floor" based on the
    /// sender's own message history.
    pub acknowledges_own_last_state_change: MessageId,
    /// Last state-changing message from ANY OTHER sender that they acknowledge
    ///
    /// This prevents the sender from ignoring third-party state changes when
    /// attempting to rewrite history. The sender must acknowledge the latest
    /// state change from other participants, creating a "floor" based on
    /// third-party activity.
    pub acknowledges_others_last_state_change: MessageId,
}

impl Acknowledgment {
    /// Creates a new acknowledgment with the required acknowledgments.
    ///
    /// # Parameters
    /// * `own_ack` - Last state-changing message from this sender
    /// * `others_ack` - Last state-changing message from other senders
    pub fn new(own_ack: MessageId, others_ack: MessageId) -> Self {
        Self {
            acknowledges_own_last_state_change: own_ack,
            acknowledges_others_last_state_change: others_ack,
        }
    }
}

/// Trait for events that can affect multiple models
pub trait GroupEvent: Debug + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    /// Returns all model IDs that this event will potentially affect
    ///
    /// The executor uses this to determine which models to load before
    /// applying the event. Models that don't exist will be skipped.
    fn applies_to(&self) -> Option<Vec<MessageId>> {
        None
    }

    /// Extracts acknowledgments from the event if it has them
    ///
    /// Returns a tuple of (own_acknowledgment, others_acknowledgment) message IDs.
    ///
    /// # Returns
    /// - `Some(acknowledgment)` - The acknowledgment message IDs
    /// - `None` - If the event has no acknowledgments
    fn acknowledgment(&self) -> Option<Acknowledgment> {
        None
    }
}

/// Generic permission context trait for flexible permission handling
///
/// Different model types can use different permission context implementations:
/// - DGO models use `PermissionContext` (group role + DGO settings)
/// - Group models might use simpler contexts (just group role)
/// - Other applications can define their own permission contexts
pub trait PermissionContext:
    Debug + Clone + Send + Sync + serde::Serialize + for<'de> serde::Deserialize<'de>
{
    /// Get the actor attempting the operation
    fn actor(&self) -> &IdentityRef;

    /// Get the group context
    fn group_id(&self) -> MessageId;

    /// Check if the actor is a confirmed group member
    fn is_group_member(&self) -> bool;
}

/// Simple permission context for group operations
///
/// This provides basic permission checking for group events based on
/// the actor's identity and group membership status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupPermissionContext {
    /// The actor attempting the operation
    pub actor: IdentityRef,
    /// The group context
    pub group_id: MessageId,
    /// Whether the actor is a confirmed group member
    pub is_member: bool,
    /// The actor's role in the group (if any)
    pub role: Option<super::events::roles::GroupRole>,
}

impl PermissionContext for GroupPermissionContext {
    fn actor(&self) -> &IdentityRef {
        &self.actor
    }

    fn group_id(&self) -> MessageId {
        self.group_id
    }

    fn is_group_member(&self) -> bool {
        self.is_member
    }
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
    type Event: GroupEvent;

    /// The type of permission context this model uses
    type PermissionContext: PermissionContext;

    type Error: Into<ExecuteError>;

    type ExecutiveKey: serde::Serialize
        + serde::de::DeserializeOwned
        + Send
        + Sync
        + Clone
        + std::fmt::Debug
        + PartialEq;

    /// Get the activity metadata for this model
    fn activity_meta(&self) -> &ActivityMeta;

    /// Execute an event with permission context (for permission-sensitive operations)
    ///
    /// This method should be used when the event requires permission checking.
    /// The default implementation calls `execute_event` and ignores the context.
    fn execute(
        &mut self,
        event: &Self::Event,
        context: &Self::PermissionContext,
    ) -> Result<Vec<ExecutionUpdateInfo<Self, Self::ExecutiveKey>>, Self::Error>;

    /// Handle redaction of this model
    ///
    /// This method is called when the model needs to be redacted (deleted/hidden).
    /// It should return appropriate ExecuteReferences for cleanup.
    fn redact(&self, context: &Self::PermissionContext) -> Result<Vec<Self>, Self::Error>;
}
