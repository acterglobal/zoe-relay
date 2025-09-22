//! Index key types for Digital Groups Organizer
//!
//! This module defines the typed keys used for different types of indexes
//! in the DGO system.

use serde::{Deserialize, Serialize};
use zoe_wire_protocol::MessageId;

use super::core::{GroupParam, ModelParam, ObjectListIndex, SectionIndex, SpecialListsIndex};

/// Typed keys for different types of indexes in the DGO system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IndexKey {
    /// Activity history for a specific group
    GroupHistory(MessageId),
    /// All models within a specific group
    GroupModels(MessageId),
    /// Activity history for a specific object
    ObjectHistory(MessageId),
    /// Objects within a section of a group (e.g., all calendar events)
    Section(SectionIndex),
    /// Objects within a section of a specific group
    GroupSection(MessageId, SectionIndex),
    /// Related objects for a specific object (e.g., comments on a task)
    ObjectList(MessageId, ObjectListIndex),
    /// Special cross-group indexes
    Special(SpecialListsIndex),
    /// Objects that have been redacted/deleted
    Redacted,
    /// Global activity history across all groups
    AllHistory,
}

/// References used for notifications and updates in the DGO system
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExecuteReference {
    /// Reference to a specific index
    Index(IndexKey),
    /// Reference to a specific model/object
    Model(MessageId),
    /// Reference to a specific group
    Group(MessageId),
    /// Reference to group-level account data
    GroupAccountData(MessageId, String),
    /// Reference to model-specific parameters
    ModelParam(MessageId, ModelParam),
    /// Reference to group-specific parameters
    GroupParam(MessageId, GroupParam),
    /// Reference to user account data
    AccountData(String),
    /// Reference to a specific model type
    ModelType(String),
}

impl ExecuteReference {
    /// Convert this reference to a storage key for persistence
    pub fn as_storage_key(&self) -> String {
        match self {
            ExecuteReference::Model(message_id) => format!("dgo::{message_id}"),
            ExecuteReference::ModelParam(message_id, param) => {
                format!("{message_id}::{param:?}")
            }
            ExecuteReference::GroupParam(group_id, param) => {
                format!("{group_id}::{param:?}")
            }
            ExecuteReference::ModelType(model_type) => model_type.clone(),
            ExecuteReference::Index(IndexKey::Special(SpecialListsIndex::InvitedTo)) => {
                "global_invited".to_owned() // Special case for global invitations
            }
            ExecuteReference::Index(index_key) => format!("index::{index_key:?}"),
            ExecuteReference::Group(group_id) => format!("group::{group_id}"),
            ExecuteReference::GroupAccountData(group_id, key) => {
                format!("group_data::{group_id}::{key}")
            }
            ExecuteReference::AccountData(key) => format!("account_data::{key}"),
        }
    }
}

// Conversion implementations for common types

impl From<MessageId> for ExecuteReference {
    fn from(value: MessageId) -> Self {
        ExecuteReference::Model(value)
    }
}

impl From<IndexKey> for ExecuteReference {
    fn from(value: IndexKey) -> Self {
        ExecuteReference::Index(value)
    }
}

impl From<SectionIndex> for ExecuteReference {
    fn from(value: SectionIndex) -> Self {
        ExecuteReference::Index(IndexKey::Section(value))
    }
}
