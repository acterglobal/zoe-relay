use blake3::Hash;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::{DgaError, DgaResult};
use zoe_app_primitives::events::GroupManagementEvent;
use zoe_app_primitives::roles::GroupRole;
use zoe_app_primitives::{GroupActivityEvent, GroupSettings, IdentityRef, Permission};
use zoe_wire_protocol::EncryptionKey;

/// The complete state of a group, maintained as an event-sourced state machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupState {
    /// The group identifier - this is the Blake3 hash of the CreateGroup message
    /// Also serves as the root event ID (used as channel tag)
    pub group_id: Hash,
    /// Current group name
    pub name: String,
    /// Current group description
    pub description: Option<String>,
    /// Group metadata
    pub metadata: BTreeMap<String, String>,
    /// Current group settings
    pub settings: GroupSettings,
    /// Group members and their roles (anyone with the key can participate)
    /// This tracks known/active participants, not access control
    pub members: HashMap<VerifyingKey, GroupMember>,
    /// Event history for this group (event ID -> event details)
    pub event_history: Vec<Hash>,
    /// Last processed event timestamp (for ordering)
    pub last_event_timestamp: u64,
    /// State version (incremented on each event)
    pub version: u64,
}

/// Information about a group member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Member's public key
    pub public_key: VerifyingKey,
    /// Member's role in the group
    pub role: GroupRole,
    /// When they joined the group
    pub joined_at: u64,
    /// When they were last active
    pub last_active: u64,
    /// Member-specific metadata
    pub metadata: BTreeMap<String, String>,
}

/// Encryption state for a group
/// This is not serialized with the group state - managed separately
#[derive(Debug, Clone)]
pub struct GroupEncryptionState {
    /// Current encryption key
    pub current_key: EncryptionKey,
    /// Previous keys (for decrypting old messages during key rotation)
    pub previous_keys: Vec<EncryptionKey>,
}

/// A snapshot of a group's state at a specific point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupStateSnapshot {
    pub state: GroupState,
    pub snapshot_at: u64,
    pub snapshot_event_id: Hash,
}

impl GroupState {
    /// Create a new group state from a CreateGroup event
    pub fn new(
        group_id: Hash, // This is both the group ID and root event ID
        name: String,
        description: Option<String>,
        metadata: BTreeMap<String, String>,
        settings: GroupSettings,
        creator: VerifyingKey,
        timestamp: u64,
    ) -> Self {
        let mut members = HashMap::new();
        members.insert(
            creator,
            GroupMember {
                public_key: creator,
                role: GroupRole::Owner,
                joined_at: timestamp,
                last_active: timestamp,
                metadata: BTreeMap::new(),
            },
        );

        Self {
            group_id,
            name,
            description,
            metadata,
            settings,
            members,
            event_history: vec![group_id], // First event is the group creation
            last_event_timestamp: timestamp,
            version: 1,
        }
    }

    /// Apply an event to this group state, returning the updated state
    pub fn apply_event(
        &mut self,
        event: &GroupActivityEvent<()>,
        event_id: Hash,
        sender: VerifyingKey,
        timestamp: u64,
    ) -> DgaResult<()> {
        // Note: Group identification is now done via channel tags, not embedded IDs
        // The caller is responsible for ensuring this event belongs to this group

        // Verify timestamp ordering (events should be processed in order)
        if timestamp < self.last_event_timestamp {
            return Err(DgaError::StateTransition(format!(
                "Event timestamp {} is older than last processed timestamp {}",
                timestamp, self.last_event_timestamp
            )));
        }

        // Apply the specific event
        match event {
            GroupActivityEvent::Management(management_event) => {
                match management_event.as_ref() {
                    GroupManagementEvent::LeaveGroup { message } => {
                        self.handle_leave_group(sender, message.clone(), timestamp)?;
                    }

                    GroupManagementEvent::UpdateGroup(group_info) => {
                        // Handle group updates - simplified since GroupInfo structure changed
                        self.name = group_info.name.clone();
                        self.settings = group_info.settings.clone();
                    }

                    GroupManagementEvent::AssignRole { target, role } => {
                        // Convert target to VerifyingKey for role update
                        if let IdentityRef::Key(member_key) = target {
                            self.handle_update_member_role(sender, *member_key, role.clone())?;
                        }
                    }

                    GroupManagementEvent::SetIdentity(_) => {
                        // Handle identity setting - for now just ensure sender is a member
                        self.handle_member_announcement(sender, timestamp)?;
                    }

                    GroupManagementEvent::RemoveFromGroup { target } => {
                        // Handle member removal
                        if let IdentityRef::Key(member_key) = target {
                            self.members.remove(member_key);
                        }
                    }
                }
            }

            GroupActivityEvent::Activity(_activity_data) => {
                // Handle custom activity
                self.handle_member_announcement(sender, timestamp)?;
            }
        }

        // Update state metadata
        self.event_history.push(event_id);
        self.last_event_timestamp = timestamp;
        self.version += 1;

        Ok(())
    }

    /// Check if a member has permission to perform an action
    pub fn check_permission(
        &self,
        member: &VerifyingKey,
        required_permission: &Permission,
    ) -> DgaResult<()> {
        match self.members.get(member) {
            Some(member_info) => {
                if member_info.role.has_permission(required_permission) {
                    Ok(())
                } else {
                    Err(DgaError::PermissionDenied(format!(
                        "Member {:?} with role {:?} does not have required permission {:?}",
                        member, member_info.role, required_permission
                    )))
                }
            }
            None => Err(DgaError::MemberNotFound {
                member: format!("{member:?}"),
                group: format!("{:?}", self.group_id),
            }),
        }
    }

    // Event handlers for each type of group activity

    /// Handle a member announcing their participation in the group
    /// In encrypted groups, anyone with the key can participate
    fn handle_member_announcement(
        &mut self,
        sender: VerifyingKey,
        timestamp: u64,
    ) -> DgaResult<()> {
        // Add or update member
        if let Some(existing_member) = self.members.get_mut(&sender) {
            existing_member.last_active = timestamp;
        } else {
            // New member - anyone with the key can participate
            self.members.insert(
                sender,
                GroupMember {
                    public_key: sender,
                    role: GroupRole::Member, // Default role for new key holders
                    joined_at: timestamp,
                    last_active: timestamp,
                    metadata: BTreeMap::new(),
                },
            );
        }

        Ok(())
    }

    fn handle_leave_group(
        &mut self,
        sender: VerifyingKey,
        _message: Option<String>,
        _timestamp: u64,
    ) -> DgaResult<()> {
        // In encrypted groups, leaving is just an announcement - they still have the key
        // This removes them from the active member list but doesn't revoke access
        if !self.members.contains_key(&sender) {
            return Err(DgaError::MemberNotFound {
                member: format!("{sender:?}"),
                group: format!("{:?}", self.group_id),
            });
        }

        // Remove from active members list
        self.members.remove(&sender);
        Ok(())
    }

    #[allow(dead_code)]
    fn handle_update_group(
        &mut self,
        sender: VerifyingKey,
        name: Option<String>,
        description: Option<String>,
        metadata_updates: BTreeMap<String, Option<String>>,
        settings_updates: Option<GroupSettings>,
    ) -> DgaResult<()> {
        // Check permission
        self.check_permission(&sender, &self.settings.permissions.update_group)?;

        // Apply updates
        if let Some(new_name) = name {
            self.name = new_name;
        }

        if let Some(new_description) = description {
            self.description = Some(new_description);
        }

        // Apply metadata updates
        for (key, value) in metadata_updates {
            match value {
                Some(v) => {
                    self.metadata.insert(key, v);
                }
                None => {
                    self.metadata.remove(&key);
                }
            }
        }

        if let Some(new_settings) = settings_updates {
            self.settings = new_settings;
        }

        Ok(())
    }

    fn handle_update_member_role(
        &mut self,
        sender: VerifyingKey,
        member: VerifyingKey,
        role: GroupRole,
    ) -> DgaResult<()> {
        // Check permission
        self.check_permission(&sender, &self.settings.permissions.assign_roles)?;

        // Check if target member exists
        let member_info =
            self.members
                .get_mut(&member)
                .ok_or_else(|| DgaError::MemberNotFound {
                    member: format!("{member:?}"),
                    group: format!("{:?}", self.group_id),
                })?;

        // Update role
        member_info.role = role;
        Ok(())
    }

    #[allow(dead_code)]
    fn handle_group_activity(
        &mut self,
        sender: VerifyingKey,
        _activity_type: String,
        _payload: Vec<u8>,
        _metadata: BTreeMap<String, String>,
        timestamp: u64,
    ) -> DgaResult<()> {
        // Check permission to post activities
        self.check_permission(&sender, &self.settings.permissions.post_activities)?;

        // Update member's last active time
        if let Some(member) = self.members.get_mut(&sender) {
            member.last_active = timestamp;
        }

        // Activity processing could be extended here for specific activity types
        Ok(())
    }

    /// Get all active members
    pub fn get_members(&self) -> &HashMap<VerifyingKey, GroupMember> {
        &self.members
    }

    /// Check if a user is a member of this group
    pub fn is_member(&self, user: &VerifyingKey) -> bool {
        self.members.contains_key(user)
    }

    /// Get a member's role
    pub fn get_member_role(&self, user: &VerifyingKey) -> Option<&GroupRole> {
        self.members.get(user).map(|m| &m.role)
    }
}
