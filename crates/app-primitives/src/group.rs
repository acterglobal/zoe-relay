//! # Group Management Primitives for Zoe Applications
//!
//! This module provides a comprehensive system for managing encrypted, distributed groups
//! using the Digital Group Assistant (DGA) protocol. The system is built around several
//! key architectural principles:
//!
//! ## 🏗️ Core Architecture
//!
//! ### Event-Sourced State Management
//! Groups maintain their state through an event-sourced approach where:
//! - All changes to group state are represented as events
//! - Events are encrypted and stored in a distributed message system
//! - Group state is reconstructed by replaying events in chronological order
//! - Each group has a unique identifier that is the Blake3 hash of its creation event
//!
//! ### Encrypted Communication
//! All group communication is encrypted using ChaCha20-Poly1305:
//! - Each group has a shared encryption key derived from mnemonic phrases or generated randomly
//! - Only participants with the correct key can decrypt and participate in group activities
//! - Key distribution happens through secure side channels (QR codes, secure messaging, etc.)
//!
//! ### Identity and Membership System
//! The system uses a sophisticated identity model:
//! - **VerifyingKeys** are the fundamental participants (cryptographic identities)
//! - **Aliases** allow users to present different identities within the same group
//! - **Roles** define what actions participants can perform
//! - **Dynamic membership** where anyone with the encryption key can participate
//!
//! ## 📊 Key Components
//!
//! ### [`GroupState`] - Unified State Management
//! The central type that combines:
//! - Core group information (name, settings, metadata)
//! - Runtime member tracking with activity timestamps
//! - Event history for audit trails and conflict resolution
//! - Advanced identity management through [`GroupMembership`]
//!
//! ### [`GroupInfo`] - Event Payload
//! Used in group creation and update events:
//! - Immutable group information for wire protocol
//! - Structured metadata using [`crate::Metadata`] types
//! - Key derivation information for encryption
//!
//! ### [`GroupMembership`] - Identity Management
//! Handles complex identity scenarios:
//! - Multiple aliases per VerifyingKey
//! - Role assignments to specific identities
//! - Display name management
//! - Authorization checking
//!
//! ## 🔐 Security Model
//!
//! ### Threat Model
//! The system assumes:
//! - Network communications may be monitored or intercepted
//! - Relay servers are semi-trusted (honest but curious)
//! - Participants may have their devices compromised
//! - Group membership may change over time
//!
//! ### Security Properties
//! - **Confidentiality**: All group content is encrypted end-to-end
//! - **Authenticity**: All messages are cryptographically signed
//! - **Forward Secrecy**: Key rotation prevents decryption of past messages
//! - **Participation Privacy**: Membership is not revealed to non-members
//!
//! ## 🚀 Usage Examples
//!
//! ### Creating a New Group
//! ```rust
//! use zoe_app_primitives::{GroupInfo, GroupSettings, GroupState, Metadata, GroupKeyInfo};
//! use zoe_wire_protocol::KeyPair;
//! use blake3::Hash;
//!
//! // Define group metadata
//! let metadata = vec![
//!     Metadata::Description("My awesome group".to_string()),
//!     Metadata::Generic { key: "category".to_string(), value: "work".to_string() },
//! ];
//!
//! // Create group info for the creation event
//! let group_info = GroupInfo {
//!     name: "Development Team".to_string(),
//!     settings: GroupSettings::default(),
//!     key_info: GroupKeyInfo::new_chacha20_poly1305(
//!         b"key_id_12345678".to_vec(),
//!         zoe_wire_protocol::crypto::KeyDerivationInfo {
//!             method: zoe_wire_protocol::crypto::KeyDerivationMethod::ChaCha20Poly1305Keygen,
//!             salt: vec![],
//!             argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
//!             context: "dga-group-key".to_string(),
//!         },
//!     ),
//!     metadata,
//! };
//!
//! // Create the actual group state
//! let creator = KeyPair::generate(&mut rand::rngs::OsRng).public_key();
//! let group_id = Hash::from([0u8; 32]); // In practice, this would be the message hash
//! let timestamp = 1234567890;
//!
//! let group_state = GroupState::new(
//!     group_id,
//!     group_info.name.clone(),
//!     group_info.settings.clone(),
//!     group_info.metadata.clone(),
//!     creator,
//!     timestamp,
//! );
//! ```
//!
//! ### Managing Group Membership
//! ```rust
//! use zoe_app_primitives::{GroupMembership, IdentityType, IdentityRef, IdentityInfo};
//! use zoe_wire_protocol::KeyPair;
//!
//! let mut membership = GroupMembership::new();
//! let user_key = KeyPair::generate(&mut rand::rngs::OsRng).public_key();
//!
//! // Check what identities a user can act as
//! let available_identities = membership.available_identities(&user_key);
//!
//! // Note: Currently returns empty set during ML-DSA transition
//! assert!(available_identities.is_empty());
//! ```
//!
//! ### Working with Structured Metadata
//! ```rust
//! use zoe_app_primitives::{GroupState, Metadata};
//! use zoe_wire_protocol::KeyPair;
//!
//! # let group_state = GroupState::new(
//! #     blake3::Hash::from([0u8; 32]),
//! #     "Test".to_string(),
//! #     zoe_app_primitives::GroupSettings::default(),
//! #     vec![],
//! #     KeyPair::generate(&mut rand::rngs::OsRng).public_key(),
//! #     1234567890,
//! # );
//!
//! // Extract description from structured metadata
//! let description = group_state.description();
//!
//! // Get key-value metadata for backward compatibility
//! let generic_metadata = group_state.generic_metadata();
//! ```
//!
//! ## 🔄 State Transitions
//!
//! Group state changes through well-defined events:
//! 1. **Creation**: [`GroupActivityEvent::UpdateGroup`] with initial [`GroupInfo`]
//! 2. **Member Activity**: Any [`GroupActivityEvent`] announces participation
//! 3. **Role Changes**: [`GroupActivityEvent::AssignRole`] updates permissions
//! 4. **Group Updates**: [`GroupActivityEvent::UpdateGroup`] modifies group info
//! 5. **Member Departure**: [`GroupActivityEvent::LeaveGroup`] removes from active list
//!
//! Each event is cryptographically signed and encrypted, ensuring authenticity and confidentiality.
//!
//! ## 🌐 Network Integration
//!
//! Groups integrate with the relay network through:
//! - **Channel Tags**: Group ID used as message channel for event routing
//! - **Subscription Filters**: Clients subscribe to specific group events
//! - **Message Ordering**: Timestamp-based ordering ensures consistent state
//! - **Catch-up Mechanism**: New participants can replay event history
//!
//! For more details on specific components, see the documentation for individual types.

// Re-export all types from submodules for backwards compatibility
pub mod events;
pub mod states;
#[cfg(test)]
mod tests {
    use super::events::join_info::GroupJoinInfo;
    use super::events::key_info::GroupKeyInfo;
    use super::events::permissions::{GroupAction, GroupPermissions, Permission};
    use super::events::roles::GroupRole;
    use super::events::settings::{EncryptionSettings, GroupSettings};
    use super::events::{GroupActivityEvent, GroupInfo};
    use crate::metadata::Metadata;
    use crate::relay::RelayEndpoint;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use zoe_wire_protocol::{Ed25519VerifyingKey, KeyPair, VerifyingKey};

    fn create_test_verifying_key() -> VerifyingKey {
        use rand::rngs::OsRng;
        use zoe_wire_protocol::KeyPair;
        let keypair = KeyPair::generate(&mut OsRng);
        keypair.public_key()
    }

    fn create_test_ed25519_verifying_key() -> Ed25519VerifyingKey {
        use rand::rngs::OsRng;
        let signing_key = KeyPair::generate_ed25519(&mut OsRng);
        match signing_key.public_key() {
            VerifyingKey::Ed25519(key) => *key,
            _ => panic!("Expected Ed25519 key from KeyPair::generate_ed25519"),
        }
    }

    fn create_test_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    fn create_test_group_key_info(key_id: blake3::Hash) -> GroupKeyInfo {
        GroupKeyInfo::new_chacha20_poly1305(key_id)
    }

    #[test]
    fn test_group_role_has_permission() {
        // Test Owner permissions
        assert!(GroupRole::Owner.has_permission(&Permission::OwnerOnly));
        assert!(GroupRole::Owner.has_permission(&Permission::AdminOrAbove));
        assert!(GroupRole::Owner.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Owner.has_permission(&Permission::AllMembers));

        // Test Admin permissions
        assert!(!GroupRole::Admin.has_permission(&Permission::OwnerOnly));
        assert!(GroupRole::Admin.has_permission(&Permission::AdminOrAbove));
        assert!(GroupRole::Admin.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Admin.has_permission(&Permission::AllMembers));

        // Test Moderator permissions
        assert!(!GroupRole::Moderator.has_permission(&Permission::OwnerOnly));
        assert!(!GroupRole::Moderator.has_permission(&Permission::AdminOrAbove));
        assert!(GroupRole::Moderator.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Moderator.has_permission(&Permission::AllMembers));

        // Test Member permissions
        assert!(!GroupRole::Member.has_permission(&Permission::OwnerOnly));
        assert!(!GroupRole::Member.has_permission(&Permission::AdminOrAbove));
        assert!(!GroupRole::Member.has_permission(&Permission::ModeratorOrAbove));
        assert!(GroupRole::Member.has_permission(&Permission::AllMembers));
    }

    #[test]
    fn test_group_role_display_name() {
        assert_eq!(GroupRole::Owner.display_name(), "Owner");
        assert_eq!(GroupRole::Admin.display_name(), "Administrator");
        assert_eq!(GroupRole::Moderator.display_name(), "Moderator");
        assert_eq!(GroupRole::Member.display_name(), "Member");
    }

    #[test]
    fn test_group_role_can_assign_role() {
        // Owner can assign any role
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Owner));
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Admin));
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Moderator));
        assert!(GroupRole::Owner.can_assign_role(&GroupRole::Member));

        // Admin cannot assign Owner, but can assign lower roles
        assert!(!GroupRole::Admin.can_assign_role(&GroupRole::Owner));
        assert!(GroupRole::Admin.can_assign_role(&GroupRole::Admin));
        assert!(GroupRole::Admin.can_assign_role(&GroupRole::Moderator));
        assert!(GroupRole::Admin.can_assign_role(&GroupRole::Member));

        // Moderator can only assign Member role
        assert!(!GroupRole::Moderator.can_assign_role(&GroupRole::Owner));
        assert!(!GroupRole::Moderator.can_assign_role(&GroupRole::Admin));
        assert!(!GroupRole::Moderator.can_assign_role(&GroupRole::Moderator));
        assert!(GroupRole::Moderator.can_assign_role(&GroupRole::Member));

        // Member cannot assign any roles
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Owner));
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Admin));
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Moderator));
        assert!(!GroupRole::Member.can_assign_role(&GroupRole::Member));
    }

    #[test]
    fn test_group_permissions_builder() {
        let permissions = GroupPermissions::new()
            .update_group(Permission::AdminOrAbove)
            .assign_roles(Permission::OwnerOnly)
            .post_activities(Permission::AllMembers)
            .update_encryption(Permission::OwnerOnly);

        assert_eq!(permissions.update_group, Permission::AdminOrAbove);
        assert_eq!(permissions.assign_roles, Permission::OwnerOnly);
        assert_eq!(permissions.post_activities, Permission::AllMembers);
        assert_eq!(permissions.update_encryption, Permission::OwnerOnly);
    }

    #[test]
    fn test_group_permissions_can_perform_action() {
        let permissions = GroupPermissions::default();

        // Test default permissions
        assert!(permissions.can_perform_action(&GroupRole::Owner, GroupAction::UpdateGroup));
        assert!(permissions.can_perform_action(&GroupRole::Admin, GroupAction::UpdateGroup));
        assert!(!permissions.can_perform_action(&GroupRole::Moderator, GroupAction::UpdateGroup));
        assert!(!permissions.can_perform_action(&GroupRole::Member, GroupAction::UpdateGroup));

        assert!(permissions.can_perform_action(&GroupRole::Owner, GroupAction::AssignRoles));
        assert!(!permissions.can_perform_action(&GroupRole::Admin, GroupAction::AssignRoles));

        assert!(permissions.can_perform_action(&GroupRole::Member, GroupAction::PostActivities));

        assert!(permissions.can_perform_action(&GroupRole::Owner, GroupAction::UpdateEncryption));
        assert!(!permissions.can_perform_action(&GroupRole::Admin, GroupAction::UpdateEncryption));
    }

    #[test]
    fn test_group_key_info() {
        let key_id = blake3::Hash::from([1u8; 32]);

        let key_info = GroupKeyInfo::new_chacha20_poly1305(key_id);

        assert_eq!(key_info.key_id(), &key_id);
        assert_eq!(key_info.algorithm(), "ChaCha20-Poly1305");
    }

    #[test]
    fn test_group_key_info_matches_key_id() {
        let key_id = blake3::Hash::from([1u8; 32]);
        let other_key_id = blake3::Hash::from([2u8; 32]);
        let key_info = GroupKeyInfo::new_chacha20_poly1305(key_id);

        assert!(key_info.matches_key_id(&key_id));
        assert!(!key_info.matches_key_id(&other_key_id));
    }

    #[test]
    fn test_group_settings_builder() {
        let permissions = GroupPermissions::default();
        let encryption_settings = EncryptionSettings::default();

        let settings = GroupSettings::new()
            .permissions(permissions.clone())
            .encryption_settings(encryption_settings.clone());

        assert_eq!(settings.permissions, permissions);
        assert_eq!(settings.encryption_settings, encryption_settings);
    }

    #[test]
    fn test_encryption_settings_builder() {
        let settings = EncryptionSettings::new().with_key_rotation(3600);

        assert!(settings.key_rotation_enabled);
        assert_eq!(settings.key_rotation_interval, Some(3600));
    }

    #[test]
    fn test_relay_endpoint() {
        let address = create_test_socket_addr();
        let _public_key = create_test_verifying_key();

        let endpoint = RelayEndpoint::new(address, create_test_ed25519_verifying_key())
            .with_name("Test Relay".to_string())
            .with_metadata(Metadata::Generic {
                key: "region".to_string(),
                value: "us-west".to_string(),
            });

        assert_eq!(endpoint.address, address);
        // Note: endpoint uses Ed25519 key, not ML-DSA key
        assert_eq!(endpoint.name, Some("Test Relay".to_string()));
        assert_eq!(endpoint.metadata.len(), 1);
        if let Some(Metadata::Generic { key, value }) = endpoint.metadata.first() {
            assert_eq!(key, "region");
            assert_eq!(value, "us-west");
        } else {
            panic!("Expected generic metadata");
        }
    }

    #[test]
    fn test_relay_endpoint_display_name() {
        let address = create_test_socket_addr();
        let _public_key = create_test_verifying_key();

        // Without name, should use address
        let endpoint_no_name = RelayEndpoint::new(address, create_test_ed25519_verifying_key());
        assert_eq!(endpoint_no_name.display_name(), address.to_string());

        // With name, should use name
        let endpoint_with_name = endpoint_no_name.with_name("Test Relay".to_string());
        assert_eq!(endpoint_with_name.display_name(), "Test Relay");
    }

    #[test]
    fn test_group_join_info() {
        let channel_id = "test_channel_123".to_string();
        let group_info = GroupInfo {
            name: "Test Group".to_string(),
            settings: GroupSettings::default(),
            key_info: create_test_group_key_info(blake3::Hash::from([1u8; 32])),
            metadata: Vec::new(),
            installed_apps: vec![], // Test data
        };
        let encryption_key = [42u8; 32];
        let key_info = create_test_group_key_info(blake3::Hash::from([1u8; 32]));
        let relay_endpoint = RelayEndpoint::new(
            create_test_socket_addr(),
            create_test_ed25519_verifying_key(),
        );

        let join_info = GroupJoinInfo::new(
            channel_id.clone(),
            group_info.clone(),
            encryption_key,
            key_info.clone(),
            vec![relay_endpoint.clone()],
        )
        .with_invitation_metadata(Metadata::Generic {
            key: "inviter".to_string(),
            value: "alice".to_string(),
        });

        assert_eq!(join_info.channel_id, channel_id);
        assert_eq!(join_info.group_info, group_info);
        assert_eq!(join_info.encryption_key, encryption_key);
        assert_eq!(join_info.key_info, key_info);
        assert_eq!(join_info.relay_endpoints, vec![relay_endpoint]);
        assert_eq!(join_info.invitation_metadata.len(), 1);
        if let Some(Metadata::Generic { key, value }) = join_info.invitation_metadata.first() {
            assert_eq!(key, "inviter");
            assert_eq!(value, "alice");
        } else {
            panic!("Expected generic metadata");
        }
    }

    #[test]
    fn test_group_join_info_relay_methods() {
        let relay1 = RelayEndpoint::new(
            create_test_socket_addr(),
            create_test_ed25519_verifying_key(),
        )
        .with_name("Primary".to_string());
        let relay2 = RelayEndpoint::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            create_test_ed25519_verifying_key(),
        )
        .with_name("Secondary".to_string());

        let mut join_info = GroupJoinInfo::new(
            "test".to_string(),
            GroupInfo {
                name: "Test".to_string(),
                settings: GroupSettings::default(),
                key_info: create_test_group_key_info(blake3::Hash::from([1u8; 32])),
                metadata: Vec::new(),
                installed_apps: vec![], // Test data
            },
            [0u8; 32],
            create_test_group_key_info(blake3::Hash::from([1u8; 32])),
            vec![relay1.clone()],
        );

        // Test initial state
        assert!(join_info.has_relays());
        assert_eq!(join_info.primary_relay(), Some(&relay1).cloned());
        assert_eq!(join_info.relays_by_priority().len(), 1);

        // Add another relay
        join_info = join_info.add_relay(relay2.clone());
        assert_eq!(join_info.relays_by_priority().len(), 2);
        assert_eq!(join_info.primary_relay(), Some(&relay1).cloned()); // First one is still primary

        // Test with no relays
        let empty_join_info = GroupJoinInfo::new(
            "test".to_string(),
            GroupInfo {
                name: "Test".to_string(),
                settings: GroupSettings::default(),
                key_info: create_test_group_key_info(blake3::Hash::from([1u8; 32])),
                metadata: Vec::new(),
                installed_apps: vec![], // Test data
            },
            [0u8; 32],
            create_test_group_key_info(blake3::Hash::from([1u8; 32])),
            vec![],
        );

        assert!(!empty_join_info.has_relays());
        assert_eq!(empty_join_info.primary_relay(), None);
        assert!(empty_join_info.relays_by_priority().is_empty());
    }

    #[test]
    fn test_group_info() {
        // Test creating a GroupInfo struct
        let group_info = GroupInfo {
            name: "Test Group".to_string(),
            settings: GroupSettings::default(),
            key_info: create_test_group_key_info(blake3::Hash::from([1u8; 32])),
            metadata: Vec::new(),
            installed_apps: vec![], // Test data
        };

        // Just test that we can create and clone the struct
        let _cloned = group_info.clone();
    }

    #[test]
    fn test_group_permissions_default() {
        let permissions = GroupPermissions::default();

        assert_eq!(permissions.update_group, Permission::AdminOrAbove);
        assert_eq!(permissions.assign_roles, Permission::OwnerOnly);
        assert_eq!(permissions.post_activities, Permission::AllMembers);
        assert_eq!(permissions.update_encryption, Permission::OwnerOnly);
    }

    #[test]
    fn test_encryption_settings_default() {
        let settings = EncryptionSettings::default();

        assert!(!settings.key_rotation_enabled);
        assert_eq!(settings.key_rotation_interval, None);
    }

    #[test]
    fn test_group_settings_default() {
        let settings = GroupSettings::default();

        assert_eq!(settings.permissions, GroupPermissions::default());
        assert_eq!(settings.encryption_settings, EncryptionSettings::default());
    }

    #[test]
    fn test_postcard_serialization_group_activity_event() {
        use super::events::GroupInfoUpdate;
        let event = GroupActivityEvent::UpdateGroup(vec![
            GroupInfoUpdate::Name("Test Group".to_string()),
            GroupInfoUpdate::Settings(GroupSettings::default()),
            GroupInfoUpdate::KeyInfo(create_test_group_key_info(blake3::Hash::from([1u8; 32]))),
            GroupInfoUpdate::SetMetadata(Vec::new()),
        ]);

        let serialized = postcard::to_stdvec(&event).expect("Failed to serialize");
        let deserialized: GroupActivityEvent =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_postcard_serialization_group_role() {
        for role in [
            GroupRole::Owner,
            GroupRole::Admin,
            GroupRole::Moderator,
            GroupRole::Member,
        ] {
            let serialized = postcard::to_stdvec(&role).expect("Failed to serialize");
            let deserialized: GroupRole =
                postcard::from_bytes(&serialized).expect("Failed to deserialize");
            assert_eq!(role, deserialized);
        }
    }

    #[test]
    fn test_postcard_serialization_permission() {
        for permission in [
            Permission::OwnerOnly,
            Permission::AdminOrAbove,
            Permission::ModeratorOrAbove,
            Permission::AllMembers,
        ] {
            let serialized = postcard::to_stdvec(&permission).expect("Failed to serialize");
            let deserialized: Permission =
                postcard::from_bytes(&serialized).expect("Failed to deserialize");
            assert_eq!(permission, deserialized);
        }
    }

    #[test]
    fn test_postcard_serialization_group_join_info() {
        let join_info = GroupJoinInfo::new(
            "test_channel".to_string(),
            GroupInfo {
                name: "Test".to_string(),
                settings: GroupSettings::default(),
                key_info: create_test_group_key_info(blake3::Hash::from([1u8; 32])),
                metadata: Vec::new(),
                installed_apps: vec![], // Test data
            },
            [42u8; 32],
            create_test_group_key_info(blake3::Hash::from([1u8; 32])),
            vec![RelayEndpoint::new(
                create_test_socket_addr(),
                create_test_ed25519_verifying_key(),
            )],
        );

        let serialized = postcard::to_stdvec(&join_info).expect("Failed to serialize");
        let deserialized: GroupJoinInfo =
            postcard::from_bytes(&serialized).expect("Failed to deserialize");

        assert_eq!(join_info, deserialized);
    }
}
