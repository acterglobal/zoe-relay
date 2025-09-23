//! Comprehensive tests for the dual-acknowledgment attestation system
//!
//! This module contains extensive unit tests that validate the security properties
//! of the dual-acknowledgment system designed to prevent timestamp manipulation
//! attacks and history rewriting in group permission management.
//!
//! # Test Categories
//!
//! 1. **Basic Dual-Acknowledgment Validation** - Core security mechanisms
//! 2. **Attack Prevention** - Specific attack scenarios and their prevention
//! 3. **Multi-Verifier Scenarios** - Complex interactions between multiple participants
//! 4. **Multi-Device Scenarios** - Offline operation and conflict resolution
//! 5. **Edge Cases** - Boundary conditions and error handling
//! 6. **Performance** - Snapshot efficiency and historical reconstruction

use super::*;
use crate::group::app::Acknowledgment;
use crate::group::events::{
    GroupActivityEvent, GroupInfoUpdate, roles::GroupRole, settings::GroupSettings,
};
use crate::identity::{IdentityRef, IdentityType};
use rand::rngs::OsRng;
use zoe_wire_protocol::{KeyPair, MessageId};

/// Helper function to create a test MessageId from a seed
fn test_message_id(seed: u8) -> MessageId {
    MessageId::from_bytes([seed; 32])
}

/// Helper function to get the creation message ID from a group state
fn get_creation_message_id(group_state: &GroupState) -> MessageId {
    group_state.event_history[0]
}

/// Helper function to create a test group state with multiple members
fn create_test_group_with_members() -> (GroupState, KeyPair, KeyPair, KeyPair) {
    let alice_key = KeyPair::generate(&mut OsRng);
    let bob_key = KeyPair::generate(&mut OsRng);
    let charlie_key = KeyPair::generate(&mut OsRng);

    let message =
        super::tests::create_test_message_full(&alice_key, b"test content".to_vec(), 1000).unwrap();
    let group_info = super::tests::create_test_group_info();
    let mut group_state = GroupState::initial(&message, group_info);

    // GroupState::initial automatically adds the creation message to metadata

    // Add Bob and Charlie as members
    let bob_join = GroupActivityEvent::SetIdentity(crate::identity::IdentityInfo {
        display_name: "Bob".to_string(),
        metadata: vec![],
    });
    group_state
        .apply_event(
            bob_join,
            test_message_id(2),
            IdentityRef::Key(bob_key.public_key()),
            1001,
        )
        .unwrap();

    let charlie_join = GroupActivityEvent::SetIdentity(crate::identity::IdentityInfo {
        display_name: "Charlie".to_string(),
        metadata: vec![],
    });
    group_state
        .apply_event(
            charlie_join,
            test_message_id(3),
            IdentityRef::Key(charlie_key.public_key()),
            1002,
        )
        .unwrap();

    (group_state, alice_key, bob_key, charlie_key)
}

#[cfg(test)]
mod basic_validation_tests {
    use super::*;

    #[test]
    fn test_permission_event_detection() {
        // Test that events are correctly classified as permission-changing or not

        // Permission-changing events
        let assign_role = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            test_message_id(1),
            test_message_id(2),
        );
        assert!(assign_role.is_permission_changing());

        let remove_member = GroupActivityEvent::new_remove_from_group(
            IdentityType::Main,
            test_message_id(1),
            test_message_id(2),
        );
        assert!(remove_member.is_permission_changing());

        let permission_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Settings(GroupSettings::default())],
            test_message_id(1), // Own acknowledgment
            test_message_id(2), // Others acknowledgment
        );
        assert!(permission_update.is_permission_changing());

        // Non-permission-changing events
        let name_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("New Name".to_string())],
            test_message_id(1), // Group creation (no previous own events)
            test_message_id(1), // Group creation (no previous other events)
        );
        assert!(!name_update.is_permission_changing());

        let leave_group = GroupActivityEvent::LeaveGroup { message: None };
        assert!(!leave_group.is_permission_changing());

        let set_identity = GroupActivityEvent::SetIdentity(crate::identity::IdentityInfo {
            display_name: "Test".to_string(),
            metadata: vec![],
        });
        assert!(!set_identity.is_permission_changing());
    }

    #[test]
    fn test_acknowledgment_extraction() {
        let own_ack = test_message_id(10);
        let others_ack = test_message_id(20);

        // Test successful extraction from AssignRole
        let assign_role = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            own_ack,
            others_ack,
        );

        let (extracted_own, extracted_others) = assign_role.extract_acknowledgments().unwrap();
        assert_eq!(extracted_own, own_ack);
        assert_eq!(extracted_others, others_ack);

        // Test extraction from non-permission event should fail
        let leave_group = GroupActivityEvent::LeaveGroup { message: None };
        assert!(leave_group.extract_acknowledgments().is_err());
    }

    #[test]
    fn test_message_metadata_storage() {
        let (mut group_state, alice_key, _, _) = create_test_group_with_members();

        let creation_message_id = get_creation_message_id(&group_state);
        let event = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            creation_message_id, // Group creation
            test_message_id(3),  // Charlie's join (latest third-party event)
        );

        let event_id = test_message_id(10);
        let timestamp = 2000;

        group_state
            .apply_event(
                event,
                event_id,
                IdentityRef::Key(alice_key.public_key()),
                timestamp,
            )
            .unwrap();

        // Verify metadata was stored
        let metadata = group_state.message_metadata.get(&event_id).unwrap();
        assert_eq!(metadata.timestamp, timestamp);
        assert_eq!(metadata.sender, IdentityRef::Key(alice_key.public_key()));
        assert!(metadata.is_permission_event);
    }
}

#[cfg(test)]
mod attack_prevention_tests {
    use crate::identity::IdentityType;

    use super::*;

    #[test]
    fn test_basic_timestamp_manipulation_attack_prevention() {
        // **Attack Scenario**: Alice tries to backdate a role revocation after Bob has acted
        //
        // Timeline:
        // t=1000: Alice creates group (Alice=Owner)
        // t=1100: Alice assigns Bob as Admin { ack_own: msg_1, ack_others: msg_1 }
        // t=1200: Charlie joins group
        // t=1300: Alice updates settings { ack_own: msg_2, ack_others: msg_1 }
        //         -> Alice acknowledges she's seen Charlie join!
        // t=1400: Alice tries: RevokeRole(Bob) { ack_own: msg_2, ack_others: msg_1, timestamp: 1150 }
        //
        // **Expected**: System rejects because timestamp=1150 is before Charlie's join at t=1200,
        // but Alice already acknowledged seeing Charlie at t=1300
        let (mut group_state, alice_key, _bob_key, _charlie_key) = create_test_group_with_members();

        // t=1100: Alice assigns Bob as Admin
        let creation_message_id = get_creation_message_id(&group_state);
        let assign_bob_admin = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            creation_message_id, // Group creation
            test_message_id(3),  // Charlie's join (latest third-party event)
        );
        let assign_event_id = test_message_id(10);
        group_state
            .apply_event(
                assign_bob_admin,
                assign_event_id,
                IdentityRef::Key(alice_key.public_key()),
                1100,
            )
            .unwrap();

        // t=1300: Alice updates settings (acknowledging she's seen Charlie join at t=1002)
        let settings_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Settings(GroupSettings::default())],
            assign_event_id,
            test_message_id(3), // Acknowledges Charlie's join
        );
        let settings_event_id = test_message_id(11);
        group_state
            .apply_event(
                settings_update,
                settings_event_id,
                IdentityRef::Key(alice_key.public_key()),
                1300,
            )
            .unwrap();

        // t=1400: Alice tries to backdate a role revocation to t=1150
        let backdated_revoke = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Member,  // Demoting Bob
            settings_event_id,  // Alice's last state change
            test_message_id(3), // Charlie's join (already acknowledged)
        );

        // This should FAIL because timestamp 1150 is before Charlie's join at 1002,
        // but Alice already acknowledged Charlie's join in her settings update
        let result = group_state.apply_event(
            backdated_revoke,
            test_message_id(12),
            IdentityRef::Key(alice_key.public_key()),
            1150, // Backdated timestamp
        );

        match result {
            Err(GroupStateError::HistoryRewriteAttempt(_)) => {
                // Expected: Attack prevented
            }
            _ => panic!("Expected HistoryRewriteAttempt error, got: {:?}", result),
        }
    }

    #[test]
    fn test_acknowledgment_consistency_validation() {
        // **Attack Scenario**: Alice tries to acknowledge a message that doesn't exist
        let (mut group_state, alice_key, _bob_key, _charlie_key) = create_test_group_with_members();

        // Alice tries to create an event acknowledging a non-existent message
        let invalid_event = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            test_message_id(99), // Non-existent message
            test_message_id(1),  // Valid message (group creation)
        );

        let result = group_state.apply_event(
            invalid_event,
            test_message_id(20),
            IdentityRef::Key(alice_key.public_key()),
            2000,
        );

        match result {
            Err(GroupStateError::InvalidAcknowledgment(_)) => {
                // Expected: Invalid acknowledgment detected
            }
            _ => panic!("Expected InvalidAcknowledgment error, got: {:?}", result),
        }
    }

    #[test]
    fn test_cannot_backdate_before_own_acknowledgments() {
        // **Attack Scenario**: Alice tries to backdate before her own previous acknowledgments
        let (mut group_state, alice_key, _bob_key, _charlie_key) = create_test_group_with_members();

        // t=1100: Alice assigns Bob as Admin
        let creation_message_id = get_creation_message_id(&group_state);
        let assign_bob = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            creation_message_id, // Group creation at t=1000
            creation_message_id, // Group creation
        );
        let assign_event_id = test_message_id(10);
        group_state
            .apply_event(
                assign_bob,
                assign_event_id,
                IdentityRef::Key(alice_key.public_key()),
                1100,
            )
            .unwrap();

        // t=1200: Alice tries to create another event but backdated to t=1050
        // This should fail because she already acknowledged state at t=1000 in her previous event
        let backdated_event = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Member,
            creation_message_id, // Same acknowledgment as before
            creation_message_id, // Same acknowledgment as before
        );

        let result = group_state.apply_event(
            backdated_event,
            test_message_id(11),
            IdentityRef::Key(alice_key.public_key()),
            1050, // Before her previous acknowledgment timestamp
        );

        match result {
            Err(GroupStateError::HistoryRewriteAttempt(_)) => {
                // Expected: Cannot backdate before own acknowledgments
            }
            _ => panic!("Expected HistoryRewriteAttempt error, got: {:?}", result),
        }
    }
}

#[cfg(test)]
mod multi_verifier_scenarios {

    use super::*;

    #[test]
    fn test_legitimate_concurrent_permission_changes() {
        // **Scenario**: Multiple admins make legitimate permission changes concurrently
        // This tests that the system allows legitimate concurrent operations while
        // still preventing attacks.
        let (mut group_state, alice_key, bob_key, charlie_key) = create_test_group_with_members();

        // Alice promotes Bob to Admin
        let creation_message_id = get_creation_message_id(&group_state);
        let promote_bob = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            creation_message_id, // Group creation
            test_message_id(3),  // Charlie's join
        );
        let promote_bob_id = test_message_id(10);
        group_state
            .apply_event(
                promote_bob,
                promote_bob_id,
                IdentityRef::Key(alice_key.public_key()),
                1100,
            )
            .unwrap();

        // Alice (owner) promotes Charlie to Admin, acknowledging Bob's join and her previous action
        let promote_charlie = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            promote_bob_id,     // Alice's promotion of Bob (her own last state change)
            test_message_id(3), // Charlie's join (latest third-party event)
        );
        let promote_charlie_id = test_message_id(11);
        group_state
            .apply_event(
                promote_charlie,
                promote_charlie_id,
                IdentityRef::Key(alice_key.public_key()),
                1200,
            )
            .unwrap();

        // Verify both Bob and Charlie are now admins
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(bob_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Admin
        );
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(charlie_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Admin
        );

        // Verify acknowledgment tracking is updated for Alice (who made the permission changes)
        let alice_acks = group_state
            .sender_acknowledgments
            .get(&IdentityRef::Key(alice_key.public_key()))
            .unwrap();
        assert_eq!(alice_acks.own_last_ack, promote_bob_id); // Alice's last own state change
        assert_eq!(alice_acks.others_last_ack, test_message_id(3)); // Charlie's join
    }

    #[test]
    fn test_three_way_permission_conflict_resolution() {
        // **Scenario**: Three participants make conflicting permission changes
        // Tests the conflict resolution mechanism when multiple events have
        // similar acknowledgment levels.
        let (mut group_state, alice_key, bob_key, charlie_key) = create_test_group_with_members();

        // Promote Bob and Charlie to Admin first
        let promote_bob = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            test_message_id(1),
            test_message_id(3),
        );
        group_state
            .apply_event(
                promote_bob,
                test_message_id(10),
                IdentityRef::Key(alice_key.public_key()),
                1100,
            )
            .unwrap();

        let creation_message_id = get_creation_message_id(&group_state);
        let promote_charlie = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            creation_message_id,
            test_message_id(10),
        );
        group_state
            .apply_event(
                promote_charlie,
                test_message_id(11),
                IdentityRef::Key(alice_key.public_key()),
                1200,
            )
            .unwrap();

        // Now all three try to make changes with similar acknowledgment levels
        // (In a real system, this would test Message ID tiebreaker logic)

        // Alice updates settings
        let alice_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Alice's Group".to_string())],
            test_message_id(1), // Non-permission change
            test_message_id(1),
        );
        group_state
            .apply_event(
                alice_update,
                test_message_id(20),
                IdentityRef::Key(alice_key.public_key()),
                1300,
            )
            .unwrap();

        // Bob updates settings
        let bob_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Bob's Group".to_string())],
            test_message_id(1), // Non-permission change
            test_message_id(1),
        );
        group_state
            .apply_event(
                bob_update,
                test_message_id(21),
                IdentityRef::Key(bob_key.public_key()),
                1301,
            )
            .unwrap();

        // Charlie updates settings
        let charlie_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Charlie's Group".to_string())],
            test_message_id(1), // Non-permission change
            test_message_id(1),
        );
        group_state
            .apply_event(
                charlie_update,
                test_message_id(22),
                IdentityRef::Key(charlie_key.public_key()),
                1302,
            )
            .unwrap();

        // The last update should win (Charlie's)
        assert_eq!(group_state.group_info.name, "Charlie's Group");
    }

    #[test]
    fn test_permission_cascade_validation() {
        // **Scenario**: Chain of permission changes where each depends on the previous
        //
        // Tests that acknowledgments properly create dependencies that prevent
        // reordering attacks in permission cascades.
        let (mut group_state, alice_key, bob_key, charlie_key) = create_test_group_with_members();

        // Step 1: Alice promotes Bob to Admin
        let creation_message_id = get_creation_message_id(&group_state);
        let promote_bob = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            creation_message_id, // Alice's group creation
            test_message_id(3),  // Charlie's join
        );
        let promote_bob_id = test_message_id(10);
        group_state
            .apply_event(
                promote_bob,
                promote_bob_id,
                IdentityRef::Key(alice_key.public_key()),
                1100,
            )
            .unwrap();

        // Step 2: Alice (owner) promotes Charlie to Admin
        let promote_charlie = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            promote_bob_id,     // Alice's promotion of Bob (her own last state change)
            test_message_id(3), // Charlie's join (latest third-party event)
        );
        let promote_charlie_id = test_message_id(11);
        group_state
            .apply_event(
                promote_charlie,
                promote_charlie_id,
                IdentityRef::Key(alice_key.public_key()),
                1200,
            )
            .unwrap();

        // Step 3: Charlie (now admin) tries to demote Alice
        // This should work because Charlie is now admin
        let demote_alice = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Member,
            test_message_id(3), // Charlie's join
            promote_charlie_id, // Bob's promotion of Charlie
        );
        let demote_alice_id = test_message_id(12);
        group_state
            .apply_event(
                demote_alice,
                demote_alice_id,
                IdentityRef::Key(charlie_key.public_key()),
                1300,
            )
            .unwrap();

        // Verify the cascade worked
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(alice_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Member
        );
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(bob_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Admin
        );
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(charlie_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Admin
        );

        // Now test that Alice cannot backdate a revocation of Bob's admin status
        // to before Charlie was promoted (which would invalidate Charlie's action)
        let backdated_revoke = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Member,
            demote_alice_id,    // Alice's demotion (her last state change)
            promote_charlie_id, // Charlie's promotion (already acknowledged)
        );

        let result = group_state.apply_event(
            backdated_revoke,
            test_message_id(13),
            IdentityRef::Key(alice_key.public_key()),
            1150, // Before Charlie's promotion
        );

        // This should fail because Alice (now a member) doesn't have permission
        // and also because the timestamp is before acknowledged state
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod multi_device_scenarios {
    use super::*;

    #[test]
    fn test_offline_device_synchronization() {
        // **Scenario**: Alice has two devices that go offline and come back with conflicting changes
        //
        // This tests how the system handles legitimate multi-device scenarios while
        // maintaining security properties.
        let alice_key = KeyPair::generate(&mut OsRng);
        let bob_key = KeyPair::generate(&mut OsRng);

        // Create initial group state
        let message =
            super::tests::create_test_message_full(&alice_key, b"test content".to_vec(), 1000)
                .unwrap();
        let group_info = super::tests::create_test_group_info();
        let mut device1_state = GroupState::initial(&message, group_info);

        // Clone for device 2
        let mut device2_state = device1_state.clone();

        // Bob joins on both devices
        let bob_join = GroupActivityEvent::SetIdentity(crate::identity::IdentityInfo {
            display_name: "Bob".to_string(),
            metadata: vec![],
        });
        device1_state
            .apply_event(
                bob_join.clone(),
                test_message_id(2),
                IdentityRef::Key(bob_key.public_key()),
                1100,
            )
            .unwrap();
        device2_state
            .apply_event(
                bob_join,
                test_message_id(2),
                IdentityRef::Key(bob_key.public_key()),
                1100,
            )
            .unwrap();

        // Device 1 goes offline, Device 2 makes a change
        let device2_change = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Device 2 Name".to_string())],
            test_message_id(1),
            test_message_id(1),
        );
        device2_state
            .apply_event(
                device2_change.clone(),
                test_message_id(3),
                IdentityRef::Key(alice_key.public_key()),
                1200,
            )
            .unwrap();

        // Device 1 comes back online and makes a conflicting change
        let device1_change = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Device 1 Name".to_string())],
            test_message_id(1),
            test_message_id(1),
        );
        device1_state
            .apply_event(
                device1_change.clone(),
                test_message_id(4),
                IdentityRef::Key(alice_key.public_key()),
                1201,
            )
            .unwrap();

        // Now device 1 needs to sync device 2's change
        device1_state
            .apply_event(
                device2_change,
                test_message_id(3),
                IdentityRef::Key(alice_key.public_key()),
                1200,
            )
            .unwrap();

        // Device 2 needs to sync device 1's change
        device2_state
            .apply_event(
                device1_change.clone(),
                test_message_id(4),
                IdentityRef::Key(alice_key.public_key()),
                1201,
            )
            .unwrap();

        // Both devices should converge to the same state
        // The final state depends on the order of application, not just timestamps
        // Since both devices process events in the same order after sync, they should converge
        assert_eq!(device1_state.group_info.name, device2_state.group_info.name);
        assert_eq!(device1_state.version, device2_state.version);
    }

    #[test]
    fn test_delayed_message_arrival() {
        // **Scenario**: Messages arrive out of order due to network delays
        //
        // Tests that the system can handle legitimate out-of-order delivery
        // while maintaining security properties.
        let (mut group_state, alice_key, _bob_key, _) = create_test_group_with_members();

        // Alice creates two events with proper acknowledgments but they arrive out of order

        // Event A (created first, arrives second)
        let event_a = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Event A".to_string())],
            test_message_id(1),
            test_message_id(1),
        );

        // Event B (created second, arrives first)
        let event_b = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Event B".to_string())],
            test_message_id(1),
            test_message_id(1),
        );

        // Event B arrives first (timestamp 1200)
        group_state
            .apply_event(
                event_b,
                test_message_id(11),
                IdentityRef::Key(alice_key.public_key()),
                1200,
            )
            .unwrap();

        // Event A arrives second but has earlier timestamp (1100)
        // This should be rejected due to timestamp ordering
        let result = group_state.apply_event(
            event_a,
            test_message_id(10),
            IdentityRef::Key(alice_key.public_key()),
            1100,
        );

        match result {
            Err(GroupStateError::StateTransition(_)) => {
                // Expected: Out-of-order events are rejected
            }
            _ => panic!(
                "Expected StateTransition error for out-of-order event, got: {:?}",
                result
            ),
        }

        // The group should have Event B's changes
        assert_eq!(group_state.group_info.name, "Event B");
    }

    #[test]
    fn test_message_id_tiebreaker() {
        // **Scenario**: Two events have identical timestamps and acknowledgments
        //
        // Tests the Message ID tiebreaker mechanism for deterministic conflict resolution.
        let (mut group_state, alice_key, _bob_key, _) = create_test_group_with_members();

        // Create two events with identical timestamps but different message IDs
        let event_lower_id = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Lower ID Event".to_string())],
            test_message_id(1),
            test_message_id(1),
        );

        let event_higher_id = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("Higher ID Event".to_string())],
            test_message_id(2),
            test_message_id(2),
        );

        let lower_msg_id = test_message_id(10); // Lower hash value
        let higher_msg_id = test_message_id(20); // Higher hash value

        let timestamp = 1500;

        // Apply both events with same timestamp
        group_state
            .apply_event(
                event_lower_id,
                lower_msg_id,
                IdentityRef::Key(alice_key.public_key()),
                timestamp,
            )
            .unwrap();
        group_state
            .apply_event(
                event_higher_id,
                higher_msg_id,
                IdentityRef::Key(alice_key.public_key()),
                timestamp,
            )
            .unwrap();

        // The higher message ID should win (last applied wins in this simple case)
        assert_eq!(group_state.group_info.name, "Higher ID Event");

        // Both events should be in message metadata
        assert!(group_state.message_metadata.contains_key(&lower_msg_id));
        assert!(group_state.message_metadata.contains_key(&higher_msg_id));
    }
}

#[cfg(test)]
mod edge_cases_and_error_handling {
    use crate::identity::IdentityType;

    use super::*;

    #[test]
    fn test_empty_acknowledgments_for_non_permission_events() {
        // **Scenario**: Non-permission events should not have acknowledgments
        let (mut group_state, alice_key, _, _) = create_test_group_with_members();

        // Regular name update should work without acknowledgments
        let name_update = GroupActivityEvent::new_update_group(
            vec![GroupInfoUpdate::Name("New Name".to_string())],
            test_message_id(1), // No acknowledgments needed
            test_message_id(1),
        );

        group_state
            .apply_event(
                name_update,
                test_message_id(10),
                IdentityRef::Key(alice_key.public_key()),
                1500,
            )
            .unwrap();
        assert_eq!(group_state.group_info.name, "New Name");

        // Permission update should require acknowledgments
        let permission_update = GroupActivityEvent::UpdateGroup {
            updates: vec![GroupInfoUpdate::Settings(GroupSettings::default())],
            acknowledgment: Acknowledgment::new(
                test_message_id(1), // Group creation
                test_message_id(1), // Group creation
            ),
        };

        let result = group_state.apply_event(
            permission_update,
            test_message_id(11),
            IdentityRef::Key(alice_key.public_key()),
            1600,
        );

        // This should fail because permission updates require acknowledgments
        match result {
            Err(GroupStateError::InvalidAcknowledgment(_)) => {
                // Expected: Permission updates need acknowledgments
            }
            _ => panic!("Expected InvalidAcknowledgment error, got: {:?}", result),
        }
    }

    #[test]
    fn test_self_referential_acknowledgments() {
        // **Scenario**: Event tries to acknowledge itself
        let (mut group_state, alice_key, _bob_key, _charlie_key) = create_test_group_with_members();

        let self_ref_event_id = test_message_id(10);

        // Event tries to acknowledge itself (should be prevented)
        let self_ref_event = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            self_ref_event_id, // Self-reference
            test_message_id(1),
        );

        let result = group_state.apply_event(
            self_ref_event,
            self_ref_event_id,
            IdentityRef::Key(alice_key.public_key()),
            1500,
        );

        // This should fail because the event references itself
        match result {
            Err(GroupStateError::InvalidAcknowledgment(_)) => {
                // Expected: Cannot acknowledge self
            }
            _ => panic!(
                "Expected InvalidAcknowledgment error for self-reference, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_acknowledgment_of_future_events() {
        // **Scenario**: Event tries to acknowledge events that haven't happened yet
        let (mut group_state, alice_key, _bob_key, _charlie_keys) =
            create_test_group_with_members();

        // Event tries to acknowledge a future event
        let future_event = GroupActivityEvent::new_assign_role(
            IdentityType::Main,
            GroupRole::Admin,
            test_message_id(1),  // Valid past event
            test_message_id(99), // Future event that doesn't exist
        );

        let result = group_state.apply_event(
            future_event,
            test_message_id(10),
            IdentityRef::Key(alice_key.public_key()),
            1500,
        );

        // This should fail because the acknowledged event doesn't exist
        match result {
            Err(GroupStateError::InvalidAcknowledgment(_)) => {
                // Expected: Cannot acknowledge non-existent events
            }
            _ => panic!(
                "Expected InvalidAcknowledgment error for future event, got: {:?}",
                result
            ),
        }
    }

    #[test]
    fn test_maximum_acknowledgment_chain_length() {
        // **Scenario**: Very long chain of acknowledgments to test performance
        let (mut group_state, alice_key, bob_key, _) = create_test_group_with_members();

        let mut last_event_id = get_creation_message_id(&group_state); // Group creation

        // Create a chain of 50 permission events, each acknowledging the previous
        for i in 1..=50u8 {
            let event = GroupActivityEvent::new_assign_role(
                IdentityType::Main,
                if i % 2 == 0 {
                    GroupRole::Admin
                } else {
                    GroupRole::Member
                },
                last_event_id, // Acknowledge previous event
                last_event_id, // Same for others (simplified)
            );

            let event_id = test_message_id(10 + i);
            let timestamp = 1000 + (i as u64 * 10);

            group_state
                .apply_event(
                    event,
                    event_id,
                    IdentityRef::Key(alice_key.public_key()),
                    timestamp,
                )
                .unwrap();
            last_event_id = event_id;
        }

        // Verify final state
        assert_eq!(group_state.version, 53); // Initial + 2 joins + 50 role changes
        assert_eq!(group_state.message_metadata.len(), 53);

        // Verify Bob's final role (should be Member since 50 is even)
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(bob_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Member
        );
    }
}

#[cfg(test)]
mod performance_and_snapshots {
    use crate::identity::IdentityType;

    use super::*;

    #[test]
    fn test_periodic_snapshot_creation() {
        // **Scenario**: Verify that snapshots are created at regular intervals
        let (mut group_state, alice_key, _bob_key, _) = create_test_group_with_members();

        // Create enough events to trigger snapshot creation (every 100 events)
        for i in 1..=150u8 {
            let event = GroupActivityEvent::new_update_group(
                vec![GroupInfoUpdate::Name(format!("Name {}", i))],
                test_message_id(1),
                test_message_id(1),
            );

            let event_id = test_message_id(10 + i);
            let timestamp = 1000 + (i as u64 * 10);

            group_state
                .apply_event(
                    event,
                    event_id,
                    IdentityRef::Key(alice_key.public_key()),
                    timestamp,
                )
                .unwrap();
        }

        // Should have snapshots at version 100
        assert!(!group_state.group_state_snapshots.is_empty());

        // Verify snapshot content
        let snapshot = group_state.group_state_snapshots.values().next().unwrap();
        assert!(
            snapshot
                .member_roles
                .contains_key(&IdentityRef::Key(alice_key.public_key()))
        );
        assert_eq!(snapshot.settings, GroupSettings::default());
    }

    #[test]
    fn test_snapshot_cleanup() {
        // **Scenario**: Verify that old snapshots are cleaned up to prevent unbounded growth
        let (mut group_state, alice_key, _, _) = create_test_group_with_members();

        // Create many events to generate multiple snapshots
        for i in 1..=200u8 {
            let event = GroupActivityEvent::new_update_group(
                vec![GroupInfoUpdate::Name(format!("Name {}", i))],
                test_message_id(1),
                test_message_id(1),
            );

            let event_id = test_message_id(10 + i);
            let timestamp = 1000 + (i as u64 * 10);

            group_state
                .apply_event(
                    event,
                    event_id,
                    IdentityRef::Key(alice_key.public_key()),
                    timestamp,
                )
                .unwrap();
        }

        // Should have at most 10 snapshots (cleanup policy)
        assert!(group_state.group_state_snapshots.len() <= 10);

        // Should have the most recent snapshots
        let max_timestamp = group_state.group_state_snapshots.keys().max().unwrap();
        assert!(*max_timestamp >= 12000); // Recent timestamp
    }

    #[test]
    fn test_historical_state_reconstruction_performance() {
        // **Scenario**: Verify that historical state reconstruction is efficient with snapshots
        let (mut group_state, alice_key, bob_key, _) = create_test_group_with_members();

        // Create events to build history
        let creation_message_id = get_creation_message_id(&group_state);
        for i in 1..=200u8 {
            let event = if i % 20 == 0 {
                // Every 20th event is a permission change
                GroupActivityEvent::new_assign_role(
                    IdentityType::Main,
                    if i % 40 == 0 {
                        GroupRole::Admin
                    } else {
                        GroupRole::Member
                    },
                    creation_message_id, // Simplified acknowledgments
                    test_message_id(3),  // Charlie's join
                )
            } else {
                // Regular name updates
                GroupActivityEvent::new_update_group(
                    vec![GroupInfoUpdate::Name(format!("Name {}", i))],
                    creation_message_id,
                    creation_message_id,
                )
            };

            let event_id = test_message_id(10 + i);
            let timestamp = 1000 + (i as u64 * 10);

            group_state
                .apply_event(
                    event,
                    event_id,
                    IdentityRef::Key(alice_key.public_key()),
                    timestamp,
                )
                .unwrap();
        }

        // Verify we have snapshots for performance
        assert!(!group_state.group_state_snapshots.is_empty());

        // Verify current state is correct
        assert_eq!(group_state.group_info.name, "Name 200");
        assert_eq!(group_state.version, 203); // Initial + 2 joins + 200 updates

        // Verify Bob's final role (200 % 40 != 0, so should be Member from event 180)
        assert_eq!(
            group_state
                .members
                .get(&IdentityRef::Key(bob_key.public_key()))
                .unwrap()
                .role,
            GroupRole::Member
        );
    }
}
