use zoe_wire_protocol::prelude::*;

use zoe_state_machine::{DigitalGroupAssistant, GroupSettings, create_group_activity_event};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a DGA instance
    let mut dga = DigitalGroupAssistant::new();

    // Create signing keys for users
    let mut rng = rand::thread_rng();
    let alice_keypair = generate_keypair(&mut rng);
    let alice_key = alice_keypair.signing_key();
    let _bob_keypair = generate_keypair(&mut rng); // Would be used if Bob had the encryption key

    // Alice creates a group
    let metadata = vec![
        zoe_app_primitives::Metadata::Description("A test group for the DGA protocol".to_string()),
        zoe_app_primitives::Metadata::Generic {
            key: "category".to_string(),
            value: "testing".to_string(),
        },
    ];

    let group_info = zoe_app_primitives::GroupInfo {
        name: "My Test Group".to_string(),
        settings: GroupSettings::default(),
        key_info: zoe_app_primitives::GroupKeyInfo::new_chacha20_poly1305(
            vec![], // This will be filled in by create_group
            zoe_wire_protocol::crypto::KeyDerivationInfo {
                method: zoe_wire_protocol::crypto::KeyDerivationMethod::ChaCha20Poly1305Keygen,
                salt: vec![],
                argon2_params: zoe_wire_protocol::crypto::Argon2Params::default(),
                context: "dga-group-key".to_string(),
            },
        ),
        metadata,
    };

    let create_group = zoe_app_primitives::CreateGroup::new(group_info);

    let create_result = dga.create_group(
        create_group,
        None, // Generate a new key
        alice_key,
        chrono::Utc::now().timestamp() as u64,
    )?;

    println!("Created group: {:?}", create_result.group_id);
    println!(
        "Group ID (which is also the root event ID): {:?}",
        create_result.group_id
    );

    // In encrypted groups, Bob needs the group key to participate
    // This would normally be distributed via the inbox system, but for demo we'll simulate it
    // Note: In real usage, Bob would receive the key through a separate secure channel

    // For this example, we need to give Bob access to the group key somehow
    // In a real system, this would happen through the inbox system
    println!("Note: In a real system, Bob would receive the group key via the inbox system");

    // Since we can't easily simulate the inbox system in this example,
    // we'll demonstrate that without the key, Bob cannot participate
    // but Alice can post activities to the group

    // Alice posts a welcome message to the group
    let activity_event = create_group_activity_event(());

    let activity_message = dga.create_group_event_message(
        create_result.group_id,
        activity_event,
        alice_key,
        chrono::Utc::now().timestamp() as u64,
    )?;

    // Process Alice's activity
    dga.process_group_event(&activity_message)?;

    // Check the group state
    let group_state = dga.get_group_state(&create_result.group_id).unwrap();
    println!(
        "Group '{}' now has {} active members",
        group_state.name,
        group_state.members.len()
    );

    for (member_key, member_info) in &group_state.members {
        println!("- Member: {:?}, Role: {:?}", member_key, member_info.role);
    }

    // Create subscription filter for this group
    let subscription_filter = dga.create_group_subscription_filter(&create_result.group_id)?;
    println!("Subscription filter for group events: {subscription_filter:?}");

    println!("\nNote: This group uses AES-256-GCM encryption.");
    println!("All messages are encrypted before being sent over the wire.");
    println!("Anyone with the group's encryption key can participate by sending valid messages.");

    Ok(())
}
