//! Test to verify that messages sent by one client are received and processed by another client's GroupManager

use anyhow::{Context, Result};
use rand::{Rng, RngCore};
use std::time::Duration;
use tokio::time::timeout;
use tracing::info;

use zoe_app_primitives::{
    digital_groups_organizer::events::admin::{
        FeaturePermission, PermissionUpdate, TextBlocksPermissionUpdate,
    },
    group::events::{GroupActivityEvent, settings::GroupSettings},
    protocol::AppProtocolVariant,
};
use zoe_state_machine::group::{CreateGroupBuilder, GroupDataUpdate};

use crate::infra::TestInfrastructure;

#[tokio::test]
async fn test_two_client_message_processing() -> Result<()> {
    let infra = TestInfrastructure::setup().await?;

    // Create two clients
    let client_a = infra.create_full_client().await?;
    let client_b = infra.create_full_client().await?;

    info!("🔧 Created two clients: Alice and Bob");

    // Alice creates a group with DGO app
    let group_name = format!("two_client_test_group_{}", rand::thread_rng().next_u64());
    let group_manager_a = client_a.group_manager();
    let mut group_updates_a = group_manager_a.subscribe_to_updates();

    let create_group_result = group_manager_a
        .create_group(
            CreateGroupBuilder::default()
                .name(group_name.clone())
                .description("A test group for two-client message testing".to_string())
                .group_settings(GroupSettings::new())
                .install_dgo_app_default(), // Install DGO app with default version
            client_a.keypair(),
        )
        .await?;

    let group_id = create_group_result.group_id.clone();
    info!(
        "📁 Alice created group '{}' with ID: {:?}",
        group_name, group_id
    );

    // Wait for Alice's group creation to be processed
    let group_id_for_alice = group_id.clone();
    let group_session_a = timeout(Duration::from_secs(2), async move {
        while let Ok(update) = group_updates_a.recv().await {
            match update {
                GroupDataUpdate::GroupAdded(session) => {
                    if session.state.group_info.group_id == group_id_for_alice {
                        return Ok(session);
                    }
                }
                GroupDataUpdate::GroupUpdated(session) => {
                    if session.state.group_info.group_id == group_id_for_alice {
                        return Ok(session);
                    }
                }
                _ => {} // Ignore other updates
            }
        }
        Err(anyhow::anyhow!("Group creation update not received"))
    })
    .await??;

    info!("✅ Alice's group creation processed successfully");

    // Bob joins the group by sharing the group creation message
    let group_manager_b = client_b.group_manager();
    let mut group_updates_b = group_manager_b.subscribe_to_updates();

    // Get the encryption key from Alice's session
    let encryption_key = group_session_a.current_key.clone();

    // Bob processes the group creation message (simulating receiving it)
    let _join_result = group_manager_b
        .join_group(create_group_result.message.clone(), encryption_key)
        .await?;

    info!("✅ Bob joined the group");

    // Wait for Bob to process the group addition
    let group_id_clone = group_id.clone();
    let group_id_clone2 = group_id.clone();
    let _group_session_b = timeout(Duration::from_secs(2), async move {
        while let Ok(update) = group_updates_b.recv().await {
            match update {
                GroupDataUpdate::GroupAdded(session) => {
                    if session.state.group_info.group_id == group_id_clone {
                        return Ok(session);
                    }
                }
                _ => {} // Ignore other updates
            }
        }
        Err(anyhow::anyhow!("Bob's group addition update not received"))
    })
    .await??;

    info!("✅ Bob processed group addition successfully");

    // Subscribe Bob's GroupManager to group updates to see if it receives Alice's messages
    let mut bob_group_updates = group_manager_b.subscribe_to_updates();

    // Alice publishes an UpdateAppSettings message
    let settings_updates = vec![
        PermissionUpdate::TextBlocks(TextBlocksPermissionUpdate::Create(
            FeaturePermission::ModeratorOrAbove,
        )),
        PermissionUpdate::TextBlocks(TextBlocksPermissionUpdate::Update(
            FeaturePermission::ModeratorOrAbove,
        )),
    ];

    let settings_data =
        postcard::to_stdvec(&settings_updates).context("Failed to serialize DGO settings")?;

    let app_settings_event = GroupActivityEvent::UpdateAppSettings {
        app_id: AppProtocolVariant::DigitalGroupsOrganizer,
        update: settings_data.clone(),
    };

    info!("⚙️ Alice publishing UpdateAppSettings message...");
    let settings_msg = group_manager_a
        .publish_group_event(&group_id, app_settings_event, client_a.keypair())
        .await?;
    let settings_message_id = *settings_msg.id();
    info!(
        "⚙️ Alice published UpdateAppSettings with ID: {:?}",
        settings_message_id
    );

    // Wait for Bob to receive and process the message through his GroupManager
    info!("🔍 Waiting for Bob's GroupManager to receive the UpdateAppSettings message...");

    let group_update = timeout(Duration::from_secs(5), async move {
        while let Ok(update) = bob_group_updates.recv().await {
            info!("📥 Bob's GroupManager received update: {:?}", update);
            match &update {
                GroupDataUpdate::GroupUpdated(session) => {
                    if session.state.group_info.group_id == group_id_clone2 {
                        info!("✅ SUCCESS: Bob's GroupManager processed the UpdateAppSettings message!");
                        return Ok(update);
                    }
                }
                _ => {} // Ignore other updates
            }
        }
        Err(anyhow::anyhow!("Bob's GroupManager did not receive group update"))
    })
    .await?;

    match group_update {
        Ok(update) => {
            info!(
                "✅ SUCCESS: Bob's GroupManager received and processed Alice's UpdateAppSettings message!"
            );
            info!("📋 Group update details: {:?}", update);
        }
        Err(e) => {
            info!(
                "❌ FAILURE: Bob's GroupManager did not receive Alice's UpdateAppSettings message: {}",
                e
            );
            return Err(e);
        }
    }

    Ok(())
}
