use super::super::Client;
use crate::error::Result;
use crate::util::DEFAULT_PORT;
use crate::{
    ClientError, OverallConnectionStatus, RelayClient, RelayClientBuilder, RelayConnectionInfo,
    RelayConnectionStatus, RelayInfo, RelayStatusUpdate,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::Duration;
use zoe_app_primitives::RelayAddress;
use zoe_wire_protocol::{KeyId, VerifyingKey};

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

// Relay management methods (only available in offline mode)
#[cfg_attr(feature = "frb-api", frb)]
impl Client {
    /// Add a relay server to the client
    ///
    /// This will attempt to connect to all addresses in the RelayAddress in random order
    /// with a 10-second timeout per attempt. Only adds the relay to local state if a
    /// connection succeeds.
    pub async fn add_relay(&self, address: RelayAddress) -> Result<()> {
        let relay_id = address.id();

        // Notify about connecting status
        self.notify_relay_status_change(
            relay_id,
            address.clone(),
            RelayConnectionStatus::Connecting,
        )
        .await;

        // Try to connect to any of the addresses
        match self.try_connect_to_relay_addresses(&address).await {
            Ok((successful_addr, relay_client)) => {
                let relay_info = RelayInfo {
                    relay_id,
                    relay_address: address.clone(),
                };

                // Update relay info with successful connection
                {
                    let mut info_map = self.relay_info.write().await;
                    info_map.insert(
                        relay_id,
                        RelayConnectionInfo {
                            info: relay_info.clone(),
                            status: RelayConnectionStatus::Connected {
                                connected_address: successful_addr,
                            },
                        },
                    );
                }

                // Add to connections
                {
                    let mut connections = self.relay_connections.write().await;
                    connections.insert(relay_id, relay_client.clone());
                }

                // Add services to multi-relay managers
                let messages_manager = relay_client
                    .persistence_manager()
                    .await
                    .messages_manager()
                    .clone();
                let blob_service = Arc::clone(relay_client.blob_service().await?);

                self.message_manager
                    .add_relay(relay_id, messages_manager, true)
                    .await?;
                self.blob_service.add_relay(relay_id, blob_service).await;

                tracing::info!(
                    "Successfully connected to relay {} at address: {}",
                    hex::encode(relay_id.as_bytes()),
                    successful_addr
                );

                // Start connection monitoring for this relay
                self.start_connection_monitoring(relay_id, relay_client.clone());

                // Update observable states
                self.update_client_secret_state().await;
                self.notify_relay_status_change(
                    relay_id,
                    address,
                    RelayConnectionStatus::Connected {
                        connected_address: successful_addr,
                    },
                )
                .await;

                Ok(())
            }
            Err(connection_errors) => {
                tracing::warn!(
                    "Failed to connect to relay {} at any address. Errors: {:?}",
                    hex::encode(relay_id.as_bytes()),
                    connection_errors
                );

                // Add to relay info with failed status so we can track and retry later
                let error_summary = connection_errors
                    .iter()
                    .map(|(addr, err)| format!("{}: {}", addr, err))
                    .collect::<Vec<_>>()
                    .join("; ");

                let relay_info = RelayInfo {
                    relay_id,
                    relay_address: address.clone(),
                };

                let failed_status = RelayConnectionStatus::Failed {
                    error: format!("All connection attempts failed: {}", error_summary),
                };

                // Store the failed relay info for future reconnection attempts
                {
                    let mut info_map = self.relay_info.write().await;
                    info_map.insert(
                        relay_id,
                        RelayConnectionInfo {
                            info: relay_info,
                            status: failed_status.clone(),
                        },
                    );
                }

                // Don't update client secret for failed connections
                // (only successful connections should be persisted)

                self.notify_relay_status_change(relay_id, address, failed_status)
                    .await;

                Err(ClientError::Generic(format!(
                    "Failed to connect to relay at any address: {}",
                    error_summary
                )))
            }
        }
    }

    /// Try to connect to a relay using all its addresses in random order
    ///
    /// Returns the successful address and relay client, or all connection errors
    async fn try_connect_to_relay_addresses(
        &self,
        address: &RelayAddress,
    ) -> std::result::Result<(SocketAddr, RelayClient), Vec<(String, ClientError)>> {
        use rand::seq::SliceRandom;

        let network_addresses: Vec<_> = address.all_addresses().iter().cloned().collect();
        if network_addresses.is_empty() {
            return Err(vec![(
                "no addresses".to_string(),
                ClientError::Generic("No addresses provided".to_string()),
            )]);
        }

        // Randomize the order of connection attempts
        let mut shuffled_addresses = network_addresses;
        shuffled_addresses.shuffle(&mut rand::thread_rng());

        let mut connection_errors = Vec::new();

        for network_addr in shuffled_addresses {
            let addr_display = network_addr.to_connection_string(Some(DEFAULT_PORT));
            tracing::debug!("Attempting to connect to relay at: {}", addr_display);

            // Resolve address with timeout
            let socket_addr = match tokio::time::timeout(
                Duration::from_secs(5), // 5s for DNS resolution
                network_addr.resolve_to_socket_addr(DEFAULT_PORT),
            )
            .await
            {
                Ok(Ok(addr)) => addr,
                Ok(Err(e)) => {
                    connection_errors.push((
                        addr_display,
                        ClientError::Generic(format!("DNS resolution failed: {}", e)),
                    ));
                    continue;
                }
                Err(_) => {
                    connection_errors.push((
                        addr_display,
                        ClientError::Generic("DNS resolution timeout".to_string()),
                    ));
                    continue;
                }
            };

            // Attempt connection with timeout
            match tokio::time::timeout(
                Duration::from_secs(10), // 10s for connection attempt
                self.connect_to_relay(address.public_key.clone(), socket_addr),
            )
            .await
            {
                Ok(Ok(relay_client)) => {
                    tracing::info!("Successfully connected to relay at: {}", socket_addr);
                    return Ok((socket_addr, relay_client));
                }
                Ok(Err(e)) => {
                    connection_errors.push((addr_display, e));
                }
                Err(_) => {
                    connection_errors.push((
                        addr_display,
                        ClientError::Generic("Connection timeout".to_string()),
                    ));
                }
            }
        }

        Err(connection_errors)
    }

    /// Remove a relay connection (offline mode only)
    pub async fn remove_relay(&self, server_public_key: VerifyingKey) -> Result<bool> {
        let relay_id = server_public_key.id();

        // Get relay info before removing
        let relay_info = {
            let info_map = self.relay_info.read().await;
            info_map.get(&relay_id).map(|info| info.info.clone())
        };

        // Stop connection monitoring
        self.stop_connection_monitoring(relay_id).await;

        // Remove from multi-relay managers
        self.message_manager.remove_relay(&relay_id).await;
        self.blob_service.remove_relay(&relay_id).await;

        // Close and remove connection
        let removed = {
            let mut connections = self.relay_connections.write().await;
            connections.remove(&relay_id)
        };

        let had_active_connection = removed.is_some();
        if let Some(relay_client) = removed {
            relay_client.close().await;
        }

        // Update relay info (or remove if it exists)
        let had_relay_info = {
            let mut info_map = self.relay_info.write().await;
            if let Some(info) = info_map.get_mut(&relay_id) {
                info.status = RelayConnectionStatus::Disconnected {
                    error: None, // Manual removal, no error
                };
                true
            } else {
                false
            }
        };

        let was_removed = had_active_connection || had_relay_info;

        tracing::info!(
            "Removed relay connection: {}",
            hex::encode(relay_id.as_bytes())
        );

        // Update observable states
        self.update_client_secret_state().await;

        // Notify about disconnection if we had the relay info
        if let Some(info) = relay_info {
            self.notify_relay_status_change(
                relay_id,
                info.relay_address,
                RelayConnectionStatus::Disconnected {
                    error: None, // Manual removal, no error
                },
            )
            .await;
        }

        Ok(was_removed)
    }

    /// Get list of all configured relays with their connection status
    pub async fn get_relay_status(&self) -> Result<Vec<RelayConnectionInfo>> {
        let info_map = self.relay_info.read().await;
        Ok(info_map.values().cloned().collect())
    }

    /// Check if any relays are currently connected
    pub async fn has_connected_relays(&self) -> bool {
        self.overall_status().await.is_connected
    }

    /// Attempt to reconnect to all failed relays
    pub async fn reconnect_failed_relays(&self) -> Result<usize> {
        let failed_relays: Vec<RelayInfo> = {
            let info_map = self.relay_info.read().await;
            info_map
                .values()
                .filter(|info| matches!(info.status, RelayConnectionStatus::Failed { .. }))
                .map(|info| info.info.clone())
                .collect()
        };

        let mut reconnected = 0;
        for relay_info in failed_relays {
            // Use the full RelayAddress which contains all configured addresses
            if self.add_relay(relay_info.relay_address).await.is_ok() {
                reconnected += 1;
            }
        }

        Ok(reconnected)
    }

    /// Connect to a specific relay (internal method)
    async fn connect_to_relay(
        &self,
        server_public_key: VerifyingKey,
        server_addr: SocketAddr,
    ) -> Result<RelayClient> {
        let relay_client = RelayClientBuilder::new()
            .server_public_key(server_public_key)
            .server_address(server_addr)
            .storage(Arc::clone(&self.storage))
            .client_keypair(Arc::clone(&self.client_secret.inner_keypair))
            .autosubscribe(true)
            .build()
            .await?;

        Ok(relay_client)
    }

    pub async fn close(&self) {
        // Stop all connection monitors
        {
            let mut monitors = self.connection_monitors.write().await;
            for (relay_id, monitor_task) in monitors.iter() {
                tracing::debug!(
                    "Stopping connection monitor for relay: {}",
                    hex::encode(relay_id.as_bytes())
                );
                monitor_task.abort();
            }
            monitors.clear();
        }

        // Close all relay connections
        let relay_clients = {
            let mut connections = self.relay_connections.write().await;
            let clients: Vec<_> = connections.values().cloned().collect();
            connections.clear();
            clients
        };

        for relay_client in relay_clients {
            relay_client.close().await;
        }
    }

    /// Create a stream of overall connection status computed from relay status updates
    ///
    /// This is a computed stream that automatically updates when any relay status changes.
    /// It maintains local state and only locks once for initial state, then updates based on
    /// incoming relay status changes without additional locking.
    pub fn overall_status_stream(&self) -> impl futures::Stream<Item = OverallConnectionStatus> {
        let client = self.clone();
        let relay_receiver = client.subscribe_to_relay_status();

        async_stream::stream! {
            let mut relay_receiver = relay_receiver;

            // Get initial status using existing function (only lock once)
            let mut current_status = client.overall_status().await;
            yield current_status.clone();

            // Keep track of relay states locally to avoid locking
            let mut relay_states = std::collections::BTreeMap::new();

            // Update local state based on relay status changes
            while let Ok(update) = relay_receiver.recv().await {
                // Update our local tracking of this relay's status
                let was_connected = relay_states.get(&update.relay_id)
                    .map(|status| matches!(status, RelayConnectionStatus::Connected { .. }))
                    .unwrap_or(false);

                let is_now_connected = matches!(update.status, RelayConnectionStatus::Connected { .. });

                // Update local relay state
                relay_states.insert(update.relay_id, update.status);

                // Update overall status based on the change
                if was_connected && !is_now_connected {
                    // A relay disconnected
                    current_status.connected_count = current_status.connected_count.saturating_sub(1);
                } else if !was_connected && is_now_connected {
                    // A relay connected
                    current_status.connected_count += 1;
                }

                // Update total count (relay was added to our tracking)
                current_status.total_count = relay_states.len();

                // Update is_connected flag
                current_status.is_connected = current_status.connected_count > 0;

                yield current_status.clone();
            }
        }
    }
    /// Calculate the current overall connection status
    ///
    /// This is computed from the current relay states, ensuring it's always accurate but makes it
    /// a bit more expensive to compute. For live updates it is recommended to use `overall_status_stream`
    /// instead.
    pub async fn overall_status(&self) -> OverallConnectionStatus {
        let (connected_count, total_count) = {
            let info_map = self.relay_info.read().await;
            let connected = info_map
                .values()
                .filter(|info| matches!(info.status, RelayConnectionStatus::Connected { .. }))
                .count();
            // Only count successfully connected or disconnected relays, not failed ones
            let total = info_map
                .values()
                .filter(|info| !matches!(info.status, RelayConnectionStatus::Failed { .. }))
                .count();
            (connected, total)
        };

        OverallConnectionStatus {
            is_connected: connected_count > 0,
            connected_count,
            total_count,
        }
    }

    /// Start monitoring a relay connection for disconnections
    fn start_connection_monitoring(&self, relay_id: KeyId, relay_client: RelayClient) {
        let client = self.clone();
        let connection = relay_client.connection().clone();
        let monitors = Arc::clone(&self.connection_monitors);

        let monitor_task = tokio::spawn(async move {
            // Monitor the connection for closure
            let closed_future = connection.closed();
            let connection_error = closed_future.await;

            let error_msg = connection_error.to_string();
            tracing::warn!(
                "Relay connection lost for relay {}: {}",
                hex::encode(relay_id.as_bytes()),
                error_msg
            );

            // Get relay info for status update
            let relay_address = {
                let info_map = client.relay_info.read().await;
                info_map
                    .get(&relay_id)
                    .map(|info| info.info.relay_address.clone())
            };

            if let Some(relay_address) = relay_address {
                // Update relay status to disconnected with error details
                {
                    let mut info_map = client.relay_info.write().await;
                    if let Some(info) = info_map.get_mut(&relay_id) {
                        info.status = RelayConnectionStatus::Disconnected {
                            error: Some(error_msg.clone()),
                        };
                    }
                }

                // Remove from active connections
                {
                    let mut connections = client.relay_connections.write().await;
                    connections.remove(&relay_id);
                }

                // Remove from multi-relay managers
                client.message_manager.remove_relay(&relay_id).await;
                client.blob_service.remove_relay(&relay_id).await;

                // Update observable states
                client.update_client_secret_state().await;

                // Notify about disconnection
                client
                    .notify_relay_status_change(
                        relay_id,
                        relay_address.clone(),
                        RelayConnectionStatus::Disconnected {
                            error: Some(error_msg),
                        },
                    )
                    .await;

                // Attempt automatic reconnection after a delay
                let reconnect_client = client.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(5)).await;

                    tracing::info!(
                        "Attempting automatic reconnection to relay: {}",
                        hex::encode(relay_id.as_bytes())
                    );

                    if let Err(e) = reconnect_client.add_relay(relay_address).await {
                        tracing::warn!(
                            "Automatic reconnection failed for relay {}: {}",
                            hex::encode(relay_id.as_bytes()),
                            e
                        );
                    }
                });
            }
        });

        // Store the monitor task
        tokio::spawn(async move {
            let mut monitor_map = monitors.write().await;
            monitor_map.insert(relay_id, monitor_task);
        });
    }

    /// Stop monitoring a relay connection
    async fn stop_connection_monitoring(&self, relay_id: KeyId) {
        let mut monitors = self.connection_monitors.write().await;
        if let Some(monitor_task) = monitors.remove(&relay_id) {
            monitor_task.abort();
        }
    }

    /// Notify about relay status change
    async fn notify_relay_status_change(
        &self,
        relay_id: KeyId,
        relay_address: RelayAddress,
        status: RelayConnectionStatus,
    ) {
        let status_update = RelayStatusUpdate {
            relay_id,
            relay_address,
            status,
        };

        // Send to broadcast channel - ignore if no receivers
        let _ = self.relay_status_sender.send(status_update);
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl Client {
    /// Subscribe to per-relay connection status updates
    ///
    /// This provides real-time updates about individual relay connection status changes.
    /// Each relay reports its status independently via this broadcast channel.
    pub fn subscribe_to_relay_status(&self) -> broadcast::Receiver<RelayStatusUpdate> {
        self.relay_status_sender.subscribe()
    }
}
