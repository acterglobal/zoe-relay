use super::super::Client;
use crate::{RelayConnectionStatus, client::ClientSecret};
use eyeball::Subscriber;

#[cfg(feature = "frb-api")]
use flutter_rust_bridge::frb;

#[cfg_attr(feature = "frb-api", frb)]
impl Client {
    /// Get the current client secret
    pub fn client_secret(&self) -> ClientSecret {
        self.client_secret_observable.get()
    }
}

#[cfg_attr(feature = "frb-api", frb(ignore))]
impl Client {
    /// Subscribe to client secret updates
    ///
    /// Third parties can use this to be notified when the client secret changes,
    /// allowing them to store updated client secrets with the current server configuration.
    pub fn subscribe_to_client_secret(&self) -> Subscriber<ClientSecret> {
        self.client_secret_observable.subscribe()
    }

    /// Update the client secret observable state with current server configuration
    pub(crate) async fn update_client_secret_state(&self) {
        // Get only successfully connected servers for persistence in client secret
        let connected_servers = {
            let info_map = self.relay_info.read().await;
            info_map
                .values()
                .filter(|info| matches!(info.status, RelayConnectionStatus::Connected { .. }))
                .map(|info| info.info.relay_address.clone())
                .collect::<Vec<_>>()
        };

        // Update client secret with current server configuration
        let mut updated_client_secret = (*self.client_secret).clone();
        updated_client_secret.servers = connected_servers;

        self.client_secret_observable.set(updated_client_secret);
    }
}
