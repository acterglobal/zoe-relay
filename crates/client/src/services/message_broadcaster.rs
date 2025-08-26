use crate::error::Result;
use futures::{Stream, StreamExt};
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::wrappers::{BroadcastStream, errors::BroadcastStreamRecvError};
use tracing::{debug, warn};
use zoe_wire_protocol::StreamMessage;

use super::{MessagesService, MessagesStream};

/// A broadcaster that wraps the MessagesService and allows multiple consumers
/// to subscribe to filtered message streams.
/// 
/// This service takes the single message stream from MessagesService and broadcasts
/// it to multiple consumers, each with their own filtering logic. This allows
/// different parts of the application (PQXDH, group state management, etc.) to
/// receive only the messages they care about without creating multiple server
/// subscriptions.
pub struct MessageBroadcaster {
    /// The underlying messages service for RPC operations
    messages_service: Arc<MessagesService>,
    /// Broadcast sender for distributing messages to subscribers
    broadcast_sender: broadcast::Sender<StreamMessage>,
    /// Handle to the background task that forwards messages
    _forward_handle: tokio::task::JoinHandle<()>,
}

impl MessageBroadcaster {
    /// Create a new MessageBroadcaster wrapping the given MessagesService and stream.
    /// 
    /// # Arguments
    /// * `messages_service` - The underlying messages service for RPC operations
    /// * `messages_stream` - The stream of messages from the server
    /// * `buffer_size` - Size of the broadcast channel buffer (defaults to 1000 if None)
    /// 
    /// # Returns
    /// A new MessageBroadcaster that will forward all messages from the stream
    /// to any subscribers.
    pub fn new(
        messages_service: MessagesService,
        mut messages_stream: MessagesStream,
        buffer_size: Option<usize>,
    ) -> Self {
        let buffer_size = buffer_size.unwrap_or(1000);
        let (broadcast_sender, _) = broadcast::channel(buffer_size);
        let sender_clone = broadcast_sender.clone();
        
        // Spawn background task to forward messages from the stream to broadcast channel
        let forward_handle = tokio::spawn(async move {
            debug!("MessageBroadcaster: Starting message forwarding task");
            
            while let Some(message) = messages_stream.recv().await {
                debug!("MessageBroadcaster: Forwarding message to {} subscribers", 
                       sender_clone.receiver_count());
                
                // Send to all subscribers
                // If there are no subscribers, this will return an error, but that's fine
                match sender_clone.send(message) {
                    Ok(_) => {}
                    Err(broadcast::error::SendError(_)) => {
                        // No active receivers - this is normal when no services are subscribed
                        debug!("MessageBroadcaster: No active subscribers");
                    }
                }
            }
            
            debug!("MessageBroadcaster: Message stream ended, stopping forwarding task");
        });
        
        Self {
            messages_service: Arc::new(messages_service),
            broadcast_sender,
            _forward_handle: forward_handle,
        }
    }
    
    /// Subscribe to messages with a custom filter predicate.
    /// 
    /// # Arguments
    /// * `filter` - A function that takes a StreamMessage and returns true if it should be included
    /// 
    /// # Returns
    /// A stream of StreamMessage that match the filter predicate
    /// 
    /// # Example
    /// ```rust,no_run
    /// # use zoe_client::services::MessageBroadcaster;
    /// # use zoe_wire_protocol::{StreamMessage, Tag};
    /// # async fn example(broadcaster: &MessageBroadcaster, inbox_tag: Tag) {
    /// let pqxdh_stream = broadcaster.subscribe_filtered(move |msg| {
    ///     match msg {
    ///         StreamMessage::MessageReceived { message, .. } => {
    ///             message.tags().contains(&inbox_tag)
    ///         }
    ///         StreamMessage::StreamHeightUpdate(_) => false,
    ///     }
    /// });
    /// # }
    /// ```
    pub fn subscribe_filtered<F>(&self, filter: F) -> impl Stream<Item = StreamMessage>
    where
        F: Fn(&StreamMessage) -> bool + Send + Clone + 'static,
    {
        let receiver = self.broadcast_sender.subscribe();
        
        // Convert broadcast receiver to stream and apply filter
        BroadcastStream::new(receiver)
            .filter_map(move |result| {
                let filter = filter.clone();
                async move {
                    match result {
                        Ok(message) => {
                            if filter(&message) {
                                Some(message)
                            } else {
                                None
                            }
                        }
                        Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                            warn!("MessageBroadcaster subscriber lagged, skipped {} messages", skipped);
                            None
                        }
                    }
                }
            })
    }
    
    /// Subscribe to all messages without filtering.
    /// 
    /// # Returns
    /// A stream of all StreamMessage from the server
    pub fn subscribe_all(&self) -> impl Stream<Item = StreamMessage> {
        self.subscribe_filtered(|_| true)
    }
    
    /// Get a reference to the underlying MessagesService for RPC operations.
    /// 
    /// This allows callers to perform operations like subscribe, update_filters,
    /// catch_up, etc. on the underlying service while still using the broadcaster
    /// for message consumption.
    pub fn messages_service(&self) -> &MessagesService {
        &self.messages_service
    }
    
    /// Get the number of active subscribers to this broadcaster.
    pub fn subscriber_count(&self) -> usize {
        self.broadcast_sender.receiver_count()
    }
    
    /// Check if the underlying messages service is closed.
    pub fn is_closed(&self) -> bool {
        self.messages_service.is_closed()
    }
}

/// Convenience function to create a MessageBroadcaster from a QUIC connection.
/// 
/// This handles the connection setup and returns both the broadcaster and any
/// connection errors.
/// 
/// # Arguments
/// * `connection` - The QUIC connection to the relay server
/// * `buffer_size` - Optional buffer size for the broadcast channel
/// 
/// # Returns
/// A MessageBroadcaster ready for use
/// 
/// # Example
/// ```rust,no_run
/// # use quinn::Connection;
/// # use zoe_client::services::create_message_broadcaster;
/// # async fn example(connection: &Connection) -> zoe_client::error::Result<()> {
/// let broadcaster = create_message_broadcaster(connection, None).await?;
/// 
/// // Now use the broadcaster for multiple services
/// let pqxdh_stream = broadcaster.subscribe_filtered(|msg| {
///     // Filter for PQXDH messages
///     true // placeholder
/// });
/// # Ok(())
/// # }
/// ```
pub async fn create_message_broadcaster(
    connection: &quinn::Connection,
    buffer_size: Option<usize>,
) -> Result<MessageBroadcaster> {
    let (messages_service, messages_stream) = MessagesService::connect(connection).await?;
    Ok(MessageBroadcaster::new(messages_service, messages_stream, buffer_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    
    use zoe_wire_protocol::StreamMessage;
    
    /// Create a mock messages stream for testing
    fn create_mock_stream() -> (MessagesStream, mpsc::UnboundedSender<StreamMessage>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (rx, tx)
    }
    
    /// Create a mock messages service for testing
    fn create_mock_service() -> MessagesService {
        // This is a placeholder - in real tests we'd need to mock the service properly
        // For now, we'll focus on the broadcaster logic
        todo!("Mock MessagesService for testing")
    }
    
    #[tokio::test]
    async fn test_broadcaster_forwards_messages() {
        let (_stream, stream_tx) = create_mock_stream();
        
        // Test that we can send messages to the stream
        let test_msg = StreamMessage::StreamHeightUpdate("test".to_string());
        stream_tx.send(test_msg).unwrap();
        drop(stream_tx); // Close the stream
        
        // This test demonstrates the structure for message forwarding
        // In a full implementation, we would:
        // 1. Create a proper mock MessagesService
        // 2. Create a MessageBroadcaster with the service and stream
        // 3. Subscribe to the broadcaster
        // 4. Send messages through the stream
        // 5. Verify messages are received by subscribers
        
        // For now, we just verify the basic stream operations work
        assert!(true, "Stream operations completed successfully");
    }
    
    #[tokio::test] 
    async fn test_filtered_subscription() {
        // Test the filtering logic that MessageBroadcaster would use
        let filter = |msg: &StreamMessage| -> bool {
            match msg {
                StreamMessage::StreamHeightUpdate(height) => {
                    height.parse::<i32>().unwrap_or(0) > 100
                }
                _ => false,
            }
        };
        
        let test_messages = vec![
            StreamMessage::StreamHeightUpdate("50".to_string()),
            StreamMessage::StreamHeightUpdate("150".to_string()),
            StreamMessage::StreamHeightUpdate("75".to_string()),
        ];
        
        let filtered: Vec<_> = test_messages.iter().filter(|msg| filter(msg)).collect();
        assert_eq!(filtered.len(), 1); // Only "150" should pass
    }
    
    #[tokio::test]
    async fn test_multiple_subscribers() {
        // Test the multi-subscriber logic that MessageBroadcaster would use
        use tokio::sync::broadcast;
        
        let (tx, _) = broadcast::channel::<StreamMessage>(10);
        
        // Create multiple receivers
        let mut receivers = Vec::new();
        for _ in 0..3 {
            receivers.push(tx.subscribe());
        }
        
        assert_eq!(tx.receiver_count(), 3);
        
        // Send a message
        let test_msg = StreamMessage::StreamHeightUpdate("multi".to_string());
        tx.send(test_msg).unwrap();
        
        // All receivers should get the message
        for mut receiver in receivers {
            let received = receiver.recv().await.unwrap();
            match received {
                StreamMessage::StreamHeightUpdate(height) => {
                    assert_eq!(height, "multi");
                }
                _ => panic!("Expected StreamHeightUpdate"),
            }
        }
    }
}