use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::{wrappers::UnboundedReceiverStream, Stream};

/// Connection status for WhatsApp client
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ConnectionStatus {
    Connected,
    Disconnected,
    Connecting,
    LoggedOut,
}

impl From<&str> for ConnectionStatus {
    fn from(s: &str) -> Self {
        match s {
            "connected" => ConnectionStatus::Connected,
            "disconnected" => ConnectionStatus::Disconnected,
            "connecting" => ConnectionStatus::Connecting,
            "logged_out" => ConnectionStatus::LoggedOut,
            _ => ConnectionStatus::Disconnected,
        }
    }
}

/// WhatsApp message information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageInfo {
    pub id: String,
    pub chat: String,
    pub sender: String,
    pub timestamp: u64,
    pub message_type: String,
    pub content: String,
}

/// WhatsApp message event (for streaming)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEvent {
    pub id: String,
    pub chat: String,
    pub sender: String,
    pub timestamp: i64,
    #[serde(rename = "type")]
    pub message_type: String,
    pub content: String,
    pub is_from_me: bool,
}

/// Contact information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub jid: String,
    pub name: Option<String>,
    pub phone: Option<String>,
}

/// Group information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub jid: String,
    pub name: String,
    pub description: Option<String>,
    pub participants: Vec<Contact>,
}

/// Response from Go functions
#[repr(C)]
struct CResponse {
    success: bool,
    data: *mut libc::c_char,
    error: *mut libc::c_char,
}

/// Status response from connection functions
#[repr(C)]
struct CStatusResponse {
    status: *mut libc::c_char,
    error: *mut libc::c_char,
}

// External Go functions via CGO
#[cfg(not(test))]
unsafe extern "C" {
    fn whatsmeow_init(db_path: *const libc::c_char) -> usize;
    fn whatsmeow_connect_async(client_ptr: usize, callback_handle: usize);
    fn whatsmeow_disconnect_async(client_ptr: usize, callback_handle: usize);
    fn whatsmeow_get_status_async(client_ptr: usize, callback_handle: usize);
    fn whatsmeow_get_qr_async(client_ptr: usize, callback_handle: usize);
    fn whatsmeow_send_message_async(
        client_ptr: usize,
        chat_jid: *const libc::c_char,
        text: *const libc::c_char,
        callback_handle: usize,
    );
    fn whatsmeow_register_message_handler(client_ptr: usize, callback_handle: usize) -> bool;
    fn whatsmeow_unregister_message_handler(client_ptr: usize) -> bool;
    fn whatsmeow_send_image_async(
        chat_jid: *const libc::c_char,
        image_path: *const libc::c_char,
        caption: *const libc::c_char,
        callback_handle: usize,
    );
    fn whatsmeow_get_contacts_async(callback_handle: usize);
    fn whatsmeow_get_groups_async(callback_handle: usize);
    fn whatsmeow_get_messages_async(
        chat_jid: *const libc::c_char,
        limit: u32,
        callback_handle: usize,
    );
    fn whatsmeow_create_group_async(
        name: *const libc::c_char,
        participants: *const libc::c_char,
        callback_handle: usize,
    );
    fn whatsmeow_join_group_async(invite_link: *const libc::c_char, callback_handle: usize);
    fn whatsmeow_mark_read_async(
        chat_jid: *const libc::c_char,
        message_id: *const libc::c_char,
        callback_handle: usize,
    );
    fn go_free(ptr: *mut libc::c_char);
}

// Mock implementations for testing
#[cfg(test)]
mod mock_ffi {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    static MOCK_INIT_SUCCESS: AtomicBool = AtomicBool::new(true);
    static MOCK_CONNECTION_STATUS: AtomicBool = AtomicBool::new(false);

    #[allow(unused)]
    pub fn set_mock_init_success(success: bool) {
        MOCK_INIT_SUCCESS.store(success, Ordering::SeqCst);
    }

    #[allow(unused)]
    pub fn set_mock_connection_status(connected: bool) {
        MOCK_CONNECTION_STATUS.store(connected, Ordering::SeqCst);
    }

    pub unsafe fn whatsmeow_init(_db_path: *const libc::c_char) -> usize {
        if MOCK_INIT_SUCCESS.load(Ordering::SeqCst) {
            0x1234 // Return a fake client pointer
        } else {
            0 // Return null pointer on failure
        }
    }

    pub unsafe fn whatsmeow_connect_async(_client_ptr: usize, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<ConnectionStatus>>);
        let _ = tx.send(Ok(ConnectionStatus::Connected));
    }

    pub unsafe fn whatsmeow_disconnect_async(_client_ptr: usize, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<ConnectionStatus>>);
        let _ = tx.send(Ok(ConnectionStatus::Disconnected));
    }

    pub unsafe fn whatsmeow_get_status_async(_client_ptr: usize, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<ConnectionStatus>>);
        let status = if MOCK_CONNECTION_STATUS.load(Ordering::SeqCst) {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        };
        let _ = tx.send(Ok(status));
    }

    pub unsafe fn whatsmeow_get_qr_async(_client_ptr: usize, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let qr_code = "https://wa.me/qr/MOCK_QR_CODE_FOR_TESTING".to_string();
        let _ = tx.send(Ok(qr_code));
    }

    pub unsafe fn whatsmeow_send_message_async(
        _client_ptr: usize,
        _chat_jid: *const libc::c_char,
        _text: *const libc::c_char,
        callback_handle: usize,
    ) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let _ = tx.send(Ok("msg_mock_123".to_string()));
    }

    pub unsafe fn whatsmeow_register_message_handler(
        _client_ptr: usize,
        _callback_handle: usize,
    ) -> bool {
        true // Mock always succeeds
    }

    pub unsafe fn whatsmeow_unregister_message_handler(_client_ptr: usize) -> bool {
        true // Mock always succeeds
    }

    pub unsafe fn whatsmeow_send_image_async(
        _chat_jid: *const libc::c_char,
        _image_path: *const libc::c_char,
        _caption: *const libc::c_char,
        callback_handle: usize,
    ) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let _ = tx.send(Ok("msg_mock_image_456".to_string()));
    }

    pub unsafe fn whatsmeow_get_contacts_async(callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_contacts = r#"[
            {
                "jid": "test1@s.whatsapp.net",
                "name": "Mock Contact 1",
                "phone": "+1234567890"
            },
            {
                "jid": "test2@s.whatsapp.net", 
                "name": "Mock Contact 2",
                "phone": "+0987654321"
            }
        ]"#;
        let _ = tx.send(Ok(mock_contacts.to_string()));
    }

    pub unsafe fn whatsmeow_get_groups_async(callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_groups = r#"[
            {
                "jid": "mockgroup@g.us",
                "name": "Mock Test Group",
                "description": "A mock group for testing",
                "participants": [
                    {
                        "jid": "test1@s.whatsapp.net",
                        "name": "Mock Contact 1",
                        "phone": "+1234567890"
                    }
                ]
            }
        ]"#;
        let _ = tx.send(Ok(mock_groups.to_string()));
    }

    pub unsafe fn whatsmeow_get_messages_async(
        _chat_jid: *const libc::c_char,
        _limit: u32,
        callback_handle: usize,
    ) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_messages = r#"[
            {
                "id": "mock_msg_1",
                "chat": "test@s.whatsapp.net",
                "sender": "sender@s.whatsapp.net",
                "timestamp": 1640995200000,
                "message_type": "text",
                "content": "Mock message content"
            }
        ]"#;
        let _ = tx.send(Ok(mock_messages.to_string()));
    }

    pub unsafe fn whatsmeow_create_group_async(
        _name: *const libc::c_char,
        _participants: *const libc::c_char,
        callback_handle: usize,
    ) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_group = r#"{
            "jid": "newmockgroup@g.us",
            "name": "New Mock Group",
            "description": null,
            "participants": []
        }"#;
        let _ = tx.send(Ok(mock_group.to_string()));
    }

    pub unsafe fn whatsmeow_join_group_async(
        _invite_link: *const libc::c_char,
        callback_handle: usize,
    ) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_group = r#"{
            "jid": "joinedmockgroup@g.us",
            "name": "Joined Mock Group",
            "description": "Joined via invite link",
            "participants": []
        }"#;
        let _ = tx.send(Ok(mock_group.to_string()));
    }

    pub unsafe fn whatsmeow_mark_read_async(
        _chat_jid: *const libc::c_char,
        _message_id: *const libc::c_char,
        callback_handle: usize,
    ) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let _ = tx.send(Ok("success".to_string()));
    }

    pub unsafe fn go_free(_ptr: *mut libc::c_char) {
        // No-op for mocks
    }
}

// Wrapper functions that choose between real FFI and mocks
#[cfg(not(test))]
mod ffi_wrapper {
    #[allow(unused_imports)]
    use super::*;

    pub unsafe fn whatsmeow_init(db_path: *const libc::c_char) -> usize {
        super::whatsmeow_init(db_path)
    }

    pub unsafe fn whatsmeow_connect_async(client_ptr: usize, callback_handle: usize) {
        super::whatsmeow_connect_async(client_ptr, callback_handle)
    }

    pub unsafe fn whatsmeow_disconnect_async(client_ptr: usize, callback_handle: usize) {
        super::whatsmeow_disconnect_async(client_ptr, callback_handle)
    }

    pub unsafe fn whatsmeow_get_status_async(client_ptr: usize, callback_handle: usize) {
        super::whatsmeow_get_status_async(client_ptr, callback_handle)
    }

    pub unsafe fn whatsmeow_get_qr_async(client_ptr: usize, callback_handle: usize) {
        super::whatsmeow_get_qr_async(client_ptr, callback_handle)
    }

    pub unsafe fn whatsmeow_send_message_async(
        client_ptr: usize,
        chat_jid: *const libc::c_char,
        text: *const libc::c_char,
        callback_handle: usize,
    ) {
        super::whatsmeow_send_message_async(client_ptr, chat_jid, text, callback_handle)
    }

    pub unsafe fn whatsmeow_register_message_handler(
        client_ptr: usize,
        callback_handle: usize,
    ) -> bool {
        super::whatsmeow_register_message_handler(client_ptr, callback_handle)
    }

    pub unsafe fn whatsmeow_unregister_message_handler(client_ptr: usize) -> bool {
        super::whatsmeow_unregister_message_handler(client_ptr)
    }

    pub unsafe fn whatsmeow_send_image_async(
        chat_jid: *const libc::c_char,
        image_path: *const libc::c_char,
        caption: *const libc::c_char,
        callback_handle: usize,
    ) {
        super::whatsmeow_send_image_async(chat_jid, image_path, caption, callback_handle)
    }

    pub unsafe fn whatsmeow_get_contacts_async(callback_handle: usize) {
        super::whatsmeow_get_contacts_async(callback_handle)
    }

    pub unsafe fn whatsmeow_get_groups_async(callback_handle: usize) {
        super::whatsmeow_get_groups_async(callback_handle)
    }

    pub unsafe fn whatsmeow_get_messages_async(
        chat_jid: *const libc::c_char,
        limit: u32,
        callback_handle: usize,
    ) {
        super::whatsmeow_get_messages_async(chat_jid, limit, callback_handle)
    }

    pub unsafe fn whatsmeow_create_group_async(
        name: *const libc::c_char,
        participants: *const libc::c_char,
        callback_handle: usize,
    ) {
        super::whatsmeow_create_group_async(name, participants, callback_handle)
    }

    pub unsafe fn whatsmeow_join_group_async(
        invite_link: *const libc::c_char,
        callback_handle: usize,
    ) {
        super::whatsmeow_join_group_async(invite_link, callback_handle)
    }

    pub unsafe fn whatsmeow_mark_read_async(
        chat_jid: *const libc::c_char,
        message_id: *const libc::c_char,
        callback_handle: usize,
    ) {
        super::whatsmeow_mark_read_async(chat_jid, message_id, callback_handle)
    }

    pub unsafe fn go_free(ptr: *mut libc::c_char) {
        super::go_free(ptr)
    }
}

#[cfg(test)]
use mock_ffi as ffi_wrapper;

// Global registry for message stream senders
lazy_static::lazy_static! {
    static ref MESSAGE_SENDERS: Arc<Mutex<HashMap<usize, mpsc::UnboundedSender<MessageEvent>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}

/// Callback functions that Go can call back to Rust
#[unsafe(no_mangle)]
extern "C" fn rust_status_callback(handle: usize, response: *const CStatusResponse) {
    let tx = unsafe { Box::from_raw(handle as *mut oneshot::Sender<Result<ConnectionStatus>>) };

    unsafe {
        if !response.is_null() {
            let status_str = if !(*response).status.is_null() {
                CStr::from_ptr((*response).status)
                    .to_string_lossy()
                    .to_string()
            } else {
                "disconnected".to_string()
            };

            let error_str = if !(*response).error.is_null() {
                Some(
                    CStr::from_ptr((*response).error)
                        .to_string_lossy()
                        .to_string(),
                )
            } else {
                None
            };

            let result = if let Some(error) = error_str {
                Err(anyhow!("Go error: {}", error))
            } else {
                Ok(ConnectionStatus::from(status_str.as_str()))
            };

            let _ = tx.send(result);

            // Free the Go allocated memory
            if !(*response).status.is_null() {
                ffi_wrapper::go_free((*response).status);
            }
            if !(*response).error.is_null() {
                ffi_wrapper::go_free((*response).error);
            }
        } else {
            let _ = tx.send(Err(anyhow!("Null response from Go")));
        }
    }
}

#[unsafe(no_mangle)]
extern "C" fn rust_response_callback(handle: usize, response: *const CResponse) {
    let tx = unsafe { Box::from_raw(handle as *mut oneshot::Sender<Result<String>>) };

    unsafe {
        if !response.is_null() {
            let data_str = if !(*response).data.is_null() {
                CStr::from_ptr((*response).data)
                    .to_string_lossy()
                    .to_string()
            } else {
                String::new()
            };

            let error_str = if !(*response).error.is_null() {
                Some(
                    CStr::from_ptr((*response).error)
                        .to_string_lossy()
                        .to_string(),
                )
            } else {
                None
            };

            let result = if (*response).success && error_str.is_none() {
                Ok(data_str)
            } else {
                Err(anyhow!(
                    "Go error: {}",
                    error_str.unwrap_or_else(|| "Unknown error".to_string())
                ))
            };

            let _ = tx.send(result);

            // Free the Go allocated memory
            if !(*response).data.is_null() {
                ffi_wrapper::go_free((*response).data);
            }
            if !(*response).error.is_null() {
                ffi_wrapper::go_free((*response).error);
            }
        } else {
            let _ = tx.send(Err(anyhow!("Null response from Go")));
        }
    }
}

/// Callback function for message events from Go
#[unsafe(no_mangle)]
extern "C" fn rust_message_callback(handle: usize, response: *const CResponse) {
    unsafe {
        if !response.is_null() && (*response).success {
            let data_str = if !(*response).data.is_null() {
                CStr::from_ptr((*response).data)
                    .to_string_lossy()
                    .to_string()
            } else {
                return;
            };

            // Parse the JSON message event
            if let Ok(message_event) = serde_json::from_str::<MessageEvent>(&data_str) {
                // Send to the appropriate stream
                if let Ok(senders) = MESSAGE_SENDERS.lock() {
                    if let Some(sender) = senders.get(&handle) {
                        let _ = sender.send(message_event);
                    }
                }
            }

            // Free the Go allocated memory
            if !(*response).data.is_null() {
                ffi_wrapper::go_free((*response).data);
            }
            if !(*response).error.is_null() {
                ffi_wrapper::go_free((*response).error);
            }
        }
    }
}

/// Main WhatsApp client wrapper
#[derive(Debug)]
pub struct WhatsAppBot {
    client_ptr: usize,
}

impl WhatsAppBot {
    /// Create a new WhatsApp bot instance with database path
    pub fn new(db_path: &str) -> Result<Self> {
        let db_path_cstring = CString::new(db_path)?;
        let db_path_ptr = db_path_cstring.as_ptr();

        let client_ptr = unsafe { ffi_wrapper::whatsmeow_init(db_path_ptr) };
        if client_ptr == 0 {
            return Err(anyhow!("Failed to initialize WhatsApp client"));
        }

        Ok(Self { client_ptr })
    }

    /// Connect and authenticate with WhatsApp
    pub async fn connect(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel::<Result<ConnectionStatus>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_connect_async(self.client_ptr, handle);
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
            .map(|_| ())
    }

    /// Disconnect from WhatsApp
    pub async fn disconnect(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel::<Result<ConnectionStatus>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_disconnect_async(self.client_ptr, handle);
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
            .map(|_| ())
    }

    /// Get current connection status
    pub async fn get_connection_status(&self) -> Result<ConnectionStatus> {
        let (tx, rx) = oneshot::channel::<Result<ConnectionStatus>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_get_status_async(self.client_ptr, handle);
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }

    /// Get the QR code for authentication
    pub async fn get_qr_code(&self) -> Result<String> {
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_get_qr_async(self.client_ptr, handle);
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }

    /// Get a stream of incoming messages
    pub fn message_stream(&self) -> Result<impl Stream<Item = MessageEvent>> {
        let (tx, rx) = mpsc::unbounded_channel();

        // Store the sender in the global registry using client_ptr as key
        {
            let mut senders = MESSAGE_SENDERS
                .lock()
                .map_err(|_| anyhow!("Failed to lock message senders"))?;
            senders.insert(self.client_ptr, tx);
        }

        // Register the message handler with Go
        let success = unsafe {
            ffi_wrapper::whatsmeow_register_message_handler(self.client_ptr, self.client_ptr)
        };

        if !success {
            // Clean up on failure
            let mut senders = MESSAGE_SENDERS
                .lock()
                .map_err(|_| anyhow!("Failed to lock message senders"))?;
            senders.remove(&self.client_ptr);
            return Err(anyhow!("Failed to register message handler"));
        }

        Ok(UnboundedReceiverStream::new(rx))
    }

    /// Stop the message stream
    pub fn stop_message_stream(&self) -> Result<()> {
        // Unregister the message handler
        let success = unsafe { ffi_wrapper::whatsmeow_unregister_message_handler(self.client_ptr) };

        // Remove from registry
        {
            let mut senders = MESSAGE_SENDERS
                .lock()
                .map_err(|_| anyhow!("Failed to lock message senders"))?;
            senders.remove(&self.client_ptr);
        }

        if !success {
            return Err(anyhow!("Failed to unregister message handler"));
        }

        Ok(())
    }

    /// Check if connected and authenticated
    pub async fn is_connected(&self) -> Result<bool> {
        match self.get_connection_status().await? {
            ConnectionStatus::Connected => Ok(true),
            _ => Ok(false),
        }
    }

    /// Send a simple text message
    pub async fn send_message(&self, to: &str, message: &str) -> Result<String> {
        let chat_jid = CString::new(to)?;
        let text = CString::new(message)?;

        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_send_message_async(
                self.client_ptr,
                chat_jid.as_ptr(),
                text.as_ptr(),
                handle,
            );
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }

    /// Send an image with optional caption
    pub async fn send_image(
        &self,
        to: &str,
        image_path: &str,
        caption: Option<&str>,
    ) -> Result<String> {
        let chat_jid = CString::new(to)?;
        let image_path_c = CString::new(image_path)?;
        let caption_c = if let Some(cap) = caption {
            CString::new(cap)?
        } else {
            CString::new("")?
        };

        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_send_image_async(
                chat_jid.as_ptr(),
                image_path_c.as_ptr(),
                caption_c.as_ptr(),
                handle,
            );
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }

    /// Get all contacts
    pub async fn get_contacts(&self) -> Result<Vec<Contact>> {
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_get_contacts_async(handle);
        }

        let contacts_json = rx
            .await
            .map_err(|_| anyhow!("Failed to receive response from Go"))??;

        let contacts: Vec<Contact> = serde_json::from_str(&contacts_json)?;
        Ok(contacts)
    }

    /// Get all groups the user is part of
    pub async fn get_groups(&self) -> Result<Vec<GroupInfo>> {
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_get_groups_async(handle);
        }

        let groups_json = rx
            .await
            .map_err(|_| anyhow!("Failed to receive response from Go"))??;

        let groups: Vec<GroupInfo> = serde_json::from_str(&groups_json)?;
        Ok(groups)
    }

    /// Get recent messages from a chat
    pub async fn get_recent_messages(
        &self,
        chat_jid: &str,
        limit: u32,
    ) -> Result<Vec<MessageInfo>> {
        let chat_jid_c = CString::new(chat_jid)?;

        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_get_messages_async(chat_jid_c.as_ptr(), limit, handle);
        }

        let messages_json = rx
            .await
            .map_err(|_| anyhow!("Failed to receive response from Go"))??;

        let messages: Vec<MessageInfo> = serde_json::from_str(&messages_json)?;
        Ok(messages)
    }

    /// Create a new group
    pub async fn create_group(&self, name: &str, participants: &[&str]) -> Result<GroupInfo> {
        let name_c = CString::new(name)?;
        let participants_json = serde_json::to_string(&participants)?;
        let participants_c = CString::new(participants_json)?;

        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_create_group_async(
                name_c.as_ptr(),
                participants_c.as_ptr(),
                handle,
            );
        }

        let group_json = rx
            .await
            .map_err(|_| anyhow!("Failed to receive response from Go"))??;

        let group: GroupInfo = serde_json::from_str(&group_json)?;
        Ok(group)
    }

    /// Join a group using an invite link
    pub async fn join_group(&self, invite_link: &str) -> Result<GroupInfo> {
        let invite_link_c = CString::new(invite_link)?;

        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_join_group_async(invite_link_c.as_ptr(), handle);
        }

        let group_json = rx
            .await
            .map_err(|_| anyhow!("Failed to receive response from Go"))??;

        let group: GroupInfo = serde_json::from_str(&group_json)?;
        Ok(group)
    }

    /// Mark a message as read
    pub async fn mark_read(&self, chat_jid: &str, message_id: &str) -> Result<()> {
        let chat_jid_c = CString::new(chat_jid)?;
        let message_id_c = CString::new(message_id)?;

        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;

        unsafe {
            ffi_wrapper::whatsmeow_mark_read_async(
                chat_jid_c.as_ptr(),
                message_id_c.as_ptr(),
                handle,
            );
        }

        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
            .map(|_| ())
    }
}

impl Default for WhatsAppBot {
    fn default() -> Self {
        Self::new("whatsapp.db").expect("Failed to create WhatsApp bot")
    }
}

// Export the main types for use by other crates
pub use WhatsAppBot as Client;

unsafe impl Send for WhatsAppBot {}
unsafe impl Sync for WhatsAppBot {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // =============================================================================
    // UNIT TESTS - Testing data models, serialization, and Rust-side logic
    // =============================================================================
    mod unit {
        use super::*;

        #[test]
        fn bot_creation() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            // Bot creation succeeded if we got here without panicking
            assert_eq!(bot.client_ptr != 0, true);
        }

        #[test]
        fn connection_status_from_string() {
            assert_eq!(
                ConnectionStatus::from("connected"),
                ConnectionStatus::Connected
            );
            assert_eq!(
                ConnectionStatus::from("disconnected"),
                ConnectionStatus::Disconnected
            );
            assert_eq!(
                ConnectionStatus::from("connecting"),
                ConnectionStatus::Connecting
            );
            assert_eq!(
                ConnectionStatus::from("logged_out"),
                ConnectionStatus::LoggedOut
            );
            assert_eq!(
                ConnectionStatus::from("unknown"),
                ConnectionStatus::Disconnected
            ); // Default
        }

        #[test]
        fn connection_status_serialization() {
            let status = ConnectionStatus::Connected;
            let serialized = serde_json::to_string(&status).unwrap();
            let deserialized: ConnectionStatus = serde_json::from_str(&serialized).unwrap();
            assert_eq!(status, deserialized);
        }

        #[test]
        fn contact_serialization() {
            let contact = Contact {
                jid: "test@s.whatsapp.net".to_string(),
                name: Some("Test User".to_string()),
                phone: Some("+1234567890".to_string()),
            };

            let serialized = serde_json::to_string(&contact).unwrap();
            let deserialized: Contact = serde_json::from_str(&serialized).unwrap();

            assert_eq!(contact.jid, deserialized.jid);
            assert_eq!(contact.name, deserialized.name);
            assert_eq!(contact.phone, deserialized.phone);
        }

        #[test]
        fn message_info_serialization() {
            let message = MessageInfo {
                id: "msg_123".to_string(),
                chat: "test@s.whatsapp.net".to_string(),
                sender: "sender@s.whatsapp.net".to_string(),
                timestamp: 1234567890,
                message_type: "text".to_string(),
                content: "Hello, World!".to_string(),
            };

            let serialized = serde_json::to_string(&message).unwrap();
            let deserialized: MessageInfo = serde_json::from_str(&serialized).unwrap();

            assert_eq!(message.id, deserialized.id);
            assert_eq!(message.chat, deserialized.chat);
            assert_eq!(message.sender, deserialized.sender);
            assert_eq!(message.timestamp, deserialized.timestamp);
            assert_eq!(message.message_type, deserialized.message_type);
            assert_eq!(message.content, deserialized.content);
        }

        #[test]
        fn group_info_serialization() {
            let participant = Contact {
                jid: "user@s.whatsapp.net".to_string(),
                name: Some("User Name".to_string()),
                phone: Some("+1234567890".to_string()),
            };

            let group = GroupInfo {
                jid: "group@g.us".to_string(),
                name: "Test Group".to_string(),
                description: Some("A test group".to_string()),
                participants: vec![participant.clone()],
            };

            let serialized = serde_json::to_string(&group).unwrap();
            let deserialized: GroupInfo = serde_json::from_str(&serialized).unwrap();

            assert_eq!(group.jid, deserialized.jid);
            assert_eq!(group.name, deserialized.name);
            assert_eq!(group.description, deserialized.description);
            assert_eq!(group.participants.len(), deserialized.participants.len());
            assert_eq!(group.participants[0].jid, deserialized.participants[0].jid);
        }

        #[test]
        fn contacts_json_parsing() {
            let json = r#"[
                {
                    "jid": "test1@s.whatsapp.net",
                    "name": "Contact 1",
                    "phone": "+1234567890"
                },
                {
                    "jid": "test2@s.whatsapp.net", 
                    "name": "Contact 2",
                    "phone": "+0987654321"
                }
            ]"#;

            let contacts: Vec<Contact> = serde_json::from_str(json).unwrap();
            assert_eq!(contacts.len(), 2);
            assert_eq!(contacts[0].jid, "test1@s.whatsapp.net");
            assert_eq!(contacts[1].jid, "test2@s.whatsapp.net");
        }

        #[test]
        fn messages_json_parsing() {
            let json = r#"[
                {
                    "id": "msg_1",
                    "chat": "test@s.whatsapp.net",
                    "sender": "sender@s.whatsapp.net",
                    "timestamp": 1234567890,
                    "message_type": "text",
                    "content": "Test message"
                }
            ]"#;

            let messages: Vec<MessageInfo> = serde_json::from_str(json).unwrap();
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].id, "msg_1");
            assert_eq!(messages[0].content, "Test message");
        }

        #[test]
        fn error_handling_invalid_json() {
            let invalid_json = r#"{"invalid": "json"#;
            let result: Result<Vec<Contact>, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err());
        }

        #[test]
        fn jid_validation_patterns() {
            let valid_jids = vec![
                "1234567890@s.whatsapp.net",
                "group123@g.us",
                "1234567890-5678901234@g.us",
            ];

            for jid in valid_jids {
                let contact = Contact {
                    jid: jid.to_string(),
                    name: None,
                    phone: None,
                };

                let serialized = serde_json::to_string(&contact).unwrap();
                let deserialized: Contact = serde_json::from_str(&serialized).unwrap();
                assert_eq!(contact.jid, deserialized.jid);
            }
        }

        #[test]
        fn whatsapp_bot_traits() {
            fn assert_send<T: Send>() {}
            fn assert_sync<T: Sync>() {}
            fn assert_debug<T: std::fmt::Debug>() {}

            assert_send::<WhatsAppBot>();
            assert_sync::<WhatsAppBot>();
            assert_debug::<WhatsAppBot>();
        }

        #[test]
        fn default_implementation() {
            // With mocks enabled, this should succeed
            let result = std::panic::catch_unwind(WhatsAppBot::default);
            // In test environment with mocks, this should succeed
            assert!(result.is_ok());
        }

        #[test]
        fn error_scenarios() {
            // Test invalid JSON scenarios
            let invalid_json = r#"{"invalid": "json structure"#;
            let result: Result<Vec<Contact>, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err());

            // Test empty responses
            let empty_contacts: Result<Vec<Contact>, _> = serde_json::from_str("[]");
            assert!(empty_contacts.is_ok());
            assert_eq!(empty_contacts.unwrap().len(), 0);
        }

        #[test]
        fn jid_formats() {
            // Test different valid JID formats
            let test_cases = vec![
                ("1234567890@s.whatsapp.net", true),  // Individual user
                ("group123@g.us", true),              // Group
                ("1234567890-5678901234@g.us", true), // Group with timestamp
                ("status@broadcast", false),          // Invalid format
                ("", false),                          // Empty JID
            ];

            for (jid, should_be_valid) in test_cases {
                let contact = Contact {
                    jid: jid.to_string(),
                    name: None,
                    phone: None,
                };

                let json_result = serde_json::to_string(&contact);
                if should_be_valid {
                    assert!(json_result.is_ok(), "JID '{jid}' should be valid");
                    if let Ok(json) = json_result {
                        let deserialize_result: Result<Contact, _> = serde_json::from_str(&json);
                        assert!(
                            deserialize_result.is_ok(),
                            "JID '{jid}' should deserialize correctly"
                        );
                    }
                }
                // Note: We don't test invalid cases because serde_json doesn't validate JID format
            }
        }
    }

    // =============================================================================
    // INTEGRATION TESTS - Testing async operations with mock FFI
    // =============================================================================
    mod integration {
        use super::*;
        use tempfile::tempdir;

        #[tokio::test]
        async fn connect_operation() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let result = bot.connect().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn disconnect_operation() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let result = bot.disconnect().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn connection_status_check() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let status = bot.get_connection_status().await.unwrap();
            assert_eq!(status, ConnectionStatus::Disconnected); // Mock returns disconnected by default
        }

        #[tokio::test]
        async fn connection_status_boolean_check() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let connected = bot.is_connected().await.unwrap();
            assert!(!connected); // Mock returns disconnected by default
        }

        #[tokio::test]
        async fn qr_code_generation() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let qr_code = bot.get_qr_code().await.unwrap();
            assert!(qr_code.contains("MOCK_QR_CODE_FOR_TESTING"));
            assert!(qr_code.starts_with("https://wa.me/qr/"));
        }

        #[tokio::test]
        async fn text_message_sending() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let message_id = bot
                .send_message("test@s.whatsapp.net", "Hello, World!")
                .await
                .unwrap();
            assert_eq!(message_id, "msg_mock_123");
        }

        #[tokio::test]
        async fn image_message_sending() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let message_id = bot
                .send_image(
                    "test@s.whatsapp.net",
                    "/path/to/image.jpg",
                    Some("Test caption"),
                )
                .await
                .unwrap();
            assert_eq!(message_id, "msg_mock_image_456");
        }

        #[tokio::test]
        async fn image_message_sending_no_caption() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let message_id = bot
                .send_image("test@s.whatsapp.net", "/path/to/image.jpg", None)
                .await
                .unwrap();
            assert_eq!(message_id, "msg_mock_image_456");
        }

        #[tokio::test]
        async fn contacts_retrieval() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let contacts = bot.get_contacts().await.unwrap();

            assert_eq!(contacts.len(), 2);
            assert_eq!(contacts[0].jid, "test1@s.whatsapp.net");
            assert_eq!(contacts[0].name, Some("Mock Contact 1".to_string()));
            assert_eq!(contacts[0].phone, Some("+1234567890".to_string()));

            assert_eq!(contacts[1].jid, "test2@s.whatsapp.net");
            assert_eq!(contacts[1].name, Some("Mock Contact 2".to_string()));
            assert_eq!(contacts[1].phone, Some("+0987654321".to_string()));
        }

        #[tokio::test]
        async fn groups_retrieval() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let groups = bot.get_groups().await.unwrap();

            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].jid, "mockgroup@g.us");
            assert_eq!(groups[0].name, "Mock Test Group");
            assert_eq!(
                groups[0].description,
                Some("A mock group for testing".to_string())
            );
            assert_eq!(groups[0].participants.len(), 1);
            assert_eq!(groups[0].participants[0].jid, "test1@s.whatsapp.net");
        }

        #[tokio::test]
        async fn recent_messages_retrieval() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let messages = bot
                .get_recent_messages("test@s.whatsapp.net", 10)
                .await
                .unwrap();

            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].id, "mock_msg_1");
            assert_eq!(messages[0].chat, "test@s.whatsapp.net");
            assert_eq!(messages[0].sender, "sender@s.whatsapp.net");
            assert_eq!(messages[0].message_type, "text");
            assert_eq!(messages[0].content, "Mock message content");
        }

        #[tokio::test]
        async fn group_creation() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let participants = vec!["user1@s.whatsapp.net", "user2@s.whatsapp.net"];
            let group = bot
                .create_group("New Test Group", &participants)
                .await
                .unwrap();

            assert_eq!(group.jid, "newmockgroup@g.us");
            assert_eq!(group.name, "New Mock Group");
            assert_eq!(group.description, None);
        }

        #[tokio::test]
        async fn group_joining() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let group = bot
                .join_group("https://chat.whatsapp.com/invite/123")
                .await
                .unwrap();

            assert_eq!(group.jid, "joinedmockgroup@g.us");
            assert_eq!(group.name, "Joined Mock Group");
            assert_eq!(
                group.description,
                Some("Joined via invite link".to_string())
            );
        }

        #[tokio::test]
        async fn message_read_marking() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();
            let result = bot.mark_read("test@s.whatsapp.net", "msg_123").await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn concurrent_operations() {
            let temp_dir = tempdir().unwrap();
            let bot =
                WhatsAppBot::new(temp_dir.path().join("whatsapp.db").to_str().unwrap()).unwrap();

            // Test that multiple async operations can run concurrently
            let (status, qr_code, contacts) = tokio::join!(
                bot.get_connection_status(),
                bot.get_qr_code(),
                bot.get_contacts()
            );

            assert!(status.is_ok());
            assert!(qr_code.is_ok());
            assert!(contacts.is_ok());

            assert_eq!(status.unwrap(), ConnectionStatus::Disconnected);
            assert!(qr_code.unwrap().contains("MOCK_QR_CODE_FOR_TESTING"));
            assert_eq!(contacts.unwrap().len(), 2);
        }
    }

    // =============================================================================
    // END-TO-END TESTS - Real WhatsApp connections (ignored by default)
    // =============================================================================
    mod e2e {
        use super::*;
        use std::io::{self, Write};

        /// Display a QR code in scannable ASCII format
        fn display_qr_code(qr_data: &str) {
            println!("\n┌─────────────────────────────────────────────────────────────┐");
            println!("│                     📱 WHATSAPP QR CODE                      │");
            println!("├─────────────────────────────────────────────────────────────┤");
            println!("│                                                             │");
            println!("│  ⚠️  IMPORTANT: This QR code connects to YOUR WhatsApp!     │");
            println!("│                                                             │");
            println!("│  📱 TO SCAN:                                                │");
            println!("│  1. Open WhatsApp on your phone                            │");
            println!("│  2. Go to Settings > Linked Devices                        │");
            println!("│  3. Tap 'Link a Device'                                     │");
            println!("│  4. Scan this QR code with your phone's camera             │");
            println!("│                                                             │");
            println!("├─────────────────────────────────────────────────────────────┤");
            println!("│                        QR CODE DATA:                       │");
            println!("├─────────────────────────────────────────────────────────────┤");

            // Display the QR code in a more readable format
            if qr_data.len() > 100 {
                // For long QR codes, display in chunks with line breaks for better readability
                let chars: Vec<char> = qr_data.chars().collect();
                let chunk_size = 55; // Fit within the box width

                for chunk in chars.chunks(chunk_size) {
                    let line: String = chunk.iter().collect();
                    println!("│ {line:55} │");
                }
            } else {
                // For shorter codes, display as-is
                println!("│ {qr_data:55} │");
            }

            println!("├─────────────────────────────────────────────────────────────┤");
            println!("│  ⏰ QR CODE EXPIRES: This code expires in 20 seconds        │");
            println!("│  🔄 REFRESH: Re-run test if code expires                    │");
            println!("│  ✅ SUCCESS: Your phone will show 'Device linked' message   │");
            println!("│                                                             │");
            println!("│  💡 TIP: Make sure you have good lighting for scanning     │");
            println!("│  📶 NETWORK: Ensure your phone has internet connection     │");
            println!("└─────────────────────────────────────────────────────────────┘");
            println!();

            // Add visual separator and clear call to action
            println!("🎯 ACTION REQUIRED:");
            println!("   📱 Scan the QR code above with your WhatsApp mobile app");
            println!("   ⏳ You have about 20 seconds before the code expires");
            println!("   🔄 If it expires, just restart this test for a new code");
            println!();
        }

        fn wait_for_user_confirmation(message: &str) {
            println!("📋 {message}");
            println!("   ⏸️  Press Enter when ready to continue...");
            let mut input = String::new();
            io::stdin().read_line(&mut input).unwrap();
        }

        #[tokio::test]
        #[ignore = "requires real WhatsApp connection and user interaction"]
        async fn full_authentication_flow() {
            println!("\n🔥 E2E Test: Full Authentication Flow");
            println!("=====================================");

            // Check if we're using real FFI or mocks
            #[cfg(test)]
            {
                println!("ℹ️  Running in MOCK MODE (simulated QR codes)");
                println!("   📝 Note: This will show 'https://wa.me/qr/MOCK_QR_CODE_FOR_TESTING'");
                println!("   🎯 For real QR codes, build without test mode");
                println!();
            }

            #[cfg(not(test))]
            {
                println!("🚀 Running in REAL MODE (actual WhatsApp servers)");
                println!("   📱 This will generate a real scannable QR code");
                println!("   ⚠️  Make sure you have a stable internet connection");
                println!("");
            }

            println!("⚠️  This test requires:");
            println!("   • Real phone number");
            println!("   • WhatsApp mobile app");
            println!("   • User interaction for QR scanning");
            println!("   • Internet connection");
            println!("   • Good lighting for QR code scanning");
            println!("   • Stable network connection");

            wait_for_user_confirmation("Have your WhatsApp mobile app ready for QR scanning");

            // Step 1: Create bot
            println!("\n1️⃣ Creating WhatsApp bot...");
            let bot = WhatsAppBot::new("whatsapp.db").expect("Failed to create WhatsApp bot");
            println!("   ✅ Bot created successfully");

            // Step 2: Get QR code for authentication
            println!("\n2️⃣ Getting QR code for authentication...");
            println!("   🔄 Requesting QR code from WhatsApp servers...");

            match bot.get_qr_code().await {
                Ok(qr_code) => {
                    if !qr_code.is_empty() {
                        // Check if this is a mock QR code
                        if qr_code.contains("MOCK_QR_CODE_FOR_TESTING") {
                            println!("   ⚠️  MOCK QR Code received (not scannable):");
                            println!("   📱 This is a simulated QR code for testing purposes");
                            println!("   🔄 To get real QR codes, run: cargo test --package whatsmeow tests::e2e::full_authentication_flow --release -- --ignored --nocapture");
                            println!();
                        } else {
                            println!("   ✅ Real QR Code received from WhatsApp servers!");
                        }

                        // Display the QR code in a scannable format
                        display_qr_code(&qr_code);

                        if qr_code.contains("MOCK_QR_CODE_FOR_TESTING") {
                            println!("🚨 MOCK MODE NOTICE:");
                            println!("   📱 The QR code above is simulated and cannot be scanned");
                            println!("   🔧 This test demonstrates the E2E flow with mock data");
                            println!(
                                "   ✅ To get real QR codes, run in release mode without test"
                            );
                            println!();
                        } else {
                            println!("🚀 NEXT STEPS:");
                            println!(
                                "   1. Use your phone's WhatsApp app to scan the QR code above"
                            );
                            println!("   2. Follow the in-app instructions to link this device");
                            println!("   3. Wait for 'Device linked' confirmation on your phone");
                        }

                        wait_for_user_confirmation(
                            "After scanning the QR code and seeing 'Device linked' on your phone",
                        );
                    } else {
                        println!("   ℹ️  No QR code needed (already authenticated)");
                        println!("   📱 Your device is already linked to WhatsApp");
                    }
                }
                Err(e) => {
                    println!("   ⚠️  QR code generation failed: {e}");
                    println!("   💡 This might be normal if already authenticated");
                    println!("   🔄 Try disconnecting and reconnecting if issues persist");
                }
            }

            // Step 3: Wait for connection and check status
            println!("\n3️⃣ Waiting for WhatsApp connection...");

            // Try connecting
            match bot.connect().await {
                Ok(_) => println!("   ✅ Connection attempt initiated"),
                Err(e) => println!("   ⚠️  Connection failed: {e}"),
            }

            // Check connection status multiple times with better feedback
            println!("   🔄 Verifying connection status...");
            let mut connected = false;

            for attempt in 1..=10 {
                println!("   📡 Connection check {attempt}/10...");

                match bot.get_connection_status().await {
                    Ok(status) => match status {
                        ConnectionStatus::Connected => {
                            println!("   🎉 SUCCESS: Connected to WhatsApp!");
                            println!("   📱 Your device is now linked and ready to use");
                            connected = true;
                            break;
                        }
                        ConnectionStatus::Connecting => {
                            println!("   🔄 Status: Connecting... (please wait)");
                        }
                        ConnectionStatus::Disconnected => {
                            println!("   📴 Status: Disconnected");
                            if attempt > 5 {
                                println!(
                                    "   💡 Try scanning the QR code again if connection fails"
                                );
                            }
                        }
                        ConnectionStatus::LoggedOut => {
                            println!("   🚪 Status: Logged out - QR code scan may be required");
                        }
                    },
                    Err(e) => println!("   ❌ Status check error: {e}"),
                }

                if attempt < 10 {
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
            }

            // Final status summary
            if connected {
                println!("\n✅ Authentication flow completed successfully!");
                println!("   🎯 Result: WhatsApp connection established");
                println!("   📱 Device: Successfully linked to your WhatsApp account");
                println!("   🔗 Status: Ready for messaging and other operations");
                println!("   🚀 Next: You can now run other E2E tests");
            } else {
                println!("\n⚠️ Authentication flow completed with warnings");
                println!("   📋 Check the status messages above for details");
                println!("   🔄 You may need to re-run this test with a fresh QR code");
                println!("   💡 Ensure your phone has a stable internet connection");
            }
        }

        #[tokio::test]
        #[ignore = "requires real WhatsApp connection and user interaction"]
        async fn send_real_message() {
            println!("\n🔧 E2E Test: Send Real Message");
            println!("==============================");
            println!("⚠️  This test requires:");
            println!("   • Authenticated WhatsApp connection");
            println!("   • Valid WhatsApp contact to message");
            println!("   • User confirmation for sending");

            let bot = WhatsAppBot::new("whatsapp.db").expect("Failed to create WhatsApp bot");

            // Check if we're connected
            println!("\n1️⃣ Checking connection status...");
            match bot.get_connection_status().await {
                Ok(ConnectionStatus::Connected) => {
                    println!("   ✅ Connected to WhatsApp");
                }
                Ok(status) => {
                    println!("   ❌ Not connected. Status: {status:?}");
                    println!("   💡 Run the authentication flow test first");
                    return;
                }
                Err(e) => {
                    println!("   ❌ Failed to check status: {e}");
                    return;
                }
            }

            // Get recipient from user
            print!("\n2️⃣ Enter recipient phone number (format: +1234567890@s.whatsapp.net): ");
            io::stdout().flush().unwrap();
            let mut recipient = String::new();
            io::stdin().read_line(&mut recipient).unwrap();
            let recipient = recipient.trim();

            if recipient.is_empty() || !recipient.contains("@s.whatsapp.net") {
                println!("   ❌ Invalid recipient format");
                return;
            }

            let test_message = format!(
                "🤖 Test message from Rust WhatsApp bot at {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            );

            println!("\n   📝 Message to send: {test_message}");
            print!("   ❓ Send this message? (y/N): ");
            io::stdout().flush().unwrap();
            let mut confirm = String::new();
            io::stdin().read_line(&mut confirm).unwrap();

            if confirm.trim().to_lowercase() != "y" && confirm.trim().to_lowercase() != "yes" {
                println!("   ❌ Message sending cancelled by user");
                return;
            }

            // Send message
            println!("\n3️⃣ Sending message...");
            match bot.send_message(recipient, &test_message).await {
                Ok(message_id) => {
                    println!("   ✅ Message sent successfully!");
                    println!("   📧 Message ID: {message_id}");
                }
                Err(e) => {
                    println!("   ❌ Failed to send message: {e}");
                }
            }

            println!("\n✅ Real message test completed");
        }
    }
}
