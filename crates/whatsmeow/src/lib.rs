use std::ffi::{CStr, CString};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

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
    fn whatsmeow_init() -> bool;
    fn whatsmeow_connect_async(callback_handle: usize);
    fn whatsmeow_disconnect_async(callback_handle: usize);
    fn whatsmeow_get_status_async(callback_handle: usize);
    fn whatsmeow_get_qr_async(callback_handle: usize);
    fn whatsmeow_send_message_async(chat_jid: *const libc::c_char, text: *const libc::c_char, callback_handle: usize);
    fn whatsmeow_send_image_async(chat_jid: *const libc::c_char, image_path: *const libc::c_char, caption: *const libc::c_char, callback_handle: usize);
    fn whatsmeow_get_contacts_async(callback_handle: usize);
    fn whatsmeow_get_groups_async(callback_handle: usize);
    fn whatsmeow_get_messages_async(chat_jid: *const libc::c_char, limit: u32, callback_handle: usize);
    fn whatsmeow_create_group_async(name: *const libc::c_char, participants: *const libc::c_char, callback_handle: usize);
    fn whatsmeow_join_group_async(invite_link: *const libc::c_char, callback_handle: usize);
    fn whatsmeow_mark_read_async(chat_jid: *const libc::c_char, message_id: *const libc::c_char, callback_handle: usize);
    fn go_free(ptr: *mut libc::c_char);
}

// Mock implementations for testing
#[cfg(test)]
mod mock_ffi {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    
    static MOCK_INIT_SUCCESS: AtomicBool = AtomicBool::new(true);
    static MOCK_CONNECTION_STATUS: AtomicBool = AtomicBool::new(false);
    
    pub fn set_mock_init_success(success: bool) {
        MOCK_INIT_SUCCESS.store(success, Ordering::SeqCst);
    }
    
    pub fn set_mock_connection_status(connected: bool) {
        MOCK_CONNECTION_STATUS.store(connected, Ordering::SeqCst);
    }
    
    pub unsafe fn whatsmeow_init() -> bool {
        MOCK_INIT_SUCCESS.load(Ordering::SeqCst)
    }
    
    pub unsafe fn whatsmeow_connect_async(callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<ConnectionStatus>>);
        let _ = tx.send(Ok(ConnectionStatus::Connected));
    }
    
    pub unsafe fn whatsmeow_disconnect_async(callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<ConnectionStatus>>);
        let _ = tx.send(Ok(ConnectionStatus::Disconnected));
    }
    
    pub unsafe fn whatsmeow_get_status_async(callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<ConnectionStatus>>);
        let status = if MOCK_CONNECTION_STATUS.load(Ordering::SeqCst) {
            ConnectionStatus::Connected
        } else {
            ConnectionStatus::Disconnected
        };
        let _ = tx.send(Ok(status));
    }
    
    pub unsafe fn whatsmeow_get_qr_async(callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let qr_code = "https://wa.me/qr/MOCK_QR_CODE_FOR_TESTING".to_string();
        let _ = tx.send(Ok(qr_code));
    }
    
    pub unsafe fn whatsmeow_send_message_async(_chat_jid: *const libc::c_char, _text: *const libc::c_char, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let _ = tx.send(Ok("msg_mock_123".to_string()));
    }
    
    pub unsafe fn whatsmeow_send_image_async(_chat_jid: *const libc::c_char, _image_path: *const libc::c_char, _caption: *const libc::c_char, callback_handle: usize) {
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
    
    pub unsafe fn whatsmeow_get_messages_async(_chat_jid: *const libc::c_char, _limit: u32, callback_handle: usize) {
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
    
    pub unsafe fn whatsmeow_create_group_async(_name: *const libc::c_char, _participants: *const libc::c_char, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_group = r#"{
            "jid": "newmockgroup@g.us",
            "name": "New Mock Group",
            "description": null,
            "participants": []
        }"#;
        let _ = tx.send(Ok(mock_group.to_string()));
    }
    
    pub unsafe fn whatsmeow_join_group_async(_invite_link: *const libc::c_char, callback_handle: usize) {
        let tx = Box::from_raw(callback_handle as *mut oneshot::Sender<Result<String>>);
        let mock_group = r#"{
            "jid": "joinedmockgroup@g.us",
            "name": "Joined Mock Group",
            "description": "Joined via invite link",
            "participants": []
        }"#;
        let _ = tx.send(Ok(mock_group.to_string()));
    }
    
    pub unsafe fn whatsmeow_mark_read_async(_chat_jid: *const libc::c_char, _message_id: *const libc::c_char, callback_handle: usize) {
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
    use super::*;
    
    pub unsafe fn whatsmeow_init() -> bool {
        super::whatsmeow_init()
    }
    
    pub unsafe fn whatsmeow_connect_async(callback_handle: usize) {
        super::whatsmeow_connect_async(callback_handle)
    }
    
    pub unsafe fn whatsmeow_disconnect_async(callback_handle: usize) {
        super::whatsmeow_disconnect_async(callback_handle)
    }
    
    pub unsafe fn whatsmeow_get_status_async(callback_handle: usize) {
        super::whatsmeow_get_status_async(callback_handle)
    }
    
    pub unsafe fn whatsmeow_get_qr_async(callback_handle: usize) {
        super::whatsmeow_get_qr_async(callback_handle)
    }
    
    pub unsafe fn whatsmeow_send_message_async(chat_jid: *const libc::c_char, text: *const libc::c_char, callback_handle: usize) {
        super::whatsmeow_send_message_async(chat_jid, text, callback_handle)
    }
    
    pub unsafe fn whatsmeow_send_image_async(chat_jid: *const libc::c_char, image_path: *const libc::c_char, caption: *const libc::c_char, callback_handle: usize) {
        super::whatsmeow_send_image_async(chat_jid, image_path, caption, callback_handle)
    }
    
    pub unsafe fn whatsmeow_get_contacts_async(callback_handle: usize) {
        super::whatsmeow_get_contacts_async(callback_handle)
    }
    
    pub unsafe fn whatsmeow_get_groups_async(callback_handle: usize) {
        super::whatsmeow_get_groups_async(callback_handle)
    }
    
    pub unsafe fn whatsmeow_get_messages_async(chat_jid: *const libc::c_char, limit: u32, callback_handle: usize) {
        super::whatsmeow_get_messages_async(chat_jid, limit, callback_handle)
    }
    
    pub unsafe fn whatsmeow_create_group_async(name: *const libc::c_char, participants: *const libc::c_char, callback_handle: usize) {
        super::whatsmeow_create_group_async(name, participants, callback_handle)
    }
    
    pub unsafe fn whatsmeow_join_group_async(invite_link: *const libc::c_char, callback_handle: usize) {
        super::whatsmeow_join_group_async(invite_link, callback_handle)
    }
    
    pub unsafe fn whatsmeow_mark_read_async(chat_jid: *const libc::c_char, message_id: *const libc::c_char, callback_handle: usize) {
        super::whatsmeow_mark_read_async(chat_jid, message_id, callback_handle)
    }
    
    pub unsafe fn go_free(ptr: *mut libc::c_char) {
        super::go_free(ptr)
    }
}

#[cfg(test)]
use mock_ffi as ffi_wrapper;

/// Callback functions that Go can call back to Rust
#[unsafe(no_mangle)]
extern "C" fn rust_status_callback(handle: usize, response: *const CStatusResponse) {
    let tx = unsafe { Box::from_raw(handle as *mut oneshot::Sender<Result<ConnectionStatus>>) };
    
    unsafe {
        if !response.is_null() {
            let status_str = if !(*response).status.is_null() {
                CStr::from_ptr((*response).status).to_string_lossy().to_string()
            } else {
                "disconnected".to_string()
            };
            
            let error_str = if !(*response).error.is_null() {
                Some(CStr::from_ptr((*response).error).to_string_lossy().to_string())
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
                CStr::from_ptr((*response).data).to_string_lossy().to_string()
            } else {
                String::new()
            };
            
            let error_str = if !(*response).error.is_null() {
                Some(CStr::from_ptr((*response).error).to_string_lossy().to_string())
            } else {
                None
            };
            
            let result = if (*response).success && error_str.is_none() {
                Ok(data_str)
            } else {
                Err(anyhow!("Go error: {}", error_str.unwrap_or_else(|| "Unknown error".to_string())))
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

/// Main WhatsApp client wrapper
#[derive(Debug)]
pub struct WhatsAppBot {
    // Empty struct for now, will be extended as needed
}

impl WhatsAppBot {
    /// Create a new WhatsApp bot instance
    pub fn new() -> Result<Self> {
        let initialized = unsafe { ffi_wrapper::whatsmeow_init() };
        if !initialized {
            return Err(anyhow!("Failed to initialize WhatsApp client"));
        }
        
        Ok(Self { })
    }
    
    /// Connect and authenticate with WhatsApp
    pub async fn connect(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel::<Result<ConnectionStatus>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;
        
        unsafe {
            ffi_wrapper::whatsmeow_connect_async(handle);
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
            ffi_wrapper::whatsmeow_disconnect_async(handle);
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
            ffi_wrapper::whatsmeow_get_status_async(handle);
        }
        
        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }
    
    /// Get the QR code for authentication
    pub async fn get_qr_code(&self) -> Result<String> {
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;
        
        unsafe {
            ffi_wrapper::whatsmeow_get_qr_async(handle);
        }
        
        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
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
            ffi_wrapper::whatsmeow_send_message_async(chat_jid.as_ptr(), text.as_ptr(), handle);
        }
        
        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }
    
    /// Send an image with optional caption
    pub async fn send_image(&self, to: &str, image_path: &str, caption: Option<&str>) -> Result<String> {
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
            ffi_wrapper::whatsmeow_send_image_async(chat_jid.as_ptr(), image_path_c.as_ptr(), caption_c.as_ptr(), handle);
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
        
        let contacts_json = rx.await
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
        
        let groups_json = rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))??;
        
        let groups: Vec<GroupInfo> = serde_json::from_str(&groups_json)?;
        Ok(groups)
    }
    
    /// Get recent messages from a chat
    pub async fn get_recent_messages(&self, chat_jid: &str, limit: u32) -> Result<Vec<MessageInfo>> {
        let chat_jid_c = CString::new(chat_jid)?;
        
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;
        
        unsafe {
            ffi_wrapper::whatsmeow_get_messages_async(chat_jid_c.as_ptr(), limit, handle);
        }
        
        let messages_json = rx.await
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
            ffi_wrapper::whatsmeow_create_group_async(name_c.as_ptr(), participants_c.as_ptr(), handle);
        }
        
        let group_json = rx.await
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
        
        let group_json = rx.await
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
            ffi_wrapper::whatsmeow_mark_read_async(chat_jid_c.as_ptr(), message_id_c.as_ptr(), handle);
        }
        
        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
            .map(|_| ())
    }
}

impl Default for WhatsAppBot {
    fn default() -> Self {
        Self::new().expect("Failed to create WhatsApp bot")
    }
}

// Export the main types for use by other crates
pub use WhatsAppBot as Client;

unsafe impl Send for WhatsAppBot {}
unsafe impl Sync for WhatsAppBot {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    // =============================================================================
    // UNIT TESTS - Testing data models, serialization, and Rust-side logic
    // =============================================================================
    mod unit {
        use super::*;

        #[test]
        fn bot_creation() {
            let bot = WhatsAppBot::new();
            assert!(bot.is_ok());
        }

        #[test]
        fn connection_status_from_string() {
            assert_eq!(ConnectionStatus::from("connected"), ConnectionStatus::Connected);
            assert_eq!(ConnectionStatus::from("disconnected"), ConnectionStatus::Disconnected);
            assert_eq!(ConnectionStatus::from("connecting"), ConnectionStatus::Connecting);
            assert_eq!(ConnectionStatus::from("logged_out"), ConnectionStatus::LoggedOut);
            assert_eq!(ConnectionStatus::from("unknown"), ConnectionStatus::Disconnected); // Default
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
            let result = std::panic::catch_unwind(|| {
                WhatsAppBot::default()
            });
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
                    assert!(json_result.is_ok(), "JID '{}' should be valid", jid);
                    if let Ok(json) = json_result {
                        let deserialize_result: Result<Contact, _> = serde_json::from_str(&json);
                        assert!(deserialize_result.is_ok(), "JID '{}' should deserialize correctly", jid);
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

        #[tokio::test]
        async fn connect_operation() {
            let bot = WhatsAppBot::new().unwrap();
            let result = bot.connect().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn disconnect_operation() {
            let bot = WhatsAppBot::new().unwrap();
            let result = bot.disconnect().await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn connection_status_check() {
            let bot = WhatsAppBot::new().unwrap();
            let status = bot.get_connection_status().await.unwrap();
            assert_eq!(status, ConnectionStatus::Disconnected); // Mock returns disconnected by default
        }

        #[tokio::test]
        async fn connection_status_boolean_check() {
            let bot = WhatsAppBot::new().unwrap();
            let connected = bot.is_connected().await.unwrap();
            assert!(!connected); // Mock returns disconnected by default
        }

        #[tokio::test]
        async fn qr_code_generation() {
            let bot = WhatsAppBot::new().unwrap();
            let qr_code = bot.get_qr_code().await.unwrap();
            assert!(qr_code.contains("MOCK_QR_CODE_FOR_TESTING"));
            assert!(qr_code.starts_with("https://wa.me/qr/"));
        }

        #[tokio::test]
        async fn text_message_sending() {
            let bot = WhatsAppBot::new().unwrap();
            let message_id = bot.send_message("test@s.whatsapp.net", "Hello, World!").await.unwrap();
            assert_eq!(message_id, "msg_mock_123");
        }

        #[tokio::test]
        async fn image_message_sending() {
            let bot = WhatsAppBot::new().unwrap();
            let message_id = bot.send_image("test@s.whatsapp.net", "/path/to/image.jpg", Some("Test caption")).await.unwrap();
            assert_eq!(message_id, "msg_mock_image_456");
        }

        #[tokio::test]
        async fn image_message_sending_no_caption() {
            let bot = WhatsAppBot::new().unwrap();
            let message_id = bot.send_image("test@s.whatsapp.net", "/path/to/image.jpg", None).await.unwrap();
            assert_eq!(message_id, "msg_mock_image_456");
        }

        #[tokio::test]
        async fn contacts_retrieval() {
            let bot = WhatsAppBot::new().unwrap();
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
            let bot = WhatsAppBot::new().unwrap();
            let groups = bot.get_groups().await.unwrap();
            
            assert_eq!(groups.len(), 1);
            assert_eq!(groups[0].jid, "mockgroup@g.us");
            assert_eq!(groups[0].name, "Mock Test Group");
            assert_eq!(groups[0].description, Some("A mock group for testing".to_string()));
            assert_eq!(groups[0].participants.len(), 1);
            assert_eq!(groups[0].participants[0].jid, "test1@s.whatsapp.net");
        }

        #[tokio::test]
        async fn recent_messages_retrieval() {
            let bot = WhatsAppBot::new().unwrap();
            let messages = bot.get_recent_messages("test@s.whatsapp.net", 10).await.unwrap();
            
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].id, "mock_msg_1");
            assert_eq!(messages[0].chat, "test@s.whatsapp.net");
            assert_eq!(messages[0].sender, "sender@s.whatsapp.net");
            assert_eq!(messages[0].message_type, "text");
            assert_eq!(messages[0].content, "Mock message content");
        }

        #[tokio::test]
        async fn group_creation() {
            let bot = WhatsAppBot::new().unwrap();
            let participants = vec!["user1@s.whatsapp.net", "user2@s.whatsapp.net"];
            let group = bot.create_group("New Test Group", &participants).await.unwrap();
            
            assert_eq!(group.jid, "newmockgroup@g.us");
            assert_eq!(group.name, "New Mock Group");
            assert_eq!(group.description, None);
        }

        #[tokio::test]
        async fn group_joining() {
            let bot = WhatsAppBot::new().unwrap();
            let group = bot.join_group("https://chat.whatsapp.com/invite/123").await.unwrap();
            
            assert_eq!(group.jid, "joinedmockgroup@g.us");
            assert_eq!(group.name, "Joined Mock Group");
            assert_eq!(group.description, Some("Joined via invite link".to_string()));
        }

        #[tokio::test]
        async fn message_read_marking() {
            let bot = WhatsAppBot::new().unwrap();
            let result = bot.mark_read("test@s.whatsapp.net", "msg_123").await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn concurrent_operations() {
            let bot = WhatsAppBot::new().unwrap();
            
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
}
