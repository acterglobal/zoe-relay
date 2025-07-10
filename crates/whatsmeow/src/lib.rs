use std::ffi::{CStr, CString};
use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Connection status for WhatsApp client
#[derive(Debug, Clone, Serialize, Deserialize)]
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
                go_free((*response).status);
            }
            if !(*response).error.is_null() {
                go_free((*response).error);
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
                go_free((*response).data);
            }
            if !(*response).error.is_null() {
                go_free((*response).error);
            }
        } else {
            let _ = tx.send(Err(anyhow!("Null response from Go")));
        }
    }
}

/// Main WhatsApp client wrapper
pub struct WhatsAppBot {
    // Empty struct for now, will be extended as needed
}

impl WhatsAppBot {
    /// Create a new WhatsApp bot instance
    pub fn new() -> Result<Self> {
        let initialized = unsafe { whatsmeow_init() };
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
            whatsmeow_connect_async(handle);
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
            whatsmeow_disconnect_async(handle);
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
            whatsmeow_get_status_async(handle);
        }
        
        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }
    
    /// Get the QR code for authentication
    pub async fn get_qr_code(&self) -> Result<String> {
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;
        
        unsafe {
            whatsmeow_get_qr_async(handle);
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
            whatsmeow_send_message_async(chat_jid.as_ptr(), text.as_ptr(), handle);
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
            whatsmeow_send_image_async(chat_jid.as_ptr(), image_path_c.as_ptr(), caption_c.as_ptr(), handle);
        }
        
        rx.await
            .map_err(|_| anyhow!("Failed to receive response from Go"))?
    }
    
    /// Get all contacts
    pub async fn get_contacts(&self) -> Result<Vec<Contact>> {
        let (tx, rx) = oneshot::channel::<Result<String>>();
        let handle = Box::into_raw(Box::new(tx)) as usize;
        
        unsafe {
            whatsmeow_get_contacts_async(handle);
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
            whatsmeow_get_groups_async(handle);
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
            whatsmeow_get_messages_async(chat_jid_c.as_ptr(), limit, handle);
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
            whatsmeow_create_group_async(name_c.as_ptr(), participants_c.as_ptr(), handle);
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
            whatsmeow_join_group_async(invite_link_c.as_ptr(), handle);
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
            whatsmeow_mark_read_async(chat_jid_c.as_ptr(), message_id_c.as_ptr(), handle);
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

    #[tokio::test]
    async fn test_bot_creation() {
        let bot = WhatsAppBot::new();
        assert!(bot.is_ok());
    }
}
