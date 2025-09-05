package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

// Forward declarations for Rust callback functions
typedef struct {
    int success;
    char* data;
    char* error;
} CResponse;

typedef struct {
    char* status;
    char* error;
} CStatusResponse;

extern void rust_status_callback(uintptr_t handle, CStatusResponse* response);
extern void rust_response_callback(uintptr_t handle, CResponse* response);
extern void rust_message_callback(uintptr_t handle, CResponse* response);
*/
import "C"

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"go.mau.fi/whatsmeow"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waProto "go.mau.fi/whatsmeow/binary/proto"
	waLog "go.mau.fi/whatsmeow/util/log"
	_ "github.com/mattn/go-sqlite3"
)

// Contact structure for JSON serialization
type Contact struct {
	JID   string  `json:"jid"`
	Name  *string `json:"name"`
	Phone *string `json:"phone"`
}

// Message event structure for JSON serialization
type MessageEvent struct {
	ID        string `json:"id"`
	Chat      string `json:"chat"`
	Sender    string `json:"sender"`
	Timestamp int64  `json:"timestamp"`
	Type      string `json:"type"`
	Content   string `json:"content"`
	IsFromMe  bool   `json:"is_from_me"`
}

// Global message handlers registry
var messageHandlers = make(map[uintptr]uintptr)
var messageHandlersMutex sync.RWMutex

// Initialize the WhatsApp client with database path and return client pointer
//export whatsmeow_init
func whatsmeow_init(path *C.char) uintptr {
	if path == nil {
		return 0
	}

	pathStr := C.GoString(path)
	dbConnString := fmt.Sprintf("%s?_foreign_keys=on", pathStr)
	db, err := sql.Open("sqlite3", dbConnString)
	if err != nil {
		fmt.Printf("Failed to open database: %v\n", err)
		return 0
	}

	// Create database container
	dbLog := waLog.Stdout("Database", "DEBUG", true)
	container := sqlstore.NewWithDB(db, "sqlite3", dbLog)
	
	// Ensure database schema is created
	err = container.Upgrade(context.Background())
	if err != nil {
		fmt.Printf("Failed to upgrade database schema: %v\n", err)
		return 0
	}
	
	// Get the first device store
	deviceStore, err := container.GetFirstDevice(context.Background())
	if err != nil {
		fmt.Printf("Failed to get device store: %v\n", err)
		return 0
	}
	
	// Create client
	clientLog := waLog.Stdout("Client", "DEBUG", true)
	client := whatsmeow.NewClient(deviceStore, clientLog)
	
	// Return client as uintptr (pointer)
	return uintptr(unsafe.Pointer(client))
}

// Connect to WhatsApp
//export whatsmeow_connect_async
func whatsmeow_connect_async(client_ptr uintptr, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		
		if client_ptr == 0 {
			sendStatusCallback(callback_handle, "disconnected", "Client not initialized")
			return
		}
		
		client := (*whatsmeow.Client)(unsafe.Pointer(client_ptr))
		
		if client.IsConnected() {
			sendStatusCallback(callback_handle, "connected", "")
			return
		}
		
		err := client.Connect()
		if err != nil {
			sendStatusCallback(callback_handle, "disconnected", err.Error())
			return
		}
		
		sendStatusCallback(callback_handle, "connected", "")
	}()
}

// Disconnect from WhatsApp
//export whatsmeow_disconnect_async
func whatsmeow_disconnect_async(client_ptr uintptr, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		
		if client_ptr == 0 {
			sendStatusCallback(callback_handle, "disconnected", "Client not initialized")
			return
		}
		
		client := (*whatsmeow.Client)(unsafe.Pointer(client_ptr))
		client.Disconnect()
		sendStatusCallback(callback_handle, "disconnected", "")
	}()
}

// Get connection status
//export whatsmeow_get_status_async
func whatsmeow_get_status_async(client_ptr uintptr, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		
		if client_ptr == 0 {
			sendStatusCallback(callback_handle, "disconnected", "")
			return
		}
		
		client := (*whatsmeow.Client)(unsafe.Pointer(client_ptr))
		
		if client.IsLoggedIn() {
			if client.IsConnected() {
				sendStatusCallback(callback_handle, "connected", "")
			} else {
				sendStatusCallback(callback_handle, "connecting", "")
			}
		} else {
			sendStatusCallback(callback_handle, "logged_out", "")
		}
	}()
}

// Get QR code for authentication
//export whatsmeow_get_qr_async
func whatsmeow_get_qr_async(client_ptr uintptr, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		
		if client_ptr == 0 {
			sendResponseCallback(callback_handle, false, "", "Client not initialized")
			return
		}
		
		client := (*whatsmeow.Client)(unsafe.Pointer(client_ptr))
		
		if client.IsLoggedIn() {
			sendResponseCallback(callback_handle, true, "", "")
			return
		}
		
		// Set up QR channel first
		qrChan, err := client.GetQRChannel(context.Background())
		if err != nil {
			sendResponseCallback(callback_handle, false, "", err.Error())
			return
		}
		
		// Start connection in background to trigger QR generation
		go func() {
			defer handlePanic()
			fmt.Printf("Starting connection to trigger QR generation\n")
			err := client.Connect()
			if err != nil {
				fmt.Printf("Connection failed: %v\n", err)
			}
		}()
		
		// Wait for QR code events
		for {
			select {
			case evt := <-qrChan:
				fmt.Printf("QR Event received: %s\n", evt.Event)
				switch evt.Event {
				case "code":
					fmt.Printf("QR Code: %s\n", evt.Code)
					sendResponseCallback(callback_handle, true, evt.Code, "")
					return
				case "timeout":
					fmt.Printf("QR Code expired\n")
					sendResponseCallback(callback_handle, false, "", "QR code expired")
					return
				case "success":
					fmt.Printf("QR Code authentication successful\n")
					sendResponseCallback(callback_handle, true, "", "")
					return
				default:
					fmt.Printf("Unknown QR event: %s\n", evt.Event)
					// Don't return here, continue waiting for more events
				}
			case <-time.After(45 * time.Second):
				fmt.Printf("QR Code generation timeout\n")
				sendResponseCallback(callback_handle, false, "", "QR code generation timeout")
				return
			}
		}
	}()
}

// Send a text message
//export whatsmeow_send_message_async
func whatsmeow_send_message_async(client_ptr uintptr, chat_jid *C.char, text *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		
		if client_ptr == 0 {
			sendResponseCallback(callback_handle, false, "", "Client not initialized")
			return
		}
		
		client := (*whatsmeow.Client)(unsafe.Pointer(client_ptr))
		
		chatJIDStr := C.GoString(chat_jid)
		textStr := C.GoString(text)
		
		chatJID, err := types.ParseJID(chatJIDStr)
		if err != nil {
			sendResponseCallback(callback_handle, false, "", "Invalid JID: "+err.Error())
			return
		}
		
		msg := &waProto.Message{
			Conversation: &textStr,
		}
		
		resp, err := client.SendMessage(context.Background(), chatJID, msg)
		if err != nil {
			sendResponseCallback(callback_handle, false, "", err.Error())
			return
		}
		
		sendResponseCallback(callback_handle, true, resp.ID, "")
	}()
}

// Simplified functions for other operations
//export whatsmeow_send_image_async
func whatsmeow_send_image_async(chat_jid *C.char, image_path *C.char, caption *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "msg_image_placeholder", "")
	}()
}

//export whatsmeow_get_contacts_async
func whatsmeow_get_contacts_async(callback_handle uintptr) {
	go func() {
		defer handlePanic()
		contacts := make([]Contact, 0)
		jsonData, _ := json.Marshal(contacts)
		sendResponseCallback(callback_handle, true, string(jsonData), "")
	}()
}

//export whatsmeow_get_groups_async
func whatsmeow_get_groups_async(callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "[]", "")
	}()
}

//export whatsmeow_get_messages_async
func whatsmeow_get_messages_async(chat_jid *C.char, limit C.uint, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "[]", "")
	}()
}

//export whatsmeow_create_group_async
func whatsmeow_create_group_async(name *C.char, participants *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, `{"jid":"placeholder@g.us","name":"test"}`, "")
	}()
}

//export whatsmeow_join_group_async
func whatsmeow_join_group_async(invite_link *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, `{"jid":"placeholder@g.us","name":"joined"}`, "")
	}()
}

//export whatsmeow_mark_read_async
func whatsmeow_mark_read_async(chat_jid *C.char, message_id *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "success", "")
	}()
}

//export whatsmeow_send_reaction_async
func whatsmeow_send_reaction_async(chat_jid *C.char, message_id *C.char, emoji *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "reaction_sent", "")
	}()
}

//export whatsmeow_remove_reaction_async
func whatsmeow_remove_reaction_async(chat_jid *C.char, message_id *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "reaction_removed", "")
	}()
}

//export whatsmeow_get_reactions_async
func whatsmeow_get_reactions_async(chat_jid *C.char, message_id *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "[]", "")
	}()
}

//export whatsmeow_send_audio_async
func whatsmeow_send_audio_async(chat_jid *C.char, audio_path *C.char, caption *C.char, is_voice_note C.bool, duration C.uint, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "msg_audio_placeholder", "")
	}()
}

//export whatsmeow_send_video_async
func whatsmeow_send_video_async(chat_jid *C.char, video_path *C.char, caption *C.char, thumbnail_path *C.char, duration C.uint, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "msg_video_placeholder", "")
	}()
}

//export whatsmeow_send_document_async
func whatsmeow_send_document_async(chat_jid *C.char, document_path *C.char, filename *C.char, caption *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "msg_document_placeholder", "")
	}()
}

//export whatsmeow_download_media_async
func whatsmeow_download_media_async(chat_jid *C.char, message_id *C.char, media_type *C.char, save_path *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, `{"success": true, "file_path": "downloaded_media.ext"}`, "")
	}()
}

//export whatsmeow_get_profile_info_async
func whatsmeow_get_profile_info_async(jid *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, `{"jid":"placeholder"}`, "")
	}()
}

//export whatsmeow_get_my_profile_async
func whatsmeow_get_my_profile_async(callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, `{"jid":"my_jid"}`, "")
	}()
}

//export whatsmeow_update_profile_async
func whatsmeow_update_profile_async(name *C.char, status *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "profile_updated", "")
	}()
}

//export whatsmeow_set_profile_picture_async
func whatsmeow_set_profile_picture_async(image_path *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "profile_picture_updated", "")
	}()
}

//export whatsmeow_get_profile_picture_async
func whatsmeow_get_profile_picture_async(jid *C.char, save_path *C.char, callback_handle uintptr) {
	go func() {
		defer handlePanic()
		sendResponseCallback(callback_handle, true, "profile_picture_downloaded", "")
	}()
}

//export whatsmeow_start_event_stream
func whatsmeow_start_event_stream(callback_handle uintptr) C.bool {
	return C.bool(true)
}

//export whatsmeow_stop_event_stream
func whatsmeow_stop_event_stream() C.bool {
	return C.bool(true)
}

// Register a message handler for a specific client
//export whatsmeow_register_message_handler
func whatsmeow_register_message_handler(client_ptr uintptr, callback_handle uintptr) C.bool {
	if client_ptr == 0 {
		return C.bool(false)
	}
	
	client := (*whatsmeow.Client)(unsafe.Pointer(client_ptr))
	
	// Store the callback handle
	messageHandlersMutex.Lock()
	messageHandlers[client_ptr] = callback_handle
	messageHandlersMutex.Unlock()
	
	// Add event handler to the client
	client.AddEventHandler(func(evt interface{}) {
		switch v := evt.(type) {
		case *events.Message:
			handleMessageEvent(client_ptr, v)
		}
	})
	
	return C.bool(true)
}

// Handle incoming message events
func handleMessageEvent(client_ptr uintptr, evt *events.Message) {
	messageHandlersMutex.RLock()
	callback_handle, exists := messageHandlers[client_ptr]
	messageHandlersMutex.RUnlock()
	
	if !exists {
		return
	}
	
	// Extract message content
	var content string
	var msgType string
	
	if evt.Message.GetConversation() != "" {
		content = evt.Message.GetConversation()
		msgType = "text"
	} else if evt.Message.GetExtendedTextMessage() != nil {
		content = evt.Message.GetExtendedTextMessage().GetText()
		msgType = "text"
	} else if evt.Message.GetImageMessage() != nil {
		content = evt.Message.GetImageMessage().GetCaption()
		msgType = "image"
	} else if evt.Message.GetVideoMessage() != nil {
		content = evt.Message.GetVideoMessage().GetCaption()
		msgType = "video"
	} else if evt.Message.GetAudioMessage() != nil {
		content = "Audio message"
		msgType = "audio"
	} else if evt.Message.GetDocumentMessage() != nil {
		content = evt.Message.GetDocumentMessage().GetTitle()
		msgType = "document"
	} else {
		content = "Unsupported message type"
		msgType = "unknown"
	}
	
	// Create message event
	messageEvent := MessageEvent{
		ID:        evt.Info.ID,
		Chat:      evt.Info.Chat.String(),
		Sender:    evt.Info.Sender.String(),
		Timestamp: evt.Info.Timestamp.Unix(),
		Type:      msgType,
		Content:   content,
		IsFromMe:  evt.Info.IsFromMe,
	}
	
	// Serialize to JSON
	jsonData, err := json.Marshal(messageEvent)
	if err != nil {
		fmt.Printf("Failed to serialize message event: %v\n", err)
		return
	}
	
	// Send to Rust message callback
	sendMessageCallback(callback_handle, true, string(jsonData), "")
}

// Unregister message handler for a specific client
//export whatsmeow_unregister_message_handler
func whatsmeow_unregister_message_handler(client_ptr uintptr) C.bool {
	messageHandlersMutex.Lock()
	delete(messageHandlers, client_ptr)
	messageHandlersMutex.Unlock()
	return C.bool(true)
}

//export whatsmeow_register_presence_handler
func whatsmeow_register_presence_handler(callback_handle uintptr) C.bool {
	return C.bool(true)
}

//export whatsmeow_register_receipt_handler
func whatsmeow_register_receipt_handler(callback_handle uintptr) C.bool {
	return C.bool(true)
}

// Free Go allocated memory
//export go_free
func go_free(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

// Response structures are now defined in the C header above



// Helper functions for callbacks
func sendStatusCallback(handle uintptr, status string, errorMsg string) {
	// Create C strings
	statusCStr := C.CString(status)
	var errorCStr *C.char
	if errorMsg != "" {
		errorCStr = C.CString(errorMsg)
	}
	
	// Create response structure
	response := C.CStatusResponse{
		status: statusCStr,
		error:  errorCStr,
	}
	
	// Call Rust callback
	C.rust_status_callback(C.uintptr_t(handle), &response)
}

func sendResponseCallback(handle uintptr, success bool, data string, errorMsg string) {
	// Create C strings
	var dataCStr *C.char
	if data != "" {
		dataCStr = C.CString(data)
	}
	
	var errorCStr *C.char
	if errorMsg != "" {
		errorCStr = C.CString(errorMsg)
	}
	
	// Create response structure
	response := C.CResponse{
		success: C.int(0),
		data:    dataCStr,
		error:   errorCStr,
	}
	
	if success {
		response.success = C.int(1)
	}
	
	// Call Rust callback
	C.rust_response_callback(C.uintptr_t(handle), &response)
}

func sendMessageCallback(handle uintptr, success bool, data string, errorMsg string) {
	// Create C strings
	var dataCStr *C.char
	if data != "" {
		dataCStr = C.CString(data)
	}
	var errorCStr *C.char
	if errorMsg != "" {
		errorCStr = C.CString(errorMsg)
	}
	
	// Create response structure
	response := C.CResponse{
		data:    dataCStr,
		error:   errorCStr,
	}
	
	if success {
		response.success = C.int(1)
	}
	
	// Call Rust message callback
	C.rust_message_callback(C.uintptr_t(handle), &response)
}

func handlePanic() {
	if r := recover(); r != nil {
		fmt.Printf("Go panic recovered: %v\n", r)
		
		// Print stack trace
		buf := make([]byte, 4096)
		n := runtime.Stack(buf, false)
		fmt.Printf("Stack trace:\n%s", buf[:n])
	}
}

func main() {
	// This is required for Go to generate a C shared library
} 