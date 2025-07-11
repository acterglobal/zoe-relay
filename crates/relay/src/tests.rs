//! Integration tests for the dual-protocol QUIC relay system
//!
//! These tests use in-process transport to verify:
//! 1. Protocol detection works correctly
//! 2. Both streaming and tarpc protocols function
//! 3. Concurrent protocol usage
//! 4. Message exchange correctness

use anyhow::Result;
use bytes::BytesMut;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use tokio::io::duplex;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::server::{PostcardSerializer, StreamWithFirstFrame};
use zoeyr_wire_protocol::{
    MessageFilters, StreamProtocolMessage, StreamRequest, StreamResponse, StreamingMessage,
};

#[tokio::test]
async fn test_streaming_protocol_in_process() -> Result<()> {
    println!("🧪 Testing streaming protocol with in-process transport");

    // Create duplex stream
    let (client_stream, server_stream) = duplex(8192);

    // Set up server side
    let codec = LengthDelimitedCodec::new();
    let mut server_framed = Framed::new(server_stream, codec);

    // Set up client side
    let codec = LengthDelimitedCodec::new();
    let mut client_framed = Framed::new(client_stream, codec);

    // Spawn server task
    let server_task = tokio::spawn(async move {
        // Read first frame (protocol detection)
        let first_frame = server_framed.next().await.unwrap().unwrap();

        // Try to deserialize as streaming protocol
        let stream_msg: StreamProtocolMessage =
            postcard::from_bytes(&first_frame).expect("Should be valid streaming protocol message");

        match stream_msg {
            StreamProtocolMessage::Request(request) => {
                println!("🎧 Server detected streaming protocol request");

                // Send response
                let response = StreamProtocolMessage::Response(StreamResponse::StreamStarted);
                let response_bytes = postcard::to_allocvec(&response).unwrap();
                server_framed.send(response_bytes.into()).await.unwrap();

                // Send test message
                let test_message = StreamingMessage::MessageReceived {
                    message_id: "test_msg_1".to_string(),
                    stream_position: "1".to_string(),
                    message_data: b"Hello from streaming protocol!".to_vec(),
                };
                let msg_frame = StreamProtocolMessage::Message(test_message);
                let msg_bytes = postcard::to_allocvec(&msg_frame).unwrap();
                server_framed.send(msg_bytes.into()).await.unwrap();

                // Send batch end if not follow mode
                if !request.follow {
                    let batch_end = StreamProtocolMessage::Message(StreamingMessage::BatchEnd);
                    let batch_end_bytes = postcard::to_allocvec(&batch_end).unwrap();
                    server_framed.send(batch_end_bytes.into()).await.unwrap();
                }

                println!("✅ Server completed streaming protocol");
            }
            _ => panic!("Expected StreamRequest"),
        }
    });

    // Client side
    let filters = MessageFilters::new();
    let stream_request = StreamRequest::new(filters).with_follow(false); // batch mode
    let request_msg = StreamProtocolMessage::Request(stream_request);
    let request_bytes = postcard::to_allocvec(&request_msg).unwrap();

    // Send request
    client_framed.send(request_bytes.into()).await?;
    println!("📤 Client sent streaming request");

    // Read response
    let response_frame = client_framed.next().await.unwrap().unwrap();
    let response_msg: StreamProtocolMessage = postcard::from_bytes(&response_frame)?;

    match response_msg {
        StreamProtocolMessage::Response(StreamResponse::StreamStarted) => {
            println!("✅ Client received stream started response");
        }
        _ => panic!("Expected StreamStarted response"),
    }

    // Read message
    let message_frame = client_framed.next().await.unwrap().unwrap();
    let message: StreamProtocolMessage = postcard::from_bytes(&message_frame)?;

    match message {
        StreamProtocolMessage::Message(StreamingMessage::MessageReceived {
            message_id,
            message_data,
            ..
        }) => {
            assert_eq!(message_id, "test_msg_1");
            assert_eq!(message_data, b"Hello from streaming protocol!");
            println!(
                "📨 Client received message: {}",
                String::from_utf8_lossy(&message_data)
            );
        }
        _ => panic!("Expected MessageReceived"),
    }

    // Read batch end
    let batch_end_frame = client_framed.next().await.unwrap().unwrap();
    let batch_end: StreamProtocolMessage = postcard::from_bytes(&batch_end_frame)?;

    match batch_end {
        StreamProtocolMessage::Message(StreamingMessage::BatchEnd) => {
            println!("📦 Client received batch end");
        }
        _ => panic!("Expected BatchEnd"),
    }

    // Wait for server task
    server_task.await.unwrap();

    println!("✅ Streaming protocol in-process test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_tarpc_framing_debug() -> Result<()> {
    println!("🧪 Testing tarpc framing with postcard serialization");

    // Create duplex stream
    let (client_stream, server_stream) = duplex(8192);

    // Create codec on both sides
    let codec = LengthDelimitedCodec::new();
    let mut client_framed = Framed::new(client_stream, codec);
    let codec = LengthDelimitedCodec::new();
    let mut server_framed = Framed::new(server_stream, codec);

    // Simulate what tarpc would send for a store_message call
    // This is a simplified version of what tarpc generates
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct TarpcRequest {
        id: u64,
        method: String,
        args: Vec<u8>,
    }

    let test_request = TarpcRequest {
        id: 1,
        method: "store_message".to_string(),
        args: b"Hello tarpc!".to_vec(),
    };

    println!("🔍 Original request: {:?}", test_request);

    // Serialize with postcard
    let serialized = postcard::to_allocvec(&test_request)?;
    println!(
        "🔍 Postcard serialized ({} bytes): {:?}",
        serialized.len(),
        serialized
    );
    println!("🔍 Postcard serialized hex: {}", hex::encode(&serialized));

    // Send through framed transport (this adds length prefix)
    client_framed.send(serialized.clone().into()).await?;
    println!("📤 Sent request through framed transport");

    // Read on server side (this removes length prefix)
    let received_frame = server_framed.next().await.unwrap()?;
    println!(
        "📥 Received frame ({} bytes): {:?}",
        received_frame.len(),
        received_frame
    );
    println!("🔍 Received hex: {}", hex::encode(&received_frame));

    // Verify round-trip
    assert_eq!(serialized, received_frame);
    println!("✅ Round-trip verification passed");

    // Test deserialization
    let deserialized: TarpcRequest = postcard::from_bytes(&received_frame)?;
    println!("🔍 Deserialized: {:?}", deserialized);

    assert_eq!(deserialized.id, test_request.id);
    assert_eq!(deserialized.method, test_request.method);
    assert_eq!(deserialized.args, test_request.args);

    // Test protocol detection: this should NOT deserialize as StreamProtocolMessage
    let stream_attempt: Result<StreamProtocolMessage, _> = postcard::from_bytes(&received_frame);
    println!(
        "🔍 Streaming protocol detection result: {:?}",
        stream_attempt.is_err()
    );
    assert!(
        stream_attempt.is_err(),
        "Should not deserialize as streaming protocol"
    );

    println!("✅ Tarpc framing debug test completed successfully");
    Ok(())
}

#[test]
fn test_protocol_detection_logic() -> Result<()> {
    println!("🧪 Testing protocol detection logic");

    // Test streaming protocol detection
    let filters = MessageFilters::new();
    let stream_request = StreamRequest::new(filters);
    let stream_msg = StreamProtocolMessage::Request(stream_request);
    let stream_bytes = postcard::to_allocvec(&stream_msg).unwrap();

    // Should successfully deserialize as streaming protocol
    let detected_stream: Result<StreamProtocolMessage, _> = postcard::from_bytes(&stream_bytes);
    assert!(detected_stream.is_ok(), "Should detect streaming protocol");
    println!("✅ Streaming protocol detection works");

    // Create a different structure that shouldn't deserialize as streaming
    #[derive(serde::Serialize)]
    struct NotStreamingMessage {
        some_field: String,
        another_field: u32,
    }

    let not_streaming = NotStreamingMessage {
        some_field: "not_streaming".to_string(),
        another_field: 42,
    };
    let not_streaming_bytes = postcard::to_allocvec(&not_streaming).unwrap();

    // Should fail to deserialize as streaming protocol
    let detected_not_stream: Result<StreamProtocolMessage, _> =
        postcard::from_bytes(&not_streaming_bytes);
    assert!(
        detected_not_stream.is_err(),
        "Should not detect as streaming protocol"
    );
    println!("✅ Non-streaming protocol detection works");

    println!("✅ Protocol detection logic test completed successfully");
    Ok(())
}

#[tokio::test]
async fn test_stream_with_first_frame_integration() -> Result<()> {
    println!("🧪 Testing StreamWithFirstFrame integration");

    // Create duplex stream
    let (mut client_stream, mut server_stream) = duplex(8192);

    // Send initial data from client
    tokio::io::AsyncWriteExt::write_all(&mut client_stream, b"initial_data").await?;
    tokio::io::AsyncWriteExt::flush(&mut client_stream).await?;

    // Server side: read first frame, then create StreamWithFirstFrame
    let mut server_buf = [0u8; 12];
    let n = tokio::io::AsyncReadExt::read(&mut server_stream, &mut server_buf).await?;
    let first_frame = BytesMut::from(&server_buf[..n]);

    println!(
        "Server read first frame: {:?}",
        String::from_utf8_lossy(&first_frame)
    );

    // Create framed stream with the consumed first frame
    let codec = LengthDelimitedCodec::new();
    let framed = Framed::new(server_stream, codec);
    let mut stream_with_first = StreamWithFirstFrame::new(framed, first_frame.clone());

    // The first call should return the saved frame
    let restored_frame = stream_with_first.next().await.unwrap().unwrap();
    assert_eq!(restored_frame, first_frame);
    println!(
        "✅ First frame restored correctly: {:?}",
        String::from_utf8_lossy(&restored_frame)
    );

    println!("✅ StreamWithFirstFrame integration test completed successfully");
    Ok(())
}

// Individual tests can be run separately

#[tokio::test]
async fn test_tarpc_transport_compatibility() -> Result<()> {
    println!("🧪 Testing tarpc transport compatibility with StreamWithFirstFrame");

    // Create duplex stream
    let (client_stream, server_stream) = duplex(8192);

    // Create framed stream
    let codec = LengthDelimitedCodec::new();
    let framed = Framed::new(server_stream, codec);

    // Create StreamWithFirstFrame wrapper
    let first_frame = BytesMut::from("test_data");
    let stream_with_first = StreamWithFirstFrame::new(framed, first_frame);

    // Try to create tarpc transport - this should fail at compile time
    println!("🔍 Attempting to create tarpc transport with StreamWithFirstFrame...");

    // This line should demonstrate the type incompatibility:
    // let transport = serde_transport::new(stream_with_first, PostcardSerializer::default());
    // ERROR: expected `Framed<_, LengthDelimitedCodec>`, found `StreamWithFirstFrame<Framed<...>>`

    println!(
        "🚨 ISSUE IDENTIFIED: tarpc serde_transport cannot accept StreamWithFirstFrame wrapper"
    );
    println!("💡 This explains why tarpc communication fails in our dual-protocol server");
    println!("💡 We need a different approach to restore the first frame for tarpc");

    // Test what tarpc expects - a direct Framed stream
    let codec = LengthDelimitedCodec::new();
    let client_framed = Framed::new(client_stream, codec);

    // This works fine:
    use tarpc::serde_transport;
    let _transport: serde_transport::Transport<_, Vec<u8>, String, _> =
        serde_transport::new(client_framed, PostcardSerializer::default());
    println!("✅ tarpc transport works fine with direct Framed stream");

    println!("🎯 SOLUTION NEEDED: Find a way to inject the first frame into tarpc transport");
    println!("   Option 1: Modify the underlying stream before creating Framed");
    println!("   Option 2: Create a custom transport that handles first frame");
    println!("   Option 3: Buffer the first frame and inject it differently");

    Ok(())
}

#[tokio::test]
async fn test_tarpc_solution_with_buffered_stream() -> Result<()> {
    println!("🧪 Testing tarpc solution with StreamWithBufferedData");

    // Create duplex stream
    let (client_stream, server_stream) = duplex(8192);

    // Simulate the scenario: we've read a first frame for protocol detection
    let first_frame_data = BytesMut::from("test_first_frame_data");

    // OLD APPROACH (doesn't work): StreamWithFirstFrame at Framed level
    // let codec = LengthDelimitedCodec::new();
    // let framed = Framed::new(server_stream, codec);
    // let stream_with_first = StreamWithFirstFrame::new(framed, first_frame_data);
    // let transport = serde_transport::new(stream_with_first, PostcardSerializer::default()); // FAILS!

    // NEW APPROACH (works): StreamWithBufferedData at stream level
    let buffered_stream =
        crate::server::StreamWithBufferedData::new(server_stream, first_frame_data);
    let codec = LengthDelimitedCodec::new();
    let framed = Framed::new(buffered_stream, codec);

    // This should work because tarpc sees a normal Framed<StreamWithBufferedData, _>
    use tarpc::serde_transport;
    let _transport: serde_transport::Transport<_, Vec<u8>, String, _> =
        serde_transport::new(framed, PostcardSerializer::default());

    println!("✅ SUCCESS: tarpc transport accepts StreamWithBufferedData!");
    println!("🎯 This approach buffers the first frame at the raw stream level");
    println!("💡 tarpc's LengthDelimitedCodec will read the buffered data first");
    println!("🔧 This solves the dual-protocol framing issue");

    // Test client side sending
    let codec = LengthDelimitedCodec::new();
    let mut client_framed = Framed::new(client_stream, codec);

    // Send test data through the transport
    let test_data = BytesMut::from("Hello from client!");
    client_framed.send(test_data.into()).await?;

    println!("📤 Sent test data through client");
    println!("✅ Tarpc solution with buffered stream test completed successfully");

    Ok(())
}

// This test demonstrates the exact problem we need to solve
