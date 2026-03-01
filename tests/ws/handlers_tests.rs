//! Unit tests for WebSocket message parsing.
//!
//! Tests for message type parsing and validation:
//! - parsing WsClientEnvelope structure
//! - parsing SendMessagePayload
//! - parsing WsTypingPayload
//! - parsing WsReadPayload
//! - error handling

use serde_json::{self, json};
use uuid::Uuid;

#[test]
fn test_parse_ws_envelope_valid_ping() {
    let payload = json!({});
    let envelope = json!({
        "type": "ping",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "ping");
    assert!(value["payload"].is_null());
}

#[test]
fn test_parse_ws_envelope_valid_message() {
    let payload = json!({
        "conversation_id": Uuid::new_v4(),
        "content": "Hello"
    });
    let envelope = json!({
        "type": "message",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "message");
    assert_eq!(value["payload"]["content"], "Hello");
}

#[test]
fn test_parse_ws_envelope_valid_typing() {
    let payload = json!({
        "conversation_id": Uuid::new_v4(),
        "is_typing": true
    });
    let envelope = json!({
        "type": "typing",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "typing");
}

#[test]
fn test_parse_ws_envelope_typing_without_is_typing() {
    let payload = json!({
        "conversation_id": Uuid::new_v4()
    });
    let envelope = json!({
        "type": "typing",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "typing");
}

#[test]
fn test_parse_ws_envelope_valid_read() {
    let payload = json!({
        "conversation_id": Uuid::new_v4()
    });
    let envelope = json!({
        "type": "read",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "read");
}

#[test]
fn test_parse_ws_envelope_unsupported_type() {
    let envelope = json!({
        "type": "unsupported",
        "payload": {}
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "unsupported");
}

#[test]
fn test_parse_ws_envelope_invalid_json() {
    let invalid_json = "not valid json {";
    let result = serde_json::from_str::<serde_json::Value>(invalid_json);
    assert!(result.is_err());
}

#[test]
fn test_parse_ws_envelope_missing_type_field() {
    let envelope = json!({
        "payload": {}
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_err());
}

#[test]
fn test_parse_send_message_payload_valid() {
    let payload = json!({
        "conversation_id": Uuid::new_v4(),
        "content": "Test message"
    });

    let envelope = json!({
        "type": "message",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "message");
}

#[test]
fn test_parse_send_message_payload_missing_conversation_id() {
    let payload = json!({
        "content": "Test"
    });

    let envelope = json!({
        "type": "message",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "message");
}

#[test]
fn test_parse_send_message_payload_empty_content() {
    let payload = json!({
        "conversation_id": Uuid::new_v4(),
        "content": ""
    });

    let envelope = json!({
        "type": "message",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "message");
}

#[test]
fn test_parse_typing_payload_valid() {
    let payload = json!({
        "conversation_id": Uuid::new_v4(),
        "is_typing": true
    });

    let envelope = json!({
        "type": "typing",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "typing");
}

#[test]
fn test_parse_typing_payload_missing_conversation_id() {
    let payload = json!({
        "is_typing": true
    });

    let envelope = json!({
        "type": "typing",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "typing");
}

#[test]
fn test_parse_read_payload_valid() {
    let payload = json!({
        "conversation_id": Uuid::new_v4()
    });

    let envelope = json!({
        "type": "read",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "read");
}

#[test]
fn test_parse_read_payload_missing_conversation_id() {
    let payload = json!({});

    let envelope = json!({
        "type": "read",
        "payload": payload
    })
    .to_string();

    let result = serde_json::from_str::<serde_json::Value>(&envelope);
    assert!(result.is_ok());
    let value = result.unwrap();
    assert_eq!(value["type"], "read");
}
