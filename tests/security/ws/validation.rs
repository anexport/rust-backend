use rust_backend::api::routes::ws::{
    WsClientEnvelope, WsReadPayload, WsSendMessagePayload, WsTypingPayload,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn ws_message_envelope_serialization() {
    let envelope = WsClientEnvelope {
        message_type: "ping".to_string(),
        payload: None,
    };

    let json = serde_json::to_string(&envelope).unwrap();
    assert!(json.contains(r#""type":"ping""#));

    let envelope_with_payload = WsClientEnvelope {
        message_type: "message".to_string(),
        payload: Some(json!({
            "conversation_id": Uuid::new_v4(),
            "content": "test"
        })),
    };

    let json_with_payload = serde_json::to_string(&envelope_with_payload).unwrap();
    assert!(json_with_payload.contains(r#""type":"message""#));
    assert!(json_with_payload.contains(r#""conversation_id""#));
    assert!(json_with_payload.contains(r#""content""#));
}

#[test]
fn ws_send_message_payload_validation() {
    let valid_payload = WsSendMessagePayload {
        conversation_id: Uuid::new_v4(),
        content: "Hello, world!".to_string(),
    };

    let valid_json = serde_json::to_value(&valid_payload).unwrap();
    assert_eq!(
        valid_json["conversation_id"],
        serde_json::Value::String(valid_payload.conversation_id.to_string())
    );
    assert_eq!(
        valid_json["content"],
        serde_json::Value::String(valid_payload.content.clone())
    );

    let missing_conversation = json!({
        "content": "test"
    });
    let result = serde_json::from_value::<WsSendMessagePayload>(missing_conversation);
    assert!(result.is_err());

    let invalid_uuid = json!({
        "conversation_id": "not-a-uuid",
        "content": "test"
    });
    let result = serde_json::from_value::<WsSendMessagePayload>(invalid_uuid);
    assert!(result.is_err());
}

#[test]
fn ws_typing_payload_validation() {
    let valid_typing = WsTypingPayload {
        conversation_id: Uuid::new_v4(),
        is_typing: Some(true),
    };

    let valid_json = serde_json::to_value(&valid_typing).unwrap();
    assert_eq!(
        valid_json["conversation_id"],
        serde_json::Value::String(valid_typing.conversation_id.to_string())
    );
    assert_eq!(valid_json["is_typing"], serde_json::Value::Bool(true));

    let typing_false = WsTypingPayload {
        conversation_id: Uuid::new_v4(),
        is_typing: Some(false),
    };
    let json_false = serde_json::to_value(&typing_false).unwrap();
    assert_eq!(json_false["is_typing"], serde_json::Value::Bool(false));

    let typing_none = json!({
        "conversation_id": Uuid::new_v4(),
    });
    let json_none = serde_json::from_value::<WsTypingPayload>(typing_none).unwrap();
    assert!(json_none.is_typing.is_none());
}

#[test]
fn ws_read_payload_validation() {
    let valid_read = WsReadPayload {
        conversation_id: Uuid::new_v4(),
    };

    let valid_json = serde_json::to_value(&valid_read).unwrap();
    assert_eq!(
        valid_json["conversation_id"],
        serde_json::Value::String(valid_read.conversation_id.to_string())
    );

    let test_conversation_id = Uuid::new_v4();
    let read_with_extra = json!({
        "conversation_id": test_conversation_id,
        "extra_field": "should be ignored"
    });
    let result = serde_json::from_value::<WsReadPayload>(read_with_extra);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.conversation_id, test_conversation_id);
}
