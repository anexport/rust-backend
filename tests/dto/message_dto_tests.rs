// Tests for message DTOs in src/api/dtos/message_dto.rs
// Tests CreateConversationRequest and SendMessageRequest validation

use chrono::Utc;
use rust_backend::api::dtos::message_dto::{
    ConversationResponse, CreateConversationRequest, MessageResponse, ParticipantResponse,
    SendMessageRequest,
};
use serde_json;
use uuid::Uuid;
use validator::Validate;

#[test]
fn test_create_conversation_request_valid_one_participant() {
    // Test valid request with one participant
    let request = CreateConversationRequest {
        participant_ids: vec![Uuid::new_v4()],
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_conversation_request_valid_multiple_participants() {
    // Test valid request with multiple participants
    let request = CreateConversationRequest {
        participant_ids: vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_conversation_request_empty_participants() {
    // Test empty participants list - should fail validation
    let request = CreateConversationRequest {
        participant_ids: vec![],
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("participant_ids"));
}

#[test]
fn test_send_message_request_valid_min_length() {
    // Test message with minimum valid length (1 character)
    let request = SendMessageRequest {
        content: "A".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_valid_max_length() {
    // Test message with maximum valid length (5000 characters)
    let request = SendMessageRequest {
        content: "A".repeat(5000),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_valid_typical_length() {
    // Test message with typical length
    let request = SendMessageRequest {
        content: "Hello, how are you today?".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_empty_content() {
    // Test empty message content - should fail validation
    let request = SendMessageRequest {
        content: "".to_string(),
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("content"));
}

#[test]
fn test_send_message_request_too_long() {
    // Test message too long (5001 characters, max is 5000)
    let request = SendMessageRequest {
        content: "A".repeat(5001),
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("content"));
}

#[test]
fn test_send_message_request_whitespace_only() {
    // Test message with only whitespace - should pass (length >= 1)
    let request = SendMessageRequest {
        content: "   ".to_string(),
    };
    // This should pass because length is 3 (>= 1)
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_newlines_and_tabs() {
    // Test message with newlines and tabs
    let request = SendMessageRequest {
        content: "Hello\n\tWorld".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_emoji() {
    // Test message with emoji
    let request = SendMessageRequest {
        content: "Hello! 😀 How are you? 🎉".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_unicode() {
    // Test message with unicode characters
    let request = SendMessageRequest {
        content: "你好，世界！".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_single_word() {
    // Test message with single word
    let request = SendMessageRequest {
        content: "Hello".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_paragraph() {
    // Test message with paragraph
    let request = SendMessageRequest {
        content: "This is a longer message that spans multiple sentences. It should still be within the 5000 character limit. Let's add some more text to make it more realistic.".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_exactly_5000_chars() {
    // Test message with exactly 5000 characters
    let request = SendMessageRequest {
        content: "A".repeat(5000),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_exactly_5001_chars() {
    // Test message with exactly 5001 characters (should fail)
    let request = SendMessageRequest {
        content: "B".repeat(5001),
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("content"));
}

#[test]
fn test_create_conversation_request_deserialization() {
    // Test deserialization from JSON
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let json = format!(r#"{{"participant_ids": ["{}", "{}"]}}"#, id1, id2);
    let request: CreateConversationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request.participant_ids.len(), 2);
    assert_eq!(request.participant_ids[0], id1);
    assert_eq!(request.participant_ids[1], id2);
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_conversation_request_deserialization_single() {
    // Test deserialization with single participant
    let id = Uuid::new_v4();
    let json = format!(r#"{{"participant_ids": ["{}"]}}"#, id);
    let request: CreateConversationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request.participant_ids.len(), 1);
    assert_eq!(request.participant_ids[0], id);
    assert!(request.validate().is_ok());
}

#[test]
fn test_create_conversation_request_deserialization_empty_array() {
    // Test deserialization with empty participant array
    let json = r#"{"participant_ids": []}"#;
    let request: CreateConversationRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.participant_ids.len(), 0);
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("participant_ids"));
}

#[test]
fn test_send_message_request_deserialization() {
    // Test deserialization from JSON
    let json = r#"{"content": "Hello, world!"}"#;
    let request: SendMessageRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.content, "Hello, world!");
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_roundtrip() {
    // Test deserialization (roundtrip not possible as struct doesn't serialize)
    let json = r#"{"content": "Hello, world!"}"#;
    let request: SendMessageRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.content, "Hello, world!");
}

#[test]
fn test_create_conversation_request_roundtrip() {
    // Test deserialization (roundtrip not possible as struct doesn't serialize)
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let json = format!(r#"{{"participant_ids": ["{}", "{}"]}}"#, id1, id2);
    let request: CreateConversationRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(request.participant_ids.len(), 2);
}

#[test]
fn test_create_conversation_request_many_participants() {
    // Test request with many participants
    let participant_ids: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();
    let request = CreateConversationRequest { participant_ids };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_special_characters() {
    // Test message with special characters
    let request = SendMessageRequest {
        content: "Hello! @#$%^&*()_+-=[]{}|;':\",./<>?".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_with_mentions() {
    // Test message with mentions
    let request = SendMessageRequest {
        content: "Hello @user, how are you?".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_with_links() {
    // Test message with links
    let request = SendMessageRequest {
        content: "Check out this link: https://example.com".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_multiline() {
    // Test multiline message
    let request = SendMessageRequest {
        content: "Line 1\nLine 2\nLine 3".to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_send_message_request_code_block() {
    // Test message with code block
    let request = SendMessageRequest {
        content: "Here's some code:\n```\nfn main() {\n    println!(\"Hello\");\n}\n```"
            .to_string(),
    };
    assert!(request.validate().is_ok());
}

#[test]
fn test_conversation_response_creation() {
    // Test ConversationResponse creation
    let id = Uuid::new_v4();
    let now = Utc::now();
    let response = ConversationResponse {
        id,
        participants: vec![],
        last_message: None,
        created_at: now,
        updated_at: now,
    };
    assert_eq!(response.id, id);
    assert!(response.participants.is_empty());
}

#[test]
fn test_message_response_creation() {
    // Test MessageResponse creation
    let id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let sender_id = Uuid::new_v4();
    let now = Utc::now();
    let response = MessageResponse {
        id,
        conversation_id,
        sender_id,
        sender_name: Some("Test User".to_string()),
        content: "Hello, world!".to_string(),
        created_at: now,
    };
    assert_eq!(response.content, "Hello, world!");
    assert_eq!(response.sender_name, Some("Test User".to_string()));
}

#[test]
fn test_participant_response_creation() {
    // Test ParticipantResponse creation
    let user_id = Uuid::new_v4();
    let now = Utc::now();
    let response = ParticipantResponse {
        user_id,
        username: Some("testuser".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
        last_read_at: Some(now),
    };
    assert_eq!(response.username, Some("testuser".to_string()));
}

#[test]
fn test_participant_response_none_fields() {
    // Test ParticipantResponse with None optional fields
    let user_id = Uuid::new_v4();
    let response = ParticipantResponse {
        user_id,
        username: None,
        avatar_url: None,
        last_read_at: None,
    };
    assert_eq!(response.username, None);
    assert_eq!(response.avatar_url, None);
    assert_eq!(response.last_read_at, None);
}

#[test]
fn test_send_message_request_validation_error_message() {
    // Test that validation error messages contain useful information
    let request = SendMessageRequest {
        content: "".to_string(),
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("content"));
}

#[test]
fn test_create_conversation_request_validation_error_message() {
    // Test that validation error messages contain useful information
    let request = CreateConversationRequest {
        participant_ids: vec![],
    };
    let result = request.validate();
    assert!(result.is_err());
    let validation_err = result.unwrap_err();
    let errors = validation_err.field_errors();
    assert!(errors.contains_key("participant_ids"));
}

#[test]
fn test_send_message_request_content_boundary_5000() {
    // Test boundary between valid and invalid content length
    let valid = SendMessageRequest {
        content: "x".repeat(5000),
    };
    assert!(valid.validate().is_ok());

    let invalid = SendMessageRequest {
        content: "x".repeat(5001),
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn test_send_message_request_content_boundary_1() {
    // Test boundary of minimum content length
    let valid = SendMessageRequest {
        content: "x".to_string(),
    };
    assert!(valid.validate().is_ok());

    let invalid = SendMessageRequest {
        content: "".to_string(),
    };
    assert!(invalid.validate().is_err());
}

#[test]
fn test_message_response_serialization() {
    // Test MessageResponse serialization
    let id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let sender_id = Uuid::new_v4();
    let now = Utc::now();
    let response = MessageResponse {
        id,
        conversation_id,
        sender_id,
        sender_name: Some("Test User".to_string()),
        content: "Hello, world!".to_string(),
        created_at: now,
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("Hello, world!"));
    assert!(json.contains("Test User"));
}

#[test]
fn test_participant_response_serialization() {
    // Test ParticipantResponse serialization
    let user_id = Uuid::new_v4();
    let response = ParticipantResponse {
        user_id,
        username: Some("testuser".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
        last_read_at: Some(Utc::now()),
    };
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("testuser"));
}
