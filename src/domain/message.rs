use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Conversation {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConversationParticipant {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub profile_id: Uuid,
    pub last_read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Message {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sender_id: Uuid,
    pub content: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN_CONTENT_LENGTH: usize = 1;
    const MAX_CONTENT_LENGTH: usize = 5000;

    fn create_test_message(content: &str) -> Message {
        Message {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            content: content.to_string(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn message_serialization_roundtrip() {
        let original = create_test_message("Hello, world!");
        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.conversation_id, original.conversation_id);
        assert_eq!(deserialized.sender_id, original.sender_id);
        assert_eq!(deserialized.content, original.content);
    }

    #[test]
    fn message_content_min_length() {
        let message = create_test_message("H");
        assert_eq!(message.content.len(), MIN_CONTENT_LENGTH);
    }

    #[test]
    fn message_content_max_length() {
        let content = "a".repeat(MAX_CONTENT_LENGTH);
        let message = create_test_message(&content);
        assert_eq!(message.content.len(), MAX_CONTENT_LENGTH);
    }

    #[test]
    fn message_content_within_bounds_serialization() {
        let short_content = "Hi";
        let short_message = create_test_message(short_content);
        let serialized_short = serde_json::to_string(&short_message).unwrap();
        let deserialized_short: Message = serde_json::from_str(&serialized_short).unwrap();
        assert_eq!(deserialized_short.content, short_content);

        let long_content = "x".repeat(1000);
        let long_message = create_test_message(&long_content);
        let serialized_long = serde_json::to_string(&long_message).unwrap();
        let deserialized_long: Message = serde_json::from_str(&serialized_long).unwrap();
        assert_eq!(deserialized_long.content.len(), 1000);
    }

    #[test]
    fn message_with_special_characters_serializes() {
        let special_contents = vec![
            "Hello! @#$%^&*()",
            "Unicode: café, 日本語, emoji 🎉",
            "Line\nbreaks\nhere",
            "Tabs\there",
            "Quotes: \"single\" and 'double'",
        ];

        for content in special_contents {
            let message = create_test_message(content);
            let serialized = serde_json::to_string(&message).unwrap();
            let deserialized: Message = serde_json::from_str(&serialized).unwrap();
            assert_eq!(deserialized.content, content);
        }
    }

    #[test]
    fn message_conversation_id_preserved() {
        let conversation_id = Uuid::new_v4();
        let message = Message {
            id: Uuid::new_v4(),
            conversation_id,
            sender_id: Uuid::new_v4(),
            content: "Test".to_string(),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.conversation_id, conversation_id);
    }

    #[test]
    fn message_sender_id_preserved() {
        let sender_id = Uuid::new_v4();
        let message = Message {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_id,
            content: "Test".to_string(),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&message).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.sender_id, sender_id);
    }

    #[test]
    fn message_deserialization_from_json() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "conversation_id": "550e8400-e29b-41d4-a716-446655440001",
            "sender_id": "550e8400-e29b-41d4-a716-446655440002",
            "content": "Hello, world!",
            "created_at": "2024-01-01T00:00:00Z"
        }"#;

        let message: Message = serde_json::from_str(json).unwrap();
        assert_eq!(message.content, "Hello, world!");
        assert_eq!(
            message.conversation_id,
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap()
        );
        assert_eq!(
            message.sender_id,
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap()
        );
    }

    #[test]
    fn conversation_serialization_roundtrip() {
        let original = Conversation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: Conversation = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, original.id);
    }

    #[test]
    fn conversation_participant_serialization_roundtrip() {
        let original = ConversationParticipant {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            profile_id: Uuid::new_v4(),
            last_read_at: None,
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: ConversationParticipant = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.conversation_id, original.conversation_id);
        assert_eq!(deserialized.profile_id, original.profile_id);
    }

    #[test]
    fn conversation_participant_with_last_read_serializes() {
        let last_read = Utc::now();
        let original = ConversationParticipant {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            profile_id: Uuid::new_v4(),
            last_read_at: Some(last_read),
            created_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&original).unwrap();
        let deserialized: ConversationParticipant = serde_json::from_str(&serialized).unwrap();

        assert!(deserialized.last_read_at.is_some());
    }
}
