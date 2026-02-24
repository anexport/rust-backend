use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateConversationRequest {
    #[validate(length(min = 1, message = "at least one participant is required"))]
    pub participant_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SendMessageRequest {
    #[validate(length(min = 1, max = 5000))]
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ConversationResponse {
    pub id: Uuid,
    pub participants: Vec<ParticipantResponse>,
    pub last_message: Option<MessageResponse>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ParticipantResponse {
    pub user_id: Uuid,
    pub username: Option<String>,
    pub avatar_url: Option<String>,
    pub last_read_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MessageResponse {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub sender_id: Uuid,
    pub sender_name: Option<String>,
    pub content: String,
    pub created_at: DateTime<Utc>,
}
