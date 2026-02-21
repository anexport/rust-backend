use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{
    ConversationResponse, CreateConversationRequest, MessageResponse, ParticipantResponse,
    SendMessageRequest,
};
use crate::domain::Message;
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::MessageRepository;

#[derive(Clone)]
pub struct MessageService {
    message_repo: Arc<dyn MessageRepository>,
}

impl MessageService {
    pub fn new(message_repo: Arc<dyn MessageRepository>) -> Self {
        Self { message_repo }
    }

    pub async fn list_conversations(&self, user_id: Uuid) -> AppResult<Vec<ConversationResponse>> {
        let conversations = self.message_repo.find_user_conversations(user_id).await?;

        Ok(conversations
            .into_iter()
            .map(|conversation| ConversationResponse {
                id: conversation.id,
                participants: Vec::<ParticipantResponse>::new(),
                last_message: None,
                created_at: conversation.created_at,
                updated_at: conversation.updated_at,
            })
            .collect())
    }

    pub async fn create_conversation(
        &self,
        user_id: Uuid,
        mut request: CreateConversationRequest,
    ) -> AppResult<ConversationResponse> {
        request.validate()?;

        if !request.participant_ids.contains(&user_id) {
            request.participant_ids.push(user_id);
        }

        let conversation = self
            .message_repo
            .create_conversation(request.participant_ids)
            .await?;

        Ok(ConversationResponse {
            id: conversation.id,
            participants: Vec::new(),
            last_message: None,
            created_at: conversation.created_at,
            updated_at: conversation.updated_at,
        })
    }

    pub async fn get_conversation(
        &self,
        user_id: Uuid,
        id: Uuid,
    ) -> AppResult<ConversationResponse> {
        let is_participant = self.message_repo.is_participant(id, user_id).await?;
        if !is_participant {
            return Err(AppError::Forbidden("not a participant".to_string()));
        }

        let conversation = self
            .message_repo
            .find_conversation(id)
            .await?
            .ok_or_else(|| AppError::NotFound("conversation not found".to_string()))?;

        Ok(ConversationResponse {
            id: conversation.id,
            participants: Vec::new(),
            last_message: None,
            created_at: conversation.created_at,
            updated_at: conversation.updated_at,
        })
    }

    pub async fn list_messages(
        &self,
        user_id: Uuid,
        conversation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<MessageResponse>> {
        if !self
            .message_repo
            .is_participant(conversation_id, user_id)
            .await?
        {
            return Err(AppError::Forbidden("not a participant".to_string()));
        }

        let messages = self
            .message_repo
            .find_messages(conversation_id, limit, offset)
            .await?;

        Ok(messages
            .into_iter()
            .map(|message| MessageResponse {
                id: message.id,
                conversation_id: message.conversation_id,
                sender_id: message.sender_id,
                sender_name: None,
                content: message.content,
                created_at: message.created_at,
            })
            .collect())
    }

    pub async fn send_message(
        &self,
        user_id: Uuid,
        conversation_id: Uuid,
        request: SendMessageRequest,
    ) -> AppResult<MessageResponse> {
        request.validate()?;

        if !self
            .message_repo
            .is_participant(conversation_id, user_id)
            .await?
        {
            return Err(AppError::Forbidden("not a participant".to_string()));
        }

        let message = Message {
            id: Uuid::new_v4(),
            conversation_id,
            sender_id: user_id,
            content: request.content,
            created_at: Utc::now(),
        };

        let created = self.message_repo.create_message(&message).await?;
        Ok(MessageResponse {
            id: created.id,
            conversation_id: created.conversation_id,
            sender_id: created.sender_id,
            sender_name: None,
            content: created.content,
            created_at: created.created_at,
        })
    }
}
