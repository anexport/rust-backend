use std::sync::Arc;

use chrono::Utc;
use tracing::info;
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{
    ConversationResponse, CreateConversationRequest, MessageResponse, ParticipantResponse,
    SendMessageRequest,
};
use crate::domain::{Message, Role};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::{MessageRepository, UserRepository};

#[derive(Clone)]
pub struct MessageService {
    user_repo: Arc<dyn UserRepository>,
    message_repo: Arc<dyn MessageRepository>,
}

impl MessageService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        message_repo: Arc<dyn MessageRepository>,
    ) -> Self {
        Self {
            user_repo,
            message_repo,
        }
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
        if !self.can_access_conversation(user_id, id).await? {
            return Err(AppError::Forbidden(
                "You are not a participant in this conversation".to_string(),
            ));
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
            .can_access_conversation(user_id, conversation_id)
            .await?
        {
            return Err(AppError::Forbidden(
                "You are not a participant in this conversation".to_string(),
            ));
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
        let (created, _) = self
            .send_message_with_participants(user_id, conversation_id, request)
            .await?;
        Ok(created)
    }

    pub async fn send_message_with_participants(
        &self,
        user_id: Uuid,
        conversation_id: Uuid,
        request: SendMessageRequest,
    ) -> AppResult<(MessageResponse, Vec<Uuid>)> {
        request.validate()?;
        let participant_ids = self
            .authorized_participant_ids(user_id, conversation_id)
            .await?;

        let message = Message {
            id: Uuid::new_v4(),
            conversation_id,
            sender_id: user_id,
            content: request.content,
            created_at: Utc::now(),
        };

        let created = self.message_repo.create_message(&message).await?;
        Ok((
            MessageResponse {
                id: created.id,
                conversation_id: created.conversation_id,
                sender_id: created.sender_id,
                sender_name: None,
                content: created.content,
                created_at: created.created_at,
            },
            participant_ids,
        ))
    }

    pub async fn mark_as_read(&self, user_id: Uuid, conversation_id: Uuid) -> AppResult<()> {
        if !self
            .can_access_conversation(user_id, conversation_id)
            .await?
        {
            return Err(AppError::Forbidden(
                "You are not a participant in this conversation".to_string(),
            ));
        }

        self.message_repo
            .mark_as_read(conversation_id, user_id)
            .await
    }

    pub async fn participant_ids(
        &self,
        user_id: Uuid,
        conversation_id: Uuid,
    ) -> AppResult<Vec<Uuid>> {
        self.authorized_participant_ids(user_id, conversation_id)
            .await
    }

    async fn authorized_participant_ids(
        &self,
        user_id: Uuid,
        conversation_id: Uuid,
    ) -> AppResult<Vec<Uuid>> {
        let participant_ids = self
            .message_repo
            .find_participant_ids(conversation_id)
            .await?;

        if participant_ids.contains(&user_id) {
            return Ok(participant_ids);
        }

        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if user.role == Role::Admin {
            info!(
                actor_user_id = %user_id,
                conversation_id = %conversation_id,
                "admin override: conversation access"
            );
            return Ok(participant_ids);
        }

        Err(AppError::Forbidden(
            "You are not a participant in this conversation".to_string(),
        ))
    }

    async fn can_access_conversation(
        &self,
        user_id: Uuid,
        conversation_id: Uuid,
    ) -> AppResult<bool> {
        if self
            .message_repo
            .is_participant(conversation_id, user_id)
            .await?
        {
            return Ok(true);
        }

        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if user.role == Role::Admin {
            info!(
                actor_user_id = %user_id,
                conversation_id = %conversation_id,
                "admin override: conversation access"
            );
            return Ok(true);
        }
        Ok(false)
    }
}
