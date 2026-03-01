#![allow(dead_code)]

use async_trait::async_trait;
use chrono::Utc;
use rust_backend::domain::{Conversation, Message};
use rust_backend::error::AppResult;
use rust_backend::infrastructure::repositories::MessageRepository;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Default)]
pub struct MockMessageRepo {
    pub conversations: Mutex<Vec<Conversation>>,
    pub messages: Mutex<Vec<Message>>,
    pub participants: Mutex<Vec<(Uuid, Uuid)>>,
    pub participant_limit: Mutex<usize>,
}

impl MockMessageRepo {
    pub fn add_conversation(&self, conv: Conversation) {
        self.conversations
            .lock()
            .expect("conversations mutex poisoned")
            .push(conv);
    }

    pub fn add_participant(&self, conversation_id: Uuid, user_id: Uuid) {
        self.participants
            .lock()
            .expect("participants mutex poisoned")
            .push((conversation_id, user_id));
    }

    pub fn add_message(&self, msg: Message) {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(msg);
    }

    pub fn with_limit(&self, limit: usize) {
        *self.participant_limit.lock().expect("limit mutex poisoned") = limit;
    }

    pub fn is_participant_sync(&self, conversation_id: Uuid, user_id: Uuid) -> bool {
        self.participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .any(|(cid, uid)| *cid == conversation_id && *uid == user_id)
    }
}

#[async_trait]
impl MessageRepository for MockMessageRepo {
    async fn find_conversation(&self, id: Uuid) -> AppResult<Option<Conversation>> {
        Ok(self
            .conversations
            .lock()
            .expect("conversations mutex poisoned")
            .iter()
            .find(|c| c.id == id)
            .cloned())
    }

    async fn find_user_conversations(&self, user_id: Uuid) -> AppResult<Vec<Conversation>> {
        let participants = self
            .participants
            .lock()
            .expect("participants mutex poisoned");
        let conversation_ids: Vec<Uuid> = participants
            .iter()
            .filter(|(_, uid)| *uid == user_id)
            .map(|(cid, _)| *cid)
            .collect();
        drop(participants);

        Ok(self
            .conversations
            .lock()
            .expect("conversations mutex poisoned")
            .iter()
            .filter(|c| conversation_ids.contains(&c.id))
            .cloned()
            .collect())
    }

    async fn create_conversation(&self, participant_ids: Vec<Uuid>) -> AppResult<Conversation> {
        let limit = *self.participant_limit.lock().expect("limit mutex poisoned");
        if limit > 0 && participant_ids.len() > limit {
            return Err(rust_backend::error::AppError::Conflict(format!(
                "Conversation cannot have more than {} participants",
                limit
            )));
        }

        let conversation = Conversation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let mut participants = self
            .participants
            .lock()
            .expect("participants mutex poisoned");
        for participant_id in participant_ids {
            participants.push((conversation.id, participant_id));
        }

        let mut conversations = self
            .conversations
            .lock()
            .expect("conversations mutex poisoned");
        conversations.push(conversation.clone());

        Ok(conversation)
    }

    async fn find_messages(
        &self,
        conversation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Message>> {
        let mut messages: Vec<Message> = self
            .messages
            .lock()
            .expect("messages mutex poisoned")
            .iter()
            .filter(|m| m.conversation_id == conversation_id)
            .cloned()
            .collect();

        messages.sort_unstable_by(|a, b| b.created_at.cmp(&a.created_at));
        let offset = offset.max(0) as usize;
        let limit = limit.max(0) as usize;

        Ok(messages.into_iter().skip(offset).take(limit).collect())
    }

    async fn create_message(&self, message: &Message) -> AppResult<Message> {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(message.clone());
        Ok(message.clone())
    }

    async fn find_participant_ids(&self, conversation_id: Uuid) -> AppResult<Vec<Uuid>> {
        Ok(self
            .participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .filter(|(cid, _)| *cid == conversation_id)
            .map(|(_, uid)| *uid)
            .collect())
    }

    async fn is_participant(&self, conversation_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        Ok(self
            .participants
            .lock()
            .expect("participants mutex poisoned")
            .iter()
            .any(|(cid, uid)| *cid == conversation_id && *uid == user_id))
    }

    async fn mark_as_read(&self, _conversation_id: Uuid, _user_id: Uuid) -> AppResult<()> {
        Ok(())
    }
}
