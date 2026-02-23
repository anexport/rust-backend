use super::traits::MessageRepository;
use crate::domain::{Conversation, Message};
use crate::error::AppResult;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

pub struct MessageRepositoryImpl {
    pool: PgPool,
}

impl MessageRepositoryImpl {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MessageRepository for MessageRepositoryImpl {
    async fn find_conversation(&self, id: Uuid) -> AppResult<Option<Conversation>> {
        let conversation = sqlx::query_as::<_, Conversation>(
            "SELECT id, created_at, updated_at FROM conversations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(conversation)
    }

    async fn find_user_conversations(&self, user_id: Uuid) -> AppResult<Vec<Conversation>> {
        let conversations = sqlx::query_as::<_, Conversation>(
            r#"
            SELECT c.id, c.created_at, c.updated_at
            FROM conversations c
            INNER JOIN conversation_participants cp ON c.id = cp.conversation_id
            WHERE cp.profile_id = $1
            ORDER BY c.updated_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(conversations)
    }

    async fn create_conversation(&self, participant_ids: Vec<Uuid>) -> AppResult<Conversation> {
        let mut tx = self.pool.begin().await?;

        let conversation: Conversation = sqlx::query_as(
            "INSERT INTO conversations (id, created_at, updated_at) VALUES (gen_random_uuid(), NOW(), NOW()) RETURNING id, created_at, updated_at"
        )
        .fetch_one(&mut *tx)
        .await?;

        for participant_id in participant_ids {
            sqlx::query(
                "INSERT INTO conversation_participants (id, conversation_id, profile_id, created_at) VALUES (gen_random_uuid(), $1, $2, NOW())"
            )
            .bind(conversation.id)
            .bind(participant_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(conversation)
    }

    async fn find_messages(
        &self,
        conversation_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> AppResult<Vec<Message>> {
        let messages = sqlx::query_as::<_, Message>(
            r#"
            SELECT id, conversation_id, sender_id, content, created_at
            FROM messages
            WHERE conversation_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(conversation_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(messages)
    }

    async fn create_message(&self, message: &Message) -> AppResult<Message> {
        let created = sqlx::query_as::<_, Message>(
            r#"
            INSERT INTO messages (id, conversation_id, sender_id, content, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, conversation_id, sender_id, content, created_at
            "#,
        )
        .bind(message.id)
        .bind(message.conversation_id)
        .bind(message.sender_id)
        .bind(&message.content)
        .bind(message.created_at)
        .fetch_one(&self.pool)
        .await?;

        sqlx::query("UPDATE conversations SET updated_at = NOW() WHERE id = $1")
            .bind(message.conversation_id)
            .execute(&self.pool)
            .await?;

        Ok(created)
    }

    async fn find_participant_ids(&self, conversation_id: Uuid) -> AppResult<Vec<Uuid>> {
        let participants = sqlx::query_scalar::<_, Uuid>(
            "SELECT profile_id FROM conversation_participants WHERE conversation_id = $1",
        )
        .bind(conversation_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(participants)
    }

    async fn is_participant(&self, conversation_id: Uuid, user_id: Uuid) -> AppResult<bool> {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM conversation_participants WHERE conversation_id = $1 AND profile_id = $2"
        )
        .bind(conversation_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }

    async fn mark_as_read(&self, conversation_id: Uuid, user_id: Uuid) -> AppResult<()> {
        sqlx::query(
            "UPDATE conversation_participants SET last_read_at = $3 WHERE conversation_id = $1 AND profile_id = $2"
        )
        .bind(conversation_id)
        .bind(user_id)
        .bind(Utc::now())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
