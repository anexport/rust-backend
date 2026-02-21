use std::sync::Mutex;

use async_trait::async_trait;
use chrono::Utc;
use rust_backend::api::dtos::SendMessageRequest;
use rust_backend::application::MessageService;
use rust_backend::domain::{Conversation, Message, Role, User};
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::{MessageRepository, UserRepository};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<Vec<User>>,
}

#[async_trait]
impl UserRepository for MockUserRepo {
    async fn find_by_id(&self, id: Uuid) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|u| u.id == id)
            .cloned())
    }

    async fn find_by_email(&self, _email: &str) -> rust_backend::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn find_by_username(
        &self,
        _username: &str,
    ) -> rust_backend::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn create(&self, user: &User) -> rust_backend::error::AppResult<User> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .push(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> rust_backend::error::AppResult<User> {
        Ok(user.clone())
    }

    async fn delete(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

struct MockMessageRepo {
    conversation: Conversation,
    participant_user_id: Uuid,
}

#[async_trait]
impl MessageRepository for MockMessageRepo {
    async fn find_conversation(
        &self,
        id: Uuid,
    ) -> rust_backend::error::AppResult<Option<Conversation>> {
        if id == self.conversation.id {
            Ok(Some(self.conversation.clone()))
        } else {
            Ok(None)
        }
    }

    async fn find_user_conversations(
        &self,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Conversation>> {
        Ok(vec![self.conversation.clone()])
    }

    async fn create_conversation(
        &self,
        _participant_ids: Vec<Uuid>,
    ) -> rust_backend::error::AppResult<Conversation> {
        Ok(self.conversation.clone())
    }

    async fn find_messages(
        &self,
        _conversation_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Message>> {
        Ok(Vec::new())
    }

    async fn create_message(&self, message: &Message) -> rust_backend::error::AppResult<Message> {
        Ok(message.clone())
    }

    async fn is_participant(
        &self,
        conversation_id: Uuid,
        user_id: Uuid,
    ) -> rust_backend::error::AppResult<bool> {
        Ok(conversation_id == self.conversation.id && user_id == self.participant_user_id)
    }

    async fn mark_as_read(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

#[actix_rt::test]
async fn non_participant_renter_cannot_send_message() {
    let conversation_id = Uuid::new_v4();
    let participant_id = Uuid::new_v4();
    let renter_id = Uuid::new_v4();

    let user_repo = std::sync::Arc::new(MockUserRepo::default());
    user_repo
        .users
        .lock()
        .expect("users mutex poisoned")
        .push(User {
            id: renter_id,
            email: "renter@example.com".to_string(),
            role: Role::Renter,
            username: Some("renter".to_string()),
            full_name: Some("Renter".to_string()),
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let message_repo = std::sync::Arc::new(MockMessageRepo {
        conversation: Conversation {
            id: conversation_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        participant_user_id: participant_id,
    });

    let service = MessageService::new(user_repo, message_repo);
    let result = service
        .send_message(
            renter_id,
            conversation_id,
            SendMessageRequest {
                content: "hello".to_string(),
            },
        )
        .await;

    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[actix_rt::test]
async fn admin_can_send_message_without_being_participant() {
    let conversation_id = Uuid::new_v4();
    let participant_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    let user_repo = std::sync::Arc::new(MockUserRepo::default());
    user_repo
        .users
        .lock()
        .expect("users mutex poisoned")
        .push(User {
            id: admin_id,
            email: "admin@example.com".to_string(),
            role: Role::Admin,
            username: Some("admin".to_string()),
            full_name: Some("Admin".to_string()),
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let message_repo = std::sync::Arc::new(MockMessageRepo {
        conversation: Conversation {
            id: conversation_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        participant_user_id: participant_id,
    });

    let service = MessageService::new(user_repo, message_repo);
    let result = service
        .send_message(
            admin_id,
            conversation_id,
            SendMessageRequest {
                content: "admin-note".to_string(),
            },
        )
        .await;

    assert!(result.is_ok());
}

#[actix_rt::test]
async fn non_participant_renter_cannot_get_conversation() {
    let conversation_id = Uuid::new_v4();
    let participant_id = Uuid::new_v4();
    let renter_id = Uuid::new_v4();

    let user_repo = std::sync::Arc::new(MockUserRepo::default());
    user_repo
        .users
        .lock()
        .expect("users mutex poisoned")
        .push(User {
            id: renter_id,
            email: "renter2@example.com".to_string(),
            role: Role::Renter,
            username: Some("renter2".to_string()),
            full_name: Some("Renter2".to_string()),
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let message_repo = std::sync::Arc::new(MockMessageRepo {
        conversation: Conversation {
            id: conversation_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        participant_user_id: participant_id,
    });

    let service = MessageService::new(user_repo, message_repo);
    let result = service.get_conversation(renter_id, conversation_id).await;

    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[actix_rt::test]
async fn admin_can_get_conversation_without_being_participant() {
    let conversation_id = Uuid::new_v4();
    let participant_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();

    let user_repo = std::sync::Arc::new(MockUserRepo::default());
    user_repo
        .users
        .lock()
        .expect("users mutex poisoned")
        .push(User {
            id: admin_id,
            email: "admin2@example.com".to_string(),
            role: Role::Admin,
            username: Some("admin2".to_string()),
            full_name: Some("Admin2".to_string()),
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let message_repo = std::sync::Arc::new(MockMessageRepo {
        conversation: Conversation {
            id: conversation_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        participant_user_id: participant_id,
    });

    let service = MessageService::new(user_repo, message_repo);
    let result = service.get_conversation(admin_id, conversation_id).await;

    assert!(result.is_ok());
}

struct PersistingMessageRepo {
    conversation: Conversation,
    participant_user_id: Uuid,
    messages: Mutex<Vec<Message>>,
}

#[async_trait]
impl MessageRepository for PersistingMessageRepo {
    async fn find_conversation(
        &self,
        id: Uuid,
    ) -> rust_backend::error::AppResult<Option<Conversation>> {
        if id == self.conversation.id {
            Ok(Some(self.conversation.clone()))
        } else {
            Ok(None)
        }
    }

    async fn find_user_conversations(
        &self,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<Vec<Conversation>> {
        Ok(vec![self.conversation.clone()])
    }

    async fn create_conversation(
        &self,
        _participant_ids: Vec<Uuid>,
    ) -> rust_backend::error::AppResult<Conversation> {
        Ok(self.conversation.clone())
    }

    async fn find_messages(
        &self,
        conversation_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> rust_backend::error::AppResult<Vec<Message>> {
        Ok(self
            .messages
            .lock()
            .expect("messages mutex poisoned")
            .iter()
            .filter(|message| message.conversation_id == conversation_id)
            .cloned()
            .collect())
    }

    async fn create_message(&self, message: &Message) -> rust_backend::error::AppResult<Message> {
        self.messages
            .lock()
            .expect("messages mutex poisoned")
            .push(message.clone());
        Ok(message.clone())
    }

    async fn is_participant(
        &self,
        conversation_id: Uuid,
        user_id: Uuid,
    ) -> rust_backend::error::AppResult<bool> {
        Ok(conversation_id == self.conversation.id && user_id == self.participant_user_id)
    }

    async fn mark_as_read(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }
}

#[actix_rt::test]
async fn message_saved_is_recoverable_via_list_messages() {
    let user_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();

    let user_repo = Arc::new(MockUserRepo::default());
    user_repo
        .users
        .lock()
        .expect("users mutex poisoned")
        .push(User {
            id: user_id,
            email: "recover@example.com".to_string(),
            role: Role::Renter,
            username: Some("recover".to_string()),
            full_name: Some("Recover User".to_string()),
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });

    let message_repo = Arc::new(PersistingMessageRepo {
        conversation: Conversation {
            id: conversation_id,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        participant_user_id: user_id,
        messages: Mutex::new(Vec::new()),
    });

    let service = MessageService::new(user_repo, message_repo);
    service
        .send_message(
            user_id,
            conversation_id,
            SendMessageRequest {
                content: "persist me".to_string(),
            },
        )
        .await
        .expect("message should be persisted");

    let recovered = service
        .list_messages(user_id, conversation_id, 50, 0)
        .await
        .expect("messages should be retrievable");
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].content, "persist me");
}
