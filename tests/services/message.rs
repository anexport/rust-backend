#![allow(unused_imports)]
use std::sync::Arc;

use super::*;
use crate::common;

use crate::common::mocks::{MockMessageRepo, MockUserRepo};
use actix_rt::test;
use chrono::{Duration, Utc};
use rust_backend::api::dtos::{CreateConversationRequest, SendMessageRequest};
use rust_backend::application::MessageService;
use rust_backend::domain::{Conversation, Message, Role, User};
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::{MessageRepository, UserRepository};
use uuid::Uuid;

fn test_user(id: Uuid, role: Role) -> User {
    User {
        id,
        email: format!("user-{}@example.com", id),
        role,
        username: Some(format!("user-{}", id)),
        full_name: Some(format!("User {}", id)),
        avatar_url: None,
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now(),
    }
}

fn service_with_limit(
    participant_limit: usize,
) -> (Arc<MockUserRepo>, Arc<MockMessageRepo>, MessageService) {
    let user_repo = Arc::new(MockUserRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    message_repo.with_limit(participant_limit);
    let service = MessageService::new(user_repo.clone(), message_repo.clone());
    (user_repo, message_repo, service)
}

fn service() -> (Arc<MockUserRepo>, Arc<MockMessageRepo>, MessageService) {
    service_with_limit(100)
}

#[test]
async fn create_conversation_adds_creator_if_not_in_participants() {
    let (_, _, service) = service();

    let creator_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    let request = CreateConversationRequest {
        participant_ids: vec![other_id],
    };

    let result = service
        .create_conversation(creator_id, request)
        .await
        .expect("create conversation should succeed");

    let participants = service
        .participant_ids(creator_id, result.id)
        .await
        .expect("should get participant ids");

    assert_eq!(participants.len(), 2);
    assert!(participants.contains(&creator_id));
    assert!(participants.contains(&other_id));
}

#[test]
async fn create_conversation_validates_min_participants() {
    let (_, _, service) = service();

    let user_id = Uuid::new_v4();

    let request = CreateConversationRequest {
        participant_ids: vec![],
    };

    let result = service.create_conversation(user_id, request).await;
    assert!(result.is_err());
}

#[test]
async fn create_conversation_enforces_participant_limit() {
    let (_, _message_repo, service) = service_with_limit(5);

    let creator_id = Uuid::new_v4();
    let participants: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();

    let request = CreateConversationRequest {
        participant_ids: participants.clone(),
    };

    let result = service.create_conversation(creator_id, request).await;

    assert!(result.is_err());
}

#[test]
async fn send_message_validates_content_length() {
    let (_, _, service) = service();

    let user_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();

    let request = SendMessageRequest {
        content: "a".to_string(),
    };

    let result = service
        .send_message(user_id, conversation_id, request)
        .await;
    assert!(result.is_err());

    let long_content = "x".repeat(5001);
    let long_request = SendMessageRequest {
        content: long_content,
    };

    let long_result = service
        .send_message(user_id, conversation_id, long_request)
        .await;
    assert!(long_result.is_err());
}

#[test]
async fn send_message_rejects_non_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let request = SendMessageRequest {
        content: "Hello".to_string(),
    };

    let result = service
        .send_message(user_id, conversation.id, request)
        .await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[test]
async fn send_message_allows_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();

    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, user_id);

    let request = SendMessageRequest {
        content: "Hello, world!".to_string(),
    };

    let result = service
        .send_message(user_id, conversation.id, request)
        .await;

    assert!(result.is_ok());
    let message_response = result.unwrap();
    assert_eq!(message_response.content, "Hello, world!");
    assert_eq!(message_response.sender_id, user_id);
    assert_eq!(message_response.conversation_id, conversation.id);
}

#[test]
async fn send_message_allows_admin_non_participant() {
    let (user_repo, message_repo, service) = service();

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(admin_id, Role::Admin))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let request = SendMessageRequest {
        content: "Admin message".to_string(),
    };

    let result = service
        .send_message(admin_id, conversation.id, request)
        .await;

    assert!(result.is_ok());
}

#[test]
async fn list_messages_returns_ordered_by_creation_time() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, user_id);

    let now = Utc::now();

    let msg1 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: user_id,
        content: "First message".to_string(),
        created_at: now - Duration::minutes(10),
    };
    let msg2 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: user_id,
        content: "Second message".to_string(),
        created_at: now - Duration::minutes(5),
    };
    let msg3 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: user_id,
        content: "Third message".to_string(),
        created_at: now,
    };

    message_repo.messages.lock().unwrap().push(msg1.clone());
    message_repo.messages.lock().unwrap().push(msg3.clone());
    message_repo.messages.lock().unwrap().push(msg2.clone());

    let result = service
        .list_messages(user_id, conversation.id, 10, 0)
        .await
        .expect("list messages should succeed");

    assert_eq!(result.len(), 3);
}

#[test]
async fn list_messages_rejects_non_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.list_messages(user_id, conversation.id, 10, 0).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[test]
async fn list_messages_allows_admin_non_participant() {
    let (user_repo, message_repo, service) = service();

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(admin_id, Role::Admin))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service
        .list_messages(admin_id, conversation.id, 10, 0)
        .await;

    assert!(result.is_ok());
}

#[test]
async fn get_conversation_rejects_non_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.get_conversation(user_id, conversation.id).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[test]
async fn get_conversation_allows_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, user_id);

    let result = service
        .get_conversation(user_id, conversation.id)
        .await
        .expect("get conversation should succeed");

    assert_eq!(result.id, conversation.id);
}

#[test]
async fn get_conversation_allows_admin_non_participant() {
    let (user_repo, message_repo, service) = service();

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(admin_id, Role::Admin))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.get_conversation(admin_id, conversation.id).await;

    assert!(result.is_ok());
}

#[test]
async fn list_conversations_returns_only_user_conversations() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conv1 = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now() - Duration::hours(2),
        updated_at: Utc::now() - Duration::hours(2),
    };
    let conv2 = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now() - Duration::hours(1),
        updated_at: Utc::now() - Duration::hours(1),
    };
    let conv3 = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conv1.clone());
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conv2.clone());
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conv3.clone());

    message_repo.add_participant(conv1.id, user_id);
    message_repo.add_participant(conv2.id, user_id);
    message_repo.add_participant(conv3.id, other_id);

    let result = service
        .list_conversations(user_id)
        .await
        .expect("list conversations should succeed");

    assert_eq!(result.len(), 2);
    assert!(result.iter().any(|c| c.id == conv1.id));
    assert!(result.iter().any(|c| c.id == conv2.id));
    assert!(!result.iter().any(|c| c.id == conv3.id));
}

#[test]
async fn mark_as_read_allows_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, user_id);

    let result = service.mark_as_read(user_id, conversation.id).await;
    assert!(result.is_ok());
}

#[test]
async fn mark_as_read_rejects_non_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.mark_as_read(user_id, conversation.id).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[test]
async fn mark_as_read_allows_admin_non_participant() {
    let (user_repo, message_repo, service) = service();

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(admin_id, Role::Admin))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.mark_as_read(admin_id, conversation.id).await;
    assert!(result.is_ok());
}

#[test]
async fn participant_ids_allows_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, user_id);

    let result = service
        .participant_ids(user_id, conversation.id)
        .await
        .expect("get participant ids should succeed");

    assert!(result.contains(&user_id));
}

#[test]
async fn participant_ids_rejects_non_participant() {
    let (user_repo, message_repo, service) = service();

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(user_id, Role::Renter))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.participant_ids(user_id, conversation.id).await;
    assert!(matches!(result, Err(AppError::Forbidden(_))));
}

#[test]
async fn participant_ids_allows_admin_non_participant() {
    let (user_repo, message_repo, service) = service();

    let admin_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo
        .create(&test_user(admin_id, Role::Admin))
        .await
        .unwrap();

    let conversation = Conversation {
        id: Uuid::new_v4(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    message_repo
        .conversations
        .lock()
        .unwrap()
        .push(conversation.clone());
    message_repo.add_participant(conversation.id, other_id);

    let result = service.participant_ids(admin_id, conversation.id).await;
    assert!(result.is_ok());
}
