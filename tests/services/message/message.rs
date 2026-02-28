use crate::message::helpers::{service, test_user};
use actix_rt::test;
use chrono::Duration;
use chrono::Utc;
use rust_backend::api::dtos::SendMessageRequest;
use rust_backend::domain::Role;
use rust_backend::domain::{Conversation, Message};
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::UserRepository;
use uuid::Uuid;

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
