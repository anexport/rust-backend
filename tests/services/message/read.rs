use crate::common::mocks::{MockMessageRepo, MockUserRepo};
use crate::message::helpers::{service, test_user};
use actix_rt::test;
use chrono::Utc;
use rust_backend::domain::Conversation;
use rust_backend::domain::Role;
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::UserRepository;
use std::sync::Arc;
use uuid::Uuid;

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
