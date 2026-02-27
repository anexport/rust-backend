use crate::common::mocks::{MockMessageRepo, MockUserRepo};
use crate::message::helpers::{service, service_with_limit, test_user};
use actix_rt::test;
use chrono::Duration;
use chrono::Utc;
use rust_backend::api::dtos::CreateConversationRequest;
use rust_backend::domain::Conversation;
use rust_backend::domain::Role;
use rust_backend::error::AppError;
use rust_backend::infrastructure::repositories::UserRepository;
use std::sync::Arc;
use uuid::Uuid;

#[test]
async fn create_conversation_adds_creator_if_not_in_participants() {
    let (user_repo, message_repo, service): (Arc<MockUserRepo>, Arc<MockMessageRepo>, _) =
        service();

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
