use crate::common::fixtures;
use crate::common::TestDb;
use chrono::{Duration, Utc};
use rust_backend::domain::*;
use rust_backend::infrastructure::repositories::*;
use uuid::Uuid;

#[tokio::test]
async fn message_repository_conversation_participant_management() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    // Create conversation with multiple participants
    let participant_ids = vec![created_user1.id, created_user2.id, created_user3.id];
    let conversation = message_repo
        .create_conversation(participant_ids.clone())
        .await
        .unwrap();

    // Verify all participants are added
    let participants = message_repo
        .find_participant_ids(conversation.id)
        .await
        .unwrap();
    assert_eq!(participants.len(), 3);
    assert!(participants.contains(&created_user1.id));
    assert!(participants.contains(&created_user2.id));
    assert!(participants.contains(&created_user3.id));

    // Verify each user is a participant
    assert!(message_repo
        .is_participant(conversation.id, created_user1.id)
        .await
        .unwrap());
    assert!(message_repo
        .is_participant(conversation.id, created_user2.id)
        .await
        .unwrap());
    assert!(message_repo
        .is_participant(conversation.id, created_user3.id)
        .await
        .unwrap());

    // Verify non-participant is not in conversation
    let user4 = fixtures::test_user();
    let created_user4 = user_repo.create(&user4).await.unwrap();
    assert!(!message_repo
        .is_participant(conversation.id, created_user4.id)
        .await
        .unwrap());
}

#[tokio::test]
async fn message_repository_message_ordering() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // Create messages with different timestamps
    let base_time = Utc::now();

    let msg1 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user1.id,
        content: "First message".to_string(),
        created_at: base_time + Duration::seconds(0),
    };
    message_repo.create_message(&msg1).await.unwrap();

    let msg2 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user2.id,
        content: "Second message".to_string(),
        created_at: base_time + Duration::seconds(1),
    };
    message_repo.create_message(&msg2).await.unwrap();

    let msg3 = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user1.id,
        content: "Third message".to_string(),
        created_at: base_time + Duration::seconds(2),
    };
    message_repo.create_message(&msg3).await.unwrap();

    // Messages should be returned in DESC order by created_at (newest first)
    let messages = message_repo
        .find_messages(conversation.id, 10, 0)
        .await
        .unwrap();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0].content, "Third message");
    assert_eq!(messages[1].content, "Second message");
    assert_eq!(messages[2].content, "First message");
}

#[tokio::test]
async fn message_repository_read_receipt_updates() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // Mark as read for user1
    message_repo
        .mark_as_read(conversation.id, created_user1.id)
        .await
        .unwrap();

    // Create a message to trigger update of conversation.updated_at
    let msg = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user1.id,
        content: "Test message".to_string(),
        created_at: Utc::now(),
    };
    message_repo.create_message(&msg).await.unwrap();

    // Mark as read for user2
    message_repo
        .mark_as_read(conversation.id, created_user2.id)
        .await
        .unwrap();

    // Verify conversation updated_at is updated
    let updated_conversation = message_repo
        .find_conversation(conversation.id)
        .await
        .unwrap()
        .unwrap();
    assert!(updated_conversation.updated_at > conversation.created_at);
}

#[tokio::test]
async fn message_repository_conversation_privacy_queries() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    // User1 and User2 in conversation 1
    let conv1 = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // User1 and User3 in conversation 2
    let conv2 = message_repo
        .create_conversation(vec![created_user1.id, created_user3.id])
        .await
        .unwrap();

    // User2 and User3 in conversation 3 (User1 not in this one)
    let conv3 = message_repo
        .create_conversation(vec![created_user2.id, created_user3.id])
        .await
        .unwrap();

    // User1 should see 2 conversations
    let user1_convs = message_repo
        .find_user_conversations(created_user1.id)
        .await
        .unwrap();
    assert_eq!(user1_convs.len(), 2);
    assert!(user1_convs.iter().any(|c| c.id == conv1.id));
    assert!(user1_convs.iter().any(|c| c.id == conv2.id));
    assert!(!user1_convs.iter().any(|c| c.id == conv3.id));

    // User2 should see 2 conversations
    let user2_convs = message_repo
        .find_user_conversations(created_user2.id)
        .await
        .unwrap();
    assert_eq!(user2_convs.len(), 2);

    // User3 should see 2 conversations
    let user3_convs = message_repo
        .find_user_conversations(created_user3.id)
        .await
        .unwrap();
    assert_eq!(user3_convs.len(), 2);
}

#[tokio::test]
async fn message_repository_non_participant_access_blocked() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // User3 is not a participant
    let is_participant = message_repo
        .is_participant(conversation.id, created_user3.id)
        .await
        .unwrap();
    assert!(!is_participant);

    // User3 should not be able to send messages to this conversation
    let msg = Message {
        id: Uuid::new_v4(),
        conversation_id: conversation.id,
        sender_id: created_user3.id,
        content: "Unauthorized message".to_string(),
        created_at: Utc::now(),
    };

    // Database trigger enforces that sender must be a participant
    let result = message_repo.create_message(&msg).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn message_repository_find_conversation_nonexistent() {
    let db = TestDb::new().await.expect("Test DB required");
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    let found = message_repo
        .find_conversation(non_existent_id)
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test]
async fn message_repository_create_conversation_with_single_participant() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user.id])
        .await
        .unwrap();

    assert_eq!(conversation.id, conversation.id);

    let participants = message_repo
        .find_participant_ids(conversation.id)
        .await
        .unwrap();
    assert_eq!(participants.len(), 1);
    assert_eq!(participants[0], created_user.id);
}

#[tokio::test]
async fn message_repository_create_conversation_empty_participants_fails() {
    let db = TestDb::new().await.expect("Test DB required");
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let result = message_repo.create_conversation(vec![]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn message_repository_find_conversation_returns_existing() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user.id])
        .await
        .unwrap();

    let found = message_repo
        .find_conversation(conversation.id)
        .await
        .unwrap();
    assert!(found.is_some());
    let found_conversation = found.unwrap();
    assert_eq!(found_conversation.id, conversation.id);
}

#[tokio::test]
async fn message_repository_find_messages_pagination() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let conversation = message_repo
        .create_conversation(vec![created_user1.id, created_user2.id])
        .await
        .unwrap();

    // Create 15 messages
    for i in 0..15 {
        let msg = Message {
            id: Uuid::new_v4(),
            conversation_id: conversation.id,
            sender_id: created_user1.id,
            content: format!("Message {}", i),
            created_at: Utc::now(),
        };
        message_repo.create_message(&msg).await.unwrap();
    }

    let page1 = message_repo
        .find_messages(conversation.id, 10, 0)
        .await
        .unwrap();
    assert_eq!(page1.len(), 10);

    let page2 = message_repo
        .find_messages(conversation.id, 10, 10)
        .await
        .unwrap();
    assert_eq!(page2.len(), 5);

    let page3 = message_repo
        .find_messages(conversation.id, 10, 20)
        .await
        .unwrap();
    assert_eq!(page3.len(), 0);
}

#[tokio::test]
async fn message_repository_duplicate_conversation_returns_existing() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let participant_ids = vec![created_user1.id, created_user2.id];

    // Create first conversation
    let conv1 = message_repo
        .create_conversation(participant_ids.clone())
        .await
        .unwrap();

    // Try to create duplicate conversation with same participants
    let conv2 = message_repo
        .create_conversation(participant_ids.clone())
        .await
        .unwrap();

    // Should return the same conversation
    assert_eq!(conv1.id, conv2.id);
    assert_eq!(conv1.created_at, conv2.created_at);
}

#[tokio::test]
async fn message_repository_duplicate_conversation_different_order() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(db.pool().clone());

    let user1 = fixtures::test_user();
    let created_user1 = user_repo.create(&user1).await.unwrap();

    let user2 = fixtures::test_user();
    let created_user2 = user_repo.create(&user2).await.unwrap();

    let user3 = fixtures::test_user();
    let created_user3 = user_repo.create(&user3).await.unwrap();

    let participant_ids1 = vec![created_user1.id, created_user2.id, created_user3.id];
    let participant_ids2 = vec![created_user3.id, created_user2.id, created_user1.id];

    // Create first conversation
    let conv1 = message_repo
        .create_conversation(participant_ids1)
        .await
        .unwrap();

    // Try to create with same participants but different order
    let conv2 = message_repo
        .create_conversation(participant_ids2)
        .await
        .unwrap();

    // Should return the same conversation (sorted by ID)
    assert_eq!(conv1.id, conv2.id);
}
