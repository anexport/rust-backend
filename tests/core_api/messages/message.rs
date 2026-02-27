use super::setup_app;
use crate::common;
use actix_web::test as actix_test;
use chrono::{Duration, Utc};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    MessageRepository, MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn test_message_pagination() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let conv = message_repo
        .create_conversation(vec![user1.id, user2.id])
        .await
        .unwrap();

    // Create 5 messages
    for i in 0..5 {
        message_repo
            .create_message(&rust_backend::domain::Message {
                id: Uuid::new_v4(),
                conversation_id: conv.id,
                sender_id: user1.id,
                content: format!("Message {}", i),
                created_at: Utc::now() + Duration::seconds(i),
            })
            .await
            .unwrap();
    }

    let token1 = create_auth0_token(user1.id, "renter");

    // Get first 2 messages
    let req = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/conversations/{}/messages?limit=2&offset=0",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 2);
    // Messages should be newest first
    assert_eq!(messages[0]["content"], "Message 4");
    assert_eq!(messages[1]["content"], "Message 3");
}

#[actix_rt::test]
async fn test_message_list_ordering() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let conv = message_repo
        .create_conversation(vec![user1.id, user2.id])
        .await
        .unwrap();

    // Create 5 messages with different timestamps (oldest first)
    for i in 0..5 {
        message_repo
            .create_message(&rust_backend::domain::Message {
                id: Uuid::new_v4(),
                conversation_id: conv.id,
                sender_id: user1.id,
                content: format!("Message {}", i),
                created_at: Utc::now() - Duration::hours(5 - i),
            })
            .await
            .unwrap();
    }

    let token1 = create_auth0_token(user1.id, "renter");

    // List messages and assert newest first
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/conversations/{}/messages", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 5);
    assert_eq!(messages[0]["content"], "Message 4");
    assert_eq!(messages[4]["content"], "Message 0");
}

#[actix_rt::test]
async fn test_pagination_edge_cases() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let conv = message_repo
        .create_conversation(vec![user1.id, user2.id])
        .await
        .unwrap();

    // Create exactly 10 messages
    for i in 0..10 {
        message_repo
            .create_message(&rust_backend::domain::Message {
                id: Uuid::new_v4(),
                conversation_id: conv.id,
                sender_id: user1.id,
                content: format!("Message {}", i),
                created_at: Utc::now() + Duration::seconds(i),
            })
            .await
            .unwrap();
    }

    let token1 = create_auth0_token(user1.id, "renter");

    // Test page 1 with limit 10 - should return all 10 messages
    let req = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/conversations/{}/messages?limit=10&offset=0",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 10);

    // Test page 2 with limit 10 - should return empty array (no more messages)
    let req = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/conversations/{}/messages?limit=10&offset=10",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 0);

    // Test negative offset - should return 400 Bad Request
    let req = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/conversations/{}/messages?limit=10&offset=-1",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
}
