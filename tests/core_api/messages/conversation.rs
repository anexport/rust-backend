use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{UserRepository, UserRepositoryImpl};
use uuid::Uuid;

#[actix_rt::test]
async fn test_conversation_crud_flow() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let token1 = create_auth0_token(user1.id, "renter");

    // 1. Create conversation
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": [user2.id]
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let conv: serde_json::Value = actix_test::read_body_json(resp).await;
    let conv_id = Uuid::parse_str(conv["id"].as_str().unwrap()).unwrap();

    // 2. List conversations
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], conv_id.to_string());

    // 3. Send message
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{}/messages", conv_id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "content": "Hello there!"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. List messages
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/conversations/{}/messages", conv_id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["content"], "Hello there!");
}

#[actix_rt::test]
async fn test_create_conversation_validates_participants() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    let token1 = create_auth0_token(user1.id, "renter");

    // Try to create conversation with NO other participants
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": []
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_conversation_list_isolation() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = rust_backend::infrastructure::repositories::MessageRepositoryImpl::new(
        test_db.pool().clone(),
    );
    use rust_backend::infrastructure::repositories::MessageRepository;

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    let user3 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();
    user_repo.create(&user3).await.unwrap();

    message_repo
        .create_conversation(vec![user1.id, user2.id])
        .await
        .unwrap();
    message_repo
        .create_conversation(vec![user1.id, user3.id])
        .await
        .unwrap();

    let token2 = create_auth0_token(user2.id, "renter");

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token2)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(list.len(), 1);
}

#[actix_rt::test]
async fn test_cannot_create_conversation_with_nonexistent_user() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    let token1 = create_auth0_token(user1.id, "renter");

    let req = actix_test::TestRequest::post()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": [Uuid::new_v4()]
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert!(resp.status().is_client_error());
}

#[actix_rt::test]
async fn test_conversation_duplicate_prevention() {
    let test_db = common::setup_test_db().await;
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let token1 = create_auth0_token(user1.id, "renter");

    // First creation
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": [user2.id]
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let conv1: serde_json::Value = actix_test::read_body_json(resp).await;

    // Second creation attempt with same participants
    let req = actix_test::TestRequest::post()
        .uri("/api/v1/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": [user2.id]
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let conv2: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(conv1["id"], conv2["id"]);
}
