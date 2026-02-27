use super::*;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    MessageRepository, MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn test_non_participant_cannot_view_conversation() {
    let test_db = common::setup_test_db().await;
    let (_, app): (AppState, _) = setup_app_with_state(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    let user3 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();
    user_repo.create(&user3).await.unwrap();

    let conv = message_repo
        .create_conversation(vec![user1.id, user2.id])
        .await
        .unwrap();
    let token3 = create_auth0_token(user3.id, "renter");

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/conversations/{}", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token3)))
        .to_request();
    let resp: actix_web::dev::ServiceResponse = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_non_participant_cannot_send_message() {
    let test_db = common::setup_test_db().await;
    let (_, app): (AppState, _) = setup_app_with_state(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    let user3 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();
    user_repo.create(&user3).await.unwrap();

    let conv = message_repo
        .create_conversation(vec![user1.id, user2.id])
        .await
        .unwrap();
    let token3 = create_auth0_token(user3.id, "renter");

    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{}/messages", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token3)))
        .set_json(serde_json::json!({
            "content": "Trying to intrude"
        }))
        .to_request();
    let resp: actix_web::dev::ServiceResponse = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
