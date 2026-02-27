use super::*;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    MessageRepository, MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};

#[actix_rt::test]
async fn test_websocket_broadcast_on_send_message() {
    let test_db = common::setup_test_db().await;
    let (state, app): (AppState, _) = setup_app_with_state(test_db.pool().clone()).await;
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
    let token1 = create_auth0_token(user1.id, "renter");

    // Register user2 in WS hub to receive broadcast
    let mut rx2 = state.ws_hub.register(user2.id);

    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{}/messages", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "content": "WS test message"
        }))
        .to_request();
    let resp: actix_web::dev::ServiceResponse = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Check if user2 received the message via WS
    let ws_msg: String = tokio::time::timeout(std::time::Duration::from_secs(5), rx2.recv())
        .await
        .expect("Timeout waiting for WS broadcast")
        .expect("WS channel closed");

    let ws_payload: serde_json::Value = serde_json::from_str(&ws_msg).unwrap();
    assert_eq!(ws_payload["type"], "new_message");
    assert_eq!(ws_payload["data"]["content"], "WS test message");
}
