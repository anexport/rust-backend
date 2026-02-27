use crate::common;
use crate::ws::helpers::{
    create_valid_auth0_token, next_text_frame, test_auth0_config, StaticJwksProvider,
    StaticProvisioningService, TEST_PUBLIC_KEY_PEM,
};
use actix_web::{web, App};
use awc::ws;
use chrono::Utc;
use futures_util::SinkExt;
use jsonwebtoken::DecodingKey;
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_jwks::JwksProvider;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[actix_rt::test]
async fn test_ws_action_handlers() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let state = common::create_app_state(pool.clone());
    let user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)"
    )
    .bind(user_id)
    .bind("ws-actions@example.com")
    .bind("Actions User")
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .expect("Failed to seed user");

    sqlx::query(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)"
    )
    .bind(other_user_id)
    .bind("other@example.com")
    .bind("Other User")
    .bind(now)
    .bind(now)
    .execute(&pool)
    .await
    .expect("Failed to seed other user");

    let conv_id = Uuid::new_v4();
    sqlx::query("INSERT INTO conversations (id, created_at, updated_at) VALUES ($1, $2, $3)")
        .bind(conv_id)
        .bind(now)
        .bind(now)
        .execute(&pool)
        .await
        .expect("Failed to seed conversation");

    sqlx::query(
        "INSERT INTO conversation_participants (id, conversation_id, profile_id, created_at) VALUES ($1, $2, $3, $4)"
    )
    .bind(Uuid::new_v4())
    .bind(conv_id)
    .bind(user_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("Failed to seed participant 1");

    sqlx::query(
        "INSERT INTO conversation_participants (id, conversation_id, profile_id, created_at) VALUES ($1, $2, $3, $4)"
    )
    .bind(Uuid::new_v4())
    .bind(conv_id)
    .bind(other_user_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("Failed to seed participant 2");

    let auth0_config = test_auth0_config();
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider {
        key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap(),
    });
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(StaticProvisioningService { user_id });

    let hub = state.ws_hub.clone();
    let srv = actix_test::start(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(auth0_config.clone()))
            .app_data(web::Data::new(jwks_provider.clone()))
            .app_data(web::Data::new(provisioning_service.clone()))
            .configure(rust_backend::api::routes::ws::configure)
    });

    let token = create_valid_auth0_token("auth0|actions");
    let ws_url = srv.url(&format!("/ws?token={}", token));
    let (_response, mut client) = awc::Client::new().ws(ws_url).connect().await.unwrap();

    // Register second user in hub to receive broadcasts
    let mut other_rx = hub.register(other_user_id);

    // 1. Test Typing Event
    client
        .send(ws::Message::Text(
            json!({
                "type": "typing",
                "payload": {
                    "conversation_id": conv_id,
                    "is_typing": true
                }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let other_msg = tokio::time::timeout(Duration::from_secs(5), other_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&other_msg).unwrap();
    assert_eq!(event["type"], "typing");
    assert_eq!(event["payload"]["user_id"], user_id.to_string());
    assert_eq!(event["payload"]["is_typing"], true);

    // Consume typing event from client's own socket (sender is a participant)
    let _ = next_text_frame(&mut client).await;

    // 2. Test Message Dispatch
    client
        .send(ws::Message::Text(
            json!({
                "type": "message",
                "payload": {
                    "conversation_id": conv_id,
                    "content": "Hello via WS"
                }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    // Both users should receive the message
    let text = next_text_frame(&mut client).await;
    let event: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["type"], "message");
    assert_eq!(event["payload"]["content"], "Hello via WS");
    assert_eq!(event["payload"]["sender_id"], user_id.to_string());

    let other_msg = tokio::time::timeout(Duration::from_secs(5), other_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&other_msg).unwrap();
    assert_eq!(event["type"], "message");
    assert_eq!(event["payload"]["content"], "Hello via WS");

    // 3. Test Read Receipt
    client
        .send(ws::Message::Text(
            json!({
                "type": "read",
                "payload": {
                    "conversation_id": conv_id
                }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let other_msg = tokio::time::timeout(Duration::from_secs(5), other_rx.recv())
        .await
        .unwrap()
        .unwrap();
    let event: serde_json::Value = serde_json::from_str(&other_msg).unwrap();
    assert_eq!(event["type"], "read");
    assert_eq!(event["payload"]["user_id"], user_id.to_string());

    // Consume read receipt from client's own socket
    let _ = next_text_frame(&mut client).await;

    client.close().await.unwrap();
}
