use std::sync::Arc;
use std::time::Duration;

use actix_web::{web, App};
use awc::ws;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::json;
use uuid::Uuid;

use rust_backend::config::Auth0Config;
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_backend::utils::auth0_jwks::JwksProvider;

use super::*;
use crate::common;

const TEST_PRIVATE_KEY_PEM: &str = include_str!("../test_private_key.pem");
const TEST_PUBLIC_KEY_PEM: &str = include_str!("../test_public_key.pem");

struct StaticJwksProvider {
    key: DecodingKey,
}

#[async_trait::async_trait]
impl JwksProvider for StaticJwksProvider {
    async fn get_decoding_key(&self, _kid: &str) -> rust_backend::error::AppResult<DecodingKey> {
        Ok(self.key.clone())
    }
}

struct StaticProvisioningService {
    user_id: Uuid,
}

#[async_trait::async_trait]
impl UserProvisioningService for StaticProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        Ok(Auth0UserContext {
            user_id: self.user_id,
            auth0_sub: claims.sub.clone(),
            role: "renter".to_string(),
            email: claims.email.clone(),
        })
    }
}

fn create_valid_auth0_token(sub: &str) -> String {
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("test-audience".to_string()),
        exp: (Utc::now() + chrono::Duration::minutes(5)).timestamp() as u64,
        iat: (Utc::now() - chrono::Duration::minutes(1)).timestamp() as u64,
        email: Some("ws-user@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Ws User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("ws-test-kid".to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes())
            .expect("private test key should parse"),
    )
    .expect("valid RS256 auth0 token should encode")
}

fn test_auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: Some("test-audience".to_string()),
        auth0_issuer: Some("https://test.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: None,
        auth0_client_secret: None,
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

async fn next_text_frame<S, E>(client: &mut S) -> String
where
    S: futures_util::Stream<Item = Result<ws::Frame, E>> + Unpin,
    E: std::fmt::Debug,
{
    let frame = tokio::time::timeout(Duration::from_secs(5), client.next())
        .await
        .expect("Timeout waiting for WebSocket frame")
        .expect("WebSocket stream closed prematurely")
        .expect("WebSocket stream error");

    match frame {
        ws::Frame::Text(text) => std::str::from_utf8(&text).unwrap().to_string(),
        ws::Frame::Ping(_) => {
            // If it's a ping, we recursively wait for the next frame
            // In a real app we'd respond to pings, but here we just want the text
            Box::pin(next_text_frame(client)).await
        }
        other => panic!("Expected text frame, got {:?}", other),
    }
}

#[actix_rt::test]
async fn test_ws_connection_initialization_and_auth() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let state = common::create_app_state(pool.clone());
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)",
        user_id,
        "ws-user@example.com",
        "Ws User",
        now,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed user");

    let auth0_config = test_auth0_config();

    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider {
        key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
            .expect("public test key should parse"),
    });

    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(StaticProvisioningService { user_id });

    let srv = actix_test::start(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(auth0_config.clone()))
            .app_data(web::Data::new(jwks_provider.clone()))
            .app_data(web::Data::new(provisioning_service.clone()))
            .configure(rust_backend::api::routes::ws::configure)
    });

    let token = create_valid_auth0_token("auth0|ws-user");

    // 1. Test successful upgrade (via query param)
    let ws_url = srv.url(&format!("/ws?token={}", token));
    let (_response, mut client) = awc::Client::new()
        .ws(ws_url)
        .connect()
        .await
        .expect("Failed to connect to WS");

    client
        .send(ws::Message::Text(r#"{"type":"ping","payload":{}}"#.into()))
        .await
        .unwrap();
    let text = next_text_frame(&mut client).await;
    let resp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(resp["type"], "pong");

    client.close().await.unwrap();

    // 2. Test rejected upgrade (missing token)
    let err = awc::Client::new().ws(srv.url("/ws")).connect().await;
    assert!(err.is_err());
}

#[actix_rt::test]
async fn test_ws_ping_pong_heartbeat() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let state = common::create_app_state(pool.clone());
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)",
        user_id,
        "ws-heartbeat@example.com",
        "Heartbeat User",
        now,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed user");

    let auth0_config = test_auth0_config();
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider {
        key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap(),
    });
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(StaticProvisioningService { user_id });

    let srv = actix_test::start(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(auth0_config.clone()))
            .app_data(web::Data::new(jwks_provider.clone()))
            .app_data(web::Data::new(provisioning_service.clone()))
            .configure(rust_backend::api::routes::ws::configure)
    });

    let token = create_valid_auth0_token("auth0|heartbeat");
    let ws_url = srv.url(&format!("/ws?token={}", token));
    let (_response, mut client) = awc::Client::new().ws(ws_url).connect().await.unwrap();

    // Test application-level ping
    client
        .send(ws::Message::Text(r#"{"type":"ping","payload":{}}"#.into()))
        .await
        .unwrap();
    let text = next_text_frame(&mut client).await;
    let resp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(resp["type"], "pong");

    // Test protocol-level ping
    client
        .send(ws::Message::Ping("hello".into()))
        .await
        .unwrap();

    let mut pong_received = false;
    for _ in 0..5 {
        let msg = tokio::time::timeout(Duration::from_secs(5), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        match msg {
            ws::Frame::Pong(bytes) => {
                assert_eq!(bytes, "hello");
                pong_received = true;
                break;
            }
            ws::Frame::Ping(_) => {
                // Ignore server heartbeats (e.g. Ping(b"ping"))
                continue;
            }
            _ => panic!("Expected pong or ping message, got {:?}", msg),
        }
    }
    assert!(pong_received, "Did not receive expected Pong message");

    client.close().await.unwrap();
}

#[actix_rt::test]
async fn test_ws_action_handlers() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let state = common::create_app_state(pool.clone());
    let user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)",
        user_id,
        "ws-actions@example.com",
        "Actions User",
        now,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed user");

    sqlx::query!(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)",
        other_user_id,
        "other@example.com",
        "Other User",
        now,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed other user");

    let conv_id = Uuid::new_v4();
    sqlx::query!(
        "INSERT INTO conversations (id, created_at, updated_at) VALUES ($1, $2, $3)",
        conv_id,
        now,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed conversation");

    sqlx::query!(
        "INSERT INTO conversation_participants (id, conversation_id, profile_id, created_at) VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        conv_id,
        user_id,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed participant 1");

    sqlx::query!(
        "INSERT INTO conversation_participants (id, conversation_id, profile_id, created_at) VALUES ($1, $2, $3, $4)",
        Uuid::new_v4(),
        conv_id,
        other_user_id,
        now
    )
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

#[actix_rt::test]
async fn test_ws_error_handling() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let state = common::create_app_state(pool.clone());
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query!(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)",
        user_id,
        "ws-errors@example.com",
        "Error User",
        now,
        now
    )
    .execute(&pool)
    .await
    .expect("Failed to seed user");

    let auth0_config = test_auth0_config();
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider {
        key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap(),
    });
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(StaticProvisioningService { user_id });

    let srv = actix_test::start(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(auth0_config.clone()))
            .app_data(web::Data::new(jwks_provider.clone()))
            .app_data(web::Data::new(provisioning_service.clone()))
            .configure(rust_backend::api::routes::ws::configure)
    });

    let token = create_valid_auth0_token("auth0|errors");
    let ws_url = srv.url(&format!("/ws?token={}", token));
    let (_response, mut client) = awc::Client::new().ws(ws_url).connect().await.unwrap();

    // 1. Unknown type
    client
        .send(ws::Message::Text(
            json!({
                "type": "unknown",
                "payload": {}
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

    let text = next_text_frame(&mut client).await;
    let resp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(resp["type"], "error");
    assert_eq!(resp["payload"]["code"], "UNSUPPORTED_TYPE");

    // 2. Malformed JSON
    client
        .send(ws::Message::Text("{not-json".into()))
        .await
        .unwrap();
    let text = next_text_frame(&mut client).await;
    let resp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(resp["type"], "error");
    assert_eq!(resp["payload"]["code"], "BAD_MESSAGE");

    // 3. Binary message
    client
        .send(ws::Message::Binary("hello".into()))
        .await
        .unwrap();
    let text = next_text_frame(&mut client).await;
    let resp: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(resp["type"], "error");
    assert_eq!(resp["payload"]["code"], "UNSUPPORTED_BINARY");

    client.close().await.unwrap();
}
