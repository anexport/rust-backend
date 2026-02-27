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
use uuid::Uuid;

#[actix_rt::test]
async fn test_ws_error_handling() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let state = common::create_app_state(pool.clone());
    let user_id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        "INSERT INTO profiles (id, email, role, full_name, created_at, updated_at) VALUES ($1, $2, 'renter', $3, $4, $5)"
    )
    .bind(user_id)
    .bind("ws-errors@example.com")
    .bind("Error User")
    .bind(now)
    .bind(now)
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
