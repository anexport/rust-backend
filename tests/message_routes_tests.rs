mod common;

use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::{Auth0Config, SecurityConfig};
use rust_backend::domain::Role;
use rust_backend::infrastructure::auth0_api::DisabledAuth0ApiClient;
use rust_backend::infrastructure::repositories::{
    AuthRepositoryImpl, CategoryRepositoryImpl, EquipmentRepositoryImpl, MessageRepository,
    MessageRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_backend::utils::auth0_jwks::JwksProvider;
use std::sync::Arc;
use uuid::Uuid;

use common::fixtures;
use common::TestDb;

// ============================================================================
// Mock Infrastructure for Auth0
// ============================================================================

struct MockJwksProvider {
    decoding_key: jsonwebtoken::DecodingKey,
}

impl MockJwksProvider {
    fn new() -> Self {
        let public_key_pem = include_str!("test_public_key.pem");
        let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .expect("failed to load test public key");
        Self { decoding_key }
    }
}

#[async_trait]
impl JwksProvider for MockJwksProvider {
    async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> rust_backend::error::AppResult<jsonwebtoken::DecodingKey> {
        if kid == "test-key-id" {
            Ok(self.decoding_key.clone())
        } else {
            Err(rust_backend::error::AppError::Unauthorized)
        }
    }
}

struct MockProvisioningService {
    db_pool: sqlx::PgPool,
}

#[async_trait]
impl UserProvisioningService for MockProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let user_repo = UserRepositoryImpl::new(self.db_pool.clone());
        let sub = &claims.sub;

        let user_id = if sub.starts_with("auth0|") {
            Uuid::parse_str(&sub[6..]).unwrap_or_else(|_| Uuid::new_v4())
        } else {
            Uuid::new_v4()
        };

        let role_str = if let Some(role_val) = claims
            .custom_claims
            .get("https://test-tenant.auth0.com/role")
        {
            role_val.as_str().unwrap_or("renter").to_string()
        } else {
            "renter".to_string()
        };

        if user_repo.find_by_id(user_id).await?.is_none() {
            let user = rust_backend::domain::User {
                id: user_id,
                email: claims
                    .email
                    .clone()
                    .unwrap_or_else(|| format!("{}@example.com", sub)),
                role: match role_str.as_str() {
                    "admin" => Role::Admin,
                    "owner" => Role::Owner,
                    _ => Role::Renter,
                },
                username: None,
                full_name: claims.name.clone(),
                avatar_url: claims.picture.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            user_repo.create(&user).await?;
        }

        Ok(Auth0UserContext {
            user_id,
            auth0_sub: sub.clone(),
            role: role_str,
            email: claims.email.clone(),
        })
    }
}

fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-tenant.auth0.com/role".to_string(),
        serde_json::json!(role),
    );

    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: format!("auth0|{}", user_id),
        aud: Audience::Single("rust-backend-test".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: Some(format!("user-{}@example.com", user_id)),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: None,
        custom_claims,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());

    let private_key_pem = include_str!("test_private_key.pem");
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to load test private key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode test token")
}

fn test_auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test-tenant.auth0.com".to_string()),
        auth0_audience: Some("rust-backend-test".to_string()),
        auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: Some("test-client-id".to_string()),
        auth0_client_secret: Some("test-client-secret".to_string()),
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

async fn setup_app(
    db_pool: sqlx::PgPool,
) -> (
    AppState,
    impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
) {
    let user_repo = Arc::new(UserRepositoryImpl::new(db_pool.clone()));
    let equipment_repo = Arc::new(EquipmentRepositoryImpl::new(db_pool.clone()));
    let category_repo = Arc::new(CategoryRepositoryImpl::new(db_pool.clone()));
    let auth_repo = Arc::new(AuthRepositoryImpl::new(db_pool.clone()));
    let message_repo = Arc::new(MessageRepositoryImpl::new(db_pool.clone()));

    let security = SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
    };

    let state = AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo.clone())),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo.clone())),
        equipment_service: Arc::new(EquipmentService::new(
            user_repo.clone(),
            equipment_repo.clone(),
        )),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo.clone())),
        security: security.clone(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(&security)),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: db_pool.clone(),
        ws_hub: routes::ws::WsConnectionHub::default(),
        auth0_api_client: Arc::new(DisabledAuth0ApiClient),
    };

    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(MockJwksProvider::new());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(MockProvisioningService {
            db_pool: db_pool.clone(),
        });

    let app = actix_test::init_service(
        App::new()
            .app_data(web::Data::new(state.clone()))
            .app_data(web::Data::new(test_auth0_config()))
            .app_data(web::Data::new(jwks_provider))
            .app_data(web::Data::new(provisioning_service))
            .configure(routes::configure),
    )
    .await;

    (state, app)
}

// ============================================================================
// TESTS
// ============================================================================

#[actix_rt::test]
async fn test_conversation_crud_flow() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let token1 = create_auth0_token(user1.id, "renter");

    // 1. Create conversation
    let req = actix_test::TestRequest::post()
        .uri("/api/conversations")
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
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], conv_id.to_string());

    // 3. Send message
    let req = actix_test::TestRequest::post()
        .uri(&format!("/api/conversations/{}/messages", conv_id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "content": "Hello there!"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. List messages
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{}/messages", conv_id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["content"], "Hello there!");
}

#[actix_rt::test]
async fn test_message_pagination() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
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
            "/api/conversations/{}/messages?limit=2&offset=0",
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
async fn test_create_conversation_validates_participants() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    let token1 = create_auth0_token(user1.id, "renter");

    // Try to create conversation with NO other participants
    let req = actix_test::TestRequest::post()
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": []
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_non_participant_cannot_view_conversation() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
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
        .uri(&format!("/api/conversations/{}", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token3)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_non_participant_cannot_send_message() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
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
        .uri(&format!("/api/conversations/{}/messages", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token3)))
        .set_json(serde_json::json!({
            "content": "Trying to intrude"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_conversation_list_isolation() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let message_repo = MessageRepositoryImpl::new(test_db.pool().clone());

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
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token2)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let list: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(list.len(), 1);
    // User 2 should only see conversation with User 1
}

#[actix_rt::test]
async fn test_cannot_create_conversation_with_nonexistent_user() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    let token1 = create_auth0_token(user1.id, "renter");

    let req = actix_test::TestRequest::post()
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": [Uuid::new_v4()]
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    // Should be 400 or 404 depending on implementation.
    // Usually 400 if validation fails.
    assert!(resp.status().is_client_error());
}

#[actix_rt::test]
async fn test_conversation_duplicate_prevention() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    let user2 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    user_repo.create(&user2).await.unwrap();

    let token1 = create_auth0_token(user1.id, "renter");

    // First creation
    let req = actix_test::TestRequest::post()
        .uri("/api/conversations")
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
        .uri("/api/conversations")
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "participant_ids": [user2.id]
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // Depending on implementation, it might return 200 OK with existing, or 201 with same ID, or 400.
    // Based on many apps, returning existing one is common.
    assert!(resp.status().is_success());
    let conv2: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(conv1["id"], conv2["id"]);
}

#[actix_rt::test]
async fn test_websocket_broadcast_on_send_message() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (state, app) = setup_app(test_db.pool().clone()).await;
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
        .uri(&format!("/api/conversations/{}/messages", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .set_json(serde_json::json!({
            "content": "WS test message"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Check if user2 received the message via WS
    let ws_msg = tokio::time::timeout(std::time::Duration::from_secs(1), rx2.recv())
        .await
        .expect("Timeout waiting for WS broadcast")
        .expect("WS channel closed");

    let ws_payload: serde_json::Value = serde_json::from_str(&ws_msg).unwrap();
    assert_eq!(ws_payload["type"], "new_message");
    assert_eq!(ws_payload["data"]["content"], "WS test message");
}

#[actix_rt::test]
async fn test_message_list_ordering() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
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
        .uri(&format!("/api/conversations/{}/messages", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 5);
    // Newest messages first (created most recently)
    assert_eq!(messages[0]["content"], "Message 4");
    assert_eq!(messages[1]["content"], "Message 3");
    assert_eq!(messages[2]["content"], "Message 2");
    assert_eq!(messages[3]["content"], "Message 1");
    assert_eq!(messages[4]["content"], "Message 0");
}

#[actix_rt::test]
async fn test_get_conversation_details_participants_only() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let (_, app) = setup_app(test_db.pool().clone()).await;
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

    // User 3 is NOT a participant, should get 403 Forbidden
    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/conversations/{}", conv.id))
        .insert_header(("Authorization", format!("Bearer {}", token3)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_pagination_edge_cases() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
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
            "/api/conversations/{}/messages?limit=10&offset=0",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 10);

    // Test page 2 with limit 10 - should return empty array (no more messages)
    let req = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/conversations/{}/messages?limit=10&offset=10",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let messages: Vec<serde_json::Value> = actix_test::read_body_json(resp).await;
    assert_eq!(messages.len(), 0);

    // Test negative offset - should return 400 Bad Request
    let req = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/conversations/{}/messages?limit=10&offset=-1",
            conv.id
        ))
        .insert_header(("Authorization", format!("Bearer {}", token1)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
