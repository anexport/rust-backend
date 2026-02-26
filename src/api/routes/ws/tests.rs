use std::sync::Arc;

use actix_web::{http::StatusCode, test as awtest, web, App};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::mpsc::error::TryRecvError;
use uuid::Uuid;

use crate::api::routes::AppState;
use crate::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use crate::config::{Auth0Config, SecurityConfig};
use crate::domain::{
    AuthIdentity, Category, Conversation, Equipment, EquipmentPhoto, Message, Role, User,
};
use crate::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, MessageRepository, UserRepository,
};
use crate::middleware::auth::JitUserProvisioningService;
use crate::observability::AppMetrics;
use crate::security::LoginThrottle;
use crate::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use crate::utils::auth0_jwks::{Auth0JwksClient, JwksProvider};

const TEST_PRIVATE_KEY_PEM: &str = include_str!("../../../../tests/test_private_key.pem");
const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../../../tests/test_public_key.pem");

struct NoopUserRepo {
    user: User,
}

#[async_trait]
impl UserRepository for NoopUserRepo {
    async fn find_by_id(&self, id: Uuid) -> crate::error::AppResult<Option<User>> {
        if id == self.user.id {
            Ok(Some(self.user.clone()))
        } else {
            Ok(None)
        }
    }

    async fn find_by_email(&self, _email: &str) -> crate::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn find_by_username(&self, _username: &str) -> crate::error::AppResult<Option<User>> {
        Ok(None)
    }

    async fn create(&self, user: &User) -> crate::error::AppResult<User> {
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> crate::error::AppResult<User> {
        Ok(user.clone())
    }

    async fn delete(&self, _id: Uuid) -> crate::error::AppResult<()> {
        Ok(())
    }
}

struct StubAuthRepo;

#[async_trait]
impl AuthRepository for StubAuthRepo {
    async fn create_identity(
        &self,
        identity: &AuthIdentity,
    ) -> crate::error::AppResult<AuthIdentity> {
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        _user_id: Uuid,
        _provider: &str,
    ) -> crate::error::AppResult<Option<AuthIdentity>> {
        Ok(None)
    }

    async fn find_identity_by_provider_id(
        &self,
        _provider: &str,
        _provider_id: &str,
    ) -> crate::error::AppResult<Option<AuthIdentity>> {
        Ok(None)
    }

    async fn upsert_identity(
        &self,
        identity: &AuthIdentity,
    ) -> crate::error::AppResult<AuthIdentity> {
        Ok(identity.clone())
    }
}

struct StaticJwksProvider {
    key: DecodingKey,
}

#[async_trait]
impl JwksProvider for StaticJwksProvider {
    async fn get_decoding_key(&self, _kid: &str) -> crate::error::AppResult<DecodingKey> {
        Ok(self.key.clone())
    }
}

struct StaticProvisioningService {
    user_id: Uuid,
}

#[async_trait]
impl crate::middleware::auth::UserProvisioningService for StaticProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> crate::error::AppResult<Auth0UserContext> {
        Ok(Auth0UserContext {
            user_id: self.user_id,
            auth0_sub: claims.sub.clone(),
            role: "renter".to_string(),
            email: claims.email.clone(),
        })
    }
}

struct NoopCategoryRepo;

#[async_trait]
impl CategoryRepository for NoopCategoryRepo {
    async fn find_all(&self) -> crate::error::AppResult<Vec<Category>> {
        Ok(Vec::new())
    }

    async fn find_by_id(&self, _id: Uuid) -> crate::error::AppResult<Option<Category>> {
        Ok(None)
    }

    async fn find_children(&self, _parent_id: Uuid) -> crate::error::AppResult<Vec<Category>> {
        Ok(Vec::new())
    }
}

struct NoopEquipmentRepo;

#[async_trait]
impl EquipmentRepository for NoopEquipmentRepo {
    async fn find_by_id(&self, _id: Uuid) -> crate::error::AppResult<Option<Equipment>> {
        Ok(None)
    }

    async fn find_all(&self, _limit: i64, _offset: i64) -> crate::error::AppResult<Vec<Equipment>> {
        Ok(Vec::new())
    }

    async fn find_by_owner(&self, _owner_id: Uuid) -> crate::error::AppResult<Vec<Equipment>> {
        Ok(Vec::new())
    }

    async fn create(&self, equipment: &Equipment) -> crate::error::AppResult<Equipment> {
        Ok(equipment.clone())
    }

    async fn update(&self, equipment: &Equipment) -> crate::error::AppResult<Equipment> {
        Ok(equipment.clone())
    }

    async fn delete(&self, _id: Uuid) -> crate::error::AppResult<()> {
        Ok(())
    }

    async fn add_photo(&self, photo: &EquipmentPhoto) -> crate::error::AppResult<EquipmentPhoto> {
        Ok(photo.clone())
    }

    async fn find_photos(
        &self,
        _equipment_id: Uuid,
    ) -> crate::error::AppResult<Vec<EquipmentPhoto>> {
        Ok(Vec::new())
    }

    async fn delete_photo(&self, _photo_id: Uuid) -> crate::error::AppResult<()> {
        Ok(())
    }
}

struct NoopMessageRepo;

#[async_trait]
impl MessageRepository for NoopMessageRepo {
    async fn find_conversation(&self, _id: Uuid) -> crate::error::AppResult<Option<Conversation>> {
        Ok(None)
    }

    async fn find_user_conversations(
        &self,
        _user_id: Uuid,
    ) -> crate::error::AppResult<Vec<Conversation>> {
        Ok(Vec::new())
    }

    async fn create_conversation(
        &self,
        _participant_ids: Vec<Uuid>,
    ) -> crate::error::AppResult<Conversation> {
        Ok(Conversation {
            id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }

    async fn find_messages(
        &self,
        _conversation_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> crate::error::AppResult<Vec<Message>> {
        Ok(Vec::new())
    }

    async fn create_message(&self, message: &Message) -> crate::error::AppResult<Message> {
        Ok(message.clone())
    }

    async fn is_participant(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> crate::error::AppResult<bool> {
        Ok(false)
    }

    async fn mark_as_read(
        &self,
        _conversation_id: Uuid,
        _user_id: Uuid,
    ) -> crate::error::AppResult<()> {
        Ok(())
    }
}

fn auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: Some("test-audience".to_string()),
        auth0_issuer: Some("https://test.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: None,
        auth0_client_secret: None,
        auth0_connection: Default::default(),
    }
}

fn test_user() -> User {
    let now = Utc::now();
    User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: Some("Test User".to_string()),
        avatar_url: None,
        created_at: now,
        updated_at: now,
    }
}

// Create a mock Auth0 token for testing
fn create_test_auth0_token(sub: &str) -> String {
    // For testing purposes, we use a simple JSON string
    // The actual Auth0 JWKS validation would fail, but in our test setup
    // we're mocking the provisioning and user lookup
    format!("test-auth0-token-{}", sub)
}

fn create_valid_auth0_token(sub: &str) -> String {
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("test-audience".to_string()),
        exp: (Utc::now() + Duration::minutes(5)).timestamp() as u64,
        iat: (Utc::now() - Duration::minutes(1)).timestamp() as u64,
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

fn security_config() -> SecurityConfig {
    SecurityConfig {
        cors_allowed_origins: vec!["http://localhost:3000".to_string()],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    }
}

fn build_state(app_environment: &str) -> AppState {
    let user = test_user();
    let user_repo: Arc<dyn UserRepository> = Arc::new(NoopUserRepo { user });
    let auth_repo: Arc<dyn AuthRepository> = Arc::new(StubAuthRepo);
    let category_repo: Arc<dyn CategoryRepository> = Arc::new(NoopCategoryRepo);
    let equipment_repo: Arc<dyn EquipmentRepository> = Arc::new(NoopEquipmentRepo);
    let message_repo: Arc<dyn MessageRepository> = Arc::new(NoopMessageRepo);
    let security = security_config();

    AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo.clone())),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo, message_repo)),
        security: security.clone(),
        login_throttle: Arc::new(LoginThrottle::new(&security)),
        app_environment: app_environment.to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: super::WsConnectionHub::default(),
        auth0_api_client: Arc::new(crate::infrastructure::auth0_api::DisabledAuth0ApiClient),
    }
}

fn test_db_pool() -> sqlx::PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:1/test_db".to_string());
    PgPoolOptions::new()
        .connect_lazy(&database_url)
        .expect("test db pool should build lazily")
}

#[actix_rt::test]
async fn ws_rejects_when_token_is_missing() {
    let auth0_config = auth0_config();
    let auth0_namespace = auth0_config.auth0_domain.clone().unwrap_or_default();
    let provisioning_service = Arc::new(JitUserProvisioningService::new(
        Arc::new(NoopUserRepo { user: test_user() }),
        Arc::new(StubAuthRepo),
        auth0_namespace,
    ));
    let auth0_jwks_client = web::Data::new(
        Auth0JwksClient::new(&auth0_config).expect("failed to build Auth0 JWKS client"),
    );

    let app = awtest::init_service(
        App::new()
            .app_data(web::Data::new(build_state("development")))
            .app_data(web::Data::new(auth0_config))
            .app_data(auth0_jwks_client)
            .app_data(web::Data::new(provisioning_service))
            .configure(super::configure),
    )
    .await;

    let request = awtest::TestRequest::get().uri("/ws").to_request();
    let response = awtest::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn ws_requires_wss_in_production() {
    let auth0_config = auth0_config();
    let auth0_namespace = auth0_config.auth0_domain.clone().unwrap_or_default();
    let provisioning_service = Arc::new(JitUserProvisioningService::new(
        Arc::new(NoopUserRepo { user: test_user() }),
        Arc::new(StubAuthRepo),
        auth0_namespace,
    ));
    let auth0_jwks_client = web::Data::new(
        Auth0JwksClient::new(&auth0_config).expect("failed to build Auth0 JWKS client"),
    );
    let token = create_test_auth0_token("test-user");

    let app = awtest::init_service(
        App::new()
            .app_data(web::Data::new(build_state("production")))
            .app_data(web::Data::new(auth0_config))
            .app_data(auth0_jwks_client)
            .app_data(web::Data::new(provisioning_service))
            .configure(super::configure),
    )
    .await;

    let request = awtest::TestRequest::get()
        .uri("/ws")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = awtest::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn ws_allows_valid_auth0_token_without_local_session() {
    let auth0_config = auth0_config();
    let token = create_valid_auth0_token("auth0|ws-no-session");
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(StaticJwksProvider {
        key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
            .expect("public test key should parse"),
    });
    let provisioning_service: Arc<dyn crate::middleware::auth::UserProvisioningService> =
        Arc::new(StaticProvisioningService {
            user_id: Uuid::new_v4(),
        });

    let app = awtest::init_service(
        App::new()
            .app_data(web::Data::new(build_state("development")))
            .app_data(web::Data::new(auth0_config))
            .app_data(web::Data::new(jwks_provider))
            .app_data(web::Data::new(provisioning_service))
            .configure(super::configure),
    )
    .await;

    let request = awtest::TestRequest::get()
        .uri("/ws")
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();

    let response = awtest::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
}

#[test]
fn extracts_token_from_authorization_header() {
    let request = awtest::TestRequest::default()
        .insert_header(("Authorization", "Bearer abc123"))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert_eq!(token.as_deref(), Some("abc123"));
}

#[test]
fn extracts_token_from_subprotocol_header() {
    let request = awtest::TestRequest::default()
        .insert_header(("Sec-WebSocket-Protocol", "bearer, fallback-token"))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert_eq!(token.as_deref(), Some("fallback-token"));
}

#[test]
fn ignores_invalid_subprotocol_format() {
    let request = awtest::TestRequest::default()
        .insert_header(("Sec-WebSocket-Protocol", "notbearer, token"))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert!(token.is_none());
}

#[test]
fn extract_ws_token_prefers_authorization_header() {
    let request = awtest::TestRequest::default()
        .insert_header(("Authorization", "Bearer auth-header-token"))
        .insert_header(("Sec-WebSocket-Protocol", "bearer, protocol-token"))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert_eq!(token.as_deref(), Some("auth-header-token"));
}

#[test]
fn extract_ws_token_rejects_lowercase_bearer_prefix_in_authorization_header() {
    let request = awtest::TestRequest::default()
        .insert_header(("Authorization", "bearer lower-token"))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert!(token.is_none());
}

#[test]
fn extract_ws_token_rejects_empty_subprotocol_token() {
    let request = awtest::TestRequest::default()
        .insert_header(("Sec-WebSocket-Protocol", "bearer,    "))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert!(token.is_none());
}

#[test]
fn extract_ws_token_accepts_mixed_case_subprotocol_prefix() {
    let request = awtest::TestRequest::default()
        .insert_header(("Sec-WebSocket-Protocol", "BeArEr, token-1"))
        .to_http_request();

    let token = super::extract_ws_token(&request);
    assert_eq!(token.as_deref(), Some("token-1"));
}

#[test]
fn malformed_ws_text_message_returns_bad_request() {
    let result = super::parse_ws_envelope("{not-json");
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn malformed_ws_text_envelope_shape_returns_bad_request() {
    let result = super::parse_ws_envelope(r#"[1,2,3]"#);
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn missing_ws_message_payload_returns_bad_request() {
    let result = super::parse_send_message_payload(None);
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn invalid_ws_message_payload_shape_returns_bad_request() {
    let result =
        super::parse_send_message_payload(Some(json!({ "conversation_id": "not-a-uuid" })));
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn invalid_ws_message_payload_content_type_returns_bad_request() {
    let result = super::parse_send_message_payload(Some(json!({
        "conversation_id": Uuid::new_v4(),
        "content": 123
    })));
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn missing_typing_payload_returns_bad_request() {
    let result = super::parse_typing_payload(None);
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn invalid_typing_payload_returns_bad_request() {
    let result = super::parse_typing_payload(Some(json!({
        "conversation_id": "not-a-uuid",
        "is_typing": true
    })));
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn missing_read_payload_returns_bad_request() {
    let result = super::parse_read_payload(None);
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn invalid_read_payload_returns_bad_request() {
    let result = super::parse_read_payload(Some(json!({
        "conversation_id": "not-a-uuid"
    })));
    assert!(matches!(result, Err(crate::error::AppError::BadRequest(_))));
}

#[test]
fn unsupported_text_message_type_is_retained_for_error_path() {
    let result = super::parse_ws_envelope(r#"{"type":"unsupported","payload":{}}"#)
        .expect("envelope should parse");
    assert_eq!(result.message_type, "unsupported");
}

#[test]
fn ws_hub_broadcasts_and_prunes_closed_sessions() {
    let hub = super::WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    let mut rx_open = hub.register(user_id);
    let rx_closed = hub.register(user_id);
    drop(rx_closed);

    hub.broadcast_to_users(&[user_id], "hello");

    assert_eq!(rx_open.try_recv(), Ok("hello".to_string()));
    assert_eq!(rx_open.try_recv(), Err(TryRecvError::Empty));

    drop(rx_open);
    hub.prune_user(user_id);
    hub.broadcast_to_users(&[user_id], "after-prune");
}

#[test]
fn ws_hub_broadcast_ignores_unknown_user() {
    let hub = super::WsConnectionHub::default();
    hub.broadcast_to_users(&[Uuid::new_v4()], "noop");
}

#[test]
fn secure_ws_request_accepts_forwarded_proto_case_insensitive() {
    let request = awtest::TestRequest::default()
        .insert_header(("x-forwarded-proto", "HTTPS"))
        .to_http_request();

    assert!(super::is_secure_ws_request(&request));
}

#[test]
fn secure_ws_request_rejects_non_https() {
    let request = awtest::TestRequest::default()
        .insert_header(("x-forwarded-proto", "http"))
        .uri("http://example.test/ws")
        .to_http_request();

    assert!(!super::is_secure_ws_request(&request));
}

#[test]
fn secure_ws_request_rejects_http_forwarded_proto_without_https_hints() {
    let request = awtest::TestRequest::default()
        .uri("http://example.test/ws")
        .insert_header(("x-forwarded-proto", "http"))
        .to_http_request();

    assert!(!super::is_secure_ws_request(&request));
}

#[test]
fn secure_ws_request_rejects_missing_scheme_and_forwarded_proto() {
    let request = awtest::TestRequest::default()
        .uri("http://example.test/ws")
        .to_http_request();

    assert!(!super::is_secure_ws_request(&request));
}

#[test]
fn secure_ws_request_accepts_forwarded_proto_list_when_https_is_first() {
    let request = awtest::TestRequest::default()
        .uri("http://example.test/ws")
        .insert_header(("x-forwarded-proto", "https,http"))
        .to_http_request();

    assert!(super::is_secure_ws_request(&request));
}

#[test]
fn parse_typing_payload_accepts_valid_shape() {
    let conversation_id = Uuid::new_v4();
    let result = super::parse_typing_payload(Some(json!({
        "conversation_id": conversation_id,
        "is_typing": true
    })));
    assert!(result.is_ok());
}

#[test]
fn parse_read_payload_accepts_valid_shape() {
    let conversation_id = Uuid::new_v4();
    let result = super::parse_read_payload(Some(json!({
        "conversation_id": conversation_id
    })));
    assert!(result.is_ok());
}

#[test]
fn ws_hub_broadcast_prunes_and_isolates_multiple_participants() {
    let hub = super::WsConnectionHub::default();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let user_c = Uuid::new_v4();

    let mut rx_a_open = hub.register(user_a);
    let rx_a_closed = hub.register(user_a);
    let mut rx_b_open = hub.register(user_b);
    let mut rx_c_open = hub.register(user_c);
    drop(rx_a_closed);

    hub.broadcast_to_users(&[user_a, user_b], "group-message");

    assert_eq!(rx_a_open.try_recv(), Ok("group-message".to_string()));
    assert_eq!(rx_b_open.try_recv(), Ok("group-message".to_string()));
    assert_eq!(rx_c_open.try_recv(), Err(TryRecvError::Empty));

    drop(rx_a_open);
    hub.prune_user(user_a);
    hub.broadcast_to_users(&[user_a], "post-prune-message");
    assert_eq!(rx_b_open.try_recv(), Err(TryRecvError::Empty));
}
