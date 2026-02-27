use super::*;
use crate::common;
use crate::common::mocks::{
    MockAuthRepo, MockCategoryRepo, MockEquipmentRepo, MockMessageRepo, MockUserRepo,
};
use actix_web::web;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, Header};
use rust_backend::api::routes::{self, AppState};
use rust_backend::config::Auth0Config;
use rust_backend::domain::{Condition, Equipment, Role, User};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub fn test_user(id: Uuid, role: Role, email: &str) -> User {
    User {
        id,
        email: email.to_string(),
        role,
        username: Some(format!("user-{}", id)),
        full_name: None,
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_equipment(id: Uuid, owner_id: Uuid) -> Equipment {
    Equipment {
        id,
        owner_id,
        category_id: Uuid::new_v4(),
        title: "Test Equipment".to_string(),
        description: None,
        daily_rate: Decimal::new(1000, 2),
        condition: Condition::Good,
        location: None,
        coordinates: None,
        is_available: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn security_config() -> rust_backend::config::SecurityConfig {
    rust_backend::config::SecurityConfig {
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

#[derive(Clone)]
pub struct MockAuth0ApiClient;
#[async_trait]
impl rust_backend::infrastructure::auth0_api::Auth0ApiClient for MockAuth0ApiClient {
    async fn signup(
        &self,
        _e: &str,
        _p: &str,
        _u: Option<&str>,
    ) -> rust_backend::error::AppResult<rust_backend::infrastructure::auth0_api::Auth0SignupResponse>
    {
        Err(rust_backend::error::AppError::Unauthorized)
    }
    async fn password_grant(
        &self,
        _e: &str,
        _p: &str,
    ) -> rust_backend::error::AppResult<rust_backend::infrastructure::auth0_api::Auth0TokenResponse>
    {
        Err(rust_backend::error::AppError::Unauthorized)
    }
}

#[derive(Clone)]
pub struct MockJitUserProvisioningService {
    pub _user_repo: Arc<MockUserRepo>,
}
#[async_trait]
impl UserProvisioningService for MockJitUserProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let user_id = claims
            .sub
            .split('|')
            .nth(1)
            .and_then(|raw| Uuid::parse_str(raw).ok())
            .unwrap_or_else(Uuid::new_v4);
        Ok(Auth0UserContext {
            user_id,
            auth0_sub: claims.sub.clone(),
            role: "owner".to_string(),
            email: claims.email.clone(),
        })
    }
}

pub struct MockJwksClient {
    pub decoding_keys: Mutex<std::collections::HashMap<String, jsonwebtoken::DecodingKey>>,
}
impl MockJwksClient {
    pub fn new() -> Self {
        let mut keys = std::collections::HashMap::new();
        let public_key_pem = include_str!("../../test_public_key.pem");
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .expect("Failed to load test_public_key.pem");
        keys.insert("test-key-id".to_string(), key);
        Self {
            decoding_keys: Mutex::new(keys),
        }
    }
}
#[async_trait]
impl rust_backend::utils::auth0_jwks::JwksProvider for MockJwksClient {
    async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> rust_backend::error::AppResult<jsonwebtoken::DecodingKey> {
        self.decoding_keys
            .lock()
            .unwrap()
            .get(kid)
            .cloned()
            .ok_or(rust_backend::error::AppError::Unauthorized)
    }
}

pub fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    let exp = (Utc::now() + Duration::hours(1)).timestamp();
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("role".to_string(), serde_json::json!(role));
    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: format!("auth0|{}", user_id),
        aud: Audience::Single("rust-backend-test".to_string()),
        exp: exp as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: None,
        email_verified: Some(true),
        name: None,
        picture: None,
        custom_claims,
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());
    let private_key_pem = include_str!("../../test_private_key.pem");
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).unwrap();
    encode(&header, &claims, &encoding_key).unwrap()
}

pub fn app_with_auth0_data(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
) -> (
    web::Data<AppState>,
    web::Data<Auth0Config>,
    web::Data<Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider>>,
    web::Data<Arc<dyn UserProvisioningService>>,
) {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let provisioning_service: Arc<dyn UserProvisioningService> =
        Arc::new(MockJitUserProvisioningService {
            _user_repo: user_repo.clone(),
        });
    let jwks_provider: Arc<dyn rust_backend::utils::auth0_jwks::JwksProvider> =
        Arc::new(MockJwksClient::new());
    let state = AppState {
        auth_service: Arc::new(rust_backend::application::AuthService::new(
            user_repo.clone(),
            auth_repo,
        )),
        admin_service: Arc::new(rust_backend::application::AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(rust_backend::application::UserService::new(
            user_repo.clone(),
            equipment_repo.clone(),
        )),
        category_service: Arc::new(rust_backend::application::CategoryService::new(
            category_repo,
        )),
        equipment_service: Arc::new(rust_backend::application::EquipmentService::new(
            user_repo.clone(),
            equipment_repo,
        )),
        message_service: Arc::new(rust_backend::application::MessageService::new(
            user_repo,
            message_repo,
        )),
        security: security_config(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &security_config(),
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(rust_backend::observability::AppMetrics::default()),
        db_pool: PgPoolOptions::new()
            .connect_lazy("postgres://localhost/test")
            .unwrap(),
        ws_hub: routes::ws::WsConnectionHub::default(),
        auth0_api_client: Arc::new(MockAuth0ApiClient),
    };
    (
        web::Data::new(state),
        web::Data::new(Auth0Config {
            auth0_domain: Some("test-tenant.auth0.com".to_string()),
            auth0_audience: Some("rust-backend-test".to_string()),
            auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
            ..Auth0Config::default()
        }),
        web::Data::new(jwks_provider),
        web::Data::new(provisioning_service),
    )
}

pub mod auth;
pub mod photos;
