#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(unused_imports)]
use std::sync::{Arc, Mutex};

use crate::common::mocks::auth0_api::MockAuth0ApiClient;
use crate::common::mocks::{
    MockAuthRepo, MockCategoryRepo, MockEquipmentRepo, MockMessageRepo, MockUserRepo,
};
use actix_web::web;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use rust_backend::api::routes::AppState;
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::{Auth0Config, SecurityConfig};
use rust_backend::domain::{
    AuthIdentity, AuthProvider, Condition, Equipment, EquipmentPhoto, Role, User,
};
use rust_backend::infrastructure::auth0_api::{Auth0SignupResponse, Auth0TokenResponse};
use rust_backend::infrastructure::repositories::{
    AuthRepository, CategoryRepository, EquipmentRepository, UserRepository,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::observability::AppMetrics;
use rust_backend::utils::auth0_claims::Auth0UserContext;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims};
use rust_backend::utils::auth0_jwks::JwksProvider;
use rust_decimal::Decimal;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

// Re-export the canonical MockAuth0ApiClient from common/mocks
// The full implementation is in tests/common/mocks/auth0_api.rs

// Equipment-search specific create_auth0_token with the right issuer/audience
// Note: This differs from common::auth0_test_helpers::create_auth0_token
// which uses "https://test-tenant.auth0.com/" issuer.
// Equipment_search tests use "https://test.auth0.com/" issuer.
pub fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert("https://test.com/role".to_string(), serde_json::json!(role));
    custom_claims.insert("role".to_string(), serde_json::json!(role));

    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: format!("auth0|{}", user_id),
        aud: Audience::Single("test-api".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: None,
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: None,
        custom_claims,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());

    let private_key_pem = include_str!("../test_private_key.pem");
    let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to load test private key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode test token")
}

// =============================================================================
// Mock JWKS Client
// =============================================================================

pub struct MockJwksClient {
    decoding_keys: Mutex<std::collections::HashMap<String, DecodingKey>>,
}

impl MockJwksClient {
    pub fn new() -> Self {
        let mut keys = std::collections::HashMap::new();
        let public_key_pem = include_str!("../test_public_key.pem");
        if let Ok(key) = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()) {
            keys.insert("test-key-id".to_string(), key);
        }
        Self {
            decoding_keys: Mutex::new(keys),
        }
    }
}

#[async_trait]
impl JwksProvider for MockJwksClient {
    async fn get_decoding_key(&self, kid: &str) -> rust_backend::error::AppResult<DecodingKey> {
        self.decoding_keys
            .lock()
            .expect("decoding_keys mutex poisoned")
            .get(kid)
            .cloned()
            .ok_or(rust_backend::error::AppError::Unauthorized)
    }
}

// =============================================================================
// Mock JitUserProvisioningService
// =============================================================================

#[derive(Clone)]
pub struct MockJitUserProvisioningService {
    user_repo: Arc<MockUserRepo>,
    auth_repo: Arc<MockAuthRepo>,
}

impl MockJitUserProvisioningService {
    pub fn new(user_repo: Arc<MockUserRepo>, auth_repo: Arc<MockAuthRepo>) -> Self {
        Self {
            user_repo,
            auth_repo,
        }
    }
}

#[async_trait]
impl UserProvisioningService for MockJitUserProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let sub_user_id = claims
            .sub
            .split('|')
            .nth(1)
            .and_then(|raw| Uuid::parse_str(raw).ok());

        let existing_user_id = {
            let users = self.user_repo.users.lock().unwrap();
            sub_user_id
                .and_then(|id| users.iter().find(|u| u.id == id).map(|u| u.id))
                .or_else(|| {
                    users
                        .iter()
                        .find(|u| u.email == claims.email.as_deref().unwrap_or(""))
                        .map(|u| u.id)
                })
        };

        let user_id = if let Some(existing_id) = existing_user_id {
            existing_id
        } else {
            let role = match map_role_from_claim(claims).as_str() {
                "admin" => Role::Admin,
                "owner" => Role::Owner,
                _ => Role::Renter,
            };
            // Create new user if not found
            let user = User {
                id: sub_user_id.unwrap_or_else(Uuid::new_v4),
                email: claims
                    .email
                    .clone()
                    .unwrap_or_else(|| format!("{}@placeholder.test", claims.sub)),
                role,
                username: None,
                full_name: claims.name.clone(),
                avatar_url: claims.picture.clone(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.user_repo.users.lock().unwrap().push(user.clone());
            user.id
        };

        let identity = AuthIdentity {
            id: Uuid::new_v4(),
            user_id,
            provider: AuthProvider::Auth0,
            provider_id: Some(claims.sub.clone()),
            password_hash: None,
            verified: claims.email_verified.unwrap_or(false),
            created_at: Utc::now(),
        };
        self.auth_repo.create_identity(&identity).await?;

        Ok(Auth0UserContext {
            user_id,
            auth0_sub: claims.sub.clone(),
            role: map_role_from_claim(claims),
            email: claims.email.clone(),
        })
    }
}

pub fn map_role_from_claim(claims: &Auth0Claims) -> String {
    // Try to get role from custom claims
    if let Some(role_value) = claims.custom_claims.get("https://test.com/role") {
        if let Some(role_str) = role_value.as_str() {
            return role_str.to_string();
        }
    }
    if let Some(role_value) = claims.custom_claims.get("role") {
        if let Some(role_str) = role_value.as_str() {
            return role_str.to_string();
        }
    }
    "renter".to_string()
}

// =============================================================================
// Helper Functions
// =============================================================================

pub fn auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: Some("test-api".to_string()),
        auth0_issuer: Some("https://test.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: Some("test-client-id".to_string()),
        auth0_client_secret: Some("test-client-secret".to_string()),
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

pub fn security_config() -> SecurityConfig {
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

// create_auth0_token is re-exported from common/auth0_test_helpers
// Use: use crate::common::auth0_test_helpers::create_auth0_token;

pub fn app_state(user_repo: Arc<MockUserRepo>, equipment_repo: Arc<MockEquipmentRepo>) -> AppState {
    app_state_with_provisioning(
        user_repo,
        equipment_repo,
        Arc::new(MockMessageRepo::default()),
    )
}

pub fn app_state_with_provisioning(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
    message_repo: Arc<MockMessageRepo>,
) -> AppState {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new());

    AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo)),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: security_config(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &security_config(),
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    }
}

pub fn app_with_auth0_data(
    user_repo: Arc<MockUserRepo>,
    equipment_repo: Arc<MockEquipmentRepo>,
) -> (
    web::Data<AppState>,
    web::Data<Auth0Config>,
    web::Data<Arc<dyn JwksProvider>>,
    web::Data<Arc<dyn UserProvisioningService>>,
) {
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new());
    let provisioning_service = Arc::new(MockJitUserProvisioningService::new(
        user_repo.clone(),
        auth_repo.clone(),
    ));
    let jwks_provider: Arc<dyn JwksProvider> = Arc::new(MockJwksClient::new());
    let auth0_jwks_client = web::Data::new(jwks_provider.clone());
    let auth0_config_data = web::Data::new(auth0_config());
    let provisioning_service_data =
        web::Data::new(provisioning_service.clone() as Arc<dyn UserProvisioningService>);

    let state = AppState {
        auth_service: Arc::new(AuthService::new(user_repo.clone(), auth_repo)),
        admin_service: Arc::new(AdminService::new(
            user_repo.clone(),
            equipment_repo.clone(),
            category_repo.clone(),
        )),
        user_service: Arc::new(UserService::new(user_repo.clone(), equipment_repo.clone())),
        category_service: Arc::new(CategoryService::new(category_repo)),
        equipment_service: Arc::new(EquipmentService::new(user_repo.clone(), equipment_repo)),
        message_service: Arc::new(MessageService::new(user_repo.clone(), message_repo)),
        security: security_config(),
        login_throttle: Arc::new(rust_backend::security::LoginThrottle::new(
            &security_config(),
        )),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    };

    (
        web::Data::new(state),
        auth0_config_data,
        auth0_jwks_client,
        provisioning_service_data,
    )
}

pub fn test_db_pool() -> sqlx::PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:1/test_db".to_string());
    PgPoolOptions::new()
        .connect_lazy(&database_url)
        .expect("test db pool should build lazily")
}

pub fn create_equipment(
    id: Uuid,
    owner_id: Uuid,
    category_id: Uuid,
    title: &str,
    daily_rate: i64,
    condition: rust_backend::domain::Condition,
    location: Option<&str>,
    lat: Option<f64>,
    lng: Option<f64>,
    is_available: bool,
) -> Equipment {
    let mut equipment = Equipment {
        id,
        owner_id,
        category_id,
        title: title.to_string(),
        description: Some(format!("Description for {}", title)),
        daily_rate: Decimal::new(daily_rate, 2),
        condition,
        location: location.map(String::from),
        coordinates: None,
        is_available,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    if let (Some(lat), Some(lng)) = (lat, lng) {
        equipment.set_coordinates(lat, lng).unwrap();
    }
    equipment
}

pub fn get_items_array(body: &serde_json::Value) -> Vec<serde_json::Value> {
    body.get("items")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

pub fn get_total(body: &serde_json::Value) -> i64 {
    body.get("total")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}

pub fn get_page(body: &serde_json::Value) -> i64 {
    body.get("page")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(1)
}

pub fn get_limit(body: &serde_json::Value) -> i64 {
    body.get("limit")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(20)
}

pub fn get_total_pages(body: &serde_json::Value) -> i64 {
    body.get("total_pages")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0)
}
