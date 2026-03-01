use std::sync::Arc;

mod common;

#[path = "auth0_endpoints/login.rs"]
pub mod login;
#[path = "auth0_endpoints/signup.rs"]
pub mod signup;
#[path = "auth0_endpoints/tokens.rs"]
pub mod tokens;

use crate::common::mocks::{
    MockAuthRepo, MockCategoryRepo, MockEquipmentRepo, MockMessageRepo, MockUserRepo,
};

use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;

use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::SecurityConfig;
use rust_backend::infrastructure::auth0_api::Auth0ApiClient;
use rust_backend::observability::AppMetrics;
use rust_backend::security::LoginThrottle;

// Re-export MockAuth0User from common/mocks
// The full implementation is in tests/common/mocks/auth0_api.rs
// MockAuth0ApiClient can be imported as: use crate::common::mocks::auth0_api::MockAuth0ApiClient;
pub use crate::common::mocks::auth0_api::MockAuth0User;

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

pub fn app_state(auth0_api_client: Arc<dyn Auth0ApiClient>) -> AppState {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let category_repo = Arc::new(MockCategoryRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

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
        login_throttle: Arc::new(LoginThrottle::new(&security_config())),
        app_environment: "test".to_string(),
        metrics: Arc::new(AppMetrics::default()),
        db_pool: test_db_pool(),
        ws_hub: rust_backend::api::routes::ws::WsConnectionHub::default(),
        auth0_api_client,
    }
}

pub fn test_db_pool() -> sqlx::PgPool {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:1/test_db".to_string());
    PgPoolOptions::new()
        .connect_lazy(&database_url)
        .expect("test db pool should build lazily")
}

#[derive(Debug, Deserialize)]
pub struct Auth0SignupResponseDto {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Debug, Deserialize)]
pub struct Auth0LoginResponseDto {
    pub access_token: String,
    pub id_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    pub token_type: String,
}
