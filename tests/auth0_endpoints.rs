use std::sync::{Arc, Mutex};

mod common;

#[path = "auth0_endpoints/signup.rs"]
pub mod signup;
#[path = "auth0_endpoints/login.rs"]
pub mod login;
#[path = "auth0_endpoints/tokens.rs"]
pub mod tokens;

use crate::common::mocks::{
    MockAuthRepo, MockCategoryRepo, MockEquipmentRepo, MockMessageRepo, MockUserRepo,
};

use actix_web::{http::StatusCode, test as actix_test, web, App};
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use rust_backend::api::routes::{self, AppState};
use rust_backend::application::{
    AdminService, AuthService, CategoryService, EquipmentService, MessageService, UserService,
};
use rust_backend::config::SecurityConfig;
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::auth0_api::{
    Auth0ApiClient, Auth0ErrorResponse, Auth0SignupResponse, Auth0TokenResponse,
};
use rust_backend::observability::AppMetrics;
use rust_backend::security::LoginThrottle;
use rust_backend::security::{cors_middleware, security_headers};

// =============================================================================
// Mock Auth0ApiClient for Actual Trait
// =============================================================================

/// Mock user stored in the in-memory database
#[derive(Debug, Clone)]
pub struct MockAuth0User {
    pub user_id: String,
    pub email: String,
    pub password: String,
    pub username: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

/// Mock implementation of Auth0ApiClient for testing
#[derive(Clone)]
pub struct MockAuth0ApiClient {
    pub users: Arc<Mutex<Vec<MockAuth0User>>>,
    /// Simulates signup failures with specific error responses
    pub signup_error: Arc<Mutex<Option<Auth0ErrorResponse>>>,
    /// Simulates login failures with specific error responses
    pub login_error: Arc<Mutex<Option<Auth0ErrorResponse>>>,
    /// Simulates service unavailability
    pub service_unavailable: Arc<Mutex<bool>>,
}

impl MockAuth0ApiClient {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(Vec::new())),
            signup_error: Arc::new(Mutex::new(None)),
            login_error: Arc::new(Mutex::new(None)),
            service_unavailable: Arc::new(Mutex::new(false)),
        }
    }

    /// Pre-register a user (simulating existing Auth0 users)
    pub fn with_user(self, user: MockAuth0User) -> Self {
        self.users.lock().unwrap().push(user);
        self
    }

    /// Set signup to return a specific error
    pub fn with_signup_error(self, error: Auth0ErrorResponse) -> Self {
        *self.signup_error.lock().unwrap() = Some(error);
        self
    }

    /// Set login to return a specific error
    pub fn with_login_error(self, error: Auth0ErrorResponse) -> Self {
        *self.login_error.lock().unwrap() = Some(error);
        self
    }

    /// Simulate service being unavailable
    pub fn with_service_unavailable(self, unavailable: bool) -> Self {
        *self.service_unavailable.lock().unwrap() = unavailable;
        self
    }

    pub fn generate_user_id(&self) -> String {
        format!("auth0|{}", Uuid::new_v4())
    }

    pub fn find_user(&self, email: &str) -> Option<MockAuth0User> {
        self.users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.email == email)
            .cloned()
    }

    /// Generate a mock RS256-style JWT token
    pub fn generate_mock_rs256_token(&self) -> String {
        let header = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0";
        let payload = "eyJpc3MiOiJodHRwczovL3Rlc3QuYXV0aDAuY29tLyIsInN1YiI6ImF1ZCI6Imh0dHBzOi8vYXBpLnRlc3QuY29tIiwiZXhwIjoxNzU3NjgwMCwiaWF0IjoxNzU3NjgwMH0";
        let signature = "bX9ja2stcnMyNTYtc2lnbmF0dXJl";
        format!("{}.{}.{}", header, payload, signature)
    }
}

impl Default for MockAuth0ApiClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Auth0ApiClient for MockAuth0ApiClient {
    async fn signup(
        &self,
        email: &str,
        password: &str,
        username: Option<&str>,
    ) -> AppResult<Auth0SignupResponse> {
        if *self.service_unavailable.lock().unwrap() {
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Auth0 service unavailable"
            )));
        }

        if let Some(error) = self.signup_error.lock().unwrap().as_ref() {
            return Err(error.to_app_error());
        }

        // Check for existing user (simulates Auth0 duplicate email check)
        if self.find_user(email).is_some() {
            return Err(AppError::Conflict("user already exists".to_string()));
        }

        // Create new user
        let user = MockAuth0User {
            user_id: self.generate_user_id(),
            email: email.to_string(),
            password: password.to_string(),
            username: username.map(|u| u.to_string()),
            name: username.map(|u| u.to_string()),
            email_verified: false, // Auth0 typically starts unverified
        };

        self.users.lock().unwrap().push(user.clone());

        Ok(Auth0SignupResponse {
            id: user.user_id,
            email: user.email,
            email_verified: user.email_verified,
            username: user.username,
            picture: None,
            name: user.name,
            created_at: Some(Utc::now().to_rfc3339()),
            updated_at: Some(Utc::now().to_rfc3339()),
        })
    }

    async fn password_grant(&self, email: &str, password: &str) -> AppResult<Auth0TokenResponse> {
        if *self.service_unavailable.lock().unwrap() {
            return Err(AppError::InternalError(anyhow::anyhow!(
                "Auth0 service unavailable"
            )));
        }

        if let Some(error) = self.login_error.lock().unwrap().as_ref() {
            return Err(error.to_app_error());
        }

        // Find and authenticate user
        let user = self
            .find_user(email)
            .ok_or_else(|| AppError::Unauthorized)?;

        if user.password != password {
            return Err(AppError::Unauthorized);
        }

        // Generate mock RS256 tokens
        let access_token = self.generate_mock_rs256_token();
        let id_token = self.generate_mock_rs256_token();

        Ok(Auth0TokenResponse {
            access_token,
            refresh_token: Some(format!("refresh_{}", Uuid::new_v4())),
            id_token,
            token_type: "Bearer".to_string(),
            expires_in: 86400,
            scope: Some("openid profile email".to_string()),
        })
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
