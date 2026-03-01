#![allow(dead_code)]

use chrono::{Duration, Utc};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use uuid::Uuid;

use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::auth0_api::{
    Auth0ApiClient, Auth0ErrorResponse, Auth0SignupResponse, Auth0TokenResponse,
};

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
        let exp = (Utc::now() + Duration::hours(1)).timestamp();
        let iat = Utc::now().timestamp();
        let payload = format!(
            r#"{{"iss":"https://test.auth0.com/","sub":"test-user","aud":"https://api.test.com","exp":{},"iat":{}}}"#,
            exp, iat
        );
        let payload_encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload.as_bytes(),
        );
        let signature = "bX9ja2stcnMyNTYtc2lnbmF0dXJl";
        format!("{}.{}.{}", header, payload_encoded, signature)
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
            return Err(error.to_app_error(reqwest::StatusCode::BAD_REQUEST));
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
            connection: String::new(),
            given_name: None,
            family_name: None,
            nickname: None,
            user_metadata: None,
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
            return Err(error.to_app_error(reqwest::StatusCode::BAD_REQUEST));
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
