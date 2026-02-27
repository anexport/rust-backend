use super::dtos::{Auth0SignupResponse, Auth0TokenResponse};
use crate::error::AppResult;
use async_trait::async_trait;

/// Trait for Auth0 API operations
#[async_trait]
pub trait Auth0ApiClient: Send + Sync {
    /// Register a new user with email/password
    async fn signup(
        &self,
        email: &str,
        password: &str,
        username: Option<&str>,
    ) -> AppResult<Auth0SignupResponse>;

    /// Authenticate a user with email/password using password grant
    async fn password_grant(&self, email: &str, password: &str) -> AppResult<Auth0TokenResponse>;
}
