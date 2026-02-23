use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,

    #[validate(length(min = 12, message = "Password must be at least 12 characters"))]
    pub password: String,

    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    pub username: Option<String>,

    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 1))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub user: UserResponse,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RefreshRequest {
    #[validate(length(min = 1))]
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct SessionAuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct OAuthCallbackRequest {
    #[validate(length(min = 1))]
    pub code: String,
    pub state: Option<String>,
}

/// Response for Auth0 password grant login
#[derive(Debug, Serialize)]
pub struct Auth0LoginResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

/// Response from Auth0 signup
#[derive(Debug, Serialize)]
pub struct Auth0SignupUserResponse {
    pub id: String,
    pub email: String,
    pub email_verified: bool,
    pub username: Option<String>,
    pub picture: Option<String>,
    pub name: Option<String>,
}
