use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Response for Auth0 password grant login
#[derive(Debug, Serialize, ToSchema)]
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

// Auth0 signup DTO for API documentation
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct Auth0SignupRequestDto {
    #[serde(alias = "email")]
    #[validate(length(min = 1, message = "Email is required"))]
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[serde(alias = "password")]
    pub password: String,
    #[serde(alias = "username")]
    pub username: Option<String>,
    #[serde(alias = "full_name")]
    pub full_name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct Auth0LoginRequestDto {
    #[serde(alias = "email")]
    pub email: String,
    #[serde(alias = "password")]
    pub password: String,
}
