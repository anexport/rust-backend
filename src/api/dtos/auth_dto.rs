use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
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
