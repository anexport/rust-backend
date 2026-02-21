use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserRequest {
    #[validate(length(min = 3, max = 50))]
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserProfileResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PublicProfileResponse {
    pub id: Uuid,
    pub username: Option<String>,
    pub avatar_url: Option<String>,
}
