use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Renter,
    Owner,
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub role: Role,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OwnerProfile {
    pub profile_id: Uuid,
    pub business_info: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RenterProfile {
    pub profile_id: Uuid,
    pub preferences: Option<serde_json::Value>,
    pub experience_level: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "auth_provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
    Email,
    Google,
    GitHub,
    Auth0,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuthIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: AuthProvider,
    pub provider_id: Option<String>,
    pub password_hash: Option<String>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub refresh_token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by: Option<Uuid>,
    pub revoked_reason: Option<String>,
    pub created_ip: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub device_info: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_serializes_to_lowercase() {
        assert_eq!(serde_json::to_string(&Role::Renter).unwrap(), "\"renter\"");
        assert_eq!(serde_json::to_string(&Role::Owner).unwrap(), "\"owner\"");
        assert_eq!(serde_json::to_string(&Role::Admin).unwrap(), "\"admin\"");
    }

    #[test]
    fn role_deserializes_from_lowercase() {
        assert_eq!(
            serde_json::from_str::<Role>("\"renter\"").unwrap(),
            Role::Renter
        );
        assert_eq!(
            serde_json::from_str::<Role>("\"owner\"").unwrap(),
            Role::Owner
        );
        assert_eq!(
            serde_json::from_str::<Role>("\"admin\"").unwrap(),
            Role::Admin
        );
    }

    #[test]
    fn role_partial_eq_works() {
        assert_eq!(Role::Renter, Role::Renter);
        assert_eq!(Role::Owner, Role::Owner);
        assert_eq!(Role::Admin, Role::Admin);
        assert_ne!(Role::Renter, Role::Owner);
        assert_ne!(Role::Owner, Role::Admin);
        assert_ne!(Role::Admin, Role::Renter);
    }

    #[test]
    fn auth_provider_serializes_to_lowercase() {
        assert_eq!(
            serde_json::to_string(&AuthProvider::Email).unwrap(),
            "\"email\""
        );
        assert_eq!(
            serde_json::to_string(&AuthProvider::Google).unwrap(),
            "\"google\""
        );
        assert_eq!(
            serde_json::to_string(&AuthProvider::GitHub).unwrap(),
            "\"github\""
        );
    }

    #[test]
    fn auth_provider_deserializes_from_lowercase() {
        assert_eq!(
            serde_json::from_str::<AuthProvider>("\"email\"").unwrap(),
            AuthProvider::Email
        );
        assert_eq!(
            serde_json::from_str::<AuthProvider>("\"google\"").unwrap(),
            AuthProvider::Google
        );
        assert_eq!(
            serde_json::from_str::<AuthProvider>("\"github\"").unwrap(),
            AuthProvider::GitHub
        );
        assert_eq!(
            serde_json::from_str::<AuthProvider>("\"auth0\"").unwrap(),
            AuthProvider::Auth0
        );
    }
}
