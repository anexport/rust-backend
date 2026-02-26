use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[sqlx(type_name = "role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Renter,
    Owner,
    Admin,
}

impl Role {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Renter => "renter",
            Self::Owner => "owner",
            Self::Admin => "admin",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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

impl Default for User {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email: "default@example.com".to_string(),
            role: Role::default(),
            username: None,
            full_name: None,
            avatar_url: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "auth_provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum AuthProvider {
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
            serde_json::to_string(&AuthProvider::Auth0).unwrap(),
            "\"auth0\""
        );
    }

    #[test]
    fn auth_provider_deserializes_from_lowercase() {
        assert_eq!(
            serde_json::from_str::<AuthProvider>("\"auth0\"").unwrap(),
            AuthProvider::Auth0
        );
    }
}
