use rust_backend::domain::equipment::{Condition, Equipment};
use rust_backend::domain::user::{AuthIdentity, AuthProvider, Role, User};
use rust_backend::domain::Category;
use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;

pub fn test_user() -> User {
    User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        role: Role::Renter,
        username: Some("testuser".to_string()),
        full_name: Some("Test User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_owner() -> User {
    User {
        id: Uuid::new_v4(),
        email: "owner@example.com".to_string(),
        role: Role::Owner,
        username: Some("owner".to_string()),
        full_name: Some("Owner User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_admin() -> User {
    User {
        id: Uuid::new_v4(),
        email: "admin@example.com".to_string(),
        role: Role::Admin,
        username: Some("admin".to_string()),
        full_name: Some("Admin User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_auth_identity(user_id: Uuid) -> AuthIdentity {
    AuthIdentity {
        id: Uuid::new_v4(),
        user_id,
        provider: AuthProvider::Email,
        provider_id: None,
        password_hash: Some("hashed_password".to_string()),
        verified: true,
        created_at: Utc::now(),
    }
}

pub fn test_equipment(owner_id: Uuid, category_id: Uuid) -> Equipment {
    Equipment {
        id: Uuid::new_v4(),
        owner_id,
        category_id,
        title: "Test Equipment".to_string(),
        description: Some("A test equipment item".to_string()),
        daily_rate: Decimal::new(1000, 2),
        condition: Condition::Good,
        location: Some("Test Location".to_string()),
        coordinates: Some("40.7128, -74.0060".to_string()),
        is_available: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_category() -> Category {
    Category {
        id: Uuid::new_v4(),
        name: "Test Category".to_string(),
        parent_id: None,
        created_at: Utc::now(),
    }
}
