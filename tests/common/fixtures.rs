#![allow(dead_code)]

use rust_backend::domain::equipment::{Condition, Equipment};
use rust_backend::domain::user::{AuthIdentity, AuthProvider, Role, User};
use rust_backend::domain::Category;
use chrono::Utc;
use rust_decimal::Decimal;
use uuid::Uuid;
use std::sync::atomic::{AtomicU64, Ordering};

// Counter for generating unique test values
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn next_id() -> u64 {
    TEST_COUNTER.fetch_add(1, Ordering::SeqCst)
}

pub fn test_user() -> User {
    let id = next_id();
    User {
        id: Uuid::new_v4(),
        email: format!("test{}@example.com", id),
        role: Role::Renter,
        username: Some(format!("testuser{}", id)),
        full_name: Some(format!("Test User {}", id)),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_owner() -> User {
    let id = next_id();
    User {
        id: Uuid::new_v4(),
        email: format!("owner{}@example.com", id),
        role: Role::Owner,
        username: Some(format!("owner{}", id)),
        full_name: Some(format!("Owner User {}", id)),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

pub fn test_admin() -> User {
    let id = next_id();
    User {
        id: Uuid::new_v4(),
        email: format!("admin{}@example.com", id),
        role: Role::Admin,
        username: Some(format!("admin{}", id)),
        full_name: Some(format!("Admin User {}", id)),
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
    let id = next_id();
    Category {
        id: Uuid::new_v4(),
        name: format!("Test Category {}", id),
        parent_id: None,
        created_at: Utc::now(),
    }
}
