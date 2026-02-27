use super::*;
use crate::common::fixtures;
use crate::common::fixtures::next_id;
use crate::common::TestDb;
use crate::common::repository_helpers::create_category;
use rust_backend::domain::*;
use rust_backend::infrastructure::repositories::*;
use rust_backend::error::AppError;
use rust_decimal::Decimal;
use chrono::{Utc, Duration};
use uuid::Uuid;

#[tokio::test]
async fn user_repository_create_and_find() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created = repo.create(&user).await.unwrap();

    assert_eq!(created.id, user.id);
    assert_eq!(created.email, user.email);
    assert_eq!(created.role, user.role);

    let found = repo.find_by_id(user.id).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().email, user.email);
}

#[tokio::test]
async fn user_repository_find_by_email_case_sensitivity() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let email = "TestUser@Example.COM";
    let mut user = user;
    user.email = email.to_string();
    repo.create(&user).await.unwrap();

    // Test exact match (PostgreSQL is case-sensitive for text)
    let found = repo.find_by_email(email).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().email, email);

    // Test case-insensitive matching - should NOT match due to case sensitivity
    let not_found = repo.find_by_email(&email.to_lowercase()).await.unwrap();
    assert!(not_found.is_none());
}

#[tokio::test]
async fn user_repository_find_by_username_positive_and_negative() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let mut user = fixtures::test_user();
    user.username = Some("lookup_user".to_string());
    let created = repo.create(&user).await.unwrap();

    let found = repo.find_by_username("lookup_user").await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().id, created.id);

    let missing = repo.find_by_username("missing_user").await.unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn user_repository_update_partial_fields() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let original_email = user.email.clone();
    let created = repo.create(&user).await.unwrap();

    // Update only some fields
    let mut updated_user = created.clone();
    updated_user.email = "updated@example.com".to_string();
    updated_user.full_name = Some("Updated Name".to_string());
    updated_user.username = Some("updateduser".to_string());

    let updated = repo.update(&updated_user).await.unwrap();

    assert_eq!(updated.id, created.id);
    assert_eq!(updated.email, "updated@example.com");
    assert_eq!(updated.full_name, Some("Updated Name".to_string()));
    assert_eq!(updated.username, Some("updateduser".to_string()));
    assert_eq!(updated.role, created.role);
    assert_ne!(updated.email, original_email);

    // Verify persisted
    let found = repo.find_by_id(updated.id).await.unwrap().unwrap();
    assert_eq!(found.email, "updated@example.com");
    assert_eq!(found.full_name, Some("Updated Name".to_string()));
}

#[tokio::test]
async fn user_repository_update_avatar_url() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created = repo.create(&user).await.unwrap();

    assert!(created.avatar_url.is_none());

    let mut updated_user = created;
    updated_user.avatar_url = Some("https://example.com/avatar.jpg".to_string());

    let updated = repo.update(&updated_user).await.unwrap();

    assert_eq!(
        updated.avatar_url,
        Some("https://example.com/avatar.jpg".to_string())
    );
}

#[tokio::test]
async fn user_repository_delete_cascade_auth_identities() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(format!("auth0|{}", next_id())),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    let _created_identity = auth_repo.create_identity(&identity).await.unwrap();

    // Verify identity exists via find_by_user_id
    let found = auth_repo
        .find_identity_by_user_id(created_user.id, "auth0")
        .await
        .unwrap();
    assert!(found.is_some());

    // Delete user
    user_repo.delete(created_user.id).await.unwrap();

    // Verify user is gone
    let found_user = user_repo.find_by_id(created_user.id).await.unwrap();
    assert!(found_user.is_none());

    // Verify identity is cascade deleted
    let found_identity = auth_repo
        .find_identity_by_provider_id(
            "auth0",
            identity
                .provider_id
                .as_deref()
                .expect("provider_id should exist"),
        )
        .await
        .unwrap();
    assert!(found_identity.is_none());
}

#[tokio::test]
async fn user_repository_delete_non_existent_id_is_noop() {
    let db = TestDb::new().await.expect("Test DB required");
    let repo = UserRepositoryImpl::new(db.pool().clone());

    let non_existent_id = Uuid::new_v4();
    repo.delete(non_existent_id).await.unwrap();

    let found = repo.find_by_id(non_existent_id).await.unwrap();
    assert!(found.is_none());
}

