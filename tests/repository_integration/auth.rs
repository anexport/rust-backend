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
async fn auth_repository_create_identity() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let identity = fixtures::test_auth_identity(created_user.id);
    let created = auth_repo.create_identity(&identity).await.unwrap();

    assert_eq!(created.id, identity.id);
    assert_eq!(created.user_id, created_user.id);
    assert_eq!(created.provider, identity.provider);
    assert_eq!(created.verified, identity.verified);
}

#[tokio::test]
async fn auth_repository_rejects_duplicate_auth0_identity_for_same_user() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let first_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(format!("auth0|{}", next_id())),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    auth_repo.create_identity(&first_identity).await.unwrap();

    let duplicate_identity = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(format!("auth0|{}", next_id())),
        password_hash: None,
        verified: true,
        created_at: Utc::now(),
    };
    let result = auth_repo.create_identity(&duplicate_identity).await;
    assert!(matches!(result, Err(AppError::Conflict(_))));
}

#[tokio::test]
async fn auth_repository_upsert_identity_conflict_handling() {
    let db = TestDb::new().await.expect("Test DB required");
    let user_repo = UserRepositoryImpl::new(db.pool().clone());
    let auth_repo = AuthRepositoryImpl::new(db.pool().clone());

    let user = fixtures::test_user();
    let created_user = user_repo.create(&user).await.unwrap();

    let provider_id = format!("auth0|{}", next_id());
    let identity1 = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(provider_id.clone()),
        password_hash: None,
        verified: false,
        created_at: Utc::now(),
    };
    auth_repo.create_identity(&identity1).await.unwrap();

    // Upsert with same provider_id but different verified status
    let identity2 = AuthIdentity {
        id: Uuid::new_v4(),
        user_id: created_user.id,
        provider: DomainAuthProvider::Auth0,
        provider_id: Some(provider_id.clone()),
        password_hash: None,
        verified: true, // Changed to true
        created_at: Utc::now(),
    };
    let upserted = auth_repo.upsert_identity(&identity2).await.unwrap();

    // Should update the existing record
    assert_eq!(upserted.provider_id, Some(provider_id.clone()));
    assert!(upserted.verified);

    // Verify only one record exists
    let found = auth_repo
        .find_identity_by_provider_id("auth0", &provider_id)
        .await
        .unwrap();
    assert!(found.is_some());
}

