use std::sync::Arc;

use chrono::Utc;
use rust_backend::application::AuthService;
use rust_backend::domain::{AuthIdentity, AuthProvider, Role, User};
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::repositories::{AuthRepository, UserRepository};
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims};
use uuid::Uuid;

use super::*;
use crate::common;
use common::mocks::{MockAuthRepo, MockUserRepo};

fn test_claims(sub: &str, email: Option<&str>) -> Auth0Claims {
    Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("test-audience".to_string()),
        exp: (Utc::now() + chrono::Duration::minutes(5)).timestamp() as u64,
        iat: (Utc::now() - chrono::Duration::minutes(1)).timestamp() as u64,
        email: email.map(|e| e.to_string()),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: Some("https://example.com/photo.jpg".to_string()),
        custom_claims: std::collections::HashMap::new(),
    }
}

#[tokio::test]
async fn test_upsert_user_from_auth0_new_user() -> AppResult<()> {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let auth_service = AuthService::new(user_repo.clone(), auth_repo.clone());

    let claims = test_claims("auth0|new-user", Some("new@example.com"));
    let context = auth_service.upsert_user_from_auth0(&claims).await?;

    assert_eq!(context.email, Some("new@example.com".to_string()));
    assert_eq!(context.auth0_sub, "auth0|new-user");

    // Verify user was created in DB
    let user = user_repo.find_by_email("new@example.com").await?.unwrap();
    assert_eq!(user.full_name, Some("Test User".to_string()));
    assert_eq!(
        user.avatar_url,
        Some("https://example.com/photo.jpg".to_string())
    );

    // Verify identity was created
    let identity = auth_repo
        .find_identity_by_provider_id("auth0", "auth0|new-user")
        .await?
        .unwrap();
    assert_eq!(identity.user_id, user.id);

    Ok(())
}

#[tokio::test]
async fn test_upsert_user_from_auth0_existing_user_no_drift() -> AppResult<()> {
    let user_id = Uuid::new_v4();
    let now = Utc::now();
    let user = User {
        id: user_id,
        email: "existing@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: Some("Test User".to_string()),
        avatar_url: Some("https://example.com/photo.jpg".to_string()),
        created_at: now,
        updated_at: now,
    };

    let user_repo = Arc::new(MockUserRepo::default());
    user_repo.create(&user).await?;

    let auth_repo = Arc::new(MockAuthRepo::default());
    auth_repo
        .create_identity(&AuthIdentity {
            id: Uuid::new_v4(),
            user_id,
            provider: AuthProvider::Auth0,
            provider_id: Some("auth0|existing".to_string()),
            password_hash: None,
            verified: true,
            created_at: now,
        })
        .await?;

    let auth_service = AuthService::new(user_repo.clone(), auth_repo.clone());
    let claims = test_claims("auth0|existing", Some("existing@example.com"));

    let context = auth_service.upsert_user_from_auth0(&claims).await?;
    assert_eq!(context.user_id, user_id);

    // Verify updated_at hasn't changed (no drift)
    let final_user = user_repo.find_by_id(user_id).await?.unwrap();
    assert_eq!(final_user.updated_at, now);

    Ok(())
}

#[tokio::test]
async fn test_upsert_user_from_auth0_data_drift_resolution() -> AppResult<()> {
    let user_id = Uuid::new_v4();
    let now = Utc::now() - chrono::Duration::hours(1);
    let user = User {
        id: user_id,
        email: "drift@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: Some("Old Name".to_string()),
        avatar_url: Some("https://example.com/old.jpg".to_string()),
        created_at: now,
        updated_at: now,
    };

    let user_repo = Arc::new(MockUserRepo::default());
    user_repo.create(&user).await?;

    let auth_repo = Arc::new(MockAuthRepo::default());
    auth_repo
        .create_identity(&AuthIdentity {
            id: Uuid::new_v4(),
            user_id,
            provider: AuthProvider::Auth0,
            provider_id: Some("auth0|drift".to_string()),
            password_hash: None,
            verified: true,
            created_at: now,
        })
        .await?;

    let auth_service = AuthService::new(user_repo.clone(), auth_repo.clone());

    let mut claims = test_claims("auth0|drift", Some("drift@example.com"));
    claims.name = Some("New Name".to_string());
    claims.picture = Some("https://example.com/new.jpg".to_string());

    let context = auth_service.upsert_user_from_auth0(&claims).await?;
    assert_eq!(context.user_id, user_id);

    // Verify user was updated in DB
    let updated_user = user_repo.find_by_id(user_id).await?.unwrap();
    assert_eq!(updated_user.full_name, Some("New Name".to_string()));
    assert_eq!(
        updated_user.avatar_url,
        Some("https://example.com/new.jpg".to_string())
    );
    assert!(updated_user.updated_at > now);

    Ok(())
}

#[tokio::test]
async fn test_upsert_user_from_auth0_race_condition_fallback() -> AppResult<()> {
    use async_trait::async_trait;

    let user_repo = Arc::new(MockUserRepo::default());

    // We need to pre-create the "other" user so that find_by_id(existing_identity.user_id) succeeds
    let other_user_id = Uuid::new_v4();
    let other_user = User {
        id: other_user_id,
        email: "other@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: Some("Other User".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    user_repo.create(&other_user).await?;

    struct RaceConditionAuthRepo {
        inner: MockAuthRepo,
        failed_once: std::sync::atomic::AtomicBool,
        other_user_id: Uuid,
    }

    #[async_trait]
    impl AuthRepository for RaceConditionAuthRepo {
        async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
            self.inner.create_identity(identity).await
        }
        async fn find_identity_by_user_id(
            &self,
            user_id: Uuid,
            provider: &str,
        ) -> AppResult<Option<AuthIdentity>> {
            self.inner.find_identity_by_user_id(user_id, provider).await
        }
        async fn find_identity_by_provider_id(
            &self,
            provider: &str,
            provider_id: &str,
        ) -> AppResult<Option<AuthIdentity>> {
            self.inner
                .find_identity_by_provider_id(provider, provider_id)
                .await
        }
        async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
            if !self
                .failed_once
                .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                // Simulate another thread creating a DIFFERENT user and identity for the same sub
                let mut other_identity = identity.clone();
                other_identity.user_id = self.other_user_id;
                self.inner.create_identity(&other_identity).await?;
                return Err(AppError::DatabaseError(sqlx::Error::RowNotFound));
            }
            self.inner.upsert_identity(identity).await
        }
    }

    let auth_repo = Arc::new(RaceConditionAuthRepo {
        inner: MockAuthRepo::default(),
        failed_once: std::sync::atomic::AtomicBool::new(false),
        other_user_id,
    });

    let auth_service = AuthService::new(user_repo.clone(), auth_repo);
    let claims = test_claims("auth0|race", Some("race@example.com"));

    let context = auth_service.upsert_user_from_auth0(&claims).await?;
    assert_eq!(context.user_id, other_user_id);

    // Verify we only have one user in the end (the orphaned one should be deleted)
    let users = user_repo.users.lock().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, other_user_id);

    Ok(())
}

#[tokio::test]
async fn test_upsert_user_from_auth0_missing_email() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let auth_service = AuthService::new(user_repo, auth_repo);

    let claims = test_claims("auth0|no-email", None);
    let result = auth_service.upsert_user_from_auth0(&claims).await;

    assert!(matches!(result, Err(AppError::BadRequest(_))));
}
