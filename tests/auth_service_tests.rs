use std::sync::{Arc, Mutex};

use actix_rt::test;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use rust_backend::api::dtos::{LoginRequest, RegisterRequest};
use rust_backend::application::AuthService;
use rust_backend::config::AuthConfig;
use rust_backend::domain::{AuthIdentity, AuthProvider, Role, User, UserSession};
use rust_backend::error::AppError;
use rust_backend::infrastructure::oauth::{OAuthClient, OAuthProviderKind, OAuthUserInfo};
use rust_backend::infrastructure::repositories::{AuthRepository, UserRepository};
use uuid::Uuid;

#[derive(Default)]
struct MockUserRepo {
    users: Mutex<Vec<User>>,
}

#[async_trait]
impl UserRepository for MockUserRepo {
    async fn find_by_id(&self, id: Uuid) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.id == id)
            .cloned())
    }

    async fn find_by_email(&self, email: &str) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.email == email)
            .cloned())
    }

    async fn find_by_username(
        &self,
        username: &str,
    ) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .iter()
            .find(|u| u.username.as_deref() == Some(username))
            .cloned())
    }

    async fn create(&self, user: &User) -> rust_backend::error::AppResult<User> {
        self.users.lock().unwrap().push(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> rust_backend::error::AppResult<User> {
        let mut users = self.users.lock().unwrap();
        if let Some(existing) = users.iter_mut().find(|u| u.id == user.id) {
            *existing = user.clone();
            return Ok(user.clone());
        }
        Err(AppError::NotFound("user not found".to_string()))
    }

    async fn delete(&self, id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut users = self.users.lock().unwrap();
        users.retain(|u| u.id != id);
        Ok(())
    }
}

#[derive(Default)]
struct MockAuthRepo {
    identities: Mutex<Vec<AuthIdentity>>,
    fail_create_identity: Mutex<bool>,
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(
        &self,
        identity: &AuthIdentity,
    ) -> rust_backend::error::AppResult<AuthIdentity> {
        if *self.fail_create_identity.lock().unwrap() {
            return Err(AppError::Conflict("username already taken".to_string()));
        }
        self.identities.lock().unwrap().push(identity.clone());
        Ok(identity.clone())
    }

    async fn find_identity_by_user_id(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .find(|i| {
                i.user_id == user_id && provider == "email" && i.provider == AuthProvider::Email
            })
            .cloned())
    }

    async fn find_identity_by_provider_id(
        &self,
        provider: &str,
        provider_id: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .find(|i| {
                let provider_match = matches!(
                    (provider, i.provider),
                    ("google", AuthProvider::Google) | ("github", AuthProvider::GitHub)
                );
                provider_match && i.provider_id.as_deref() == Some(provider_id)
            })
            .cloned())
    }

    async fn verify_email(&self, _user_id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn create_session(
        &self,
        session: &UserSession,
    ) -> rust_backend::error::AppResult<UserSession> {
        Ok(session.clone())
    }

    async fn find_session_by_token_hash(
        &self,
        _token_hash: &str,
    ) -> rust_backend::error::AppResult<Option<UserSession>> {
        Ok(None)
    }

    async fn revoke_session(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_all_sessions(&self, _user_id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_session_with_replacement(
        &self,
        _id: Uuid,
        _replaced_by: Option<Uuid>,
        _reason: Option<&str>,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn revoke_family(
        &self,
        _family_id: Uuid,
        _reason: &str,
    ) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn touch_session(&self, _id: Uuid) -> rust_backend::error::AppResult<()> {
        Ok(())
    }

    async fn has_active_session(&self, _user_id: Uuid) -> rust_backend::error::AppResult<bool> {
        Ok(true)
    }
}

#[derive(Clone)]
struct MockOAuthClient {
    profile: OAuthUserInfo,
}

#[async_trait]
impl OAuthClient for MockOAuthClient {
    async fn exchange_code(
        &self,
        _provider: OAuthProviderKind,
        _code: &str,
    ) -> rust_backend::error::AppResult<OAuthUserInfo> {
        Ok(self.profile.clone())
    }
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "test-secret".to_string(),
        jwt_kid: "v1".to_string(),
        previous_jwt_secrets: Vec::new(),
        previous_jwt_kids: Vec::new(),
        jwt_expiration_seconds: 900,
        refresh_token_expiration_days: 7,
        issuer: "rust-backend-test".to_string(),
        audience: "rust-backend-client".to_string(),
    }
}

fn existing_user(email: &str) -> User {
    User {
        id: Uuid::new_v4(),
        email: email.to_string(),
        role: Role::Renter,
        username: Some("existing".to_string()),
        full_name: Some("Existing User".to_string()),
        avatar_url: None,
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now() - Duration::days(1),
    }
}

#[test]
async fn register_returns_conflict_when_email_exists() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    user_repo
        .users
        .lock()
        .unwrap()
        .push(existing_user("taken@example.com"));

    let service = AuthService::new(user_repo, auth_repo, auth_config());
    let request = RegisterRequest {
        email: "taken@example.com".to_string(),
        password: "this-is-a-secure-password".to_string(),
        username: Some("new-user".to_string()),
        full_name: Some("New User".to_string()),
    };

    let result = service.register(request).await;
    assert!(matches!(result, Err(AppError::Conflict(_))));
}

#[test]
async fn login_returns_unauthorized_for_wrong_password() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let user = existing_user("user@example.com");
    let user_id = user.id;
    user_repo.users.lock().unwrap().push(user);

    auth_repo.identities.lock().unwrap().push(AuthIdentity {
        id: Uuid::new_v4(),
        user_id,
        provider: AuthProvider::Email,
        provider_id: None,
        password_hash: Some(
            rust_backend::utils::hash::hash_password("correct-password")
                .expect("hashing should work"),
        ),
        verified: true,
        created_at: Utc::now(),
    });

    let service = AuthService::new(user_repo, auth_repo, auth_config());
    let request = LoginRequest {
        email: "user@example.com".to_string(),
        password: "wrong-password".to_string(),
    };

    let result = service.login(request).await;
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

#[test]
async fn oauth_login_creates_new_user_and_identity() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let oauth_client = Arc::new(MockOAuthClient {
        profile: OAuthUserInfo {
            provider_id: "google-sub-123".to_string(),
            email: "oauth-new@example.com".to_string(),
            email_verified: true,
            full_name: Some("OAuth New".to_string()),
            avatar_url: None,
        },
    });

    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config())
        .with_oauth_client(oauth_client);
    let result = service
        .oauth_login(
            OAuthProviderKind::Google,
            "code",
            Some("127.0.0.1".to_string()),
        )
        .await
        .expect("oauth login should succeed");

    assert_eq!(result.user.email, "oauth-new@example.com");
    assert_eq!(user_repo.users.lock().unwrap().len(), 1);

    let identities = auth_repo.identities.lock().unwrap();
    assert!(identities.iter().any(|identity| {
        identity.provider == AuthProvider::Google
            && identity.provider_id.as_deref() == Some("google-sub-123")
    }));
}

#[test]
async fn oauth_login_links_identity_to_existing_user_by_email() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    let existing = existing_user("existing-oauth@example.com");
    let existing_id = existing.id;
    user_repo.users.lock().unwrap().push(existing);

    let oauth_client = Arc::new(MockOAuthClient {
        profile: OAuthUserInfo {
            provider_id: "gh-444".to_string(),
            email: "existing-oauth@example.com".to_string(),
            email_verified: true,
            full_name: Some("Existing OAuth".to_string()),
            avatar_url: None,
        },
    });

    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config())
        .with_oauth_client(oauth_client);
    let result = service
        .oauth_login(
            OAuthProviderKind::GitHub,
            "code",
            Some("127.0.0.1".to_string()),
        )
        .await
        .expect("oauth login should succeed");

    assert_eq!(result.user.id, existing_id);
    assert_eq!(user_repo.users.lock().unwrap().len(), 1);

    let identities = auth_repo.identities.lock().unwrap();
    assert!(identities.iter().any(|identity| {
        identity.user_id == existing_id
            && identity.provider == AuthProvider::GitHub
            && identity.provider_id.as_deref() == Some("gh-444")
    }));
}

#[test]
async fn register_cleans_up_profile_when_identity_creation_fails() {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());
    *auth_repo.fail_create_identity.lock().unwrap() = true;

    let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());
    let request = RegisterRequest {
        email: "cleanup@example.com".to_string(),
        password: "this-is-a-secure-password".to_string(),
        username: Some("cleanup-user".to_string()),
        full_name: Some("Cleanup User".to_string()),
    };

    let result = service.register(request).await;
    assert!(matches!(result, Err(AppError::Conflict(_))));
    assert_eq!(user_repo.users.lock().unwrap().len(), 0);
    assert_eq!(auth_repo.identities.lock().unwrap().len(), 0);
}
