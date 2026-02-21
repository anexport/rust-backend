use std::sync::{Arc, Mutex};

use actix_rt::test;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use rust_backend::api::dtos::{LoginRequest, RegisterRequest};
use rust_backend::application::AuthService;
use rust_backend::config::AuthConfig;
use rust_backend::domain::{AuthIdentity, AuthProvider, Role, User, UserSession};
use rust_backend::error::AppError;
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
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(
        &self,
        identity: &AuthIdentity,
    ) -> rust_backend::error::AppResult<AuthIdentity> {
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
        _provider: &str,
        _provider_id: &str,
    ) -> rust_backend::error::AppResult<Option<AuthIdentity>> {
        Ok(None)
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
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "test-secret".to_string(),
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
