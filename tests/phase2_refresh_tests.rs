use std::sync::{Arc, Mutex};

use actix_rt::test;
use async_trait::async_trait;
use chrono::{Duration, Utc};
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
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.id == id)
            .cloned())
    }

    async fn find_by_email(&self, email: &str) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.email == email)
            .cloned())
    }

    async fn find_by_username(
        &self,
        username: &str,
    ) -> rust_backend::error::AppResult<Option<User>> {
        Ok(self
            .users
            .lock()
            .expect("users mutex poisoned")
            .iter()
            .find(|user| user.username.as_deref() == Some(username))
            .cloned())
    }

    async fn create(&self, user: &User) -> rust_backend::error::AppResult<User> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .push(user.clone());
        Ok(user.clone())
    }

    async fn update(&self, user: &User) -> rust_backend::error::AppResult<User> {
        let mut users = self.users.lock().expect("users mutex poisoned");
        if let Some(existing) = users.iter_mut().find(|existing| existing.id == user.id) {
            *existing = user.clone();
        }
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> rust_backend::error::AppResult<()> {
        self.users
            .lock()
            .expect("users mutex poisoned")
            .retain(|user| user.id != id);
        Ok(())
    }
}

#[derive(Default)]
struct MockAuthRepo {
    identities: Mutex<Vec<AuthIdentity>>,
    sessions: Mutex<Vec<UserSession>>,
}

#[async_trait]
impl AuthRepository for MockAuthRepo {
    async fn create_identity(
        &self,
        identity: &AuthIdentity,
    ) -> rust_backend::error::AppResult<AuthIdentity> {
        self.identities
            .lock()
            .expect("identities mutex poisoned")
            .push(identity.clone());
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
            .expect("identities mutex poisoned")
            .iter()
            .find(|identity| identity.user_id == user_id && provider == "email")
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
        self.sessions
            .lock()
            .expect("sessions mutex poisoned")
            .push(session.clone());
        Ok(session.clone())
    }

    async fn find_session_by_token_hash(
        &self,
        token_hash: &str,
    ) -> rust_backend::error::AppResult<Option<UserSession>> {
        Ok(self
            .sessions
            .lock()
            .expect("sessions mutex poisoned")
            .iter()
            .find(|session| session.refresh_token_hash == token_hash)
            .cloned())
    }

    async fn revoke_session(&self, id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.revoked_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn revoke_all_sessions(&self, user_id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        for session in sessions
            .iter_mut()
            .filter(|session| session.user_id == user_id)
        {
            session.revoked_at = Some(Utc::now());
        }
        Ok(())
    }

    async fn revoke_session_with_replacement(
        &self,
        id: Uuid,
        replaced_by: Option<Uuid>,
        reason: Option<&str>,
    ) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.revoked_at = Some(Utc::now());
            session.replaced_by = replaced_by;
            session.revoked_reason = reason.map(str::to_string);
        }
        Ok(())
    }

    async fn revoke_family(
        &self,
        family_id: Uuid,
        reason: &str,
    ) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        for session in sessions
            .iter_mut()
            .filter(|session| session.family_id == family_id && session.revoked_at.is_none())
        {
            session.revoked_at = Some(Utc::now());
            session.revoked_reason = Some(reason.to_string());
        }
        Ok(())
    }

    async fn touch_session(&self, id: Uuid) -> rust_backend::error::AppResult<()> {
        let mut sessions = self.sessions.lock().expect("sessions mutex poisoned");
        if let Some(session) = sessions.iter_mut().find(|session| session.id == id) {
            session.last_seen_at = Some(Utc::now());
        }
        Ok(())
    }
}

fn auth_config() -> AuthConfig {
    AuthConfig {
        jwt_secret: "phase2-secret".to_string(),
        jwt_expiration_seconds: 900,
        refresh_token_expiration_days: 7,
        issuer: "rust-backend".to_string(),
        audience: "rust-backend-users".to_string(),
        jwt_kid: "v2-current".to_string(),
        previous_jwt_secrets: vec!["phase2-previous-secret".to_string()],
        previous_jwt_kids: vec!["v1-previous".to_string()],
    }
}

fn seeded_service() -> AuthService {
    let user_repo = Arc::new(MockUserRepo::default());
    let auth_repo = Arc::new(MockAuthRepo::default());

    let user = User {
        id: Uuid::new_v4(),
        email: "phase2@example.com".to_string(),
        role: Role::Renter,
        username: Some("phase2-user".to_string()),
        full_name: Some("Phase Two".to_string()),
        avatar_url: None,
        created_at: Utc::now() - Duration::days(1),
        updated_at: Utc::now() - Duration::days(1),
    };
    user_repo
        .users
        .lock()
        .expect("users mutex poisoned")
        .push(user.clone());

    auth_repo
        .identities
        .lock()
        .expect("identities mutex poisoned")
        .push(AuthIdentity {
            id: Uuid::new_v4(),
            user_id: user.id,
            provider: AuthProvider::Email,
            provider_id: None,
            password_hash: Some(
                rust_backend::utils::hash::hash_password("correct-password")
                    .expect("password hashing should succeed"),
            ),
            verified: true,
            created_at: Utc::now() - Duration::days(1),
        });

    AuthService::new(user_repo, auth_repo, auth_config())
}

#[test]
async fn refresh_rotation_replaces_old_session_token() {
    let service = seeded_service();

    let issued = service
        .issue_session_tokens(
            "phase2@example.com",
            "correct-password",
            Some("127.0.0.1".to_string()),
        )
        .await
        .expect("initial token issue should succeed");

    let rotated = service
        .refresh_session_tokens(&issued.refresh_token, Some("127.0.0.1".to_string()))
        .await
        .expect("refresh rotation should succeed");

    assert_ne!(issued.refresh_token, rotated.refresh_token);
}

#[test]
async fn refresh_reuse_revokes_token_family() {
    let service = seeded_service();

    let issued = service
        .issue_session_tokens(
            "phase2@example.com",
            "correct-password",
            Some("127.0.0.1".to_string()),
        )
        .await
        .expect("initial token issue should succeed");

    let rotated = service
        .refresh_session_tokens(&issued.refresh_token, Some("127.0.0.1".to_string()))
        .await
        .expect("first refresh should succeed");
    assert_ne!(issued.refresh_token, rotated.refresh_token);

    let replay = service
        .refresh_session_tokens(&issued.refresh_token, Some("127.0.0.1".to_string()))
        .await;
    assert!(matches!(replay, Err(AppError::Unauthorized)));

    let new_token_after_replay = service
        .refresh_session_tokens(&rotated.refresh_token, Some("127.0.0.1".to_string()))
        .await;
    assert!(matches!(
        new_token_after_replay,
        Err(AppError::Unauthorized)
    ));
}
