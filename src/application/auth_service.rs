use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{AuthResponse, LoginRequest, RegisterRequest, UserResponse};
use crate::config::AuthConfig;
use crate::domain::{AuthIdentity, AuthProvider, Role, User, UserSession};
use crate::error::{AppError, AppResult};
use crate::infrastructure::oauth::{DisabledOAuthClient, OAuthClient, OAuthProviderKind};
use crate::infrastructure::repositories::{AuthRepository, UserRepository};
use crate::utils::auth0_claims::{Auth0Claims, Auth0UserContext};
use crate::utils::hash::{hash_password, hash_refresh_token, verify_password};
use crate::utils::jwt::{create_access_token, validate_token, Claims};

#[derive(Clone)]
pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    auth_repo: Arc<dyn AuthRepository>,
    config: AuthConfig,
    oauth_client: Arc<dyn OAuthClient>,
    auth0_namespace: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserResponse,
}

impl AuthService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        auth_repo: Arc<dyn AuthRepository>,
        config: AuthConfig,
    ) -> Self {
        Self {
            user_repo,
            auth_repo,
            config,
            oauth_client: Arc::new(DisabledOAuthClient),
            auth0_namespace: None,
        }
    }

    pub fn with_oauth_client(mut self, oauth_client: Arc<dyn OAuthClient>) -> Self {
        self.oauth_client = oauth_client;
        self
    }

    pub fn with_auth0_namespace(mut self, namespace: String) -> Self {
        self.auth0_namespace = Some(namespace);
        self
    }

    pub async fn register(&self, request: RegisterRequest) -> AppResult<AuthResponse> {
        request.validate()?;

        if self
            .user_repo
            .find_by_email(&request.email)
            .await?
            .is_some()
        {
            return Err(AppError::Conflict("email already registered".to_string()));
        }

        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: request.email,
            role: Role::Renter,
            username: request.username,
            full_name: request.full_name,
            avatar_url: None,
            created_at: now,
            updated_at: now,
        };

        let user = self.user_repo.create(&user).await?;

        let identity = AuthIdentity {
            id: Uuid::new_v4(),
            user_id: user.id,
            provider: AuthProvider::Email,
            provider_id: None,
            password_hash: Some(hash_password(&request.password)?),
            verified: false,
            created_at: now,
        };
        if let Err(error) = self.auth_repo.create_identity(&identity).await {
            let _ = self.user_repo.delete(user.id).await;
            return Err(error);
        }

        let access_token = create_access_token(user.id, &role_as_str(user.role), &self.config)?;
        Ok(AuthResponse {
            access_token,
            user: map_user_response(&user),
        })
    }

    pub async fn login(&self, request: LoginRequest) -> AppResult<AuthResponse> {
        request.validate()?;

        let user = self
            .user_repo
            .find_by_email(&request.email)
            .await?
            .ok_or(AppError::Unauthorized)?;

        let identity = self
            .auth_repo
            .find_identity_by_user_id(user.id, "email")
            .await?
            .ok_or(AppError::Unauthorized)?;

        let hash = identity.password_hash.ok_or(AppError::Unauthorized)?;
        if !verify_password(&request.password, &hash)? {
            return Err(AppError::Unauthorized);
        }

        let access_token = create_access_token(user.id, &role_as_str(user.role), &self.config)?;
        Ok(AuthResponse {
            access_token,
            user: map_user_response(&user),
        })
    }

    pub async fn me(&self, user_id: Uuid) -> AppResult<UserResponse> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

        Ok(map_user_response(&user))
    }

    pub async fn verify_email(&self, user_id: Uuid) -> AppResult<()> {
        self.auth_repo.verify_email(user_id).await
    }

    pub async fn issue_session_tokens(
        &self,
        email: &str,
        password: &str,
        ip: Option<String>,
    ) -> AppResult<SessionTokens> {
        let login = LoginRequest {
            email: email.to_string(),
            password: password.to_string(),
        };
        login.validate()?;

        let user = self
            .user_repo
            .find_by_email(email)
            .await?
            .ok_or(AppError::Unauthorized)?;
        let identity = self
            .auth_repo
            .find_identity_by_user_id(user.id, "email")
            .await?
            .ok_or(AppError::Unauthorized)?;

        let hash = identity.password_hash.ok_or(AppError::Unauthorized)?;
        if !verify_password(password, &hash)? {
            return Err(AppError::Unauthorized);
        }

        self.create_session_tokens_for_user(user, Uuid::new_v4(), ip)
            .await
    }

    pub async fn refresh_session_tokens(
        &self,
        refresh_token: &str,
        ip: Option<String>,
    ) -> AppResult<SessionTokens> {
        let refresh_hash = hash_refresh_token(refresh_token);
        let now = Utc::now();
        let session = self
            .auth_repo
            .find_session_by_token_hash(&refresh_hash)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if session.revoked_at.is_some() {
            self.auth_repo
                .revoke_family(session.family_id, "refresh token replay detected")
                .await?;
            return Err(AppError::Unauthorized);
        }

        if session.expires_at <= now {
            self.auth_repo
                .revoke_session_with_replacement(session.id, None, Some("refresh token expired"))
                .await?;
            return Err(AppError::Unauthorized);
        }

        self.auth_repo.touch_session(session.id).await?;

        let user = self
            .user_repo
            .find_by_id(session.user_id)
            .await?
            .ok_or(AppError::Unauthorized)?;

        let issued = self
            .create_session_tokens_for_user(user, session.family_id, ip)
            .await?;

        let replacement_hash = hash_refresh_token(&issued.refresh_token);
        let replacement = self
            .auth_repo
            .find_session_by_token_hash(&replacement_hash)
            .await?
            .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("created session not found")))?;

        self.auth_repo
            .revoke_session_with_replacement(session.id, Some(replacement.id), Some("rotated"))
            .await?;

        Ok(issued)
    }

    pub async fn logout(&self, refresh_token: &str) -> AppResult<()> {
        let refresh_hash = hash_refresh_token(refresh_token);
        let session = self
            .auth_repo
            .find_session_by_token_hash(&refresh_hash)
            .await?
            .ok_or(AppError::Unauthorized)?;

        if session.revoked_at.is_some() {
            return Err(AppError::Unauthorized);
        }

        self.auth_repo
            .revoke_session_with_replacement(session.id, None, Some("logout"))
            .await
    }

    pub fn validate_access_token(&self, token: &str) -> AppResult<Claims> {
        validate_token(token, &self.config)
    }

    pub async fn oauth_login(
        &self,
        provider: OAuthProviderKind,
        code: &str,
        ip: Option<String>,
    ) -> AppResult<SessionTokens> {
        let profile = self.oauth_client.exchange_code(provider, code).await?;

        let provider_key = provider_as_str(provider);

        if let Some(identity) = self
            .auth_repo
            .find_identity_by_provider_id(provider_key, &profile.provider_id)
            .await?
        {
            let user = self
                .user_repo
                .find_by_id(identity.user_id)
                .await?
                .ok_or(AppError::Unauthorized)?;
            return self
                .create_session_tokens_for_user(user, Uuid::new_v4(), ip)
                .await;
        }

        let user = if let Some(existing) = self.user_repo.find_by_email(&profile.email).await? {
            existing
        } else {
            let now = Utc::now();
            self.user_repo
                .create(&User {
                    id: Uuid::new_v4(),
                    email: profile.email.clone(),
                    role: Role::Renter,
                    username: None,
                    full_name: profile.full_name.clone(),
                    avatar_url: profile.avatar_url.clone(),
                    created_at: now,
                    updated_at: now,
                })
                .await?
        };

        if self
            .auth_repo
            .find_identity_by_provider_id(provider_key, &profile.provider_id)
            .await?
            .is_none()
        {
            self.auth_repo
                .create_identity(&AuthIdentity {
                    id: Uuid::new_v4(),
                    user_id: user.id,
                    provider: provider_as_domain(provider),
                    provider_id: Some(profile.provider_id),
                    password_hash: None,
                    verified: profile.email_verified,
                    created_at: Utc::now(),
                })
                .await?;
        }

        self.create_session_tokens_for_user(user, Uuid::new_v4(), ip)
            .await
    }

    pub async fn ensure_active_session_for_user(&self, user_id: Uuid) -> AppResult<()> {
        if self.auth_repo.has_active_session(user_id).await? {
            return Ok(());
        }
        Err(AppError::Unauthorized)
    }

    pub async fn upsert_user_from_auth0(&self, claims: &Auth0Claims) -> AppResult<Auth0UserContext> {
        if let Some(identity) = self
            .auth_repo
            .find_identity_by_provider_id("auth0", &claims.sub)
            .await?
        {
            let user = self
                .user_repo
                .find_by_id(identity.user_id)
                .await?
                .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("user not found for auth0 identity")))?;
            
            let updated_user = self.maybe_update_user_from_claims(&user, claims).await?;
            let namespace = self.auth0_namespace.as_deref().unwrap_or("");
            Ok(Auth0UserContext::from_claims(claims, updated_user.id, namespace))
        } else {
            self.create_user_from_auth0(claims).await
        }
    }

    async fn maybe_update_user_from_claims(&self, user: &User, claims: &Auth0Claims) -> AppResult<User> {
        let email_changed = claims.email.as_ref() != Some(&user.email);
        let name_changed = claims.name.as_ref() != user.full_name.as_ref();
        let avatar_changed = claims.picture.as_ref() != user.avatar_url.as_ref();

        if !email_changed && !name_changed && !avatar_changed {
            return Ok(user.clone());
        }

        let now = Utc::now();
        let updated = User {
            email: claims.email.clone().unwrap_or_else(|| user.email.clone()),
            full_name: claims.name.clone().or(user.full_name.clone()),
            avatar_url: claims.picture.clone().or(user.avatar_url.clone()),
            updated_at: now,
            ..user.clone()
        };

        self.user_repo.update(&updated).await
    }

    async fn create_user_from_auth0(&self, claims: &Auth0Claims) -> AppResult<Auth0UserContext> {
        let email = claims.email.clone().ok_or_else(|| {
            AppError::BadRequest("email is required for new users".to_string())
        })?;

        let now = Utc::now();
        let user = User {
            id: Uuid::new_v4(),
            email: email.clone(),
            role: Role::Renter,
            username: None,
            full_name: claims.name.clone(),
            avatar_url: claims.picture.clone(),
            created_at: now,
            updated_at: now,
        };

        let user = self.user_repo.create(&user).await?;

        let identity = AuthIdentity {
            id: Uuid::new_v4(),
            user_id: user.id,
            provider: AuthProvider::Auth0,
            provider_id: Some(claims.sub.clone()),
            password_hash: None,
            verified: claims.email_verified.unwrap_or(false),
            created_at: now,
        };

        match self.auth_repo.upsert_identity(&identity).await {
            Ok(_) => {}
            Err(AppError::DatabaseError(_)) => {
                if let Some(existing_identity) = self
                    .auth_repo
                    .find_identity_by_provider_id("auth0", &claims.sub)
                    .await?
                {
                    let existing_user = self
                        .user_repo
                        .find_by_id(existing_identity.user_id)
                        .await?
                        .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("user not found for auth0 identity")))?;
                    let _ = self.user_repo.delete(user.id).await;
                    let namespace = self.auth0_namespace.as_deref().unwrap_or("");
                    return Ok(Auth0UserContext::from_claims(claims, existing_user.id, namespace));
                }
                return Err(AppError::InternalError(anyhow::anyhow!("failed to create auth identity")));
            }
            Err(e) => {
                let _ = self.user_repo.delete(user.id).await;
                return Err(e);
            }
        }

        let namespace = self.auth0_namespace.as_deref().unwrap_or("");
        Ok(Auth0UserContext::from_claims(claims, user.id, namespace))
    }

    pub fn refresh_expiry(&self) -> Duration {
        Duration::days(self.config.refresh_token_expiration_days as i64)
    }

    async fn create_session_tokens_for_user(
        &self,
        user: User,
        family_id: Uuid,
        ip: Option<String>,
    ) -> AppResult<SessionTokens> {
        let raw_refresh_token = format!("{}.{}", Uuid::new_v4(), Uuid::new_v4());
        let now = Utc::now();
        let session = UserSession {
            id: Uuid::new_v4(),
            user_id: user.id,
            family_id,
            refresh_token_hash: hash_refresh_token(&raw_refresh_token),
            expires_at: now + self.refresh_expiry(),
            revoked_at: None,
            replaced_by: None,
            revoked_reason: None,
            created_ip: ip,
            last_seen_at: Some(now),
            device_info: None,
            created_at: now,
        };
        self.auth_repo.create_session(&session).await?;

        let access_token = create_access_token(user.id, &role_as_str(user.role), &self.config)?;
        Ok(SessionTokens {
            access_token,
            refresh_token: raw_refresh_token,
            user: map_user_response(&user),
        })
    }
}

fn map_user_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id,
        email: user.email.clone(),
        role: role_as_str(user.role),
        username: user.username.clone(),
        full_name: user.full_name.clone(),
        avatar_url: user.avatar_url.clone(),
    }
}

fn role_as_str(role: Role) -> String {
    match role {
        Role::Renter => "renter".to_string(),
        Role::Owner => "owner".to_string(),
        Role::Admin => "admin".to_string(),
    }
}

fn provider_as_str(provider: OAuthProviderKind) -> &'static str {
    match provider {
        OAuthProviderKind::Google => "google",
        OAuthProviderKind::GitHub => "github",
    }
}

fn provider_as_domain(provider: OAuthProviderKind) -> AuthProvider {
    match provider {
        OAuthProviderKind::Google => AuthProvider::Google,
        OAuthProviderKind::GitHub => AuthProvider::GitHub,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use crate::config::AuthConfig;
    use crate::infrastructure::repositories::{AuthRepository, UserRepository};
    use crate::utils::hash::hash_password;

    #[derive(Default)]
    struct MockUserRepository {
        users_by_id: Mutex<HashMap<Uuid, User>>,
        email_to_user_id: Mutex<HashMap<String, Uuid>>,
        username_to_user_id: Mutex<HashMap<String, Uuid>>,
    }

    impl MockUserRepository {
        fn insert_user(&self, user: User) {
            let mut users = self
                .users_by_id
                .lock()
                .expect("users mutex should not be poisoned");
            let mut emails = self
                .email_to_user_id
                .lock()
                .expect("email mutex should not be poisoned");
            let mut usernames = self
                .username_to_user_id
                .lock()
                .expect("username mutex should not be poisoned");

            emails.insert(user.email.clone(), user.id);
            if let Some(username) = &user.username {
                usernames.insert(username.clone(), user.id);
            }
            users.insert(user.id, user);
        }
    }

    #[async_trait]
    impl UserRepository for MockUserRepository {
        async fn find_by_id(&self, id: Uuid) -> AppResult<Option<User>> {
            let users = self
                .users_by_id
                .lock()
                .expect("users mutex should not be poisoned");
            Ok(users.get(&id).cloned())
        }

        async fn find_by_email(&self, email: &str) -> AppResult<Option<User>> {
            let user_id = self
                .email_to_user_id
                .lock()
                .expect("email mutex should not be poisoned")
                .get(email)
                .copied();
            let users = self
                .users_by_id
                .lock()
                .expect("users mutex should not be poisoned");
            Ok(user_id.and_then(|id| users.get(&id).cloned()))
        }

        async fn find_by_username(&self, username: &str) -> AppResult<Option<User>> {
            let user_id = self
                .username_to_user_id
                .lock()
                .expect("username mutex should not be poisoned")
                .get(username)
                .copied();
            let users = self
                .users_by_id
                .lock()
                .expect("users mutex should not be poisoned");
            Ok(user_id.and_then(|id| users.get(&id).cloned()))
        }

        async fn create(&self, user: &User) -> AppResult<User> {
            self.insert_user(user.clone());
            Ok(user.clone())
        }

        async fn update(&self, user: &User) -> AppResult<User> {
            self.insert_user(user.clone());
            Ok(user.clone())
        }

        async fn delete(&self, id: Uuid) -> AppResult<()> {
            let maybe_user = self
                .users_by_id
                .lock()
                .expect("users mutex should not be poisoned")
                .remove(&id);
            if let Some(user) = maybe_user {
                self.email_to_user_id
                    .lock()
                    .expect("email mutex should not be poisoned")
                    .remove(&user.email);
                if let Some(username) = user.username {
                    self.username_to_user_id
                        .lock()
                        .expect("username mutex should not be poisoned")
                        .remove(&username);
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockAuthRepository {
        identities: Mutex<HashMap<(Uuid, String), AuthIdentity>>,
        identities_by_provider_id: Mutex<HashMap<(String, String), AuthIdentity>>,
        sessions: Mutex<HashMap<Uuid, UserSession>>,
        sessions_by_token_hash: Mutex<HashMap<String, Uuid>>,
    }

    impl MockAuthRepository {
        fn insert_identity(&self, identity: AuthIdentity) {
            let key = (
                identity.user_id,
                provider_as_str(identity.provider).to_string(),
            );
            self.identities
                .lock()
                .expect("identities mutex should not be poisoned")
                .insert(key, identity.clone());

            if let Some(provider_id) = &identity.provider_id {
                self.identities_by_provider_id
                    .lock()
                    .expect("provider identities mutex should not be poisoned")
                    .insert(
                        (
                            provider_as_str(identity.provider).to_string(),
                            provider_id.clone(),
                        ),
                        identity,
                    );
            }
        }

        fn insert_session(&self, session: UserSession) {
            self.sessions_by_token_hash
                .lock()
                .expect("session hash mutex should not be poisoned")
                .insert(session.refresh_token_hash.clone(), session.id);
            self.sessions
                .lock()
                .expect("sessions mutex should not be poisoned")
                .insert(session.id, session);
        }

        fn session_by_token_hash(&self, token_hash: &str) -> Option<UserSession> {
            let session_id = self
                .sessions_by_token_hash
                .lock()
                .expect("session hash mutex should not be poisoned")
                .get(token_hash)
                .copied();
            let sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            session_id.and_then(|id| sessions.get(&id).cloned())
        }

        fn session_by_id(&self, id: Uuid) -> Option<UserSession> {
            self.sessions
                .lock()
                .expect("sessions mutex should not be poisoned")
                .get(&id)
                .cloned()
        }
    }

    #[async_trait]
    impl AuthRepository for MockAuthRepository {
        async fn create_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
            self.insert_identity(identity.clone());
            Ok(identity.clone())
        }

        async fn find_identity_by_user_id(
            &self,
            user_id: Uuid,
            provider: &str,
        ) -> AppResult<Option<AuthIdentity>> {
            Ok(self
                .identities
                .lock()
                .expect("identities mutex should not be poisoned")
                .get(&(user_id, provider.to_string()))
                .cloned())
        }

        async fn find_identity_by_provider_id(
            &self,
            provider: &str,
            provider_id: &str,
        ) -> AppResult<Option<AuthIdentity>> {
            Ok(self
                .identities_by_provider_id
                .lock()
                .expect("provider identities mutex should not be poisoned")
                .get(&(provider.to_string(), provider_id.to_string()))
                .cloned())
        }

        async fn upsert_identity(&self, identity: &AuthIdentity) -> AppResult<AuthIdentity> {
            self.insert_identity(identity.clone());
            Ok(identity.clone())
        }

        async fn verify_email(&self, user_id: Uuid) -> AppResult<()> {
            let mut identities = self
                .identities
                .lock()
                .expect("identities mutex should not be poisoned");
            for ((identity_user_id, _), identity) in identities.iter_mut() {
                if *identity_user_id == user_id {
                    identity.verified = true;
                }
            }
            Ok(())
        }

        async fn create_session(&self, session: &UserSession) -> AppResult<UserSession> {
            self.insert_session(session.clone());
            Ok(session.clone())
        }

        async fn find_session_by_token_hash(
            &self,
            token_hash: &str,
        ) -> AppResult<Option<UserSession>> {
            Ok(self.session_by_token_hash(token_hash))
        }

        async fn revoke_session(&self, id: Uuid) -> AppResult<()> {
            let mut sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            if let Some(session) = sessions.get_mut(&id) {
                session.revoked_at = Some(Utc::now());
            }
            Ok(())
        }

        async fn revoke_session_with_replacement(
            &self,
            id: Uuid,
            replaced_by: Option<Uuid>,
            reason: Option<&str>,
        ) -> AppResult<()> {
            let mut sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            if let Some(session) = sessions.get_mut(&id) {
                session.revoked_at = Some(Utc::now());
                session.replaced_by = replaced_by;
                session.revoked_reason = reason.map(|value| value.to_string());
            }
            Ok(())
        }

        async fn revoke_all_sessions(&self, user_id: Uuid) -> AppResult<()> {
            let mut sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            for session in sessions.values_mut() {
                if session.user_id == user_id && session.revoked_at.is_none() {
                    session.revoked_at = Some(Utc::now());
                }
            }
            Ok(())
        }

        async fn revoke_family(&self, family_id: Uuid, reason: &str) -> AppResult<()> {
            let mut sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            for session in sessions.values_mut() {
                if session.family_id == family_id && session.revoked_at.is_none() {
                    session.revoked_at = Some(Utc::now());
                    session.revoked_reason = Some(reason.to_string());
                }
            }
            Ok(())
        }

        async fn touch_session(&self, id: Uuid) -> AppResult<()> {
            let mut sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            if let Some(session) = sessions.get_mut(&id) {
                session.last_seen_at = Some(Utc::now());
            }
            Ok(())
        }

        async fn has_active_session(&self, user_id: Uuid) -> AppResult<bool> {
            let sessions = self
                .sessions
                .lock()
                .expect("sessions mutex should not be poisoned");
            Ok(sessions.values().any(|session| {
                session.user_id == user_id
                    && session.revoked_at.is_none()
                    && session.expires_at > Utc::now()
            }))
        }

    }

    fn auth_config() -> AuthConfig {
        AuthConfig {
            jwt_secret: "test-secret".to_string(),
            jwt_kid: "test-kid".to_string(),
            previous_jwt_secrets: Vec::new(),
            previous_jwt_kids: Vec::new(),
            jwt_expiration_seconds: 900,
            refresh_token_expiration_days: 7,
            issuer: "rust-backend-tests".to_string(),
            audience: "rust-backend-client".to_string(),
        }
    }

    fn provider_as_str(provider: AuthProvider) -> &'static str {
        match provider {
            AuthProvider::Email => "email",
            AuthProvider::Google => "google",
            AuthProvider::GitHub => "github",
            AuthProvider::Auth0 => "auth0",
        }
    }

    fn test_user(email: &str) -> User {
        let now = Utc::now();
        User {
            id: Uuid::new_v4(),
            email: email.to_string(),
            role: Role::Renter,
            username: Some("tester".to_string()),
            full_name: Some("Test User".to_string()),
            avatar_url: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn test_session(user_id: Uuid, family_id: Uuid, raw_token: &str) -> UserSession {
        UserSession {
            id: Uuid::new_v4(),
            user_id,
            family_id,
            refresh_token_hash: hash_refresh_token(raw_token),
            expires_at: Utc::now() + Duration::days(1),
            revoked_at: None,
            replaced_by: None,
            revoked_reason: None,
            created_ip: None,
            last_seen_at: None,
            device_info: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn register_returns_conflict_on_duplicate_email() {
        let user_repo = Arc::new(MockUserRepository::default());
        let auth_repo = Arc::new(MockAuthRepository::default());
        let service = AuthService::new(user_repo.clone(), auth_repo, auth_config());

        user_repo.insert_user(test_user("duplicate@example.com"));

        let request = RegisterRequest {
            email: "duplicate@example.com".to_string(),
            password: "a-very-strong-password".to_string(),
            username: Some("someone".to_string()),
            full_name: Some("Someone".to_string()),
        };

        let result = service.register(request).await;
        assert!(matches!(result, Err(AppError::Conflict(_))));
    }

    #[tokio::test]
    async fn login_returns_unauthorized_on_wrong_password() {
        let user_repo = Arc::new(MockUserRepository::default());
        let auth_repo = Arc::new(MockAuthRepository::default());
        let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

        let user = test_user("login@example.com");
        user_repo.insert_user(user.clone());
        auth_repo.insert_identity(AuthIdentity {
            id: Uuid::new_v4(),
            user_id: user.id,
            provider: AuthProvider::Email,
            provider_id: None,
            password_hash: Some(
                hash_password("correct-password").expect("password hash should be created"),
            ),
            verified: true,
            created_at: Utc::now(),
        });

        let result = service
            .login(LoginRequest {
                email: "login@example.com".to_string(),
                password: "wrong-password".to_string(),
            })
            .await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn refresh_session_tokens_rotates_and_revokes_old_session() {
        let user_repo = Arc::new(MockUserRepository::default());
        let auth_repo = Arc::new(MockAuthRepository::default());
        let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

        let user = test_user("rotate@example.com");
        let family_id = Uuid::new_v4();
        let previous_raw_token = "refresh-token-old";
        let previous_session = test_session(user.id, family_id, previous_raw_token);
        let previous_session_id = previous_session.id;

        user_repo.insert_user(user);
        auth_repo.insert_session(previous_session);

        let result = service
            .refresh_session_tokens(previous_raw_token, Some("127.0.0.1".to_string()))
            .await
            .expect("refresh should rotate");

        let revoked_old = auth_repo
            .session_by_id(previous_session_id)
            .expect("old session should still exist");
        assert!(revoked_old.revoked_at.is_some());
        assert_eq!(revoked_old.revoked_reason.as_deref(), Some("rotated"));
        assert!(revoked_old.replaced_by.is_some());

        let new_session = auth_repo
            .session_by_token_hash(&hash_refresh_token(&result.refresh_token))
            .expect("new session should exist");
        assert_eq!(new_session.family_id, family_id);
        assert!(new_session.revoked_at.is_none());
    }

    #[tokio::test]
    async fn refresh_session_tokens_revokes_family_on_replay() {
        let user_repo = Arc::new(MockUserRepository::default());
        let auth_repo = Arc::new(MockAuthRepository::default());
        let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

        let user = test_user("replay@example.com");
        let family_id = Uuid::new_v4();
        user_repo.insert_user(user.clone());

        let replayed_raw_token = "refresh-token-replayed";
        let active_raw_token = "refresh-token-active";

        let mut replayed = test_session(user.id, family_id, replayed_raw_token);
        replayed.revoked_at = Some(Utc::now() - Duration::minutes(1));
        replayed.revoked_reason = Some("logout".to_string());

        let active = test_session(user.id, family_id, active_raw_token);
        let active_session_id = active.id;

        auth_repo.insert_session(replayed);
        auth_repo.insert_session(active);

        let result = service
            .refresh_session_tokens(replayed_raw_token, None)
            .await;
        assert!(matches!(result, Err(AppError::Unauthorized)));

        let active_after = auth_repo
            .session_by_id(active_session_id)
            .expect("active family session should exist");
        assert!(active_after.revoked_at.is_some());
        assert_eq!(
            active_after.revoked_reason.as_deref(),
            Some("refresh token replay detected")
        );
    }

    #[tokio::test]
    async fn logout_revokes_session_when_refresh_token_is_valid() {
        let user_repo = Arc::new(MockUserRepository::default());
        let auth_repo = Arc::new(MockAuthRepository::default());
        let service = AuthService::new(user_repo.clone(), auth_repo.clone(), auth_config());

        let user = test_user("logout@example.com");
        user_repo.insert_user(user.clone());

        let family_id = Uuid::new_v4();
        let raw_token = "refresh-token-logout";
        let session = test_session(user.id, family_id, raw_token);
        let session_id = session.id;
        auth_repo.insert_session(session);

        service
            .logout(raw_token)
            .await
            .expect("logout should revoke active session");

        let revoked = auth_repo
            .session_by_id(session_id)
            .expect("session should remain present");
        assert!(revoked.revoked_at.is_some());
        assert_eq!(revoked.revoked_reason.as_deref(), Some("logout"));
        assert!(revoked.replaced_by.is_none());
    }
}
