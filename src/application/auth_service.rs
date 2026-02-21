use std::sync::Arc;

use chrono::{Duration, Utc};
use uuid::Uuid;
use validator::Validate;

use crate::api::dtos::{AuthResponse, LoginRequest, RegisterRequest, UserResponse};
use crate::config::AuthConfig;
use crate::domain::{AuthIdentity, AuthProvider, Role, User, UserSession};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::{AuthRepository, UserRepository};
use crate::utils::hash::{hash_password, hash_refresh_token, verify_password};
use crate::utils::jwt::create_access_token;

#[derive(Clone)]
pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    auth_repo: Arc<dyn AuthRepository>,
    config: AuthConfig,
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
        }
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
        self.auth_repo.create_identity(&identity).await?;

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
            if session.replaced_by.is_some() {
                self.auth_repo
                    .revoke_family(session.family_id, "refresh token replay detected")
                    .await?;
            }
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

    pub fn logout_not_implemented(&self) -> AppResult<()> {
        Err(AppError::BadRequest(
            "logout with session revocation will be implemented in phase 2".to_string(),
        ))
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
