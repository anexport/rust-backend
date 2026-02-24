use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::api::dtos::UserResponse;
use crate::domain::{AuthIdentity, AuthProvider, Role, User};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::{AuthRepository, UserRepository};
use crate::utils::auth0_claims::{Auth0Claims, Auth0UserContext};

#[derive(Clone)]
pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    auth_repo: Arc<dyn AuthRepository>,
    auth0_namespace: Option<String>,
}

impl AuthService {
    pub fn new(user_repo: Arc<dyn UserRepository>, auth_repo: Arc<dyn AuthRepository>) -> Self {
        Self {
            user_repo,
            auth_repo,
            auth0_namespace: None,
        }
    }

    pub fn with_auth0_namespace(mut self, namespace: String) -> Self {
        self.auth0_namespace = Some(namespace);
        self
    }

    pub async fn me(&self, user_id: Uuid) -> AppResult<UserResponse> {
        let user = self
            .user_repo
            .find_by_id(user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("user not found".to_string()))?;

        Ok(map_user_response(&user))
    }

    pub async fn ensure_active_session_for_user(&self, _user_id: Uuid) -> AppResult<()> {
        // Since we are using Auth0 tokens, we don't have local sessions to check here.
        // The middleware handles token validation.
        Ok(())
    }

    pub async fn upsert_user_from_auth0(
        &self,
        claims: &Auth0Claims,
    ) -> AppResult<Auth0UserContext> {
        if let Some(identity) = self
            .auth_repo
            .find_identity_by_provider_id("auth0", &claims.sub)
            .await?
        {
            let user = self
                .user_repo
                .find_by_id(identity.user_id)
                .await?
                .ok_or_else(|| {
                    AppError::InternalError(anyhow::anyhow!("user not found for auth0 identity"))
                })?;

            let updated_user = self.maybe_update_user_from_claims(&user, claims).await?;
            let namespace = self.auth0_namespace.as_deref().unwrap_or("");
            Ok(Auth0UserContext::from_claims(
                claims,
                updated_user.id,
                namespace,
            ))
        } else {
            self.create_user_from_auth0(claims).await
        }
    }

    async fn maybe_update_user_from_claims(
        &self,
        user: &User,
        claims: &Auth0Claims,
    ) -> AppResult<User> {
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
        let email = claims
            .email
            .clone()
            .ok_or_else(|| AppError::BadRequest("email is required for new users".to_string()))?;

        let now = Utc::now();
        let existing_user = self.user_repo.find_by_email(&email).await?;
        let user = if let Some(existing) = existing_user {
            self.maybe_update_user_from_claims(&existing, claims)
                .await?
        } else {
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
            self.user_repo.create(&user).await?
        };

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
                        .ok_or_else(|| {
                            AppError::InternalError(anyhow::anyhow!(
                                "user not found for auth0 identity"
                            ))
                        })?;
                    let _ = self.user_repo.delete(user.id).await;
                    let namespace = self.auth0_namespace.as_deref().unwrap_or("");
                    return Ok(Auth0UserContext::from_claims(
                        claims,
                        existing_user.id,
                        namespace,
                    ));
                }
                return Err(AppError::InternalError(anyhow::anyhow!(
                    "failed to create auth identity"
                )));
            }
            Err(e) => {
                let _ = self.user_repo.delete(user.id).await;
                return Err(e);
            }
        }

        let namespace = self.auth0_namespace.as_deref().unwrap_or("");
        Ok(Auth0UserContext::from_claims(claims, user.id, namespace))
    }
}

fn map_user_response(user: &User) -> UserResponse {
    UserResponse {
        id: user.id,
        email: user.email.clone(),
        role: user.role.to_string(),
        username: user.username.clone(),
        full_name: user.full_name.clone(),
        avatar_url: user.avatar_url.clone(),
    }
}
