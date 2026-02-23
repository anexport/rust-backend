use std::sync::Arc;

use actix_web::{dev::Payload, http::header::AUTHORIZATION, web, FromRequest, HttpRequest};
use async_trait::async_trait;
use chrono::Utc;
use tracing::info;

use crate::config::Auth0Config;
use crate::domain::{AuthIdentity, AuthProvider, Role, User};
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::{AuthRepository, UserRepository};
use crate::utils::auth0_claims::Auth0UserContext;
use crate::utils::auth0_jwks::{validate_auth0_token, JwksProvider};

#[async_trait]
pub trait UserProvisioningService: Send + Sync {
    async fn provision_user(
        &self,
        claims: &crate::utils::auth0_claims::Auth0Claims,
    ) -> AppResult<Auth0UserContext>;
}

pub struct JitUserProvisioningService {
    user_repo: Arc<dyn UserRepository>,
    auth_repo: Arc<dyn AuthRepository>,
    auth0_namespace: String,
}

impl JitUserProvisioningService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        auth_repo: Arc<dyn AuthRepository>,
        auth0_namespace: String,
    ) -> Self {
        Self {
            user_repo,
            auth_repo,
            auth0_namespace,
        }
    }
}

#[async_trait]
impl UserProvisioningService for JitUserProvisioningService {
    async fn provision_user(
        &self,
        claims: &crate::utils::auth0_claims::Auth0Claims,
    ) -> AppResult<Auth0UserContext> {
        let provider_id = claims.sub.clone();

        if let Some(identity) = self
            .auth_repo
            .find_identity_by_provider_id("auth0", &provider_id)
            .await?
        {
            let user = self
                .user_repo
                .find_by_id(identity.user_id)
                .await?
                .ok_or_else(|| {
                    AppError::InternalError(anyhow::anyhow!(
                        "user not found for existing auth0 identity"
                    ))
                })?;

            info!(
                auth0_sub = %claims.sub,
                user_id = %user.id,
                "authenticated existing auth0 user"
            );

            return Ok(Auth0UserContext::from_claims(
                claims,
                user.id,
                &self.auth0_namespace,
            ));
        }

        let user = if let Some(existing) = self
            .user_repo
            .find_by_email(claims.email.as_deref().unwrap_or(""))
            .await?
        {
            existing
        } else {
            let now = Utc::now();
            self.user_repo
                .create(&User {
                    id: uuid::Uuid::new_v4(),
                    email: claims
                        .email
                        .clone()
                        .unwrap_or_else(|| format!("{}@auth0.placeholder", claims.sub)),
                    role: Role::Renter,
                    username: None,
                    full_name: claims.name.clone(),
                    avatar_url: claims.picture.clone(),
                    created_at: now,
                    updated_at: now,
                })
                .await?
        };

        self.auth_repo
            .create_identity(&AuthIdentity {
                id: uuid::Uuid::new_v4(),
                user_id: user.id,
                provider: AuthProvider::Auth0,
                provider_id: Some(provider_id.clone()),
                password_hash: None,
                verified: claims.email_verified.unwrap_or(false),
                created_at: Utc::now(),
            })
            .await?;

        info!(
            auth0_sub = %claims.sub,
            user_id = %user.id,
            "provisioned new user from auth0"
        );

        Ok(Auth0UserContext::from_claims(
            claims,
            user.id,
            &self.auth0_namespace,
        ))
    }
}

pub struct Auth0AuthenticatedUser(pub Auth0UserContext);

impl FromRequest for Auth0AuthenticatedUser {
    type Error = AppError;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = AppResult<Self>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            let token = match req.headers().get(AUTHORIZATION) {
                Some(header) => match header.to_str() {
                    Ok(value) => match value.strip_prefix("Bearer ") {
                        Some(token) if !token.is_empty() => token,
                        _ => return Err(AppError::Unauthorized),
                    },
                    Err(_) => return Err(AppError::Unauthorized),
                },
                None => return Err(AppError::Unauthorized),
            };

            let jwks_client = req
                .app_data::<web::Data<Arc<dyn JwksProvider>>>()
                .ok_or_else(|| {
                    AppError::InternalError(anyhow::anyhow!("missing JwksProvider app data"))
                })?;
            let auth0_config = req.app_data::<web::Data<Auth0Config>>().ok_or_else(|| {
                AppError::InternalError(anyhow::anyhow!("missing Auth0Config app data"))
            })?;
            let provisioning_service = req
                .app_data::<web::Data<Arc<dyn UserProvisioningService>>>()
                .ok_or_else(|| {
                    AppError::InternalError(anyhow::anyhow!(
                        "missing UserProvisioningService app data"
                    ))
                })?;

            let claims =
                validate_auth0_token(token, jwks_client.as_ref().as_ref(), auth0_config.get_ref())
                    .await?;
            let user_context = provisioning_service.provision_user(&claims).await?;
            Ok(Auth0AuthenticatedUser(user_context))
        })
    }
}
