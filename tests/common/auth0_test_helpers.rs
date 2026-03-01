#![allow(dead_code)]

use async_trait::async_trait;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, DecodingKey, Header};
use rust_backend::config::Auth0Config;
use rust_backend::infrastructure::repositories::{
    AuthRepository, AuthRepositoryImpl, UserRepository, UserRepositoryImpl,
};
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_backend::utils::auth0_jwks::JwksProvider;
use uuid::Uuid;

pub struct MockJwksProvider {
    pub decoding_key: DecodingKey,
}

impl MockJwksProvider {
    pub fn new() -> Self {
        let public_key_pem = include_str!("../test_public_key.pem");
        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .expect("failed to load test public key");
        Self { decoding_key }
    }
}

#[async_trait]
impl JwksProvider for MockJwksProvider {
    async fn get_decoding_key(&self, kid: &str) -> rust_backend::error::AppResult<DecodingKey> {
        if kid == "test-key-id" {
            Ok(self.decoding_key.clone())
        } else {
            Err(rust_backend::error::AppError::Unauthorized)
        }
    }
}

pub struct MockProvisioningService {
    pub db_pool: sqlx::PgPool,
}

#[async_trait]
impl UserProvisioningService for MockProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        let user_repo = UserRepositoryImpl::new(self.db_pool.clone());
        let auth_repo = AuthRepositoryImpl::new(self.db_pool.clone());

        let sub = &claims.sub;

        // Try to find existing identity
        if let Some(identity) = auth_repo.find_identity_by_provider_id("auth0", sub).await? {
            let user = user_repo
                .find_by_id(identity.user_id)
                .await?
                .ok_or_else(|| {
                    rust_backend::error::AppError::NotFound("user not found".to_string())
                })?;
            return Ok(Auth0UserContext {
                user_id: user.id,
                auth0_sub: sub.clone(),
                role: user.role.to_string(),
                email: Some(user.email),
            });
        }

        // Otherwise use the role from claims or default to renter
        let role_str = if let Some(role_val) = claims
            .custom_claims
            .get("https://test-tenant.auth0.com/role")
        {
            role_val.as_str().unwrap_or("renter").to_string()
        } else {
            "renter".to_string()
        };

        let user_id = if let Some(id_part) = sub.strip_prefix("auth0|") {
            Uuid::parse_str(id_part).unwrap_or_else(|_| Uuid::new_v4())
        } else {
            Uuid::new_v4()
        };

        // Try to find existing user by email if identity not found
        if let Some(email) = &claims.email {
            if let Some(user) = user_repo.find_by_email(email).await? {
                // Link identity for next time
                auth_repo
                    .create_identity(&rust_backend::domain::AuthIdentity {
                        id: Uuid::new_v4(),
                        user_id: user.id,
                        provider: rust_backend::domain::AuthProvider::Auth0,
                        provider_id: Some(sub.clone()),
                        password_hash: None,
                        verified: claims.email_verified.unwrap_or(false),
                        created_at: Utc::now(),
                    })
                    .await
                    .map_err(|e| {
                        rust_backend::error::AppError::InternalError(anyhow::anyhow!(
                            "Failed to link identity: {}",
                            e
                        ))
                    })?;

                return Ok(Auth0UserContext {
                    user_id: user.id,
                    auth0_sub: sub.clone(),
                    role: user.role.to_string(),
                    email: Some(user.email),
                });
            }
        }

        Ok(Auth0UserContext {
            user_id,
            auth0_sub: sub.clone(),
            role: role_str,
            email: claims.email.clone(),
        })
    }
}

pub fn create_auth0_token(user_id: Uuid, role: &str) -> String {
    create_auth0_token_with_email(user_id, role, None)
}

pub fn create_auth0_token_with_email(user_id: Uuid, role: &str, email: Option<String>) -> String {
    let mut custom_claims = std::collections::HashMap::new();
    custom_claims.insert(
        "https://test-tenant.auth0.com/role".to_string(),
        serde_json::json!(role),
    );

    let claims = Auth0Claims {
        iss: "https://test-tenant.auth0.com/".to_string(),
        sub: format!("auth0|{}", user_id),
        aud: Audience::Single("rust-backend-test".to_string()),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as u64,
        iat: (Utc::now() - Duration::hours(1)).timestamp() as u64,
        email: email.or_else(|| Some(format!("user-{}@example.com", user_id))),
        email_verified: Some(true),
        name: Some("Test User".to_string()),
        picture: None,
        custom_claims,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key-id".to_string());

    let private_key_pem = include_str!("../test_private_key.pem");
    let encoding_key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .expect("Failed to load test private key");

    encode(&header, &claims, &encoding_key).expect("Failed to encode test token")
}

pub fn test_auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test-tenant.auth0.com".to_string()),
        auth0_audience: Some("rust-backend-test".to_string()),
        auth0_issuer: Some("https://test-tenant.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: Some("test-client-id".to_string()),
        auth0_client_secret: Some("test-client-secret".to_string()),
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}
