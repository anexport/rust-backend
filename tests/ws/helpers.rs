use awc::ws;
use chrono::Utc;
use futures_util::StreamExt;
use jsonwebtoken::{encode, Algorithm, DecodingKey, EncodingKey, Header};
use rust_backend::config::Auth0Config;
use rust_backend::middleware::auth::UserProvisioningService;
use rust_backend::utils::auth0_claims::{Audience, Auth0Claims, Auth0UserContext};
use rust_backend::utils::auth0_jwks::JwksProvider;
use std::time::Duration;
use uuid::Uuid;

pub const TEST_PRIVATE_KEY_PEM: &str = include_str!("../test_private_key.pem");
pub const TEST_PUBLIC_KEY_PEM: &str = include_str!("../test_public_key.pem");

pub struct StaticJwksProvider {
    pub key: DecodingKey,
}

#[async_trait::async_trait]
impl JwksProvider for StaticJwksProvider {
    async fn get_decoding_key(&self, _kid: &str) -> rust_backend::error::AppResult<DecodingKey> {
        Ok(self.key.clone())
    }
}

pub struct StaticProvisioningService {
    pub user_id: Uuid,
}

#[async_trait::async_trait]
impl UserProvisioningService for StaticProvisioningService {
    async fn provision_user(
        &self,
        claims: &Auth0Claims,
    ) -> rust_backend::error::AppResult<Auth0UserContext> {
        Ok(Auth0UserContext {
            user_id: self.user_id,
            auth0_sub: claims.sub.clone(),
            role: "renter".to_string(),
            email: claims.email.clone(),
        })
    }
}

pub fn create_valid_auth0_token(sub: &str) -> String {
    let claims = Auth0Claims {
        iss: "https://test.auth0.com/".to_string(),
        sub: sub.to_string(),
        aud: Audience::Single("test-audience".to_string()),
        exp: (Utc::now() + chrono::Duration::minutes(5)).timestamp() as u64,
        iat: (Utc::now() - chrono::Duration::minutes(1)).timestamp() as u64,
        email: Some("ws-user@example.com".to_string()),
        email_verified: Some(true),
        name: Some("Ws User".to_string()),
        picture: None,
        custom_claims: std::collections::HashMap::new(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("ws-test-kid".to_string());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes())
            .expect("private test key should parse"),
    )
    .expect("valid RS256 auth0 token should encode")
}

pub fn test_auth0_config() -> Auth0Config {
    Auth0Config {
        auth0_domain: Some("test.auth0.com".to_string()),
        auth0_audience: Some("test-audience".to_string()),
        auth0_issuer: Some("https://test.auth0.com/".to_string()),
        jwks_cache_ttl_secs: 3600,
        auth0_client_id: None,
        auth0_client_secret: None,
        auth0_connection: "Username-Password-Authentication".to_string(),
    }
}

pub async fn next_text_frame<S, E>(client: &mut S) -> String
where
    S: futures_util::Stream<Item = Result<ws::Frame, E>> + Unpin,
    E: std::fmt::Debug,
{
    loop {
        let frame = tokio::time::timeout(Duration::from_secs(5), client.next())
            .await
            .expect("Timeout waiting for WebSocket frame")
            .expect("WebSocket stream closed prematurely")
            .expect("WebSocket stream error");

        match frame {
            ws::Frame::Text(text) => return std::str::from_utf8(&text).unwrap().to_string(),
            ws::Frame::Ping(_) => {
                // If it's a ping, we just wait for the next frame
                continue;
            }
            other => panic!("Expected text frame, got {:?}", other),
        }
    }
}
