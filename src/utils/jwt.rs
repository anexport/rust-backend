use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::AuthConfig;
use crate::error::{AppError, AppResult};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub exp: usize,
    pub iat: usize,
    pub jti: Uuid,
    pub iss: String,
    pub aud: String,
    pub role: String,
}

pub fn create_access_token(user_id: Uuid, role: &str, config: &AuthConfig) -> AppResult<String> {
    let now = Utc::now();
    let exp = now + Duration::seconds(config.jwt_expiration_seconds as i64);

    let claims = Claims {
        sub: user_id,
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
        jti: Uuid::new_v4(),
        iss: config.issuer.clone(),
        aud: config.audience.clone(),
        role: role.to_string(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|e| AppError::InternalError(e.into()))
}

pub fn validate_token(token: &str, config: &AuthConfig) -> AppResult<Claims> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[&config.issuer]);
    validation.set_audience(&[&config.audience]);

    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AppError::TokenExpired,
        _ => AppError::InvalidToken,
    })
}
