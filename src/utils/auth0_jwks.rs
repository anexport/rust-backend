use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use reqwest::Client;
use serde::Deserialize;
use std::time::Duration;
use tracing::{error, warn};

use crate::config::Auth0Config;
use crate::error::{AppError, AppResult};
use crate::utils::auth0_claims::Auth0Claims;

#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
    pub kty: String,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(rename = "use", default)]
    pub use_: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Trait for JWKS key resolution - allows mocking in tests
#[async_trait]
pub trait JwksProvider: Send + Sync {
    async fn get_decoding_key(&self, kid: &str) -> AppResult<DecodingKey>;
}

pub struct Auth0JwksClient {
    client: Client,
    jwks_url: String,
    cache: Cache<String, Vec<u8>>,
}

impl Auth0JwksClient {
    pub fn new(config: &Auth0Config) -> AppResult<Self> {
        let domain = config.auth0_domain.as_ref().ok_or_else(|| {
            AppError::InternalError(anyhow::anyhow!("Auth0 domain not configured"))
        })?;

        let jwks_url = format!("https://{}/.well-known/jwks.json", domain);

        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(config.jwks_cache_ttl_secs))
            .max_capacity(1)
            .build();

        Ok(Self {
            client: Client::new(),
            jwks_url,
            cache,
        })
    }

    pub async fn get_signing_key(&self, kid: &str) -> AppResult<Vec<u8>> {
        if let Some(modulus_bytes) = self.cache.get(kid).await {
            return Ok(modulus_bytes);
        }

        let jwks = self.fetch_jwks().await?;

        let jwk = jwks.keys.iter().find(|k| k.kid == kid).ok_or_else(|| {
            warn!(
                kid = %kid,
                available_kids = ?jwks.keys.iter().map(|k| &k.kid).collect::<Vec<_>>(),
                auth_failure_category = "unknown_kid",
                "Auth0 token validation failed: unknown key ID"
            );
            AppError::Unauthorized
        })?;

        let modulus_bytes = self.jwk_to_modulus(jwk)?;

        self.cache
            .insert(kid.to_string(), modulus_bytes.clone())
            .await;

        Ok(modulus_bytes)
    }

    async fn fetch_jwks(&self) -> AppResult<Jwks> {
        let response = self.client.get(&self.jwks_url).send().await.map_err(|e| {
            error!(
                error = %e,
                url = %self.jwks_url,
                auth_failure_category = "jwks_fetch_failed",
                "Failed to fetch JWKS from Auth0"
            );
            AppError::InternalError(anyhow::anyhow!("Failed to fetch JWKS: {}", e))
        })?;

        if !response.status().is_success() {
            let status = response.status();
            error!(
                status = %status,
                url = %self.jwks_url,
                auth_failure_category = "jwks_fetch_failed",
                "JWKS endpoint returned non-success status"
            );
            return Err(AppError::InternalError(anyhow::anyhow!(
                "JWKS fetch failed with status: {}",
                status
            )));
        }

        let jwks: Jwks = response.json().await.map_err(|e| {
            error!(
                error = %e,
                auth_failure_category = "jwks_fetch_failed",
                "Failed to parse JWKS response"
            );
            AppError::InternalError(anyhow::anyhow!("Failed to parse JWKS: {}", e))
        })?;

        Ok(jwks)
    }

    fn jwk_to_modulus(&self, jwk: &Jwk) -> AppResult<Vec<u8>> {
        let n_bytes = URL_SAFE_NO_PAD.decode(&jwk.n).map_err(|e| {
            error!(
                error = %e,
                kid = %jwk.kid,
                "Failed to decode JWK modulus"
            );
            AppError::InternalError(anyhow::anyhow!("Invalid JWK modulus: {}", e))
        })?;

        Ok(n_bytes)
    }

    pub async fn get_decoding_key(&self, kid: &str) -> AppResult<DecodingKey> {
        let modulus_bytes = self.get_signing_key(kid).await?;

        let jwks = self.fetch_jwks().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .ok_or(AppError::Unauthorized)?;

        let e_bytes = URL_SAFE_NO_PAD.decode(&jwk.e).map_err(|e| {
            error!(
                error = %e,
                kid = %kid,
                "Failed to decode JWK exponent"
            );
            AppError::InternalError(anyhow::anyhow!("Invalid JWK exponent: {}", e))
        })?;

        DecodingKey::from_rsa_components(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&modulus_bytes),
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&e_bytes),
        )
        .map_err(|e| {
            error!(
                error = %e,
                kid = %kid,
                "Failed to create RSA decoding key"
            );
            AppError::InternalError(anyhow::anyhow!("Failed to create decoding key: {}", e))
        })
    }
}

#[async_trait]
impl JwksProvider for Auth0JwksClient {
    async fn get_decoding_key(&self, kid: &str) -> AppResult<DecodingKey> {
        self.get_decoding_key(kid).await
    }
}

pub async fn validate_auth0_token(
    token: &str,
    client: &dyn JwksProvider,
    config: &Auth0Config,
) -> AppResult<Auth0Claims> {
    let header = decode_header(token).map_err(|e| {
        warn!(
            error = %e,
            auth_failure_category = "invalid_signature",
            "Failed to decode token header"
        );
        AppError::Unauthorized
    })?;

    let kid = header.kid.ok_or_else(|| {
        warn!(
            auth_failure_category = "invalid_signature",
            "Token header missing kid"
        );
        AppError::Unauthorized
    })?;

    let decoding_key = client
        .get_decoding_key(&kid)
        .await
        .map_err(|_| AppError::Unauthorized)?;

    let expected_issuer = config
        .issuer()
        .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("Auth0 issuer not configured")))?;

    let expected_audience = config
        .auth0_audience
        .as_ref()
        .ok_or_else(|| AppError::InternalError(anyhow::anyhow!("Auth0 audience not configured")))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[&expected_issuer]);
    validation.set_audience(&[expected_audience]);

    let token_data = decode::<Auth0Claims>(token, &decoding_key, &validation).map_err(|e| {
        let kind = e.kind();
        match kind {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                warn!(auth_failure_category = "expired", "Auth0 token has expired");
                AppError::TokenExpired
            }
            jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                warn!(
                    auth_failure_category = "expired",
                    "Auth0 token not yet valid (nbf)"
                );
                AppError::Unauthorized
            }
            jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                warn!(
                    expected_issuer = %expected_issuer,
                    auth_failure_category = "wrong_issuer",
                    "Auth0 token has invalid issuer"
                );
                AppError::Unauthorized
            }
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                warn!(
                    expected_audience = %expected_audience,
                    auth_failure_category = "wrong_audience",
                    "Auth0 token has invalid audience"
                );
                AppError::Unauthorized
            }
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                warn!(
                    auth_failure_category = "invalid_signature",
                    "Auth0 token has invalid signature"
                );
                AppError::Unauthorized
            }
            _ => {
                warn!(
                    error = %e,
                    auth_failure_category = "invalid_signature",
                    "Auth0 token validation failed"
                );
                AppError::Unauthorized
            }
        }
    })?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::utils::auth0_claims::Audience;
    use chrono::{Duration, Utc};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    const TEST_PRIVATE_KEY_PEM: &str = include_str!("../../tests/test_private_key.pem");
    const TEST_PUBLIC_KEY_PEM: &str = include_str!("../../tests/test_public_key.pem");

    struct CountingJwksProvider {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl JwksProvider for CountingJwksProvider {
        async fn get_decoding_key(&self, _kid: &str) -> AppResult<DecodingKey> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(AppError::Unauthorized)
        }
    }

    struct StaticJwksProvider {
        key: DecodingKey,
    }

    #[async_trait]
    impl JwksProvider for StaticJwksProvider {
        async fn get_decoding_key(&self, _kid: &str) -> AppResult<DecodingKey> {
            Ok(self.key.clone())
        }
    }

    fn test_claims(issuer: &str, audience: &str, exp: i64) -> Auth0Claims {
        Auth0Claims {
            iss: issuer.to_string(),
            sub: "auth0|test-user".to_string(),
            aud: Audience::Single(audience.to_string()),
            exp: exp as u64,
            iat: (Utc::now() - Duration::minutes(1)).timestamp() as u64,
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            picture: None,
            custom_claims: HashMap::new(),
        }
    }

    fn create_hs256_token(kid: Option<&str>) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = kid.map(str::to_string);
        encode(
            &header,
            &test_claims(
                "https://test.auth0.com/",
                "test-api",
                (Utc::now() + Duration::minutes(5)).timestamp(),
            ),
            &EncodingKey::from_secret(b"unused"),
        )
        .expect("failed to encode HS256 token")
    }

    fn create_rs256_token(issuer: &str, audience: &str, exp: i64, kid: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        encode(
            &header,
            &test_claims(issuer, audience, exp),
            &EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes())
                .expect("private key should parse"),
        )
        .expect("failed to encode RS256 token")
    }

    fn tamper_signature(token: &str) -> String {
        let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
        assert_eq!(parts.len(), 3, "token should have 3 sections");
        let mut signature = URL_SAFE_NO_PAD
            .decode(&parts[2])
            .expect("signature should be valid base64url");
        if let Some(first) = signature.first_mut() {
            *first ^= 0x01;
        }
        parts[2] = URL_SAFE_NO_PAD.encode(signature);
        parts.join(".")
    }

    fn spawn_one_shot_jwks_server(body: String) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request_buffer = [0_u8; 2048];
                let _ = stream.read(&mut request_buffer);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn aud_single_contains_matching_audience() {
        let aud = Audience::Single("test-audience".to_string());
        assert!(aud.contains("test-audience"));
        assert!(!aud.contains("other-audience"));
    }

    #[test]
    fn aud_multiple_contains_matching_audience() {
        let aud = Audience::Multiple(vec!["audience-1".to_string(), "audience-2".to_string()]);
        assert!(aud.contains("audience-1"));
        assert!(aud.contains("audience-2"));
        assert!(!aud.contains("audience-3"));
    }

    fn test_config() -> Auth0Config {
        Auth0Config {
            auth0_domain: Some("test.auth0.com".to_string()),
            auth0_audience: Some("test-api".to_string()),
            auth0_issuer: Some("https://test.auth0.com/".to_string()),
            jwks_cache_ttl_secs: 3600,
            auth0_client_id: None,
            auth0_client_secret: None,
            auth0_connection: Default::default(),
        }
    }

    #[test]
    fn jwks_client_constructs_correct_url() {
        let config = test_config();
        let client = Auth0JwksClient::new(&config).unwrap();
        assert_eq!(
            client.jwks_url,
            "https://test.auth0.com/.well-known/jwks.json"
        );
    }

    #[test]
    fn jwks_client_fails_without_domain() {
        let config = Auth0Config {
            auth0_domain: None,
            auth0_audience: Some("test-api".to_string()),
            auth0_issuer: None,
            jwks_cache_ttl_secs: 3600,
            auth0_client_id: None,
            auth0_client_secret: None,
            auth0_connection: Default::default(),
        };
        let result = Auth0JwksClient::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn issuer_fallback_to_domain() {
        let config = Auth0Config {
            auth0_domain: Some("example.auth0.com".to_string()),
            auth0_audience: Some("api".to_string()),
            auth0_issuer: None,
            jwks_cache_ttl_secs: 3600,
            auth0_client_id: None,
            auth0_client_secret: None,
            auth0_connection: Default::default(),
        };
        assert_eq!(
            config.issuer(),
            Some("https://example.auth0.com/".to_string())
        );
    }

    #[test]
    fn jwk_deserializes_correctly() {
        let json = r#"{
            "kid": "test-key-id",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig"
        }"#;

        let jwk: Jwk = serde_json::from_str(json).unwrap();
        assert_eq!(jwk.kid, "test-key-id");
        assert_eq!(jwk.kty, "RSA");
        assert_eq!(jwk.alg, Some("RS256".to_string()));
        assert_eq!(jwk.use_, Some("sig".to_string()));
    }

    #[test]
    fn jwks_deserializes_correctly() {
        let json = r#"{
            "keys": [
                {
                    "kid": "key1",
                    "n": "modulus1",
                    "e": "AQAB",
                    "kty": "RSA"
                },
                {
                    "kid": "key2",
                    "n": "modulus2",
                    "e": "AQAB",
                    "kty": "RSA"
                }
            ]
        }"#;

        let jwks: Jwks = serde_json::from_str(json).unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(jwks.keys[0].kid, "key1");
        assert_eq!(jwks.keys[1].kid, "key2");
    }

    #[tokio::test]
    async fn validate_auth0_token_rejects_malformed_token_without_jwks_lookup() {
        let provider = CountingJwksProvider {
            calls: AtomicUsize::new(0),
        };

        let result = validate_auth0_token("not-a-jwt", &provider, &test_config()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validate_auth0_token_rejects_token_without_kid_header() {
        let provider = CountingJwksProvider {
            calls: AtomicUsize::new(0),
        };

        let token = create_hs256_token(None);
        let result = validate_auth0_token(&token, &provider, &test_config()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn validate_auth0_token_maps_key_resolution_failures_to_unauthorized() {
        let provider = CountingJwksProvider {
            calls: AtomicUsize::new(0),
        };
        let token = create_hs256_token(Some("missing-key"));

        let result = validate_auth0_token(&token, &provider, &test_config()).await;

        assert!(matches!(result, Err(AppError::Unauthorized)));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn validate_auth0_token_fails_when_issuer_is_not_configured() {
        let mut config = test_config();
        config.auth0_domain = None;
        config.auth0_issuer = None;
        let token = create_hs256_token(Some("test-kid"));
        let provider = StaticJwksProvider {
            key: DecodingKey::from_secret(b"unused"),
        };

        let result = validate_auth0_token(&token, &provider, &config).await;

        assert!(matches!(result, Err(AppError::InternalError(_))));
    }

    #[tokio::test]
    async fn validate_auth0_token_fails_when_audience_is_not_configured() {
        let mut config = test_config();
        config.auth0_audience = None;
        let token = create_hs256_token(Some("test-kid"));
        let provider = StaticJwksProvider {
            key: DecodingKey::from_secret(b"unused"),
        };

        let result = validate_auth0_token(&token, &provider, &config).await;

        assert!(matches!(result, Err(AppError::InternalError(_))));
    }

    #[tokio::test]
    async fn get_signing_key_returns_cached_value_on_cache_hit() {
        let config = test_config();
        let client = Auth0JwksClient::new(&config).expect("client should build");
        let cached = vec![1_u8, 2, 3, 4];
        client
            .cache
            .insert("cached-kid".to_string(), cached.clone())
            .await;

        let result = client.get_signing_key("cached-kid").await;

        assert_eq!(result.expect("cache hit should succeed"), cached);
    }

    #[test]
    fn jwk_to_modulus_returns_error_for_invalid_base64_modulus() {
        let client = Auth0JwksClient::new(&test_config()).expect("client should build");
        let invalid = Jwk {
            kid: "invalid-modulus".to_string(),
            n: "%%%".to_string(),
            e: "AQAB".to_string(),
            kty: "RSA".to_string(),
            alg: None,
            use_: None,
        };

        let result = client.jwk_to_modulus(&invalid);
        assert!(matches!(result, Err(AppError::InternalError(_))));
    }

    #[tokio::test]
    async fn get_decoding_key_returns_error_for_invalid_base64_exponent() {
        let config = test_config();
        let mut client = Auth0JwksClient::new(&config).expect("client should build");
        client
            .cache
            .insert("bad-exponent-kid".to_string(), vec![1_u8, 2, 3, 4])
            .await;

        client.jwks_url = spawn_one_shot_jwks_server(
            r#"{"keys":[{"kid":"bad-exponent-kid","n":"AQAB","e":"%%invalid","kty":"RSA"}]}"#
                .to_string(),
        );

        let result = client.get_decoding_key("bad-exponent-kid").await;
        assert!(matches!(result, Err(AppError::InternalError(_))));
    }

    #[tokio::test]
    async fn validate_auth0_token_maps_expired_signature_to_token_expired() {
        let token = create_rs256_token(
            "https://test.auth0.com/",
            "test-api",
            (Utc::now() - Duration::minutes(10)).timestamp(),
            "test-kid",
        );
        let provider = StaticJwksProvider {
            key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
                .expect("public key should parse"),
        };

        let result = validate_auth0_token(&token, &provider, &test_config()).await;
        assert!(matches!(result, Err(AppError::TokenExpired)));
    }

    #[tokio::test]
    async fn validate_auth0_token_maps_invalid_issuer_to_unauthorized() {
        let token = create_rs256_token(
            "https://wrong-issuer.example/",
            "test-api",
            (Utc::now() + Duration::minutes(5)).timestamp(),
            "test-kid",
        );
        let provider = StaticJwksProvider {
            key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
                .expect("public key should parse"),
        };

        let result = validate_auth0_token(&token, &provider, &test_config()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn validate_auth0_token_maps_invalid_audience_to_unauthorized() {
        let token = create_rs256_token(
            "https://test.auth0.com/",
            "wrong-audience",
            (Utc::now() + Duration::minutes(5)).timestamp(),
            "test-kid",
        );
        let provider = StaticJwksProvider {
            key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
                .expect("public key should parse"),
        };

        let result = validate_auth0_token(&token, &provider, &test_config()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }

    #[tokio::test]
    async fn validate_auth0_token_maps_invalid_signature_to_unauthorized() {
        let valid = create_rs256_token(
            "https://test.auth0.com/",
            "test-api",
            (Utc::now() + Duration::minutes(5)).timestamp(),
            "test-kid",
        );
        let token = tamper_signature(&valid);
        let provider = StaticJwksProvider {
            key: DecodingKey::from_rsa_pem(TEST_PUBLIC_KEY_PEM.as_bytes())
                .expect("public key should parse"),
        };

        let result = validate_auth0_token(&token, &provider, &test_config()).await;
        assert!(matches!(result, Err(AppError::Unauthorized)));
    }
}
