use async_trait::async_trait;
use oauth2::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use oauth2::http::{HeaderValue, Method};
use oauth2::reqwest::async_http_client;
use oauth2::{HttpRequest, HttpResponse};
use serde::Deserialize;

use crate::config::OAuthConfig;
use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Copy)]
pub enum OAuthProviderKind {
    Google,
    GitHub,
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider_id: String,
    pub email: String,
    pub email_verified: bool,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
}

#[async_trait]
pub trait OAuthClient: Send + Sync {
    async fn exchange_code(
        &self,
        provider: OAuthProviderKind,
        code: &str,
    ) -> AppResult<OAuthUserInfo>;
}

pub struct DisabledOAuthClient;

#[async_trait]
impl OAuthClient for DisabledOAuthClient {
    async fn exchange_code(
        &self,
        _provider: OAuthProviderKind,
        _code: &str,
    ) -> AppResult<OAuthUserInfo> {
        Err(AppError::BadRequest(
            "oauth client is not configured".to_string(),
        ))
    }
}

pub struct HttpOAuthClient {
    config: OAuthConfig,
}

impl HttpOAuthClient {
    pub fn new(config: OAuthConfig) -> Self {
        Self { config }
    }
}

#[derive(Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    picture: Option<String>,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    name: Option<String>,
    avatar_url: Option<String>,
    email: Option<String>,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    verified: bool,
    primary: bool,
}

#[async_trait]
impl OAuthClient for HttpOAuthClient {
    async fn exchange_code(
        &self,
        provider: OAuthProviderKind,
        code: &str,
    ) -> AppResult<OAuthUserInfo> {
        match provider {
            OAuthProviderKind::Google => self.exchange_google(code).await,
            OAuthProviderKind::GitHub => self.exchange_github(code).await,
        }
    }
}

impl HttpOAuthClient {
    async fn exchange_google(&self, code: &str) -> AppResult<OAuthUserInfo> {
        let token: OAuthTokenResponse = http_json(
            Method::POST,
            "https://oauth2.googleapis.com/token",
            None,
            Some(serde_json::json!({
                "code": code,
                "client_id": self.config.google_client_id,
                "client_secret": self.config.google_client_secret,
                "grant_type": "authorization_code",
                "redirect_uri": "postmessage",
            })),
            false,
        )
        .await?;

        let profile: GoogleUserInfo = http_json(
            Method::GET,
            "https://www.googleapis.com/oauth2/v3/userinfo",
            Some(&token.access_token),
            None,
            false,
        )
        .await?;

        Ok(OAuthUserInfo {
            provider_id: profile.sub,
            email: profile.email,
            email_verified: profile.email_verified,
            full_name: profile.name,
            avatar_url: profile.picture,
        })
    }

    async fn exchange_github(&self, code: &str) -> AppResult<OAuthUserInfo> {
        let token: OAuthTokenResponse = http_json(
            Method::POST,
            "https://github.com/login/oauth/access_token",
            None,
            Some(serde_json::json!({
                "client_id": self.config.github_client_id,
                "client_secret": self.config.github_client_secret,
                "code": code,
            })),
            true,
        )
        .await?;

        let user: GithubUser = http_json(
            Method::GET,
            "https://api.github.com/user",
            Some(&token.access_token),
            None,
            true,
        )
        .await?;

        let email = if let Some(email) = user.email.clone() {
            Some((email, true))
        } else {
            let mut emails: Vec<GithubEmail> = http_json(
                Method::GET,
                "https://api.github.com/user/emails",
                Some(&token.access_token),
                None,
                true,
            )
            .await?;

            emails.sort_by_key(|email| (!email.primary, !email.verified));
            emails
                .into_iter()
                .next()
                .map(|email| (email.email, email.verified))
        };

        let Some((email, email_verified)) = email else {
            return Err(AppError::BadRequest(
                "github account did not provide an email".to_string(),
            ));
        };

        Ok(OAuthUserInfo {
            provider_id: user.id.to_string(),
            email,
            email_verified,
            full_name: user.name,
            avatar_url: user.avatar_url,
        })
    }
}

async fn http_json<T: for<'de> Deserialize<'de>>(
    method: Method,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<serde_json::Value>,
    github_compat: bool,
) -> AppResult<T> {
    let mut request = HttpRequest {
        url: url
            .parse()
            .map_err(|_| AppError::BadRequest(format!("invalid url: {url}")))?,
        method,
        headers: oauth2::http::HeaderMap::new(),
        body: body
            .map(|payload| payload.to_string().into_bytes())
            .unwrap_or_default(),
    };

    request
        .headers
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    request
        .headers
        .insert(ACCEPT, HeaderValue::from_static("application/json"));
    if github_compat {
        request
            .headers
            .insert(USER_AGENT, HeaderValue::from_static("rust-backend-oauth"));
    }
    if let Some(token) = bearer_token {
        let value = format!("Bearer {token}");
        request.headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&value)
                .map_err(|_| AppError::BadRequest("invalid auth header value".to_string()))?,
        );
    }

    let response: HttpResponse = async_http_client(request)
        .await
        .map_err(|error| AppError::BadRequest(format!("oauth provider request failed: {error}")))?;

    if !response.status_code.is_success() {
        return Err(AppError::BadRequest(format!(
            "oauth provider request rejected with status {}",
            response.status_code
        )));
    }

    serde_json::from_slice(&response.body)
        .map_err(|_| AppError::BadRequest("invalid oauth provider response".to_string()))
}
