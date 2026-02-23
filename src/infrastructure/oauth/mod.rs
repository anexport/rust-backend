pub mod auth0_api_client;

use async_trait::async_trait;
use reqwest::{Client, header::{ACCEPT, CONTENT_TYPE, USER_AGENT}};
use serde::Deserialize;

use crate::config::OAuthConfig;
use crate::error::{AppError, AppResult};

// Re-export Auth0 API client types
pub use auth0_api_client::{
    Auth0ApiClient,
    SignupRequest,
    SignupResponse,
    PasswordGrantRequest,
    PasswordGrantResponse,
};

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
            "Social login is not available. Please use email and password instead.".to_string(),
        ))
    }
}

pub struct HttpOAuthClient {
    config: OAuthConfig,
    client: Client,
}

impl HttpOAuthClient {
    pub fn new(config: OAuthConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
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
            &self.client,
            reqwest::Method::POST,
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
            &self.client,
            reqwest::Method::GET,
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
            &self.client,
            reqwest::Method::POST,
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
            &self.client,
            reqwest::Method::GET,
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
                &self.client,
                reqwest::Method::GET,
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
                "Your GitHub account does not have a public email. Please add an email to your GitHub profile or use a different sign-in method.".to_string(),
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
    client: &Client,
    method: reqwest::Method,
    url: &str,
    bearer_token: Option<&str>,
    body: Option<serde_json::Value>,
    github_compat: bool,
) -> AppResult<T> {
    let mut request = client.request(method, url);

    request = request.header(CONTENT_TYPE, "application/json");
    request = request.header(ACCEPT, "application/json");

    if github_compat {
        request = request.header(USER_AGENT, "rust-backend-oauth");
    }

    if let Some(token) = bearer_token {
        request = request.bearer_auth(token);
    }

    if let Some(payload) = body {
        request = request.json(&payload);
    }

    let response = request
        .send()
        .await
        .map_err(|_| AppError::BadRequest("Unable to connect to sign-in provider. Please try again later.".to_string()))?;

    if !response.status().is_success() {
        return Err(AppError::BadRequest(
            "Sign-in was rejected by the provider. Please try again or use a different sign-in method.".to_string(),
        ));
    }

    response
        .json()
        .await
        .map_err(|_| AppError::BadRequest("Received an invalid response from the sign-in provider. Please try again later.".to_string()))
}

#[cfg(test)]
mod tests {
    use super::{DisabledOAuthClient, OAuthClient, OAuthProviderKind};
    use crate::error::AppError;

    const DISABLED_OAUTH_MESSAGE: &str =
        "Social login is not available. Please use email and password instead.";

    #[tokio::test]
    async fn disabled_oauth_client_rejects_google_exchange_code() {
        let client = DisabledOAuthClient;

        let result = client
            .exchange_code(OAuthProviderKind::Google, "test-code")
            .await;

        assert!(matches!(
            result,
            Err(AppError::BadRequest(message)) if message == DISABLED_OAUTH_MESSAGE
        ));
    }

    #[tokio::test]
    async fn disabled_oauth_client_rejects_github_exchange_code() {
        let client = DisabledOAuthClient;

        let result = client
            .exchange_code(OAuthProviderKind::GitHub, "test-code")
            .await;

        assert!(matches!(
            result,
            Err(AppError::BadRequest(message)) if message == DISABLED_OAUTH_MESSAGE
        ));
    }
}
