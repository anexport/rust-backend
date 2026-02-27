use super::client::{DisabledAuth0ApiClient, HttpAuth0ApiClient};
use super::dtos::{Auth0ErrorResponse, Auth0SignupResponse};
use super::traits::Auth0ApiClient;
use crate::config::Auth0Config;
use crate::error::AppError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn auth0_error(code: &str, description: &str) -> Auth0ErrorResponse {
    Auth0ErrorResponse {
        code: code.to_string(),
        description: description.to_string(),
        error: String::new(),
        error_description: String::new(),
        name: String::new(),
    }
}

fn client_with_domain(domain: &str) -> HttpAuth0ApiClient {
    HttpAuth0ApiClient::new(Auth0Config {
        auth0_domain: Some(domain.to_string()),
        ..Default::default()
    })
    .expect("client should construct with domain")
}

#[test]
fn new_fails_without_domain() {
    let result = HttpAuth0ApiClient::new(Auth0Config {
        auth0_domain: None,
        ..Default::default()
    });

    assert!(matches!(result, Err(AppError::InternalError(_))));
}

#[test]
fn builds_signup_and_token_urls_from_domain() {
    let client = client_with_domain("tenant.auth0.com");

    assert_eq!(
        client.signup_url(),
        "https://tenant.auth0.com/dbconnections/signup"
    );
    assert_eq!(
        client.oauth_token_url(),
        "https://tenant.auth0.com/oauth/token"
    );
}

#[test]
fn maps_user_exists_to_conflict() {
    let err = auth0_error("user_exists", "The user already exists.");
    assert!(matches!(err.to_app_error(), AppError::Conflict(_)));
}

#[test]
fn maps_invalid_password_to_bad_request() {
    let err = auth0_error("invalid_password", "Password is too weak.");
    assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
}

#[test]
fn maps_invalid_grant_to_unauthorized() {
    let err = auth0_error("invalid_grant", "Wrong email or password.");
    assert!(matches!(err.to_app_error(), AppError::Unauthorized));
}

#[test]
fn maps_auth_id_already_exists_to_conflict() {
    let err = auth0_error("auth_id_already_exists", "Account already exists.");
    assert!(matches!(err.to_app_error(), AppError::Conflict(_)));
}

#[test]
fn maps_invalid_signup_to_bad_request() {
    let err = auth0_error("invalid_signup", "Invalid signup payload.");
    assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
}

#[test]
fn maps_bad_request_to_bad_request() {
    let err = auth0_error("bad_request", "Bad request.");
    assert!(matches!(err.to_app_error(), AppError::BadRequest(_)));
}

#[test]
fn maps_access_denied_to_unauthorized() {
    let err = auth0_error("access_denied", "Denied.");
    assert!(matches!(err.to_app_error(), AppError::Unauthorized));
}

#[test]
fn maps_unknown_error_to_internal_error() {
    let err = auth0_error("unknown_error", "Something went wrong.");
    assert!(matches!(err.to_app_error(), AppError::InternalError(_)));
}

#[test]
fn signup_response_parses_minimal_payload() {
    let payload = r#"{
        "_id":"auth0|123",
        "email":"user@example.com",
        "email_verified":false
    }"#;

    let parsed: Auth0SignupResponse =
        serde_json::from_str(payload).expect("minimal payload should deserialize");

    assert_eq!(parsed.id, "auth0|123");
    assert_eq!(parsed.email, "user@example.com");
    assert!(!parsed.email_verified);
}

#[tokio::test]
async fn disabled_client_signup_returns_service_unavailable() {
    let client = DisabledAuth0ApiClient;

    let result = client.signup("user@example.com", "password", None).await;

    assert!(matches!(
        result,
        Err(AppError::ServiceUnavailable { service, message })
        if service == "Auth0"
            && message == "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
    ));
}

#[tokio::test]
async fn disabled_client_password_grant_returns_service_unavailable() {
    let client = DisabledAuth0ApiClient;

    let result = client.password_grant("user@example.com", "password").await;

    assert!(matches!(
        result,
        Err(AppError::ServiceUnavailable { service, message })
        if service == "Auth0"
            && message == "Auth0 is not configured. Please set AUTH0_DOMAIN and AUTH0_AUDIENCE."
    ));
}

#[tokio::test]
async fn handle_error_returns_internal_error_for_unparsable_payload() {
    let client = client_with_domain("tenant.auth0.com");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("address should exist");

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept should succeed");
        let mut buffer = [0_u8; 1024];
        let _ = socket.read(&mut buffer).await;
        socket
            .write_all(
                b"HTTP/1.1 502 Bad Gateway
Content-Type: text/plain
Content-Length: 8
Connection: close

not-json",
            )
            .await
            .expect("response should write");
    });

    let response = reqwest::Client::new()
        .get(format!("http://{}/error", addr))
        .send()
        .await
        .expect("request should succeed");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.handle_error(response),
    )
    .await
    .expect("Test timed out");
    server.await.expect("server task should complete");

    // 5xx errors now map to ServiceUnavailable with generic message
    assert!(matches!(result, AppError::ServiceUnavailable { service, .. } if service == "Auth0"));
}

#[tokio::test]
async fn handle_error_400_unknown_code_maps_to_bad_request() {
    let client = client_with_domain("tenant.auth0.com");
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("address should exist");

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept should succeed");
        let mut buffer = [0_u8; 1024];
        let _ = socket.read(&mut buffer).await;
        let payload = r#"{"code":"unknown_code","description":"Custom Auth0 validation failure"}"#;
        let response = format!(
            "HTTP/1.1 400 Bad Request
Content-Type: application/json
Content-Length: {}
Connection: close

{}",
            payload.len(),
            payload
        );
        socket
            .write_all(response.as_bytes())
            .await
            .expect("response should write");
    });

    let response = reqwest::Client::new()
        .get(format!("http://{}/error", addr))
        .send()
        .await
        .expect("request should succeed");

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.handle_error(response),
    )
    .await
    .expect("Test timed out");
    server.await.expect("server task should complete");

    assert!(matches!(
        result,
        AppError::InternalError(_) // Unknown codes now map to InternalError with generic message
    ));
}
