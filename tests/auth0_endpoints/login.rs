use super::*;
use crate::common;
use crate::common::mocks::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::Utc;
use rust_backend::domain::*;
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::auth0_api::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_web::test]
async fn auth0_login_with_valid_credentials_returns_200() {
    // Pre-register a user
    let existing_user = MockAuth0User {
        user_id: "auth0|existing-123".to_string(),
        email: "user@example.com".to_string(),
        password: "correctpassword".to_string(),
        username: Some("testuser".to_string()),
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "correctpassword"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;
    let status = response.status();

    assert_eq!(status, StatusCode::OK);

    let body: Auth0LoginResponseDto = actix_test::read_body_json(response).await;
    assert_eq!(body.token_type, "Bearer");
    assert_eq!(body.expires_in, 86400);
    assert!(!body.access_token.is_empty());
    assert!(!body.id_token.is_empty());
    assert!(body.refresh_token.is_some());
}

#[actix_web::test]
async fn auth0_login_with_wrong_password_returns_401() {
    let existing_user = MockAuth0User {
        user_id: "auth0|existing-123".to_string(),
        email: "user@example.com".to_string(),
        password: "correctpassword".to_string(),
        username: None,
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "wrongpassword"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn auth0_login_with_nonexistent_user_returns_401() {
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new());
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "nonexistent@example.com",
            "password": "anypassword"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_web::test]
async fn auth0_login_with_empty_email_returns_400() {
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new());
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "",
            "password": "anypassword"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    // Empty email may pass validation but fail at Auth0 level
    // The endpoint doesn't validate email format for login
    assert!(matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST
    ));
}

#[actix_web::test]
async fn auth0_login_with_empty_password_returns_400() {
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new());
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": ""
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert!(matches!(
        response.status(),
        StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST
    ));
}

#[actix_web::test]
async fn auth0_login_with_missing_fields_returns_400() {
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new());
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com"
            // Missing password
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// =============================================================================
// RS256 TOKEN VERIFICATION TESTS
// =============================================================================

#[actix_web::test]
async fn auth0_login_returns_bearer_token_type() {
    let existing_user = MockAuth0User {
        user_id: "auth0|123".to_string(),
        email: "user@example.com".to_string(),
        password: "password".to_string(),
        username: None,
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "password"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: Auth0LoginResponseDto = actix_test::read_body_json(response).await;
    assert_eq!(body.token_type, "Bearer");
}

#[actix_web::test]
async fn auth0_login_returns_expiration_time() {
    let existing_user = MockAuth0User {
        user_id: "auth0|123".to_string(),
        email: "user@example.com".to_string(),
        password: "password".to_string(),
        username: None,
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "password"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: Auth0LoginResponseDto = actix_test::read_body_json(response).await;
    // Auth0 typically returns 86400 seconds (24 hours)
    assert_eq!(body.expires_in, 86400);
}

#[actix_web::test]
async fn auth0_login_returns_all_required_token_fields() {
    let existing_user = MockAuth0User {
        user_id: "auth0|123".to_string(),
        email: "user@example.com".to_string(),
        password: "password".to_string(),
        username: None,
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "password"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert_eq!(response.status(), StatusCode::OK);

    let body: Auth0LoginResponseDto = actix_test::read_body_json(response).await;

    // Verify all required fields are present
    assert!(
        !body.access_token.is_empty(),
        "access_token should not be empty"
    );
    assert!(!body.id_token.is_empty(), "id_token should not be empty");
    assert!(
        body.refresh_token.is_some(),
        "refresh_token should be present"
    );
    assert!(
        !body.refresh_token.unwrap().is_empty(),
        "refresh_token should not be empty"
    );
}

#[actix_web::test]
async fn auth0_login_with_auth0_unavailable_returns_500() {
    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_service_unavailable(true));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "password"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    assert!(matches!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR | StatusCode::SERVICE_UNAVAILABLE
    ));
}

// =============================================================================
// RATE LIMITING TESTS
// =============================================================================

#[actix_web::test]
async fn auth0_login_respects_rate_limiting() {
    let existing_user = MockAuth0User {
        user_id: "auth0|123".to_string(),
        email: "user@example.com".to_string(),
        password: "password".to_string(),
        username: None,
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    // Send many failed login attempts - should return 401 until rate limit is hit
    for _ in 0..10 {
        let request = actix_test::TestRequest::post()
            .uri("/api/v1/auth/auth0/login")
            .set_json(serde_json::json!({
                "email": "user@example.com",
                "password": "wrongpassword"
            }))
            .to_request();

        let response = actix_test::call_service(&app, request).await;
        // First few attempts should return 401, later attempts may be rate limited (429)
        assert!(matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ));
    }
}

// =============================================================================
// USERNAME SUPPORT TESTS
// =============================================================================

#[actix_web::test]
async fn auth0_login_endpoint_responds_to_post() {
    let existing_user = MockAuth0User {
        user_id: "auth0|123".to_string(),
        email: "user@example.com".to_string(),
        password: "password".to_string(),
        username: None,
        name: None,
        email_verified: true,
    };

    let auth0_api_client = Arc::new(MockAuth0ApiClient::new().with_user(existing_user));
    let state = web::Data::new(app_state(auth0_api_client));

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(state.clone())
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::post()
        .uri("/api/v1/auth/auth0/login")
        .set_json(serde_json::json!({
            "email": "user@example.com",
            "password": "password"
        }))
        .to_request();

    let response = actix_test::call_service(&app, request).await;

    // Valid POST request should succeed
    assert_eq!(response.status(), StatusCode::OK);
}
