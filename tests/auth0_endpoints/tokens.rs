use super::*;
use crate::common::mocks::*;
use crate::common;
use actix_web::{test as actix_test, App, web, http::StatusCode};
use rust_backend::domain::*;
use rust_backend::error::{AppError, AppResult};
use rust_backend::infrastructure::auth0_api::*;
use rust_backend::security::{cors_middleware, security_headers};
use uuid::Uuid;
use chrono::Utc;
use std::sync::Arc;

#[actix_web::test]
async fn auth0_tokens_have_jwt_structure() {
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

    // JWT tokens should have 3 parts separated by dots
    let parts: Vec<&str> = body.access_token.split('.').collect();
    assert_eq!(
        parts.len(),
        3,
        "JWT should have 3 parts: header.payload.signature"
    );

    let id_parts: Vec<&str> = body.id_token.split('.').collect();
    assert_eq!(
        id_parts.len(),
        3,
        "ID token should have 3 parts: header.payload.signature"
    );
}

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

