use super::*;
use crate::common;
use crate::common::mocks::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::{Duration, Utc};
use rust_backend::api::routes;
use rust_backend::api::routes::AppState;
use rust_backend::domain::*;
use rust_backend::infrastructure::repositories::*;
use rust_backend::security::{cors_middleware, security_headers};
use rust_decimal::Decimal;
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn metrics_route_is_registered() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_ne!(response.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn metrics_route_requires_private_network_or_admin_auth() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/metrics").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn security_headers_are_present() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/health").to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-content-type-options"));
    assert!(response.headers().contains_key("x-frame-options"));
    assert!(response.headers().contains_key("referrer-policy"));
}

#[actix_rt::test]
async fn cors_preflight_respects_allowlist() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let allowed_preflight = actix_test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/api/v1/auth/auth0/login")
        .insert_header(("Origin", "http://localhost:3000"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_request();
    let allowed_response = actix_test::call_service(&app, allowed_preflight).await;
    assert_eq!(allowed_response.status(), StatusCode::OK);
    assert_eq!(
        allowed_response
            .headers()
            .get("access-control-allow-origin")
            .expect("allow origin header missing"),
        "http://localhost:3000"
    );

    let denied_preflight = actix_test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/api/v1/auth/auth0/login")
        .insert_header(("Origin", "http://evil.example"))
        .insert_header(("Access-Control-Request-Method", "POST"))
        .to_request();
    let denied_response = actix_test::call_service(&app, denied_preflight).await;
    assert_eq!(denied_response.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn auth_me_rejects_when_authorization_header_missing() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/api/v1/auth/me")
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn metrics_allows_admin_token_from_non_private_request() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let mut state = app_state(user_repo, equipment_repo);
    state.security.metrics_allow_private_only = true;
    state.security.metrics_admin_token = Some("ops-secret".to_string());

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/metrics")
        .insert_header(("x-admin-token", "ops-secret"))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn ws_upgrade_requires_authorization() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/ws")
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn ws_upgrade_requires_wss_in_production() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let mut state = app_state(user_repo, equipment_repo);
    state.app_environment = "production".to_string();

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get()
        .uri("/ws")
        .insert_header(("Connection", "Upgrade"))
        .insert_header(("Upgrade", "websocket"))
        .insert_header(("Sec-WebSocket-Version", "13"))
        .insert_header(("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn ready_endpoint_checks_dependencies() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let state = app_state(user_repo, equipment_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let request = actix_test::TestRequest::get().uri("/ready").to_request();
    let response = actix_test::call_service(&app, request).await;
    let has_test_db_url =
        std::env::var("TEST_DATABASE_URL").is_ok() || std::env::var("DATABASE_URL").is_ok();
    if has_test_db_url {
        assert_eq!(response.status(), StatusCode::OK);
    } else {
        // After fix: ready endpoint returns 503 ServiceUnavailable instead of 500
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

// Message routes tests
