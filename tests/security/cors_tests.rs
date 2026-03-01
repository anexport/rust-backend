//! Tests for CORS middleware configuration
//!
//! This module tests that the CORS middleware properly:
//! - Allows requests from configured origins
//! - Blocks requests from unconfigured origins
//! - Returns appropriate CORS headers

use actix_web::{http::header, test as actix_test, App, HttpResponse};
use rust_backend::config::SecurityConfig;
use rust_backend::security::cors_middleware;

fn test_config() -> SecurityConfig {
    SecurityConfig {
        cors_allowed_origins: vec![
            "http://localhost:3000".to_string(),
            "https://app.example.com".to_string(),
            "https://admin.example.com".to_string(),
        ],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 5,
        login_lockout_seconds: 300,
        login_backoff_base_ms: 200,
        global_rate_limit_per_minute: 300,
        global_rate_limit_burst_size: 30,
        global_rate_limit_authenticated_per_minute: 1000,
    }
}

#[actix_rt::test]
async fn test_cors_allows_configured_origin() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );
}

#[actix_rt::test]
async fn test_cors_allows_https_origin() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "https://app.example.com"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://app.example.com"
    );
}

#[actix_rt::test]
async fn test_cors_blocks_unconfigured_origin() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://evil.com"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // Request should succeed but without CORS headers
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[actix_rt::test]
async fn test_cors_blocks_malicious_origin() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://malicious.com"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[actix_rt::test]
async fn test_cors_allows_multiple_configured_origins() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    // Test first origin
    let req1 = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request();
    let resp1 = actix_test::call_service(&app, req1).await;
    assert_eq!(
        resp1
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );

    // Test second origin
    let req2 = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "https://admin.example.com"))
        .to_request();
    let resp2 = actix_test::call_service(&app, req2).await;
    assert_eq!(
        resp2
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "https://admin.example.com"
    );
}

#[actix_rt::test]
async fn test_cors_empty_allowed_origins_blocks_all() {
    let mut config = test_config();
    config.cors_allowed_origins = vec![];
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://example.com"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // Should have no CORS headers when allowlist is empty
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[actix_rt::test]
async fn test_cors_origin_case_sensitivity() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    // Test exact match case
    let req1 = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request();
    let resp1 = actix_test::call_service(&app, req1).await;
    assert!(resp1
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_some());

    // Test different case (domains are case-insensitive but our implementation does exact match)
    // This documents current behavior - may need adjustment if case-insensitivity is desired
    let req2 = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://LocalHost:3000"))
        .to_request();
    let resp2 = actix_test::call_service(&app, req2).await;
    // Exact match required by current implementation
    assert!(resp2
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[actix_rt::test]
async fn test_cors_origin_with_port_mismatch() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    // Configured: http://localhost:3000
    // Request with different port should be blocked
    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://localhost:4000"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[actix_rt::test]
async fn test_cors_origin_without_protocol_mismatch() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    // Configured: https://app.example.com
    // Request with http (not https) should be blocked
    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://app.example.com"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[actix_rt::test]
async fn test_cors_allows_options_request_from_allowed_origin() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/")
        .insert_header((header::ORIGIN, "http://localhost:3000"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // OPTIONS should succeed with CORS headers for preflight
    assert_eq!(resp.status(), actix_web::http::StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap(),
        "http://localhost:3000"
    );
}
