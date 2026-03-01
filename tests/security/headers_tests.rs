//! Tests for security headers middleware
//!
//! This module tests that the security_headers middleware properly:
//! - Adds HSTS header with max-age and includeSubDomains
//! - Adds X-Content-Type-Options: nosniff
//! - Adds X-Frame-Options: DENY
//! - Adds Referrer-Policy: strict-origin-when-cross-origin
//! - Adds Content-Security-Policy

use actix_web::{test as actix_test, App, HttpResponse};
use rust_backend::security::security_headers;

#[actix_rt::test]
async fn test_security_headers_adds_hsts() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let hsts_header = resp.headers().get("Strict-Transport-Security");
    assert!(hsts_header.is_some(), "HSTS header should be present");
    assert_eq!(hsts_header.unwrap(), "max-age=31536000; includeSubDomains");
}

#[actix_rt::test]
async fn test_security_headers_adds_x_content_type_options() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let xcto_header = resp.headers().get("X-Content-Type-Options");
    assert!(
        xcto_header.is_some(),
        "X-Content-Type-Options header should be present"
    );
    assert_eq!(xcto_header.unwrap(), "nosniff");
}

#[actix_rt::test]
async fn test_security_headers_adds_x_frame_options() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let xfo_header = resp.headers().get("X-Frame-Options");
    assert!(
        xfo_header.is_some(),
        "X-Frame-Options header should be present"
    );
    assert_eq!(xfo_header.unwrap(), "DENY");
}

#[actix_rt::test]
async fn test_security_headers_adds_referrer_policy() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let referrer_header = resp.headers().get("Referrer-Policy");
    assert!(
        referrer_header.is_some(),
        "Referrer-Policy header should be present"
    );
    assert_eq!(referrer_header.unwrap(), "strict-origin-when-cross-origin");
}

#[actix_rt::test]
async fn test_security_headers_adds_content_security_policy() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let csp_header = resp.headers().get("Content-Security-Policy");
    assert!(csp_header.is_some(), "CSP header should be present");
    assert_eq!(
        csp_header.unwrap(),
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    );
}

#[actix_rt::test]
async fn test_security_headers_all_headers_present() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let headers = resp.headers();

    // Verify all expected security headers are present
    assert!(headers.get("Strict-Transport-Security").is_some());
    assert!(headers.get("X-Content-Type-Options").is_some());
    assert!(headers.get("X-Frame-Options").is_some());
    assert!(headers.get("Referrer-Policy").is_some());
    assert!(headers.get("Content-Security-Policy").is_some());
}

#[actix_rt::test]
async fn test_security_headers_on_different_status_codes() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/ok", actix_web::web::get().to(HttpResponse::Ok))
            .route(
                "/not_found",
                actix_web::web::get().to(HttpResponse::NotFound),
            )
            .route(
                "/error",
                actix_web::web::get().to(HttpResponse::InternalServerError),
            ),
    )
    .await;

    // Test with 200 OK
    let req1 = actix_test::TestRequest::get().uri("/ok").to_request();
    let resp1 = actix_test::call_service(&app, req1).await;
    assert!(resp1.headers().get("Content-Security-Policy").is_some());

    // Test with 404 Not Found
    let req2 = actix_test::TestRequest::get()
        .uri("/not_found")
        .to_request();
    let resp2 = actix_test::call_service(&app, req2).await;
    assert!(resp2.headers().get("Content-Security-Policy").is_some());

    // Test with 500 Internal Server Error
    let req3 = actix_test::TestRequest::get().uri("/error").to_request();
    let resp3 = actix_test::call_service(&app, req3).await;
    assert!(resp3.headers().get("Content-Security-Policy").is_some());
}

#[actix_rt::test]
async fn test_security_headers_with_options_request() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::default()
        .method(actix_web::http::Method::OPTIONS)
        .uri("/")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;

    // Security headers should still be present on OPTIONS
    assert!(resp.headers().get("Content-Security-Policy").is_some());
    assert!(resp.headers().get("X-Frame-Options").is_some());
}

#[actix_rt::test]
async fn test_security_headers_with_post_request() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::post().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::post().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    // Security headers should be present on POST
    assert!(resp.headers().get("Content-Security-Policy").is_some());
    assert!(resp.headers().get("X-Frame-Options").is_some());
}

#[actix_rt::test]
async fn test_security_headers_csp_frame_ancestors_none() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let csp = resp
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap();

    // Verify frame-ancestors is set to 'none' to prevent clickjacking
    assert!(csp.contains("frame-ancestors 'none'"));
}

#[actix_rt::test]
async fn test_security_headers_csp_object_src_none() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let csp = resp
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap();

    // Verify object-src is set to 'none' to prevent plugin content
    assert!(csp.contains("object-src 'none'"));
}

#[actix_rt::test]
async fn test_security_headers_csp_default_src_self() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(HttpResponse::Ok)),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let csp = resp
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap();

    // Verify default-src is set to 'self'
    assert!(csp.contains("default-src 'self'"));
}

#[actix_rt::test]
async fn test_security_headers_middleware_does_not_override_existing_headers() {
    // This test documents the current behavior
    // DefaultHeaders in actix-web does NOT override existing headers
    let app = actix_test::init_service(App::new().wrap(security_headers()).route(
        "/",
        actix_web::web::get().to(|| async {
            HttpResponse::Ok()
                .insert_header(("X-Frame-Options", "SAMEORIGIN"))
                .finish()
        }),
    ))
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    // The header from the handler should take precedence over middleware
    let xfo = resp.headers().get("X-Frame-Options").unwrap();
    assert_eq!(
        xfo, "SAMEORIGIN",
        "Handler's header should override middleware"
    );
}
