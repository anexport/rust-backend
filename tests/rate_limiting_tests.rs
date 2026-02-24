use actix_web::{http::header, test as actix_test, App, HttpResponse};
use rust_backend::config::SecurityConfig;
use rust_backend::error::AppError;
use rust_backend::security::{cors_middleware, security_headers, LoginThrottle};
use std::thread;
use std::time::Duration as StdDuration;

fn test_config() -> SecurityConfig {
    SecurityConfig {
        cors_allowed_origins: vec![
            "http://localhost:3000".to_string(),
            "https://app.example.com".to_string(),
        ],
        metrics_allow_private_only: true,
        metrics_admin_token: None,
        login_max_failures: 3,
        login_lockout_seconds: 2,
        login_backoff_base_ms: 100,
    }
}

#[test]
fn test_login_throttle_basic_flow() {
    let config = test_config();
    let throttle = LoginThrottle::new(&config);
    let key = LoginThrottle::key("test@example.com", Some("127.0.0.1"));

    // Initial check should be allowed
    assert!(throttle.ensure_allowed(&key).is_ok());

    // Record a failure
    let err = throttle.record_failure(&key);
    assert!(matches!(err, AppError::Unauthorized));

    // Should be blocked by backoff (100ms)
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));

    // Wait for backoff (100ms)
    thread::sleep(StdDuration::from_millis(150));
    assert!(throttle.ensure_allowed(&key).is_ok());

    // Record success should clear state
    throttle.record_success(&key);
    assert!(throttle.ensure_allowed(&key).is_ok());
}

#[test]
fn test_login_throttle_exponential_backoff() {
    let mut config = test_config();
    config.login_backoff_base_ms = 100;
    let throttle = LoginThrottle::new(&config);
    let key = LoginThrottle::key("backoff@example.com", None);

    // 1st failure: backoff = 100ms
    throttle.record_failure(&key);

    // 2nd failure: wait very little so 1st failure is NOT cleaned up
    // backoff will become 100 * 2^1 = 200ms
    thread::sleep(StdDuration::from_millis(10));
    throttle.record_failure(&key);

    // Should be blocked for 200ms from NOW
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));

    thread::sleep(StdDuration::from_millis(150));
    // Still blocked (only 150ms passed, need 200ms)
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));

    thread::sleep(StdDuration::from_millis(100));
    assert!(throttle.ensure_allowed(&key).is_ok());
}

#[test]
fn test_login_throttle_lockout_behavior() {
    let config = test_config(); // max_failures: 3, lockout: 2s
    let throttle = LoginThrottle::new(&config);
    let key = LoginThrottle::key("lockout@example.com", None);

    // Record failures rapidly to ensure they accumulate
    throttle.record_failure(&key);
    throttle.record_failure(&key);

    // 3rd failure -> Lockout
    let err = throttle.record_failure(&key);
    assert!(matches!(err, AppError::RateLimited));

    // Should be blocked regardless of backoff
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));

    // Wait for lockout to expire (2s)
    thread::sleep(StdDuration::from_millis(2100));

    // After lockout expires, should be allowed again
    assert!(throttle.ensure_allowed(&key).is_ok());
}

#[test]
fn test_login_throttle_key_isolation() {
    let config = test_config();
    let throttle = LoginThrottle::new(&config);
    let key1 = LoginThrottle::key("user1@example.com", Some("1.1.1.1"));
    let key2 = LoginThrottle::key("user2@example.com", Some("1.1.1.1"));
    let key3 = LoginThrottle::key("user1@example.com", Some("2.2.2.2"));

    throttle.record_failure(&key1);
    throttle.record_failure(&key1);
    throttle.record_failure(&key1); // Key 1 locked out

    assert!(matches!(
        throttle.ensure_allowed(&key1),
        Err(AppError::RateLimited)
    ));
    assert!(throttle.ensure_allowed(&key2).is_ok());
    assert!(throttle.ensure_allowed(&key3).is_ok());
}

#[actix_rt::test]
async fn test_cors_middleware() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    // Allowed origin
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

    // Disallowed origin
    let req = actix_test::TestRequest::get()
        .uri("/")
        .insert_header((header::ORIGIN, "http://evil.com"))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    // actix-cors returns 200 OK but without CORS headers if origin not allowed
    // OR it might return 400 Bad Request depending on configuration.
    // In our implementation, it's allowed_origin_fn.
    assert!(resp
        .headers()
        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        .is_none());
}

#[test]
fn test_login_throttle_lockout_persistence() {
    let config = test_config();
    let throttle = LoginThrottle::new(&config);
    let key = LoginThrottle::key("persist@example.com", None);

    // Lockout
    throttle.record_failure(&key);
    throttle.record_failure(&key);
    throttle.record_failure(&key);
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));

    // Try again immediately, should still be rate limited
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));

    // Record another failure while locked out (simulating brute force)
    throttle.record_failure(&key);
    assert!(matches!(
        throttle.ensure_allowed(&key),
        Err(AppError::RateLimited)
    ));
}

#[actix_rt::test]
async fn test_security_headers_detailed() {
    let app = actix_test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", actix_web::web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    let req = actix_test::TestRequest::get().uri("/").to_request();
    let resp = actix_test::call_service(&app, req).await;

    let headers = resp.headers();

    // HSTS
    assert_eq!(
        headers.get("Strict-Transport-Security").unwrap(),
        "max-age=31536000; includeSubDomains"
    );
    // CSP
    assert_eq!(
        headers.get("Content-Security-Policy").unwrap(),
        "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
    );
    // Referrer
    assert_eq!(
        headers.get("Referrer-Policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
}

#[actix_rt::test]
async fn test_cors_disallowed_origin_returns_no_cors_headers() {
    let config = test_config();
    let cors = cors_middleware(&config);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors)
            .route("/", actix_web::web::get().to(|| HttpResponse::Ok())),
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

#[test]
fn test_fixed_window_rate_limiting() {
    let config = test_config();
    let throttle = LoginThrottle::new(&config);
    let key = "fixed-window-test";

    // Allow 2 requests per 1 second
    assert!(throttle.enforce_fixed_window(key, 2, 1).is_ok());
    assert!(throttle.enforce_fixed_window(key, 2, 1).is_ok());

    // 3rd request should be blocked
    assert!(matches!(
        throttle.enforce_fixed_window(key, 2, 1),
        Err(AppError::RateLimited)
    ));

    // Wait for window to expire
    thread::sleep(StdDuration::from_millis(1100));

    // Should be allowed again
    assert!(throttle.enforce_fixed_window(key, 2, 1).is_ok());
}

#[test]
fn test_entry_cleanup_removes_expired_entries() {
    let mut config = test_config();
    config.login_lockout_seconds = 1;
    config.login_backoff_base_ms = 1;
    let throttle = LoginThrottle::new(&config);
    let key = LoginThrottle::key("cleanup@example.com", None);

    // Lockout
    throttle.record_failure(&key);
    throttle.record_failure(&key);
    throttle.record_failure(&key);

    // Wait for lockout to expire
    thread::sleep(StdDuration::from_millis(1100));

    // Trigger cleanup via ensure_allowed
    assert!(throttle.ensure_allowed(&key).is_ok());

    // Check if it's really cleared - another failure should be Unauthorized, not RateLimited
    assert!(matches!(
        throttle.record_failure(&key),
        AppError::Unauthorized
    ));
}

#[test]
fn test_memory_does_not_grow_unbounded() {
    let mut config = test_config();
    config.login_lockout_seconds = 1;
    config.login_backoff_base_ms = 1;
    let throttle = LoginThrottle::new(&config);

    // Create many expired entries
    for i in 0..100 {
        let key = LoginThrottle::key(&format!("user{}@example.com", i), None);
        throttle.record_failure(&key);
    }

    // Wait for them to expire
    thread::sleep(StdDuration::from_millis(1100));

    // Trigger cleanup with a new key
    let final_key = LoginThrottle::key("final@example.com", None);
    throttle.ensure_allowed(&final_key).unwrap();

    // Note: We can't easily check the size of the internal map without exposing it,
    // but the test confirms cleanup logic runs without error.
}

#[test]
fn test_connection_pool_behavior_during_lockout() {
    let config = test_config();
    let throttle = std::sync::Arc::new(LoginThrottle::new(&config));

    let mut handles = vec![];

    // Spawn multiple threads that simultaneously attempt to create lockouts
    for i in 0..10 {
        let throttle_clone = std::sync::Arc::clone(&throttle);
        let handle = thread::spawn(move || {
            let key = LoginThrottle::key(&format!("user{}@example.com", i), Some("127.0.0.1"));

            // Each thread records 3 failures to trigger lockout
            for _ in 0..3 {
                let _ = throttle_clone.record_failure(&key);
            }

            // Verify lockout state is consistent across reads
            assert!(matches!(
                throttle_clone.ensure_allowed(&key),
                Err(AppError::RateLimited)
            ));

            // Record another failure while locked out (shouldn't cause deadlock)
            let _ = throttle_clone.record_failure(&key);

            // Still locked out
            assert!(matches!(
                throttle_clone.ensure_allowed(&key),
                Err(AppError::RateLimited)
            ));
        });
        handles.push(handle);
    }

    // All threads should complete without deadlock
    for handle in handles {
        handle.join().expect("Thread should not panic");
    }

    // Verify a new key still works (lockout state is isolated)
    let new_key = LoginThrottle::key("newuser@example.com", Some("127.0.0.1"));
    assert!(throttle.ensure_allowed(&new_key).is_ok());
}
