pub mod cors;
pub mod headers;
pub mod login_throttle;
pub mod rate_limit;

pub use cors::cors_middleware;
pub use headers::security_headers;
pub use login_throttle::LoginThrottle;
pub use rate_limit::global_rate_limiting;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SecurityConfig;
    use crate::error::AppError;
    use chrono::{Duration, Utc};

    fn test_security_config(lockout_seconds: u64) -> SecurityConfig {
        SecurityConfig {
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            metrics_allow_private_only: true,
            metrics_admin_token: None,
            login_max_failures: 3,
            login_lockout_seconds: lockout_seconds,
            login_backoff_base_ms: 1,
            global_rate_limit_per_minute: 300,
            global_rate_limit_burst_size: 30,
            global_rate_limit_authenticated_per_minute: 1000,
        }
    }

    #[test]
    fn login_throttle_expires_state_after_ttl() {
        let throttle = LoginThrottle::new(&test_security_config(1));
        let key = LoginThrottle::key("user@example.com", Some("203.0.113.10"));

        assert!(matches!(
            throttle.record_failure(&key),
            AppError::Unauthorized
        ));
        assert!(matches!(
            throttle.record_failure(&key),
            AppError::Unauthorized
        ));

        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Expired state should be evicted and failures start over at 1.
        assert!(matches!(
            throttle.record_failure(&key),
            AppError::Unauthorized
        ));
    }

    #[test]
    fn login_throttle_success_clears_state() {
        let throttle = LoginThrottle::new(&test_security_config(60));
        let key = LoginThrottle::key("user@example.com", Some("203.0.113.20"));

        assert!(matches!(
            throttle.record_failure(&key),
            AppError::Unauthorized
        ));
        throttle.record_success(&key);
        assert!(throttle.ensure_allowed(&key).is_ok());
    }

    #[test]
    fn fixed_window_rate_limit_blocks_after_limit() {
        let throttle = LoginThrottle::new(&test_security_config(60));
        let key = LoginThrottle::key("equipment_public_list", Some("198.51.100.77"));

        assert!(throttle.enforce_fixed_window(&key, 2, 60).is_ok());
        assert!(throttle.enforce_fixed_window(&key, 2, 60).is_ok());
        assert!(matches!(
            throttle.enforce_fixed_window(&key, 2, 60),
            Err(AppError::RateLimited)
        ));
    }

    #[test]
    fn record_failure_does_not_panic_when_failures_counter_is_maxed() {
        let throttle = LoginThrottle::new(&test_security_config(60));
        let key = LoginThrottle::key("overflow@example.com", Some("198.51.100.55"));
        let now = Utc::now();
        {
            let mut entries = throttle.write_entries();
            entries.insert(
                key.clone(),
                login_throttle::LoginAttemptState {
                    failures: u32::MAX,
                    locked_until: Some(now + Duration::seconds(60)),
                    next_allowed_at: Some(now + Duration::seconds(1)),
                },
            );
        }

        let result = std::panic::catch_unwind(|| throttle.record_failure(&key));
        assert!(result.is_ok(), "record_failure must not panic on overflow");
    }

    #[test]
    fn global_rate_limiting_panics_when_rate_limit_exceeds_60000() {
        let config = SecurityConfig {
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            metrics_allow_private_only: true,
            metrics_admin_token: None,
            login_max_failures: 3,
            login_lockout_seconds: 300,
            login_backoff_base_ms: 200,
            global_rate_limit_per_minute: 60_001, // Exceeds 60,000
            global_rate_limit_burst_size: 30,
            global_rate_limit_authenticated_per_minute: 1000,
        };

        let result = std::panic::catch_unwind(|| {
            global_rate_limiting(&config);
        });

        assert!(
            result.is_err(),
            "global_rate_limiting should panic when rate_limit_per_minute > 60,000"
        );
    }

    #[test]
    fn global_rate_limiting_succeeds_at_max_valid_rate_limit() {
        let config = SecurityConfig {
            cors_allowed_origins: vec!["http://localhost:3000".to_string()],
            metrics_allow_private_only: true,
            metrics_admin_token: None,
            login_max_failures: 3,
            login_lockout_seconds: 300,
            login_backoff_base_ms: 200,
            global_rate_limit_per_minute: 60_000, // Maximum valid value
            global_rate_limit_burst_size: 30,
            global_rate_limit_authenticated_per_minute: 1000,
        };

        let result = std::panic::catch_unwind(|| {
            global_rate_limiting(&config);
        });

        assert!(
            result.is_ok(),
            "global_rate_limiting should succeed when rate_limit_per_minute = 60,000"
        );
    }
}
