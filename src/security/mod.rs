use actix_cors::Cors;
use actix_governor::{governor::middleware::NoOpMiddleware, Governor, GovernorConfigBuilder};
use actix_web::middleware::DefaultHeaders;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::config::SecurityConfig;
use crate::error::{AppError, AppResult};

pub fn cors_middleware(config: &SecurityConfig) -> Cors {
    let allowlist = config.cors_allowed_origins.clone();

    Cors::default()
        .supports_credentials()
        .allow_any_header()
        .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        .allowed_origin_fn(move |origin, _| {
            origin
                .to_str()
                .ok()
                .map(|value| allowlist.iter().any(|allowed| allowed == value))
                .unwrap_or(false)
        })
}

pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add((
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        ))
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
        .add((
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
        ))
}

/// Create a global rate limiting middleware
///
/// This middleware applies rate limiting to all API endpoints based on IP address.
/// The default configuration is used for anonymous requests.
///
/// # Configuration
/// - `global_rate_limit_per_minute`: Requests per minute (must be > 0 and <= 60,000)
/// - `global_rate_limit_burst_size`: Burst capacity (allows short-term spikes)
pub fn global_rate_limiting(
    security_config: &SecurityConfig,
) -> Governor<actix_governor::PeerIpKeyExtractor, NoOpMiddleware> {
    // Validate rate limit configuration to prevent division by zero and unreasonable values
    let rate_limit_per_minute = security_config.global_rate_limit_per_minute;
    if rate_limit_per_minute == 0 {
        panic!(
            "global_rate_limit_per_minute must be greater than 0, got {}",
            rate_limit_per_minute
        );
    }
    if rate_limit_per_minute > 60_000 {
        panic!(
            "global_rate_limit_per_minute must not exceed 60,000 (to allow valid per-millisecond conversion), got {}",
            rate_limit_per_minute
        );
    }

    // Burst size should be reasonable (between 1 and 1000)
    let burst_size = security_config.global_rate_limit_burst_size;
    if burst_size == 0 {
        panic!(
            "global_rate_limit_burst_size must be greater than 0, got {}",
            burst_size
        );
    }
    if burst_size > 1000 {
        tracing::warn!(
            burst_size,
            "global_rate_limit_burst_size is unusually high; consider reducing to avoid abuse"
        );
    }

    // Create governor configuration
    // Use per_millisecond since actix-governor expects u64
    let requests_per_millisecond = (60_000 / rate_limit_per_minute) as u64;
    let governor_config = GovernorConfigBuilder::default()
        .per_millisecond(requests_per_millisecond)
        .burst_size(burst_size)
        .finish()
        .expect("Failed to build governor config");

    // Create Governor with default key extractor (PeerIpKeyExtractor) and middleware (NoOpMiddleware)
    Governor::new(&governor_config)
}

pub struct LoginThrottle {
    entries: RwLock<HashMap<String, LoginAttemptState>>,
    max_failures: u32,
    lockout_seconds: u64,
    backoff_base_ms: u64,
}

impl LoginThrottle {
    pub fn new(config: &SecurityConfig) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_failures: config.login_max_failures,
            lockout_seconds: config.login_lockout_seconds,
            backoff_base_ms: config.login_backoff_base_ms,
        }
    }

    pub fn key(email: &str, ip: Option<&str>) -> String {
        format!("{email}|{}", ip.unwrap_or("unknown"))
    }

    fn write_entries(&self) -> std::sync::RwLockWriteGuard<'_, HashMap<String, LoginAttemptState>> {
        self.entries.write().unwrap_or_else(|e| {
            tracing::warn!("Login throttle lock was poisoned, recovering the lock");
            e.into_inner()
        })
    }

    fn cleanup_expired_entries(
        entries: &mut HashMap<String, LoginAttemptState>,
        now: DateTime<Utc>,
    ) {
        entries.retain(|_, state| {
            let latest_block = state
                .locked_until
                .into_iter()
                .chain(state.next_allowed_at)
                .max();
            latest_block.is_some_and(|until| until > now)
        });
    }

    pub fn enforce_fixed_window(
        &self,
        key: &str,
        max_requests: u32,
        window_seconds: u64,
    ) -> AppResult<()> {
        let now = Utc::now();
        let mut entries = self.write_entries();
        Self::cleanup_expired_entries(&mut entries, now);
        let mut entry = entries.get(key).cloned().unwrap_or_default();

        if let Some(window_end) = entry.locked_until {
            if window_end <= now {
                entry.failures = 0;
                entry.locked_until = None;
            }
        }

        if entry.locked_until.is_none() {
            entry.locked_until = Some(now + Duration::seconds(window_seconds as i64));
        }

        entry.failures = entry.failures.saturating_add(1);
        entries.insert(key.to_string(), entry.clone());

        if entry.failures > max_requests {
            return Err(AppError::RateLimited);
        }

        Ok(())
    }

    pub fn ensure_allowed(&self, key: &str) -> AppResult<()> {
        let now = Utc::now();
        let mut entries = self.write_entries();
        Self::cleanup_expired_entries(&mut entries, now);
        if let Some(state) = entries.get(key) {
            if state.locked_until.is_some_and(|until| until > now) {
                return Err(AppError::RateLimited);
            }
            if state.next_allowed_at.is_some_and(|next| next > now) {
                return Err(AppError::RateLimited);
            }
        }

        Ok(())
    }

    pub fn record_success(&self, key: &str) {
        let mut entries = self.write_entries();
        entries.remove(key);
    }

    pub fn record_failure(&self, key: &str) -> AppError {
        let now = Utc::now();
        let mut entries = self.write_entries();
        Self::cleanup_expired_entries(&mut entries, now);
        let mut entry = entries.get(key).cloned().unwrap_or_default();
        entry.failures = entry.failures.saturating_add(1);

        let exponent = (entry.failures.saturating_sub(1)).min(8);
        let backoff_ms = self.backoff_base_ms.saturating_mul(1_u64 << exponent);
        entry.next_allowed_at = Some(now + Duration::milliseconds(backoff_ms as i64));

        if entry.failures >= self.max_failures {
            entry.failures = 0;
            entry.locked_until = Some(now + Duration::seconds(self.lockout_seconds as i64));
            entries.insert(key.to_string(), entry);
            return AppError::RateLimited;
        }

        entries.insert(key.to_string(), entry);
        AppError::Unauthorized
    }
}

#[derive(Clone, Default)]
struct LoginAttemptState {
    failures: u32,
    locked_until: Option<DateTime<Utc>>,
    next_allowed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
                LoginAttemptState {
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
