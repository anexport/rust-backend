use actix_cors::Cors;
use actix_web::middleware::DefaultHeaders;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::Mutex;

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
        .add(("Referrer-Policy", "no-referrer"))
        .add((
            "Content-Security-Policy",
            "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
        ))
}

pub struct LoginThrottle {
    entries: Mutex<HashMap<String, LoginAttemptState>>,
    max_failures: u32,
    lockout_seconds: u64,
    backoff_base_ms: u64,
}

impl LoginThrottle {
    pub fn new(config: &SecurityConfig) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_failures: config.login_max_failures,
            lockout_seconds: config.login_lockout_seconds,
            backoff_base_ms: config.login_backoff_base_ms,
        }
    }

    pub fn key(email: &str, ip: Option<&str>) -> String {
        format!("{email}|{}", ip.unwrap_or("unknown"))
    }

    pub fn ensure_allowed(&self, key: &str) -> AppResult<()> {
        let now = Utc::now();
        let entries = self.entries.lock().map_err(|_| {
            AppError::InternalError(anyhow::anyhow!("login throttle lock poisoned"))
        })?;
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
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(key);
        }
    }

    pub fn record_failure(&self, key: &str) -> AppError {
        let now = Utc::now();
        let mut entries = match self.entries.lock() {
            Ok(entries) => entries,
            Err(_) => {
                return AppError::InternalError(anyhow::anyhow!("login throttle lock poisoned"))
            }
        };
        let entry = entries.entry(key.to_string()).or_default();
        entry.failures += 1;

        let exponent = (entry.failures.saturating_sub(1)).min(8);
        let backoff_ms = self.backoff_base_ms.saturating_mul(1_u64 << exponent);
        entry.next_allowed_at = Some(now + Duration::milliseconds(backoff_ms as i64));

        if entry.failures >= self.max_failures {
            entry.failures = 0;
            entry.locked_until = Some(now + Duration::seconds(self.lockout_seconds as i64));
            return AppError::RateLimited;
        }

        AppError::Unauthorized
    }
}

#[derive(Default)]
struct LoginAttemptState {
    failures: u32,
    locked_until: Option<DateTime<Utc>>,
    next_allowed_at: Option<DateTime<Utc>>,
}
