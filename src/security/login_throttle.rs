use crate::config::SecurityConfig;
use crate::error::{AppError, AppResult};
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::RwLock;

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

    pub fn write_entries(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, HashMap<String, LoginAttemptState>> {
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
pub struct LoginAttemptState {
    pub failures: u32,
    pub locked_until: Option<DateTime<Utc>>,
    pub next_allowed_at: Option<DateTime<Utc>>,
}
