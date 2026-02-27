pub fn default_host() -> String {
    "0.0.0.0".to_string()
}

pub fn default_port() -> u16 {
    8080
}

pub fn default_environment() -> String {
    "development".to_string()
}

pub fn default_db_acquire_timeout_seconds() -> u64 {
    10
}

pub fn default_db_idle_timeout_seconds() -> u64 {
    600
}

pub fn default_db_max_lifetime_seconds() -> u64 {
    1800
}

pub fn default_db_test_before_acquire() -> bool {
    true
}

pub fn default_jwt_kid() -> String {
    "v1".to_string()
}

pub fn default_jwks_cache_ttl_secs() -> u64 {
    3600
}

pub fn default_auth0_connection() -> String {
    "Username-Password-Authentication".to_string()
}

pub fn default_cors_allowed_origins() -> Vec<String> {
    vec!["http://localhost:3000".to_string()]
}

pub fn default_metrics_allow_private_only() -> bool {
    true
}

pub fn default_login_max_failures() -> u32 {
    5
}

pub fn default_login_lockout_seconds() -> u64 {
    300
}

pub fn default_login_backoff_base_ms() -> u64 {
    200
}

pub fn default_global_rate_limit_per_minute() -> u32 {
    300
}

pub fn default_global_rate_limit_burst_size() -> u32 {
    30
}

pub fn default_global_rate_limit_authenticated_per_minute() -> u32 {
    1000
}

pub fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}
