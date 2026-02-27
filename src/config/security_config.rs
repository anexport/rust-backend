use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    #[serde(default = "crate::config::defaults::default_cors_allowed_origins")]
    pub cors_allowed_origins: Vec<String>,
    #[serde(default = "crate::config::defaults::default_metrics_allow_private_only")]
    pub metrics_allow_private_only: bool,
    #[serde(default)]
    pub metrics_admin_token: Option<String>,
    #[serde(default = "crate::config::defaults::default_login_max_failures")]
    pub login_max_failures: u32,
    #[serde(default = "crate::config::defaults::default_login_lockout_seconds")]
    pub login_lockout_seconds: u64,
    #[serde(default = "crate::config::defaults::default_login_backoff_base_ms")]
    pub login_backoff_base_ms: u64,
    #[serde(default = "crate::config::defaults::default_global_rate_limit_per_minute")]
    pub global_rate_limit_per_minute: u32,
    #[serde(default = "crate::config::defaults::default_global_rate_limit_burst_size")]
    pub global_rate_limit_burst_size: u32,
    #[serde(default = "crate::config::defaults::default_global_rate_limit_authenticated_per_minute")]
    pub global_rate_limit_authenticated_per_minute: u32,
}
