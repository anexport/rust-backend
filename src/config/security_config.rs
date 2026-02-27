use serde::Deserialize;

#[derive(Deserialize, Clone)]
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
    #[serde(
        default = "crate::config::defaults::default_global_rate_limit_authenticated_per_minute"
    )]
    pub global_rate_limit_authenticated_per_minute: u32,
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("cors_allowed_origins", &self.cors_allowed_origins)
            .field(
                "metrics_allow_private_only",
                &self.metrics_allow_private_only,
            )
            .field(
                "metrics_admin_token",
                &self.metrics_admin_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("login_max_failures", &self.login_max_failures)
            .field("login_lockout_seconds", &self.login_lockout_seconds)
            .field("login_backoff_base_ms", &self.login_backoff_base_ms)
            .field(
                "global_rate_limit_per_minute",
                &self.global_rate_limit_per_minute,
            )
            .field(
                "global_rate_limit_burst_size",
                &self.global_rate_limit_burst_size,
            )
            .field(
                "global_rate_limit_authenticated_per_minute",
                &self.global_rate_limit_authenticated_per_minute,
            )
            .finish()
    }
}
