use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    #[serde(default = "crate::config::defaults::default_db_acquire_timeout_seconds")]
    pub acquire_timeout_seconds: u64,
    #[serde(default = "crate::config::defaults::default_db_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    #[serde(default = "crate::config::defaults::default_db_max_lifetime_seconds")]
    pub max_lifetime_seconds: u64,
    #[serde(default = "crate::config::defaults::default_db_test_before_acquire")]
    pub test_before_acquire: bool,
}
