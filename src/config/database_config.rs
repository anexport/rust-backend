use serde::Deserialize;

#[derive(Deserialize, Clone)]
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

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("url", &"[REDACTED]")
            .field("max_connections", &self.max_connections)
            .field("min_connections", &self.min_connections)
            .field("acquire_timeout_seconds", &self.acquire_timeout_seconds)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field("max_lifetime_seconds", &self.max_lifetime_seconds)
            .field("test_before_acquire", &self.test_before_acquire)
            .finish()
    }
}
