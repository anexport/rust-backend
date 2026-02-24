use crate::config::DatabaseConfig;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_seconds))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout_seconds)))
        .max_lifetime(Some(Duration::from_secs(config.max_lifetime_seconds)))
        .test_before_acquire(config.test_before_acquire)
        .connect(&config.url)
        .await
}

#[cfg(test)]
mod tests {
    use super::create_pool;
    use crate::config::DatabaseConfig;

    #[tokio::test]
    async fn create_pool_returns_error_for_invalid_url() {
        let config = DatabaseConfig {
            url: "not-a-valid-database-url".to_string(),
            max_connections: 5,
            min_connections: 1,
            acquire_timeout_seconds: 10,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
            test_before_acquire: true,
        };

        let result = create_pool(&config).await;

        assert!(matches!(result, Err(sqlx::Error::Configuration(_))));
    }

    #[tokio::test]
    async fn create_pool_uses_configured_connection_bounds() {
        let config = DatabaseConfig {
            url: "postgres://user:password@127.0.0.1:1/test_db".to_string(),
            max_connections: 7,
            min_connections: 3,
            acquire_timeout_seconds: 10,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 1800,
            test_before_acquire: true,
        };

        let result = create_pool(&config).await;

        assert!(result.is_err());
    }
}
