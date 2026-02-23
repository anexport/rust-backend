use crate::config::DatabaseConfig;
use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn create_pool(config: &DatabaseConfig) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
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
        };

        let result = create_pool(&config).await;

        assert!(result.is_err());
    }
}
