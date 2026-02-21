use sqlx::PgPool;

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    // Keep this module as the single embed point for sqlx migration files.
    sqlx::migrate!("./migrations").run(pool).await
}
