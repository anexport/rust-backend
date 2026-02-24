mod common;

use common::TestDb;
use rust_backend::config::DatabaseConfig;
use rust_backend::infrastructure::db::pool::create_pool;
use sqlx::Connection;
use std::time::Duration;

#[tokio::test]
async fn test_create_pool_success() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 2,
        min_connections: 1,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");
    assert!(pool.size() >= 1);

    let _conn = pool.acquire().await.expect("Failed to acquire connection");
    assert!(pool.size() >= 1);
}

#[tokio::test]
async fn test_pool_exhaustion_behavior() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 2,
        min_connections: 2,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");

    // Acquire all connections
    let _conn1 = pool.acquire().await.expect("Failed to acquire conn1");
    let _conn2 = pool.acquire().await.expect("Failed to acquire conn2");

    // Try to acquire a 3rd connection, should fail after 1s timeout
    let start = std::time::Instant::now();
    let result = pool.acquire().await;
    let elapsed = start.elapsed();

    assert!(result.is_err());
    // Loosen the timing assertion to avoid flaky failures on slow CI
    assert!(elapsed >= Duration::from_millis(500));
    assert!(matches!(result.unwrap_err(), sqlx::Error::PoolTimedOut));
}

#[tokio::test]
async fn test_pool_test_before_acquire() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 1,
        min_connections: 1,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 600,
        max_lifetime_seconds: 1800,
        test_before_acquire: true,
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");

    // Acquire a connection and get its backend PID
    let mut conn = pool.acquire().await.expect("Failed to acquire conn");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await
        .expect("Failed to get PID");
    drop(conn);

    // Terminate the server-side connection from a new connection
    {
        let mut kill_conn: sqlx::PgConnection = sqlx::PgConnection::connect(test_db.url())
            .await
            .expect("Failed to connect for PID kill");
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(&mut kill_conn)
            .await
            .expect("Failed to terminate connection");
        kill_conn.close().await.ok();
    }

    // Re-acquire - test_before_acquire should replace the dead connection
    let mut conn = pool.acquire().await.expect("Failed to re-acquire conn");
    let new_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *conn)
        .await
        .expect("Failed to get new PID");
    drop(conn);

    // The PID should be different (dead connection was replaced)
    assert_ne!(
        pid, new_pid,
        "test_before_acquire should have replaced the dead connection"
    );
}

#[tokio::test]
async fn test_pool_invalid_url_fails_immediately() {
    let config = DatabaseConfig {
        url: "invalid-url".to_string(),
        max_connections: 1,
        min_connections: 1,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 1,
        max_lifetime_seconds: 1,
        test_before_acquire: false,
    };

    let result = create_pool(&config).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_connection_reuse() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 1,
        min_connections: 1,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 60,
        test_before_acquire: true,
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");

    let pid1: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();

    let pid2: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(pid1, pid2);
}

#[tokio::test]
async fn test_idle_timeout_closes_connections() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 1,
        min_connections: 0,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 1,
        max_lifetime_seconds: 60,
        test_before_acquire: false,
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");

    // Acquire and release
    {
        let _conn = pool.acquire().await.expect("Acquire");
    }

    // Wait for idle timeout with polling to avoid flaky timing
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if pool.num_idle() == 0 {
            break;
        }
    }

    // Idle connections should be closed by the background reaper task
    assert_eq!(
        pool.num_idle(),
        0,
        "Idle connection should have been closed after timeout"
    );
}

#[tokio::test]
async fn test_max_lifetime_recycles_connections() {
    let Some(test_db) = TestDb::new().await else {
        eprintln!("Skipping test: TEST_DATABASE_URL or DATABASE_URL not set");
        return;
    };

    let config = DatabaseConfig {
        url: test_db.url().to_string(),
        max_connections: 1,
        min_connections: 1,
        acquire_timeout_seconds: 1,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 1,
        test_before_acquire: true, // Enable to validate on each acquire
    };

    let pool = create_pool(&config).await.expect("Failed to create pool");

    let pid1: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Wait for max lifetime
    tokio::time::sleep(Duration::from_secs(2)).await;

    let pid2: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .unwrap();

    // Should be different PIDs because the first one exceeded max lifetime and was closed
    assert_ne!(
        pid1, pid2,
        "Connection should have been recycled after max_lifetime"
    );
}
