mod common;
use common::setup_test_db;
use reqwest::StatusCode;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::test]
async fn test_application_boot_and_readiness() {
    // 1. Build the binary (ensure it's up to date)
    let status = Command::new("cargo")
        .args(["build", "--bin", "rust-backend"])
        .status()
        .expect("failed to build binary");
    assert!(status.success());

    // Allocate ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral port");
    let port = listener.local_addr().expect("failed to get local addr").port();
    drop(listener); // Release port for the application to bind to

    let test_db = setup_test_db().await;
    let database_url = test_db.url();

    // 2. Spawn the process
    let mut child = Command::new("./target/debug/rust-backend")
        .env("APP_PORT", port.to_string())
        .env("DATABASE_URL", database_url)
        .env(
            "APP_AUTH__JWT_SECRET",
            "test-secret-at-least-32-chars-long-needed",
        )
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn process");

    // 3. Poll /health and /ready
    let client = reqwest::Client::new();
    let health_url = format!("http://localhost:{}/health", port);
    let ready_url = format!("http://localhost:{}/ready", port);

    let mut success = false;
    for _ in 0..45 {
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status() == StatusCode::OK => {
                match client.get(&ready_url).send().await {
                    Ok(ready_resp) if ready_resp.status() == StatusCode::OK => {
                        success = true;
                        break;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        sleep(Duration::from_secs(1)).await;
    }

    if !success {
        // Kill child before waiting for output to avoid hanging
        child.kill().ok();
        let output = child.wait_with_output().expect("failed to wait for child");
        eprintln!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Application failed to become ready within 45 seconds");
    }

    // 4. Send SIGTERM (on Unix)
    #[cfg(unix)]
    {
        use libc::{kill, SIGTERM};
        let pid = child.id() as i32;
        unsafe { kill(pid, SIGTERM) };
    }
    #[cfg(not(unix))]
    {
        child.kill().expect("failed to kill process");
    }

    // 5. Wait for exit
    let exit_status = child.wait().expect("failed to wait for child");
    assert!(exit_status.success() || exit_status.code().is_none());
}

#[tokio::test]
async fn test_application_fails_fast_on_bad_config() {
    // 1. Build the binary
    let _ = setup_test_db().await; // Ensure common is used
    let status = Command::new("cargo")
        .args(["build", "--bin", "rust-backend"])
        .status()
        .expect("failed to build binary");
    assert!(status.success());

    // 2. Spawn the process with malformed DATABASE_URL
    let child = Command::new("./target/debug/rust-backend")
        .env("APP_DATABASE__URL", "not-a-valid-url")
        .env(
            "APP_AUTH__JWT_SECRET",
            "test-secret-at-least-32-chars-long-needed",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to wait for process");

    // 3. Assert it failed
    assert!(!child.success());
}
