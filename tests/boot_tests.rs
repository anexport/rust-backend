use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::time::sleep;
use reqwest::StatusCode;

#[tokio::test]
async fn test_application_boot_and_readiness() {
    // 1. Build the binary (ensure it's up to date)
    let status = Command::new("cargo")
        .args(["build", "--bin", "rust-backend"])
        .status()
        .expect("failed to build binary");
    assert!(status.success());

    let port = 3015; // Switched to 3015
    let database_url = std::env::var("TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/postgres".to_string());

    // 2. Spawn the process
    // Figment with Env::prefixed("APP_") will map APP_PORT to AppConfig.port
    let mut child = Command::new("./target/debug/rust-backend")
        .env("APP_PORT", port.to_string())
        .env("APP_DATABASE__URL", &database_url)
        .env("APP_AUTH__JWT_SECRET", "test-secret-at-least-32-chars-long-needed")
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
    for _ in 0..45 { // Increased to 45 seconds to allow for migrations
        match client.get(&health_url).send().await {
            Ok(resp) if resp.status() == StatusCode::OK => {
                // Now check readiness (DB check)
                match client.get(&ready_url).send().await {
                    Ok(ready_resp) if ready_resp.status() == StatusCode::OK => {
                        success = true;
                        break;
                    }
                    Ok(ready_resp) => {
                        eprintln!("Ready check returned status: {}", ready_resp.status());
                    }
                    Err(_e) => {
                        // eprintln!("Ready check failed: {}", _e);
                    }
                }
            }
            Ok(resp) => {
                eprintln!("Health check returned status: {}", resp.status());
            }
            Err(_e) => {
                // eprint!("(polling...) ");
            }
        }
        sleep(Duration::from_secs(1)).await;
    }

    if !success {
        // Print output for debugging
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
    
    // In production, SIGTERM should result in graceful shutdown (exit code 0 usually)
    // On Unix, SIGTERM might result in signal 15 exit status.
    assert!(success, "Application failed to become ready within 45 seconds");
    assert!(exit_status.success() || exit_status.code().is_none());
}

#[tokio::test]
async fn test_application_fails_fast_on_bad_config() {
    // 1. Build the binary
    let status = Command::new("cargo")
        .args(["build", "--bin", "rust-backend"])
        .status()
        .expect("failed to build binary");
    assert!(status.success());

    // 2. Spawn the process with malformed DATABASE_URL
    let child = Command::new("./target/debug/rust-backend")
        .env("APP_DATABASE__URL", "not-a-valid-url")
        .env("APP_AUTH__JWT_SECRET", "test-secret-at-least-32-chars-long-needed")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to wait for process");

    // 3. Assert it failed
    assert!(!child.success());
}
