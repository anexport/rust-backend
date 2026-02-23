use tracing::error;
use uuid::Uuid;

pub fn capture_unexpected_5xx(path: &str, method: &str, status: u16, request_id: &str) {
    let event_id = Uuid::new_v4();
    error!(
        event_id = %event_id,
        request_id = %request_id,
        method = %method,
        path = %path,
        status = status,
        "error-tracking capture for unexpected 5xx"
    );
}

#[cfg(test)]
mod tests {
    use super::capture_unexpected_5xx;

    #[test]
    fn capture_unexpected_5xx_does_not_panic() {
        let result = std::panic::catch_unwind(|| {
            capture_unexpected_5xx("/api/test", "GET", 500, "req-123");
        });

        assert!(result.is_ok());
    }
}
