use crate::error::{AppError, AppResult};
use tracing::error;
use uuid::Uuid;

pub fn capture_unexpected_5xx(
    path: &str,
    method: &str,
    status: u16,
    request_id: &str,
) -> AppResult<Uuid> {
    if status < 500 {
        return Err(AppError::BadRequest(
            "capture_unexpected_5xx requires an HTTP 5xx status".to_string(),
        ));
    }

    let event_id = Uuid::new_v4();
    error!(
        tracking_backend = "log",
        event_id = %event_id,
        request_id = %request_id,
        method = %method,
        path = %path,
        status = status,
        "error-tracking capture for unexpected 5xx"
    );
    Ok(event_id)
}

#[cfg(test)]
mod tests {
    use super::capture_unexpected_5xx;
    use crate::error::AppError;

    #[test]
    fn capture_unexpected_5xx_does_not_panic() {
        let result = std::panic::catch_unwind(|| {
            let event_id = capture_unexpected_5xx("/api/test", "GET", 500, "req-123")
                .expect("capture should succeed for 5xx status");
            assert_ne!(event_id, uuid::Uuid::nil());
        });

        assert!(result.is_ok());
    }

    #[test]
    fn capture_unexpected_5xx_rejects_non_5xx_status() {
        let error = capture_unexpected_5xx("/api/test", "GET", 400, "req-123")
            .expect_err("non-5xx status must be rejected");
        assert!(matches!(error, AppError::BadRequest(_)));
    }
}
