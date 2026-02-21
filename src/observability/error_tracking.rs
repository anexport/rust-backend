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
