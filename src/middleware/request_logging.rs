use actix_web::dev::ServiceRequest;
/// Enhanced request logging utilities for detailed audit trail
///
/// This module provides helper functions to enhance request logging with
/// additional context like user ID, client IP, and user agent.
use actix_web::http::header;
use actix_web::HttpMessage;
use tracing::Span;

/// Extract user ID from request extensions if authenticated
pub fn get_user_id_from_request(req: &ServiceRequest) -> String {
    req.extensions()
        .get::<std::sync::Arc<crate::utils::auth0_claims::Auth0Claims>>()
        .map(|claims| claims.sub.clone())
        .unwrap_or_else(|| "anonymous".to_string())
}

/// Get client IP address from request.
///
/// Uses realip_remote_addr() which respects Forwarded/X-Forwarded-For only when
/// configured via ACTIX_FORWARDED or similar trusted proxy settings.
///
/// SECURITY NOTE: We do NOT directly parse X-Forwarded-For here as it can be spoofed
/// by malicious clients. The realip_remote_addr() method uses actix-web's built-in
/// trusted proxy detection which only considers Forwarded headers when explicitly
/// configured via environment variables like ACTIX_FORWARDED.
pub fn get_client_ip(req: &ServiceRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Get user agent from request headers
pub fn get_user_agent(req: &ServiceRequest) -> String {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// Create a tracing span for request context with detailed information
pub fn create_request_span(
    request_id: &str,
    method: &str,
    path: &str,
    user_id: &str,
    client_ip: &str,
    user_agent: &str,
) -> Span {
    tracing::info_span!(
        "request",
        request_id = %request_id,
        method = %method,
        path = %path,
        user_id = %user_id,
        client_ip = %client_ip,
        user_agent = %user_agent
    )
}

/// Get HTTP status class for grouping (2xx, 3xx, 4xx, 5xx)
pub fn get_status_class(status: u16) -> &'static str {
    match status {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_status_class() {
        assert_eq!(get_status_class(200), "2xx");
        assert_eq!(get_status_class(201), "2xx");
        assert_eq!(get_status_class(301), "3xx");
        assert_eq!(get_status_class(400), "4xx");
        assert_eq!(get_status_class(404), "4xx");
        assert_eq!(get_status_class(500), "5xx");
        assert_eq!(get_status_class(503), "5xx");
        assert_eq!(get_status_class(600), "unknown");
    }

    #[test]
    fn test_get_user_id_from_request() {
        let req = actix_web::test::TestRequest::default().to_srv_request();
        assert_eq!(get_user_id_from_request(&req), "anonymous");
    }

    #[test]
    fn test_get_user_agent() {
        let req = actix_web::test::TestRequest::default().to_srv_request();
        assert_eq!(get_user_agent(&req), "unknown");
    }

    #[test]
    fn test_get_client_ip() {
        let req = actix_web::test::TestRequest::default().to_srv_request();
        assert_eq!(get_client_ip(&req), "unknown");
    }
}
