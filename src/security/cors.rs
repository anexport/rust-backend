use crate::config::SecurityConfig;
use actix_cors::Cors;

pub fn cors_middleware(config: &SecurityConfig) -> Cors {
    let allowlist = config.cors_allowed_origins.clone();

    Cors::default()
        .supports_credentials()
        .allow_any_header()
        .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
        .allowed_origin_fn(move |origin, _| {
            origin
                .to_str()
                .ok()
                .map(|value| allowlist.iter().any(|allowed| allowed == value))
                .unwrap_or(false)
        })
}
