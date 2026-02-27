use crate::config::SecurityConfig;
use actix_governor::{governor::middleware::NoOpMiddleware, Governor, GovernorConfigBuilder};

pub fn global_rate_limiting(
    security_config: &SecurityConfig,
) -> Governor<actix_governor::PeerIpKeyExtractor, NoOpMiddleware> {
    let rate_limit_per_minute = security_config.global_rate_limit_per_minute;
    let burst_size = security_config.global_rate_limit_burst_size;

    if burst_size > 1000 {
        tracing::warn!(
            burst_size,
            "global_rate_limit_burst_size is unusually high; consider reducing to avoid abuse"
        );
    }

    let milliseconds_per_request = (60_000 / rate_limit_per_minute) as u64;
    let governor_config = GovernorConfigBuilder::default()
        .per_millisecond(milliseconds_per_request)
        .burst_size(burst_size)
        .finish()
        .expect("Failed to build governor config");

    Governor::new(&governor_config)
}
