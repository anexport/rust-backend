use actix_governor::{governor::middleware::NoOpMiddleware, Governor, GovernorConfigBuilder};
use crate::config::SecurityConfig;

pub fn global_rate_limiting(
    security_config: &SecurityConfig,
) -> Governor<actix_governor::PeerIpKeyExtractor, NoOpMiddleware> {
    let rate_limit_per_minute = security_config.global_rate_limit_per_minute;
    if rate_limit_per_minute == 0 {
        panic!(
            "global_rate_limit_per_minute must be greater than 0, got {}",
            rate_limit_per_minute
        );
    }
    if rate_limit_per_minute > 60_000 {
        panic!(
            "global_rate_limit_per_minute must not exceed 60,000 (to allow valid per-millisecond conversion), got {}",
            rate_limit_per_minute
        );
    }

    let burst_size = security_config.global_rate_limit_burst_size;
    if burst_size == 0 {
        panic!(
            "global_rate_limit_burst_size must be greater than 0, got {}",
            burst_size
        );
    }
    if burst_size > 1000 {
        tracing::warn!(
            burst_size,
            "global_rate_limit_burst_size is unusually high; consider reducing to avoid abuse"
        );
    }

    let requests_per_millisecond = (60_000 / rate_limit_per_minute) as u64;
    let governor_config = GovernorConfigBuilder::default()
        .per_millisecond(requests_per_millisecond)
        .burst_size(burst_size)
        .finish()
        .expect("Failed to build governor config");

    Governor::new(&governor_config)
}
