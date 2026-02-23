pub mod error_tracking;

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct AppMetrics {
    request_count: AtomicU64,
    error_count: AtomicU64,
    auth_failure_count: AtomicU64,
    ws_connections: AtomicU64,
    latency_total_ms: AtomicU64,
    latency_count: AtomicU64,
}

impl AppMetrics {
    pub fn record_request(&self, status: u16, latency_ms: u64) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
        if status >= 500 {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_total_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_auth_failure(&self) {
        self.auth_failure_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ws_connected(&self) {
        self.ws_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ws_disconnected(&self) {
        self.ws_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self, db_size: u32, db_idle: usize) -> String {
        let count = self.request_count.load(Ordering::Relaxed).max(1);
        let avg_latency = self.latency_total_ms.load(Ordering::Relaxed) as f64 / count as f64;

        format!(
            concat!(
                "# TYPE http_requests_total counter\n",
                "http_requests_total {}\n",
                "# TYPE http_error_total counter\n",
                "http_error_total {}\n",
                "# TYPE auth_failures_total counter\n",
                "auth_failures_total {}\n",
                "# TYPE ws_connections gauge\n",
                "ws_connections {}\n",
                "# TYPE http_latency_avg_ms gauge\n",
                "http_latency_avg_ms {:.2}\n",
                "# TYPE db_pool_size gauge\n",
                "db_pool_size {}\n",
                "# TYPE db_pool_idle gauge\n",
                "db_pool_idle {}\n",
            ),
            self.request_count.load(Ordering::Relaxed),
            self.error_count.load(Ordering::Relaxed),
            self.auth_failure_count.load(Ordering::Relaxed),
            self.ws_connections.load(Ordering::Relaxed),
            avg_latency,
            db_size,
            db_idle,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::AppMetrics;

    #[test]
    fn record_request_increments_request_count() {
        let metrics = AppMetrics::default();

        metrics.record_request(200, 25);

        let rendered = metrics.render_prometheus(0, 0);
        assert!(rendered.contains("http_requests_total 1"));
    }

    #[test]
    fn record_request_5xx_increments_error_count() {
        let metrics = AppMetrics::default();

        metrics.record_request(503, 12);

        let rendered = metrics.render_prometheus(0, 0);
        assert!(rendered.contains("http_error_total 1"));
    }

    #[test]
    fn record_auth_failure_increments_counter() {
        let metrics = AppMetrics::default();

        metrics.record_auth_failure();

        let rendered = metrics.render_prometheus(0, 0);
        assert!(rendered.contains("auth_failures_total 1"));
    }

    #[test]
    fn ws_connected_and_disconnected_update_gauge() {
        let metrics = AppMetrics::default();

        metrics.ws_connected();
        metrics.ws_connected();
        metrics.ws_disconnected();

        let rendered = metrics.render_prometheus(0, 0);
        assert!(rendered.contains("ws_connections 1"));
    }

    #[test]
    fn render_prometheus_includes_all_metrics_with_expected_values() {
        let metrics = AppMetrics::default();

        metrics.record_request(200, 20);
        metrics.record_request(503, 40);
        metrics.record_auth_failure();
        metrics.record_auth_failure();
        metrics.ws_connected();

        let rendered = metrics.render_prometheus(8, 3);

        assert!(rendered.contains("# TYPE http_requests_total counter"));
        assert!(rendered.contains("http_requests_total 2"));
        assert!(rendered.contains("# TYPE http_error_total counter"));
        assert!(rendered.contains("http_error_total 1"));
        assert!(rendered.contains("# TYPE auth_failures_total counter"));
        assert!(rendered.contains("auth_failures_total 2"));
        assert!(rendered.contains("# TYPE ws_connections gauge"));
        assert!(rendered.contains("ws_connections 1"));
        assert!(rendered.contains("# TYPE http_latency_avg_ms gauge"));
        assert!(rendered.contains("http_latency_avg_ms 30.00"));
        assert!(rendered.contains("# TYPE db_pool_size gauge"));
        assert!(rendered.contains("db_pool_size 8"));
        assert!(rendered.contains("# TYPE db_pool_idle gauge"));
        assert!(rendered.contains("db_pool_idle 3"));
    }
}
