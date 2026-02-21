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
