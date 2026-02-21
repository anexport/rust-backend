# Observability Setup

This directory contains baseline observability assets for staging/production.

## Files

- `prometheus-scrape.yml`: Prometheus scrape job for `/metrics`.
- `alert-rules.yml`: Prometheus alert rules for 5xx rate, auth spikes, latency, and WS drops.
- `grafana-dashboard-rust-backend.json`: Importable dashboard for core backend SLO signals.
- `promtail-config.yml`: Promtail pipeline to ship backend logs to Loki.

## Rollout Steps

1. Configure `METRICS_ADMIN_TOKEN` in Prometheus runtime environment.
2. Mount `prometheus-scrape.yml` and `alert-rules.yml` into Prometheus.
3. Import `grafana-dashboard-rust-backend.json` into Grafana.
4. Deploy Promtail with `promtail-config.yml` on backend hosts.
5. Run a smoke test: hit `/health`, `/ready`, `/metrics`, login endpoint, and WS connect.

## Smoke-Test Queries

- Request rate: `sum(rate(http_requests_total[5m]))`
- 5xx rate: `sum(rate(http_requests_total{status=~"5.."}[5m]))`
- Auth failure rate: `rate(auth_failures_total[5m])`
- WS connections: `ws_connections`
