# Cutover Runbook

Date: February 21, 2026

## Pre-cutover
1. Confirm latest migrations applied.
2. Run dry-run import and validation scripts.
3. Confirm rollback playbook owners are online.

## Cutover Window Steps
1. Enable maintenance mode for writes.
2. Execute export/transform/import pipeline.
3. Run validation report checks.
4. Switch traffic to Rust backend.
5. Monitor auth failures, 5xx, websocket connections, and latency for 30 minutes.

## Exit Criteria
- Critical endpoints healthy
- No high-severity auth/session anomalies
- Error and latency metrics within limits
