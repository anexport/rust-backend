# On-call Runbook

Date: February 21, 2026

## Auth Outage
1. Check `/health`, `/ready`, and auth failure counters.
2. Verify JWT key configuration and key-ring values.
3. Validate DB connectivity for sessions table.
4. Roll back to last stable release if unresolved in 15 minutes.

## DB Outage
1. Confirm pool exhaustion and DB reachability.
2. Fail over to standby / restore as needed.
3. Keep `/ready` failing until DB is healthy.

## WebSocket Degradation
1. Check connection count and heartbeat timeouts.
2. Verify auth on upgrade errors.
3. Force reconnect guidance: recover missed messages via REST endpoint.
