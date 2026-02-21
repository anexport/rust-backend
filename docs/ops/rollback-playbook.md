# Rollback Playbook

Date: February 21, 2026

## Trigger Conditions
- Elevated 5xx rates post-cutover
- Authentication/session failures above threshold
- Data integrity mismatch in production validation

## Steps
1. Stop write traffic to the Rust backend.
2. Re-point traffic to previous stable app release.
3. Restore previous DB snapshot / PITR target if data corruption detected.
4. Verify auth, equipment CRUD, messaging, and websocket connectivity.
5. Publish incident status update and next checkpoint.

## Owners
- Rollback Commander: Platform On-call
- DB Rollback Owner: Database On-call
- App Rollback Owner: Backend On-call
