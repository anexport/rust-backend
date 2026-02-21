# WebSocket Reconnect and Missed-Message Contract

## Transport Model

- Delivery is at-most-once per active socket.
- Messages are persisted before broadcast.
- If the client disconnects, missed messages must be recovered via REST.

## Reconnect Procedure

1. Reconnect to `WS /ws` with a valid JWT.
2. On successful socket open, fetch missed messages:
   - `GET /api/conversations/:id/messages?limit=50&offset=0`
3. Merge REST messages into local store using `message.id` deduplication.
4. Resume live WS processing.

## Client Tracking Requirements

- Persist `last_seen_message_id` per conversation.
- Persist `last_seen_message_created_at` per conversation.
- On reconnect, request most recent page(s) until `last_seen_message_id` is found.
- If not found within retention window, perform full conversation backfill.

## Event Handling

- `type=message`: append if unseen.
- `type=typing`: transient UI state only; never persist.
- `type=read`: update read cursor for sender in conversation state.
- `type=error`: log and continue unless socket closes.

## Failure Modes

- JWT expired or invalid: refresh session and reconnect.
- 90s heartbeat timeout: close socket and reconnect with backoff.
- Network churn: exponential reconnect backoff (`1s, 2s, 4s, ...`, cap 30s).

## Consistency Rule

REST is source-of-truth after reconnect. WS is source-of-truth only while connected.
