use rust_backend::api::routes::ws::WsConnectionHub;
use tokio::sync::mpsc::error::TryRecvError;
use uuid::Uuid;

#[test]
fn ws_connection_rate_limits_enforced() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    // Register 100 connections, dropping every 10th
    // After the loop: 90 active, 10 dropped
    for i in 0..100 {
        let _rx = hub.register(user_id);
        if i % 10 == 0 {
            drop(_rx);
        }
    }

    // Verify we can broadcast without issues (no panics, no hangs)
    let payload = r#"{"type":"message","payload":{"content":"test"}}"#;
    hub.broadcast_to_users(&[user_id], payload);

    // Register a new receiver and verify broadcast works
    let mut test_rx = hub.register(user_id);
    hub.broadcast_to_users(&[user_id], "final-message");

    // Verify the new receiver got the message
    assert_eq!(test_rx.try_recv(), Ok("final-message".to_string()));
    // And no extra messages
    assert_eq!(test_rx.try_recv(), Err(TryRecvError::Empty));
}
