use rust_backend::api::routes::ws::WsConnectionHub;
use tokio::sync::mpsc::error::TryRecvError;
use uuid::Uuid;

#[test]
fn ws_connection_hub_registers_and_prunes_users() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    // Register a receiver and drop it
    let rx = hub.register(user_id);
    drop(rx);

    // Prune should remove the closed connection
    hub.prune_user(user_id);

    // After pruning, broadcast should not deliver to any receivers
    hub.broadcast_to_users(&[user_id], "after-prune");

    // Register a new receiver and verify it works
    let mut rx2 = hub.register(user_id);
    hub.broadcast_to_users(&[user_id], "new-registration");

    // New receiver should get the message
    assert_eq!(rx2.try_recv(), Ok("new-registration".to_string()));
    // And channel should be empty after
    assert_eq!(rx2.try_recv(), Err(TryRecvError::Empty));
}

#[test]
fn ws_connection_hub_broadcasts_to_users() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    // Register 3 receivers for the same user
    let mut rx1 = hub.register(user_id);
    let mut rx2 = hub.register(user_id);
    let mut rx3 = hub.register(user_id);

    // Broadcast a message to all receivers of this user
    let payload = r#"{"type":"message","payload":{"content":"test"}}"#;
    hub.broadcast_to_users(&[user_id], payload);

    // All 3 receivers should receive the message
    assert_eq!(rx1.try_recv(), Ok(payload.to_string()));
    assert_eq!(rx2.try_recv(), Ok(payload.to_string()));
    assert_eq!(rx3.try_recv(), Ok(payload.to_string()));

    // Each receiver's channel should be empty after receiving
    assert_eq!(rx1.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(rx2.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(rx3.try_recv(), Err(TryRecvError::Empty));
}

#[test]
fn ws_connection_hub_broadcasts_only_to_target_participants() {
    let hub = WsConnectionHub::default();
    let user_a = Uuid::new_v4();
    let user_b = Uuid::new_v4();
    let user_c = Uuid::new_v4();

    let mut rx_a = hub.register(user_a);
    let mut rx_b = hub.register(user_b);
    let mut rx_c = hub.register(user_c);

    hub.broadcast_to_users(&[user_a, user_b], "participant-message");

    assert_eq!(rx_a.try_recv(), Ok("participant-message".to_string()));
    assert_eq!(rx_b.try_recv(), Ok("participant-message".to_string()));
    assert_eq!(rx_c.try_recv(), Err(TryRecvError::Empty));
}

#[test]
fn ws_connection_hub_prunes_closed_connections_during_broadcast() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    let mut rx_open = hub.register(user_id);
    let rx_closed = hub.register(user_id);
    drop(rx_closed);

    hub.broadcast_to_users(&[user_id], "first");
    assert_eq!(rx_open.try_recv(), Ok("first".to_string()));

    drop(rx_open);
    hub.prune_user(user_id);

    let mut rx_new = hub.register(user_id);
    hub.broadcast_to_users(&[user_id], "second");
    assert_eq!(rx_new.try_recv(), Ok("second".to_string()));
}

#[test]
fn ws_connection_hub_handles_concurrent_broadcasts() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    // Register a receiver for receiving broadcasts
    let mut rx = hub.register(user_id);

    // Broadcast 10 messages concurrently using std::thread
    let hub_clone = hub.clone();
    let user_id_clone = user_id;
    let handle = std::thread::spawn(move || {
        for i in 0..10 {
            hub_clone.broadcast_to_users(&[user_id_clone], &format!("message-{}", i));
        }
    });

    // Wait for all broadcasts to complete
    handle.join().expect("Thread panicked");

    // Verify we received all 10 messages (order not guaranteed)
    let mut received_messages = Vec::new();
    for _ in 0..10 {
        match rx.try_recv() {
            Ok(msg) => received_messages.push(msg),
            Err(e) => panic!("Expected 10 messages but got error: {:?}", e),
        }
    }

    // Verify channel is empty after receiving all messages
    assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));

    // Verify all expected messages were received
    assert_eq!(received_messages.len(), 10);
    for i in 0..10 {
        let expected = format!("message-{}", i);
        assert!(
            received_messages.contains(&expected),
            "Expected message '{}' not found in received messages",
            expected
        );
    }
}
