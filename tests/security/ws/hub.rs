use rust_backend::api::routes::ws::WsConnectionHub;
use tokio::sync::mpsc::error::TryRecvError;
use uuid::Uuid;

#[test]
fn ws_connection_hub_registers_and_prunes_users() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    let _rx = hub.register(user_id);
    hub.prune_user(user_id);
    let _rx2 = hub.register(user_id);
}

#[test]
fn ws_connection_hub_broadcasts_to_users() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    let _rx1 = hub.register(user_id);
    let _rx2 = hub.register(user_id);
    let _rx3 = hub.register(user_id);

    let payload = r#"{"type":"message","payload":{"content":"test"}}"#;
    hub.broadcast_to_users(&[user_id], payload);
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

    let _rx = hub.register(user_id);
    drop(_rx);

    let payload = r#"{"type":"message","payload":{"content":"test"}}"#;
    hub.broadcast_to_users(&[user_id], payload);
}
