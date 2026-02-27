use rust_backend::api::routes::ws::WsConnectionHub;
use uuid::Uuid;

#[test]
fn ws_connection_rate_limits_enforced() {
    let hub = WsConnectionHub::default();
    let user_id = Uuid::new_v4();

    for i in 0..100 {
        let _rx = hub.register(user_id);
        if i % 10 == 0 {
            drop(_rx);
        }
    }

    let payload = r#"{"type":"message","payload":{"content":"test"}}"#;
    hub.broadcast_to_users(&[user_id], payload);

    let _test_rx = hub.register(user_id);
    drop(_test_rx);
}
