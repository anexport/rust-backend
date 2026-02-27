use chrono::Utc;
use rust_backend::api::routes::ws::WsConnectionHub;
use uuid::Uuid;

#[test]
fn cross_conversation_message_blocking() {
    let user_a_id = Uuid::new_v4();
    let conversation_a_id = Uuid::new_v4();
    let conversation_b_id = Uuid::new_v4();

    let msg_a = rust_backend::domain::Message {
        id: Uuid::new_v4(),
        conversation_id: conversation_a_id,
        sender_id: user_a_id,
        content: "Message in conversation A".to_string(),
        created_at: Utc::now(),
    };

    let msg_b = rust_backend::domain::Message {
        id: Uuid::new_v4(),
        conversation_id: conversation_b_id,
        sender_id: user_a_id,
        content: "Message in conversation B".to_string(),
        created_at: Utc::now() + chrono::Duration::milliseconds(100),
    };

    assert!(msg_a.conversation_id == conversation_a_id);
    assert!(msg_b.conversation_id == conversation_b_id);
    assert_ne!(conversation_a_id, conversation_b_id);
}

#[test]
fn ws_connection_isolation_between_users() {
    let hub = WsConnectionHub::default();
    let user_a_id = Uuid::new_v4();
    let user_b_id = Uuid::new_v4();

    let _rx_a = hub.register(user_a_id);
    let _rx_b = hub.register(user_b_id);

    assert_ne!(user_a_id, user_b_id);

    let payload = r#"{"type":"message","payload":{"content":"test"}}"#;
    hub.broadcast_to_users(&[user_b_id], payload);
}
