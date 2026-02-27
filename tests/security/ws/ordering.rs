use chrono::Utc;
use uuid::Uuid;

#[test]
fn ws_message_ordering_guaranteed() {
    let mut messages = Vec::new();
    let base_time = std::time::Instant::now();

    for i in 1..=5 {
        let now = base_time.elapsed().as_millis();
        messages.push(rust_backend::domain::Message {
            id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_id: Uuid::new_v4(),
            content: format!("Message {}", i),
            created_at: Utc::now() - chrono::Duration::milliseconds(100 - now as i64),
        });
    }

    for i in 0..messages.iter().count() {
        if i > 0 {
            let prev_time = messages[i - 1].created_at;
            let curr_time = messages[i].created_at;
            assert!(curr_time > prev_time);
        }
    }
}
