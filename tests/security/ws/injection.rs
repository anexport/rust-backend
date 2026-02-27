use rust_backend::api::routes::ws::WsSendMessagePayload;
use uuid::Uuid;

#[test]
fn xss_payload_is_properly_quoted() {
    let xss_payload = "<script>alert('xss')</script>";
    let payload = WsSendMessagePayload {
        conversation_id: Uuid::new_v4(),
        content: xss_payload.to_string(),
    };

    let json = serde_json::to_value(&payload).unwrap();
    let content = json["content"].as_str().unwrap();
    assert_eq!(content, xss_payload);

    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("alert"));
}

#[test]
fn sql_injection_payload_is_treated_as_string() {
    let sqli_payload = "'; DROP TABLE users; --";
    let payload = WsSendMessagePayload {
        conversation_id: Uuid::new_v4(),
        content: sqli_payload.to_string(),
    };

    let json = serde_json::to_value(&payload).unwrap();
    let content = json["content"].as_str().unwrap();
    assert_eq!(content, sqli_payload);

    let serialized = serde_json::to_string(&payload).unwrap();
    assert!(serialized.contains("DROP TABLE"));
}
