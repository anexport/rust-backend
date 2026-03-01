use super::*;
use crate::common;
use crate::common::mocks::*;
use actix_web::{http::StatusCode, test as actix_test, web, App};
use chrono::{Duration, Utc};
use rust_backend::api::routes;
use rust_backend::domain::*;
use rust_backend::security::{cors_middleware, security_headers};
use std::sync::Arc;
use uuid::Uuid;

#[actix_rt::test]
async fn send_message_fails_for_non_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "nonparticipant-msg@example.com".to_string(),
        role: Role::Renter,
        username: Some("nonparticipant-msg".to_string()),
        full_name: Some("Non Participant Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": "Hello, world!"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn send_message_succeeds_for_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "participant-msg@example.com".to_string(),
        role: Role::Renter,
        username: Some("participant-msg".to_string()),
        full_name: Some("Participant Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": "Hello, world!"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[actix_rt::test]
async fn send_message_validates_content_length() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "validator-msg@example.com".to_string(),
        role: Role::Renter,
        username: Some("validator-msg".to_string()),
        full_name: Some("Validator Msg".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let short_request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": ""
        }))
        .to_request();
    let short_response = actix_test::call_service(&app, short_request).await;
    assert_eq!(short_response.status(), StatusCode::BAD_REQUEST);

    let long_content = "x".repeat(5001);
    let long_request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .set_json(serde_json::json!({
            "content": long_content
        }))
        .to_request();
    let long_response = actix_test::call_service(&app, long_request).await;
    assert_eq!(long_response.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn list_messages_respects_pagination() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "paginator@example.com".to_string(),
        role: Role::Renter,
        username: Some("paginator".to_string()),
        full_name: Some("Paginator".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, user_id);

    let now = Utc::now();
    for i in 0..10 {
        message_repo.add_message(Message {
            id: Uuid::new_v4(),
            conversation_id,
            sender_id: user_id,
            content: format!("Message {}", i),
            created_at: now + Duration::seconds(i),
        });
    }

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri(&format!(
            "/api/v1/conversations/{conversation_id}/messages?limit=5&offset=0"
        ))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = actix_test::read_body_json(response).await;
    let messages = body.as_array().expect("messages should be an array");
    assert_eq!(messages.len(), 5);
}

#[actix_rt::test]
async fn list_messages_fails_for_non_participant() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());

    let user_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();

    user_repo.push(User {
        id: user_id,
        email: "nonparticipant-list@example.com".to_string(),
        role: Role::Renter,
        username: Some("nonparticipant-list".to_string()),
        full_name: Some("Non Participant List".to_string()),
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });

    let conversation_id = Uuid::new_v4();
    message_repo.add_conversation(Conversation {
        id: conversation_id,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    });
    message_repo.add_participant(conversation_id, other_id);

    let (state, auth0_config_data, jwks_client, provisioning_service) =
        app_with_auth0_data_and_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(state)
            .app_data(auth0_config_data)
            .app_data(jwks_client)
            .app_data(provisioning_service)
            .configure(routes::configure),
    )
    .await;

    let token = create_auth0_token(user_id, "renter");

    let request = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn send_message_requires_authentication() {
    let user_repo = Arc::new(MockUserRepo::default());
    let equipment_repo = Arc::new(MockEquipmentRepo::default());
    let message_repo = Arc::new(MockMessageRepo::default());
    let state = app_state_with_message_repo(user_repo.clone(), equipment_repo, message_repo);

    let app = actix_test::init_service(
        App::new()
            .wrap(cors_middleware(&security_config()))
            .wrap(security_headers())
            .app_data(web::Data::new(common::test_auth_config()))
            .app_data(web::Data::new(state))
            .configure(routes::configure),
    )
    .await;

    let conversation_id = Uuid::new_v4();

    let request = actix_test::TestRequest::post()
        .uri(&format!("/api/v1/conversations/{conversation_id}/messages"))
        .set_json(serde_json::json!({
            "content": "Hello, world!"
        }))
        .to_request();
    let response = actix_test::call_service(&app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
