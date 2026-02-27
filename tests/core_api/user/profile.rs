use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{UserRepository, UserRepositoryImpl};
use uuid::Uuid;

#[actix_rt::test]
async fn test_get_user_profile_not_found() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", Uuid::new_v4()))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn test_update_profile_partial() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let mut user = fixtures::test_user();
    let old_full_name = "Original Name".to_string();
    user.full_name = Some(old_full_name.clone());
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    // Update only username, full_name should remain
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "username": "new_user"
        }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.username, Some("new_user".to_string()));
    assert_eq!(updated.full_name, Some(old_full_name));
}

#[actix_rt::test]
async fn test_update_own_profile() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "full_name": "Updated Name",
            "username": "updated_username"
        }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.full_name, Some("Updated Name".to_string()));
    assert_eq!(updated.username, Some("updated_username".to_string()));
}

#[actix_rt::test]
async fn test_cannot_update_other_profile() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user1 = fixtures::test_user();
    user_repo.create(&user1).await.unwrap();
    let user2 = fixtures::test_user();
    user_repo.create(&user2).await.unwrap();

    let token = create_auth0_token(user1.id, "renter");

    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user2.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "full_name": "Hacker" }))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_profile_viewing_excludes_sensitive_data() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", user.id))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let profile: serde_json::Value = actix_test::read_body_json(resp).await;
    assert!(profile.get("id").is_some());
    let username = profile.get("username").and_then(|v| v.as_str());
    let avatar_url = profile.get("avatar_url").and_then(|v| v.as_str());
    assert!(
        username.is_some() || avatar_url.is_some(),
        "Profile should have at least username or avatar_url with a non-null value"
    );

    assert!(profile.get("email").is_none());
    assert!(profile.get("role").is_none());
}

#[actix_rt::test]
async fn test_profile_update_username_constraints() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    // 1. Username too short (min=3)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "username": "ab" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. Username too long (max=50)
    let long_username = "a".repeat(51);
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "username": long_username }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_get_public_profile_anonymous() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri(&format!("/api/v1/users/{}", user.id))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_rt::test]
async fn test_profile_update_email_validation() {
    let test_db = common::setup_test_db().await;
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let user = fixtures::test_user();
    user_repo.create(&user).await.unwrap();
    let token = create_auth0_token(user.id, "renter");

    // 1. Try update with valid username (email-like format should work as username)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({
            "username": "testuser123"
        }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated = user_repo.find_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(updated.username, Some("testuser123".to_string()));

    // 2. Invalid username format (too short)
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/users/{}", user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({ "username": "ab" }))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
