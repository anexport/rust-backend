use super::*;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test, App};
use rust_backend::api::routes;
use rust_backend::domain::Role;
use rust_backend::infrastructure::repositories::{
    CategoryRepositoryImpl, EquipmentRepositoryImpl, UserRepositoryImpl,
};
use uuid::Uuid;

#[actix_rt::test]
async fn update_equipment_401_unauthorized() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool);

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[actix_rt::test]
async fn update_equipment_403_forbidden() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let equipment_repo = EquipmentRepositoryImpl::new(pool.clone());
    let category_repo = CategoryRepositoryImpl::new(pool.clone());

    let cat = common::fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();
    user_repo
        .create(&test_user(other_id, Role::Owner, "other@e.c"))
        .await
        .unwrap();

    let mut eq = test_equipment(Uuid::new_v4(), owner_id);
    eq.category_id = cat.id;
    equipment_repo.create(&eq).await.unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn update_equipment_404_not_found() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let owner_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::put()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(serde_json::json!({"title": "New Title"}))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[actix_rt::test]
async fn delete_equipment_403_forbidden() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let equipment_repo = EquipmentRepositoryImpl::new(pool.clone());
    let category_repo = CategoryRepositoryImpl::new(pool.clone());

    let cat = common::fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    let owner_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();
    user_repo
        .create(&test_user(other_id, Role::Owner, "other@e.c"))
        .await
        .unwrap();

    let mut eq = test_equipment(Uuid::new_v4(), owner_id);
    eq.category_id = cat.id;
    equipment_repo.create(&eq).await.unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(other_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}", eq.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn delete_equipment_404_not_found() {
    let test_db = common::setup_test_db().await;
    let pool = test_db.pool().clone();
    let (state, auth0_config, jwks, provisioning) = app_with_auth0_data(pool.clone());

    let user_repo = UserRepositoryImpl::new(pool.clone());
    let owner_id = Uuid::new_v4();
    user_repo
        .create(&test_user(owner_id, Role::Owner, "o@e.c"))
        .await
        .unwrap();

    let app = actix_test::init_service(
        App::new()
            .app_data(state)
            .app_data(auth0_config)
            .app_data(jwks)
            .app_data(provisioning)
            .configure(routes::configure),
    )
    .await;
    let token = create_auth0_token(owner_id, "owner");
    let req = actix_test::TestRequest::delete()
        .uri(&format!("/api/v1/equipment/{}", Uuid::new_v4()))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
