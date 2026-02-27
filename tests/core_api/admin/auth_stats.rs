use super::setup_app;
use crate::common;
use actix_web::{http::StatusCode, test as actix_test};
use common::auth0_test_helpers::create_auth0_token;
use common::fixtures;
use common::TestDb;
use rust_backend::infrastructure::repositories::{
    CategoryRepository, CategoryRepositoryImpl, EquipmentRepository, EquipmentRepositoryImpl,
    UserRepository, UserRepositoryImpl,
};

#[actix_rt::test]
async fn test_admin_stats_authorization() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;

    // 1. Unauthenticated (401)
    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/stats")
        .to_request();
    let resp = actix_test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Authenticated as Renter (403)
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let renter = fixtures::test_user();
    user_repo.create(&renter).await.unwrap();
    let token = create_auth0_token(renter.id, "renter");

    let routes = vec![
        "/api/v1/admin/stats",
        "/api/v1/admin/users",
        "/api/v1/admin/equipment",
        "/api/v1/admin/categories",
    ];

    for route in routes {
        let req = actix_test::TestRequest::get()
            .uri(route)
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();
        let resp = actix_test::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Route {} should be forbidden for renter",
            route
        );
    }
}

#[actix_rt::test]
async fn test_get_stats_empty_db() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/stats")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    let stats: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(stats["total_users"], 1); // Only admin
    assert_eq!(stats["total_equipment"], 0);
    assert_eq!(stats["total_categories"], 0);
}

#[actix_rt::test]
async fn test_stats_includes_available_equipment_count() {
    let Some(test_db) = TestDb::new().await else {
        return;
    };
    let app = setup_app(test_db.pool().clone()).await;
    let user_repo = UserRepositoryImpl::new(test_db.pool().clone());
    let equipment_repo = rust_backend::infrastructure::repositories::EquipmentRepositoryImpl::new(
        test_db.pool().clone(),
    );
    let category_repo = rust_backend::infrastructure::repositories::CategoryRepositoryImpl::new(
        test_db.pool().clone(),
    );

    let admin = fixtures::test_admin();
    user_repo.create(&admin).await.unwrap();
    let token = create_auth0_token(admin.id, "admin");

    let owner = fixtures::test_owner();
    user_repo.create(&owner).await.unwrap();
    let cat = fixtures::test_category();
    category_repo.create(&cat).await.unwrap();

    // 2 available, 1 not
    let mut eq1 = fixtures::test_equipment(owner.id, cat.id);
    eq1.is_available = true;
    equipment_repo.create(&eq1).await.unwrap();

    let mut eq2 = fixtures::test_equipment(owner.id, cat.id);
    eq2.is_available = true;
    equipment_repo.create(&eq2).await.unwrap();

    let mut eq3 = fixtures::test_equipment(owner.id, cat.id);
    eq3.is_available = false;
    equipment_repo.create(&eq3).await.unwrap();

    let req = actix_test::TestRequest::get()
        .uri("/api/v1/admin/stats")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = actix_test::call_service(&app, req).await;
    let stats: serde_json::Value = actix_test::read_body_json(resp).await;
    assert_eq!(stats["total_equipment"], 3);
    assert_eq!(stats["available_equipment"], 2);
}
