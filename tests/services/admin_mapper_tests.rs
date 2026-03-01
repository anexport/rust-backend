use chrono::Utc;
use rust_backend::api::dtos::AdminCategoryResponse;
use rust_backend::application::{
    map_category, map_user_detail, normalize_pagination, parse_optional_role, parse_role,
};
use rust_backend::domain::{Category, Role, User};
use rust_backend::error::AppError;
use uuid::Uuid;

fn test_category(id: Uuid, name: &str, parent_id: Option<Uuid>) -> Category {
    Category {
        id,
        name: name.to_string(),
        parent_id,
        created_at: Utc::now(),
    }
}

fn test_user(id: Uuid, role: Role) -> User {
    User {
        id,
        email: format!("user-{}@example.com", id),
        role,
        username: Some(format!("user-{}", id)),
        full_name: Some("Test User".to_string()),
        avatar_url: Some("https://example.com/avatar.jpg".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

// normalize_pagination tests

#[test]
fn normalize_pagination_clamps_page_to_minimum() {
    let (page, per_page, offset) = normalize_pagination(0, 20);
    assert_eq!(page, 1);
    assert_eq!(per_page, 20);
    assert_eq!(offset, 0);
}

#[test]
fn normalize_pagination_clamps_page_to_negative() {
    let (page, per_page, offset) = normalize_pagination(-5, 20);
    assert_eq!(page, 1);
    assert_eq!(per_page, 20);
    assert_eq!(offset, 0);
}

#[test]
fn normalize_pagination_keeps_page_valid() {
    let (page, per_page, offset) = normalize_pagination(5, 20);
    assert_eq!(page, 5);
    assert_eq!(per_page, 20);
    assert_eq!(offset, 80); // (5-1)*20 = 80
}

#[test]
fn normalize_pagination_clamps_per_page_minimum() {
    let (page, per_page, offset) = normalize_pagination(1, 0);
    assert_eq!(page, 1);
    assert_eq!(per_page, 1);
    assert_eq!(offset, 0);
}

#[test]
fn normalize_pagination_clamps_per_page_negative() {
    let (page, per_page, offset) = normalize_pagination(1, -10);
    assert_eq!(page, 1);
    assert_eq!(per_page, 1);
    assert_eq!(offset, 0);
}

#[test]
fn normalize_pagination_clamps_per_page_maximum() {
    let (page, per_page, offset) = normalize_pagination(1, 200);
    assert_eq!(page, 1);
    assert_eq!(per_page, 100);
    assert_eq!(offset, 0);
}

#[test]
fn normalize_pagination_calculates_offset_correctly() {
    let test_cases = vec![(1, 10, 0), (2, 10, 10), (3, 25, 50), (10, 5, 45)];

    for (page, per_page, expected_offset) in test_cases {
        let (_, _, offset) = normalize_pagination(page, per_page);
        assert_eq!(offset, expected_offset);
    }
}

#[test]
fn normalize_pagination_saturates_on_overflow() {
    // When page * per_page would overflow, it should saturate
    let (page, per_page, offset) = normalize_pagination(i64::MAX, 10);
    assert_eq!(page, i64::MAX);
    assert_eq!(per_page, 10);
    assert!(offset >= 0); // Should not panic/overflow
}

// parse_role tests

#[test]
fn parse_role_accepts_renter() {
    let result = parse_role("renter").unwrap();
    assert_eq!(result, Role::Renter);
}

#[test]
fn parse_role_accepts_owner() {
    let result = parse_role("owner").unwrap();
    assert_eq!(result, Role::Owner);
}

#[test]
fn parse_role_accepts_admin() {
    let result = parse_role("admin").unwrap();
    assert_eq!(result, Role::Admin);
}

#[test]
fn parse_role_handles_uppercase() {
    let result = parse_role("ADMIN").unwrap();
    assert_eq!(result, Role::Admin);
}

#[test]
fn parse_role_handles_mixed_case() {
    let result = parse_role("Owner").unwrap();
    assert_eq!(result, Role::Owner);
}

#[test]
fn parse_role_trims_whitespace() {
    let result = parse_role("  renter  ").unwrap();
    assert_eq!(result, Role::Renter);
}

#[test]
fn parse_role_rejects_invalid_role() {
    let result = parse_role("invalid");
    assert!(matches!(result, Err(AppError::BadRequest(_))));
    if let Err(AppError::BadRequest(msg)) = result {
        assert!(msg.contains("Role must be one of"));
        assert!(msg.contains("renter"));
        assert!(msg.contains("owner"));
        assert!(msg.contains("admin"));
    }
}

#[test]
fn parse_role_rejects_empty_string() {
    let result = parse_role("");
    assert!(matches!(result, Err(AppError::BadRequest(_))));
}

#[test]
fn parse_role_rejects_whitespace_only() {
    let result = parse_role("   ");
    assert!(matches!(result, Err(AppError::BadRequest(_))));
}

// parse_optional_role tests

#[test]
fn parse_optional_role_accepts_some_valid() {
    let result = parse_optional_role(Some("owner")).unwrap();
    assert_eq!(result, Some(Role::Owner));
}

#[test]
fn parse_optional_role_accepts_none() {
    let result = parse_optional_role(None).unwrap();
    assert_eq!(result, None);
}

#[test]
fn parse_optional_role_rejects_some_invalid() {
    let result = parse_optional_role(Some("invalid"));
    assert!(matches!(result, Err(AppError::BadRequest(_))));
}

#[test]
fn parse_optional_role_handles_whitespace() {
    let result = parse_optional_role(Some("  admin  ")).unwrap();
    assert_eq!(result, Some(Role::Admin));
}

// map_category tests

#[test]
fn map_category_maps_all_fields() {
    let id = Uuid::new_v4();
    let parent_id = Some(Uuid::new_v4());

    let category = test_category(id, "Audio", parent_id);
    let created_at = category.created_at;

    let response: AdminCategoryResponse = map_category(category);

    assert_eq!(response.id, id);
    assert_eq!(response.name, "Audio");
    assert_eq!(response.parent_id, parent_id);
    assert_eq!(response.created_at, created_at);
}

#[test]
fn map_category_handles_none_parent() {
    let id = Uuid::new_v4();
    let category = test_category(id, "Root Category", None);

    let response: AdminCategoryResponse = map_category(category);

    assert_eq!(response.id, id);
    assert_eq!(response.name, "Root Category");
    assert_eq!(response.parent_id, None);
}

// map_user_detail tests

#[test]
fn map_user_detail_maps_all_fields() {
    let id = Uuid::new_v4();
    let user = test_user(id, Role::Admin);
    let equipment_count = 5_i64;

    let response = map_user_detail(user.clone(), equipment_count);

    assert_eq!(response.id, id);
    assert_eq!(response.email, user.email);
    assert_eq!(response.role, "admin");
    assert_eq!(response.username, user.username);
    assert_eq!(response.full_name, user.full_name);
    assert_eq!(response.avatar_url, user.avatar_url);
    assert_eq!(response.created_at, user.created_at);
    assert_eq!(response.updated_at, user.updated_at);
    assert_eq!(response.equipment_count, equipment_count);
}

#[test]
fn map_user_detail_handles_zero_equipment_count() {
    let user = test_user(Uuid::new_v4(), Role::Renter);

    let response = map_user_detail(user.clone(), 0);

    assert_eq!(response.equipment_count, 0);
}

#[test]
fn map_user_detail_role_string_conversion() {
    assert_eq!(
        map_user_detail(test_user(Uuid::new_v4(), Role::Renter), 0).role,
        "renter"
    );
    assert_eq!(
        map_user_detail(test_user(Uuid::new_v4(), Role::Owner), 0).role,
        "owner"
    );
    assert_eq!(
        map_user_detail(test_user(Uuid::new_v4(), Role::Admin), 0).role,
        "admin"
    );
}

#[test]
fn map_user_detail_handles_optional_fields() {
    let id = Uuid::new_v4();
    let user = User {
        id,
        email: "minimal@example.com".to_string(),
        role: Role::Renter,
        username: None,
        full_name: None,
        avatar_url: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let response = map_user_detail(user, 0);

    assert_eq!(response.username, None);
    assert_eq!(response.full_name, None);
    assert_eq!(response.avatar_url, None);
}
