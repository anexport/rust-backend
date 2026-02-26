use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::fmt;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Deserialize)]
pub struct AdminListQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub search: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AdminStatsResponse {
    pub total_users: i64,
    pub total_equipment: i64,
    pub available_equipment: i64,
    pub total_categories: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AdminUserRow {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub equipment_count: i64,
}

impl fmt::Debug for AdminUserRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminUserRow")
            .field("id", &self.id)
            .field("email", &"[REDACTED]")
            .field("role", &self.role)
            .field("username", &self.username)
            .field("full_name", &self.full_name.as_ref().map(|_| "[REDACTED]"))
            .field("created_at", &self.created_at)
            .field("equipment_count", &self.equipment_count)
            .finish()
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminUserListResponse {
    pub users: Vec<AdminUserRow>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AdminUserDetailResponse {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub username: Option<String>,
    pub full_name: Option<String>,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub equipment_count: i64,
}

impl fmt::Debug for AdminUserDetailResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminUserDetailResponse")
            .field("id", &self.id)
            .field("email", &"[REDACTED]")
            .field("role", &self.role)
            .field("username", &self.username)
            .field("full_name", &self.full_name.as_ref().map(|_| "[REDACTED]"))
            .field(
                "avatar_url",
                &self.avatar_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("equipment_count", &self.equipment_count)
            .finish()
    }
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminUpdateRoleRequest {
    #[validate(length(min = 1, message = "Role is required"))]
    pub role: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminEquipmentRow {
    pub id: Uuid,
    pub title: String,
    pub owner_email: String,
    pub category_name: String,
    pub daily_rate: Decimal,
    pub is_available: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminEquipmentListResponse {
    pub equipment: Vec<AdminEquipmentRow>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
}

#[derive(Debug, Deserialize)]
pub struct AdminUpdateAvailabilityRequest {
    pub is_available: bool,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AdminCategoryRequest {
    #[validate(length(
        min = 2,
        max = 100,
        message = "Category name must be between 2 and 100 characters"
    ))]
    pub name: String,
    pub parent_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct AdminCategoryResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::AdminUserDetailResponse;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn admin_user_detail_debug_redacts_pii_fields() {
        let response = AdminUserDetailResponse {
            id: Uuid::new_v4(),
            email: "admin@example.com".to_string(),
            role: "admin".to_string(),
            username: Some("admin_user".to_string()),
            full_name: Some("Admin User".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            equipment_count: 3,
        };

        let debug_output = format!("{response:?}");
        assert!(!debug_output.contains("admin@example.com"));
        assert!(!debug_output.contains("Admin User"));
        assert!(!debug_output.contains("avatar.png"));
        assert!(debug_output.contains("[REDACTED]"));
    }
}
