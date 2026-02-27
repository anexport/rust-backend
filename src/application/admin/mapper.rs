use crate::api::dtos::{AdminCategoryResponse, AdminUserDetailResponse};
use crate::domain::{Category, Role, User};
use crate::error::{AppError, AppResult};

pub fn normalize_pagination(page: i64, per_page: i64) -> (i64, i64, i64) {
    let page = page.max(1);
    let per_page = per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;
    (page, per_page, offset)
}

pub fn parse_role(input: &str) -> AppResult<Role> {
    match input.trim().to_ascii_lowercase().as_str() {
        "renter" => Ok(Role::Renter),
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        _ => Err(AppError::BadRequest(
            "Role must be one of: renter, owner, admin".to_string(),
        )),
    }
}

pub fn parse_optional_role(input: Option<&str>) -> AppResult<Option<Role>> {
    input.map(parse_role).transpose()
}

pub fn map_category(category: Category) -> AdminCategoryResponse {
    AdminCategoryResponse {
        id: category.id,
        name: category.name,
        parent_id: category.parent_id,
        created_at: category.created_at,
    }
}

pub fn map_user_detail(user: User, equipment_count: i64) -> AdminUserDetailResponse {
    AdminUserDetailResponse {
        id: user.id,
        email: user.email,
        role: user.role.to_string(),
        username: user.username,
        full_name: user.full_name,
        avatar_url: user.avatar_url,
        created_at: user.created_at,
        updated_at: user.updated_at,
        equipment_count,
    }
}
