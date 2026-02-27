use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::CategoryRepository;
use uuid::Uuid;

pub async fn validate_category_parent(
    category_repo: &dyn CategoryRepository,
    category_id: Option<Uuid>,
    parent_id: Option<Uuid>,
) -> AppResult<()> {
    let Some(mut cursor) = parent_id else {
        return Ok(());
    };

    if Some(cursor) == category_id {
        return Err(AppError::BadRequest(
            "category cannot be its own parent".to_string(),
        ));
    }

    let mut visited = std::collections::HashSet::new();

    loop {
        if !visited.insert(cursor) {
            return Err(AppError::BadRequest(
                "category hierarchy contains a cycle".to_string(),
            ));
        }

        let parent = category_repo
            .find_by_id(cursor)
            .await?
            .ok_or_else(|| AppError::BadRequest("parent category not found".to_string()))?;

        if Some(parent.id) == category_id {
            return Err(AppError::BadRequest(
                "category parent relationship would create a cycle".to_string(),
            ));
        }

        let Some(next_cursor) = parent.parent_id else {
            return Ok(());
        };

        cursor = next_cursor;
    }
}
