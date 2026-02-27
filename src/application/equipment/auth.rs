use crate::domain::Role;
use crate::error::{AppError, AppResult};
use crate::infrastructure::repositories::UserRepository;
use uuid::Uuid;

pub async fn check_equipment_access(
    user_repo: &dyn UserRepository,
    actor_user_id: Uuid,
    owner_id: Uuid,
) -> AppResult<()> {
    if owner_id == actor_user_id {
        return Ok(());
    }

    let actor = user_repo
        .find_by_id(actor_user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if actor.role == Role::Admin {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "You do not have permission to modify this equipment".to_string(),
    ))
}
