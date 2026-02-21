use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct CategoryResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub children: Vec<CategoryResponse>,
}
