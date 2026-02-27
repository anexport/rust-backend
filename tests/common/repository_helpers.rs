use crate::common::TestDb;
use rust_backend::domain::Category;

pub async fn create_category(db: &TestDb, category: &Category) -> sqlx::Result<Category> {
    let created = sqlx::query_as::<_, Category>(
        "INSERT INTO categories (id, name, parent_id, created_at) VALUES ($1, $2, $3, $4) RETURNING id, name, parent_id, created_at"
    )
    .bind(category.id)
    .bind(&category.name)
    .bind(category.parent_id)
    .bind(category.created_at)
    .fetch_one(db.pool())
    .await?;
    Ok(created)
}
