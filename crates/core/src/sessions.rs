//! User session lifecycle management.
//! Handles session creation, token expiration checks, and global/individual session revocation.

use crate::error::{AuthError, Result};
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub project_id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Creates a new active session token row inside the database.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `project_id`: ID of the tenant project.
/// - `user_id`: Target user account UUID.
/// - `user_agent`: Optional caller device metadata.
/// - `ip_address`: Optional caller network IP address.
/// - `ttl_days`: Number of days until this session expires.
pub async fn create_session(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    user_id: Uuid,
    user_agent: Option<String>,
    ip_address: Option<String>,
    ttl_days: i64,
) -> Result<Session> {
    let session_id = Uuid::now_v7();
    let expires_at = Utc::now() + Duration::days(ttl_days);

    let session = sqlx::query_as::<_, Session>(
        "INSERT INTO sessions (id, user_id, project_id, user_agent, ip_address, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, user_id, project_id, user_agent, ip_address, expires_at, created_at, updated_at"
    )
    .bind(session_id)
    .bind(user_id)
    .bind(project_id)
    .bind(user_agent)
    .bind(ip_address)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;

    Ok(session)
}

/// Query and retrieve an active user session by its ID.
/// Automatically verifies expiration date criteria.
pub async fn get_session(pool: &sqlx::PgPool, id: Uuid) -> Result<Session> {
    let session = sqlx::query_as::<_, Session>(
        "SELECT id, user_id, project_id, user_agent, ip_address, expires_at, created_at, updated_at
         FROM sessions
         WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match session {
        Some(s) if s.expires_at > Utc::now() => Ok(s),
        _ => Err(AuthError::SessionNotFound),
    }
}

/// Deletes a specific user session from the database.
/// This action immediately invalidates any corresponding refresh tokens.
pub async fn revoke_session(pool: &sqlx::PgPool, id: Uuid) -> Result<()> {
    let rows_affected = sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();

    if rows_affected == 0 {
        return Err(AuthError::SessionNotFound);
    }
    Ok(())
}

/// Deletes all active sessions for a target user profile.
/// Commonly triggered during manual password resets or security overrides.
pub async fn revoke_all_user_sessions(pool: &sqlx::PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}
