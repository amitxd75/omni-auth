//! User active session query and revocation route handlers.
//! Allows users to view and revoke individual or all active browser/client logins.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use uuid::Uuid;

use crate::middleware::{AppState, AuthenticatedUser};

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_current: bool,
}

/// HTTP GET handler that lists all currently active, non-expired sessions associated with the user account.
pub async fn list_sessions_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "SELECT id, user_agent, ip_address, expires_at, created_at
         FROM sessions
         WHERE user_id = $1 AND expires_at > NOW()
         ORDER BY created_at DESC",
        user_ctx.user_id
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(rows) => {
            let sessions: Vec<SessionResponse> = rows
                .into_iter()
                .map(|r| SessionResponse {
                    id: r.id,
                    user_agent: r.user_agent,
                    ip_address: r.ip_address,
                    expires_at: r.expires_at,
                    created_at: r.created_at,
                    is_current: r.id == user_ctx.session_id,
                })
                .collect();

            (StatusCode::OK, Json(sessions)).into_response()
        }
        Err(e) => {
            tracing::error!("Failed to fetch sessions: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database query failure" })),
            )
                .into_response()
        }
    }
}

/// HTTP DELETE handler to revoke (terminate) a specific active session.
/// Sends a `session.deleted` event notification via webhook on successful deletion.
pub async fn revoke_session_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Path(session_id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "DELETE FROM sessions WHERE id = $1 AND user_id = $2 RETURNING id",
        session_id,
        user_ctx.user_id
    )
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => {
            // Trigger session.deleted webhook event
            crate::webhooks::trigger_webhook(
                state.db.clone(),
                user_ctx.project.id,
                "session.deleted",
                json!({
                    "session_id": row.id,
                    "user_id": user_ctx.user_id,
                }),
            );

            (
                StatusCode::OK,
                Json(json!({ "message": "Session revoked successfully" })),
            )
                .into_response()
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "Session not found or unauthorized" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to revoke session: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database deletion failure" })),
            )
                .into_response()
        }
    }
}

/// HTTP DELETE handler to revoke all other active user sessions (log out other devices),
/// leaving only the calling client's active session active.
pub async fn revoke_all_sessions_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
) -> impl IntoResponse {
    let result = sqlx::query!(
        "DELETE FROM sessions WHERE user_id = $1 AND id != $2 RETURNING id",
        user_ctx.user_id,
        user_ctx.session_id
    )
    .fetch_all(&state.db)
    .await;

    match result {
        Ok(rows) => {
            for row in rows {
                crate::webhooks::trigger_webhook(
                    state.db.clone(),
                    user_ctx.project.id,
                    "session.deleted",
                    json!({
                        "session_id": row.id,
                        "user_id": user_ctx.user_id,
                    }),
                );
            }

            (
                StatusCode::OK,
                Json(json!({ "message": "All other sessions revoked successfully" })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("Failed to revoke other sessions: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database deletion failure" })),
            )
                .into_response()
        }
    }
}
