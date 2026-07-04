//! Administrative route handlers.
//! Exposes endpoints for tenant workspace creations and global outbound webhook registration.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::middleware::AppState;
use omni_auth_core::{projects::Project, webhooks::register_webhook_endpoint};

#[derive(Debug, Deserialize)]
pub struct CreateProjectRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub project_id: Uuid,
    pub url: String,
    pub secret: String,
}

/// HTTP POST handler to generate a new tenant project workspace.
/// Creates a unique workspace with custom Ed25519 signing keys and API secrets.
pub async fn create_project_handler(
    _admin: crate::middleware::AdminAuth,
    State(state): State<AppState>,
    Json(payload): Json<CreateProjectRequest>,
) -> impl IntoResponse {
    let project_id = Uuid::now_v7();
    let (priv_key, pub_key) = match omni_auth_core::projects::generate_keypair() {
        Ok(k) => k,
        Err(e) => {
            tracing::error!("Key generation failed: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Cryptography engine error" })),
            )
                .into_response();
        }
    };
    let api_key = omni_auth_core::projects::generate_api_key();

    let result = sqlx::query_as::<_, Project>(
        "INSERT INTO projects (id, name, jwt_private_key, jwt_public_key, api_key)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at",
    )
    .bind(project_id)
    .bind(&payload.name)
    .bind(&priv_key)
    .bind(&pub_key)
    .bind(&api_key)
    .fetch_one(&state.db)
    .await;

    match result {
        Ok(project) => (StatusCode::CREATED, Json(project)).into_response(),
        Err(e) => {
            tracing::error!("Failed to create project: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database write failure" })),
            )
                .into_response()
        }
    }
}

/// HTTP POST handler to register a new webhook destination endpoint for a target project.
pub async fn create_webhook_handler(
    _admin: crate::middleware::AdminAuth,
    State(state): State<AppState>,
    Json(payload): Json<CreateWebhookRequest>,
) -> impl IntoResponse {
    match register_webhook_endpoint(&state.db, payload.project_id, &payload.url, &payload.secret)
        .await
    {
        Ok(endpoint) => (StatusCode::CREATED, Json(endpoint)).into_response(),
        Err(e) => {
            tracing::error!("Webhook registration failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database write failure" })),
            )
                .into_response()
        }
    }
}
