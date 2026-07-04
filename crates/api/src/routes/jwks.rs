//! JSON Web Key Set (JWKS) public discovery endpoints.
//! Allows external clients and resource servers to retrieve tenant public verification keys.

use crate::middleware::AppState;
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use base64::prelude::*;
use omni_auth_core::projects::get_project;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct JwksQuery {
    pub project_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct JwkKey {
    pub kty: String,
    pub r#use: String,
    pub crv: String,
    pub kid: String,
    pub x: String,
}

#[derive(Debug, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<JwkKey>,
}

/// HTTP GET handler exposing standard RFC 7517 JSON Web Key Sets.
/// Maps and encodes the project's Ed25519 public verification key parameters to standard Base64URL-encoded strings.
pub async fn jwks_handler(
    State(state): State<AppState>,
    Query(query): Query<JwksQuery>,
) -> impl IntoResponse {
    let project = match get_project(&state.db, query.project_id).await {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Project not found" })),
            )
                .into_response();
        }
    };

    // Decode base64 public key to raw bytes
    let pub_key_bytes = match BASE64_STANDARD.decode(&project.jwt_public_key) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Failed to decode public key: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Invalid project public key configuration" })),
            )
                .into_response();
        }
    };

    // Encode key parameter using base64url no padding
    let x = BASE64_URL_SAFE_NO_PAD.encode(&pub_key_bytes);

    let jwk = JwkKey {
        kty: "OKP".to_string(),
        r#use: "sig".to_string(),
        crv: "Ed25519".to_string(),
        kid: project.id.to_string(),
        x,
    };

    (StatusCode::OK, Json(JwksResponse { keys: vec![jwk] })).into_response()
}
