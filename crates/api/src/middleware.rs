//! Shared API middleware and request extractors.
//! Implements global state, user/admin authentication extractors, and request-header parsing helpers.

use crate::config::Config;
use axum::{
    Json,
    extract::FromRequestParts,
    http::{HeaderMap, StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use omni_auth_core::{
    projects::{DEFAULT_PROJECT_ID, Project, get_project},
    tokens::{AccessTokenClaims, verify_access_token},
};
use serde_json::json;
use uuid::Uuid;

/// Main shared application state containing database pools and global configuration parameters.
#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::PgPool,
    pub redis: redis::aio::ConnectionManager,
    pub config: Config,
    pub http_client: reqwest::Client,
}

/// Resolved context of an authenticated API user caller.
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub project: Project,
}

/// Helper parsing the client-supplied project UUID from request headers.
/// Falls back to the global nil UUID default project if fallback option is enabled.
///
/// # Parameters
/// - `headers`: Map of HTTP headers in the incoming request.
/// - `config`: Configuration reference to verify fallback settings.
#[allow(clippy::result_large_err)]
pub fn get_project_id_from_headers(headers: &HeaderMap, config: &Config) -> Result<Uuid, Response> {
    let header_val = headers.get("x-project-id");
    match header_val {
        Some(val) => {
            let s = val.to_str().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "Invalid x-project-id header format" })),
                )
                    .into_response()
            })?;
            Uuid::parse_str(s).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "Invalid x-project-id UUID format" })),
                )
                    .into_response()
            })
        }
        None => {
            if config.allow_default_project_fallback {
                Ok(DEFAULT_PROJECT_ID)
            } else {
                Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "Missing x-project-id header" })),
                )
                    .into_response())
            }
        }
    }
}

/// Extractor used to authenticate master admin/superuser actions.
/// Matches the request headers against the configured `ADMIN_API_KEY`.
pub struct AdminAuth;

impl<S> FromRequestParts<S> for AdminAuth
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let axum::extract::State(app_state) =
            axum::extract::State::<AppState>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Internal state error" })),
                    )
                        .into_response()
                })?;

        let expected_key = match &app_state.config.admin_api_key {
            Some(key) if !key.trim().is_empty() => key,
            _ => {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "Admin API key is not configured on this server" })),
                )
                    .into_response());
            }
        };

        let incoming_key = parts
            .headers
            .get("x-admin-api-key")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| h.strip_prefix("Bearer "))
            });

        match incoming_key {
            Some(key) => {
                use ring::digest::{self, SHA256};

                let expected_hash = digest::digest(&SHA256, expected_key.as_bytes());
                let incoming_hash = digest::digest(&SHA256, key.as_bytes());

                if constant_time_eq(expected_hash.as_ref(), incoming_hash.as_ref()) {
                    Ok(AdminAuth)
                } else {
                    Err((
                        StatusCode::UNAUTHORIZED,
                        Json(json!({ "error": "Invalid or missing Admin API Key" })),
                    )
                        .into_response())
                }
            }
            _ => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or missing Admin API Key" })),
            )
                .into_response()),
        }
    }
}

/// Extractor used to authenticate client-side SaaS backend servers connecting to OmniAuth.
/// Validates the private project `api_key` (secret key) against the database registry.
#[allow(dead_code)]
pub struct ProjectAuth {
    pub project: Project,
}

impl<S> FromRequestParts<S> for ProjectAuth
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    #[allow(clippy::result_large_err)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let axum::extract::State(app_state) =
            axum::extract::State::<AppState>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Internal state error" })),
                    )
                        .into_response()
                })?;

        let incoming_key = parts
            .headers
            .get("x-project-secret")
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                parts
                    .headers
                    .get(axum::http::header::AUTHORIZATION)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| h.strip_prefix("Bearer "))
            });

        let api_key = match incoming_key {
            Some(key) => key,
            None => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Missing Project API Key" })),
                )
                    .into_response());
            }
        };

        let project = sqlx::query_as::<_, Project>(
            "SELECT id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at FROM projects WHERE api_key = $1"
        )
        .bind(api_key)
        .fetch_optional(&app_state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database query failed during project API key auth: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Database query error" })),
            )
                .into_response()
        })?;

        match project {
            Some(p) => Ok(ProjectAuth { project: p }),
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid Project API Key" })),
            )
                .into_response()),
        }
    }
}

/// Extractor used to authenticate standard user API calls by verifying a signed JWT.
/// Resolves project keys, decodes token claims, and verifies session active status in the database.
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    AppState: axum::extract::FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Resolve AppState
        let axum::extract::State(app_state) =
            axum::extract::State::<AppState>::from_request_parts(parts, state)
                .await
                .map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "Internal state error" })),
                    )
                        .into_response()
                })?;

        // Extract Authorization header
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Missing Authorization header" })),
                )
                    .into_response()
            })?;

        if !auth_header.starts_with("Bearer ") {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid Authorization header format" })),
            )
                .into_response());
        }

        let token = &auth_header[7..];

        // Insecurely decode the claims first to find the project ID
        let raw_claims = jsonwebtoken::dangerous::insecure_decode::<AccessTokenClaims>(token)
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Invalid or malformed token" })),
                )
                    .into_response()
            })?;

        let project_id = Uuid::parse_str(&raw_claims.claims.project_id).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid project ID in token" })),
            )
                .into_response()
        })?;

        // Retrieve the project configuration (with its public key) from DB
        let project = get_project(&app_state.db, project_id).await.map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Project not found or inactive" })),
            )
                .into_response()
        })?;

        // Verify the token signature using the retrieved project public key
        let claims = verify_access_token(&project, token).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired token" })),
            )
                .into_response()
        })?;

        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid token subject" })),
            )
                .into_response()
        })?;

        let session_id = Uuid::parse_str(&claims.sid).map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid token session ID" })),
            )
                .into_response()
        })?;

        // Verify session is active in the database (OA-H5)
        let _session = omni_auth_core::sessions::get_session(&app_state.db, session_id)
            .await
            .map_err(|_| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({ "error": "Session is invalid or has been revoked" })),
                )
                    .into_response()
            })?;

        Ok(AuthenticatedUser {
            user_id,
            session_id,
            project,
        })
    }
}

/// Helper to format and secure HTTP-Only refresh token cookies at root Path=/ (OA-L3)
pub fn make_cookie(token: &str, max_age_days: i64) -> String {
    let max_age_seconds = max_age_days * 24 * 60 * 60;
    format!(
        "refresh_token={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        token, max_age_seconds
    )
}

/// Helper to format cookie removal
pub fn make_clear_cookie() -> String {
    "refresh_token=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string()
}

/// Constant-time byte slice comparison to mitigate timing attacks (OA-C4)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
