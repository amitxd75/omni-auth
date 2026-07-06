//! Multi-Factor Authentication (MFA/TOTP) route handlers.
//! Handles TOTP registration enrollment, verification ticket checking, and authentication state transitions.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::middleware::{AppState, AuthenticatedUser, make_cookie};
use crate::routes::auth::AuthResponse;
use omni_auth_core::{
    mfa::{generate_mfa_secret, verify_totp},
    projects::get_project,
    sessions::create_session,
    tokens::{MfaTicketClaims, generate_tokens, verify_mfa_ticket},
    users::{get_user_by_id, update_mfa_settings},
};
use ring::hmac;

#[derive(Debug, Deserialize)]
pub struct EnableMfaRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct DisableMfaRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyMfaRequest {
    pub mfa_ticket: String,
    pub code: String,
}

/// Helper that verifies a TOTP code and invalidates it using a 90s Redis lockout key to prevent replay attacks (OA-L6).
async fn verify_and_invalidate_totp(
    redis_conn: &mut redis::aio::ConnectionManager,
    user_id: Uuid,
    secret: &str,
    code: &str,
) -> Result<bool, Response> {
    // verify_totp checks only past and current steps (OA-L5) and returns Option<u64>
    let step = match verify_totp(secret, code) {
        Some(s) => s,
        None => return Ok(false),
    };

    let key = hmac::Key::new(hmac::HMAC_SHA256, b"totp-used-salt");
    let message = format!("totp-used:{}:{}", user_id, step);
    let signature = hmac::sign(&key, message.as_bytes());
    let signature_hex = hex::encode(signature.as_ref());
    let redis_key = format!("totp_used:{}", signature_hex);

    let exists: bool = redis::Cmd::exists(&redis_key)
        .query_async(redis_conn)
        .await
        .unwrap_or(false);

    if exists {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "This verification code has already been used. Please wait for a new code." })),
        ).into_response());
    }

    let _: () = redis::Cmd::set_ex(&redis_key, "1", 90)
        .query_async(redis_conn)
        .await
        .unwrap_or_default();

    Ok(true)
}

/// HTTP GET handler to initialize TOTP MFA setup.
/// Generates a secure random shared secret and returns a standard `otpauth://` setup URL.
pub async fn enroll_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
) -> impl IntoResponse {
    let user = match get_user_by_id(&state.db, user_ctx.project.id, user_ctx.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "User not found" })),
            )
                .into_response();
        }
    };

    let secret = generate_mfa_secret();
    let otpauth_url = format!(
        "otpauth://totp/omni-auth:{}?secret={}&issuer=omni-auth",
        user.email, secret
    );

    // Store provisional secret in Redis (OA-M6)
    let mut redis_conn = state.redis.clone();
    let provisional_key = format!("mfa_provisional:{}", user_ctx.user_id);
    let _: () = redis::Cmd::set_ex(&provisional_key, &secret, 900)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({
            "secret": secret,
            "otpauth_url": otpauth_url
        })),
    )
        .into_response()
}

/// HTTP POST handler to verify and finalize enabling MFA for a user account.
/// Saves the verified shared secret TOTP key to the database.
pub async fn enable_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(payload): Json<EnableMfaRequest>,
) -> impl IntoResponse {
    let mut redis_conn = state.redis.clone();
    let provisional_key = format!("mfa_provisional:{}", user_ctx.user_id);

    // Retrieve provisional secret from Redis (OA-M6)
    let secret_opt: Option<String> = redis::Cmd::get(&provisional_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);

    let secret = match secret_opt {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "MFA enrollment has expired or was not initiated. Please call enroll first." })),
            )
                .into_response();
        }
    };

    match verify_and_invalidate_totp(&mut redis_conn, user_ctx.user_id, &secret, &payload.code)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid verification code" })),
            )
                .into_response();
        }
        Err(err_resp) => return err_resp,
    }

    // Delete provisional secret
    let _: () = redis::Cmd::del(&provisional_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();

    match update_mfa_settings(&state.db, user_ctx.user_id, Some(secret), true).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "MFA enabled successfully" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to update MFA settings: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP POST handler to disable MFA/TOTP for a user account.
/// Checks the submitted code against the user's active secret key before clearing.
pub async fn disable_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(payload): Json<DisableMfaRequest>,
) -> impl IntoResponse {
    let user = match get_user_by_id(&state.db, user_ctx.project.id, user_ctx.user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "User not found" })),
            )
                .into_response();
        }
    };

    let secret = match &user.mfa_secret {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "MFA is not enabled" })),
            )
                .into_response();
        }
    };

    let mut redis_conn = state.redis.clone();
    match verify_and_invalidate_totp(&mut redis_conn, user_ctx.user_id, &secret, &payload.code)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid verification code" })),
            )
                .into_response();
        }
        Err(err_resp) => return err_resp,
    }

    match update_mfa_settings(&state.db, user_ctx.user_id, None, false).await {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "MFA disabled successfully" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to disable MFA: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}

/// HTTP POST handler to verify an MFA/TOTP code and complete the sign-in loop.
///
/// Decodes the short-lived `mfa_ticket` token, checks the user's TOTP secret key,
/// validates the submitted code, creates a new active session, and issues
/// access tokens and HttpOnly refresh cookies on success.
pub async fn verify_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<VerifyMfaRequest>,
) -> Response {
    // 1. Decode mfa_ticket insecurely to find project_id
    let raw_claims =
        match jsonwebtoken::dangerous::insecure_decode::<MfaTicketClaims>(&payload.mfa_ticket) {
            Ok(c) => c,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": "Invalid MFA ticket format" })),
                )
                    .into_response();
            }
        };

    let project_id = match Uuid::parse_str(&raw_claims.claims.project_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "Invalid project ID in ticket" })),
            )
                .into_response();
        }
    };

    let project = match get_project(&state.db, project_id).await {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "Project not found" })),
            )
                .into_response();
        }
    };

    // 2. Verify ticket signature
    let user_id = match verify_mfa_ticket(&project, &payload.mfa_ticket) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid or expired MFA ticket" })),
            )
                .into_response();
        }
    };

    // 3. Fetch user
    let user = match get_user_by_id(&state.db, project.id, user_id).await {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "User not found" })),
            )
                .into_response();
        }
    };

    let secret = match &user.mfa_secret {
        Some(s) => s.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "MFA is not enabled for this user" })),
            )
                .into_response();
        }
    };

    // 4. Verify TOTP code
    let mut redis_conn = state.redis.clone();
    match verify_and_invalidate_totp(&mut redis_conn, user.id, &secret, &payload.code).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid verification code" })),
            )
                .into_response();
        }
        Err(err_resp) => return err_resp,
    }

    // 5. Create session & tokens
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok().map(String::from));
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|h| h.to_str().ok()))
        .map(|s| s.split(',').next().unwrap_or("").trim().to_string());

    let session = match create_session(
        &state.db,
        project.id,
        user.id,
        user_agent,
        ip_address,
        state.config.refresh_token_ttl_days,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to create session: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    let tokens = generate_tokens(
        &project,
        user.id,
        session.id,
        state.config.access_token_ttl_mins,
        state.config.refresh_token_ttl_days,
    );

    let (access_token, refresh_token, _) = match tokens {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to generate tokens: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            make_cookie(&refresh_token, state.config.refresh_token_ttl_days),
        )],
        Json(AuthResponse {
            access_token,
            user: user.into(),
        }),
    )
        .into_response()
}
