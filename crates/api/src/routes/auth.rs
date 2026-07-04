use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::middleware::{AppState, AuthenticatedUser, get_project_id_from_headers};
use crate::redis::{
    IdempotencyStatus, check_idempotency, set_idempotency_completed, set_idempotency_in_progress,
};
use omni_auth_core::{
    error::AuthError,
    projects::get_project,
    sessions::{create_session, revoke_session},
    tokens::{RefreshTokenClaims, generate_tokens, rotate_refresh_token, verify_refresh_token},
    users::{User, hash_password, login, signup, verify_password},
};

#[derive(Debug, Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
}

impl From<User> for UserResponse {
    fn from(u: User) -> Self {
        UserResponse {
            id: u.id,
            email: u.email,
            email_verified: u.email_verified,
            mfa_enabled: u.mfa_enabled,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Helper to extract cookie value manually from headers
fn get_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').map(|c| c.trim()).find_map(|c| {
                let (k, v) = c.split_once('=')?;
                if k == name { Some(v.to_string()) } else { None }
            })
        })
}

/// Helper to format refresh token cookie
fn make_cookie(token: &str, max_age_days: i64) -> String {
    let max_age_seconds = max_age_days * 24 * 60 * 60;
    format!(
        "refresh_token={}; Path=/v1/auth; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        token, max_age_seconds
    )
}

/// Helper to format cookie removal
fn make_clear_cookie() -> String {
    "refresh_token=; Path=/v1/auth; HttpOnly; Secure; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string()
}

pub async fn signup_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<SignupRequest>,
) -> Response {
    let idempotency_key = headers.get("Idempotency-Key").and_then(|h| h.to_str().ok());

    let mut redis_conn = state.redis.clone();

    // 1. If Idempotency-Key is present, check cache
    if let Some(key) = idempotency_key {
        match check_idempotency(&mut redis_conn, key).await {
            Ok(Some(status)) => match status {
                IdempotencyStatus::InProgress => {
                    return (
                        StatusCode::CONFLICT,
                        Json(json!({ "error": "Request already in progress" })),
                    )
                        .into_response();
                }
                IdempotencyStatus::Completed { status, body } => {
                    let mut headers = HeaderMap::new();
                    headers.insert(
                        header::CONTENT_TYPE,
                        header::HeaderValue::from_static("application/json"),
                    );
                    return (
                        StatusCode::from_u16(status).unwrap_or(StatusCode::OK),
                        headers,
                        body,
                    )
                        .into_response();
                }
            },
            Err(e) => {
                tracing::error!("Idempotency check failed: {:?}", e);
            }
            _ => {}
        }

        if let Err(e) = set_idempotency_in_progress(&mut redis_conn, key).await {
            tracing::error!("Failed to set idempotency InProgress: {:?}", e);
        }
    }

    // Resolve project ID from headers and retrieve project
    let project_id = match get_project_id_from_headers(&headers, &state.config) {
        Ok(id) => id,
        Err(err_resp) => {
            if let Some(key) = idempotency_key {
                let _ = set_idempotency_completed(
                    &mut redis_conn,
                    key,
                    StatusCode::BAD_REQUEST.as_u16(),
                    "{\"error\":\"Missing or invalid x-project-id header\"}",
                )
                .await;
            }
            return err_resp;
        }
    };
    let project = match get_project(&state.db, project_id).await {
        Ok(p) => p,
        Err(_) => {
            let status = StatusCode::NOT_FOUND;
            let body_json = json!({ "error": "Project not found" });
            let body_str = body_json.to_string();
            if let Some(key) = idempotency_key {
                let _ = set_idempotency_completed(&mut redis_conn, key, status.as_u16(), &body_str)
                    .await;
            }
            return (status, Json(body_json)).into_response();
        }
    };

    // 2. Perform registration
    let user_res = signup(&state.db, project.id, &payload.email, &payload.password).await;

    let user = match user_res {
        Ok(u) => u,
        Err(AuthError::UserAlreadyExists) => {
            let status = StatusCode::BAD_REQUEST;
            let body_json = json!({ "error": "Email already registered" });
            let body_str = body_json.to_string();

            if let Some(key) = idempotency_key {
                let _ = set_idempotency_completed(&mut redis_conn, key, status.as_u16(), &body_str)
                    .await;
            }
            return (status, Json(body_json)).into_response();
        }
        Err(e) => {
            tracing::error!("Signup error: {:?}", e);
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            let body_json = json!({ "error": "Internal server error" });
            let body_str = body_json.to_string();

            if let Some(key) = idempotency_key {
                let _ = set_idempotency_completed(&mut redis_conn, key, status.as_u16(), &body_str)
                    .await;
            }
            return (status, Json(body_json)).into_response();
        }
    };

    // Generate and send email verification OTP
    use rand::RngExt;
    let otp_code = format!("{:06}", rand::rng().random_range(100000..1000000));
    let redis_key = format!("email_verify:{}", user.email);
    let _: () = redis::Cmd::set_ex(&redis_key, &otp_code, 900)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();
    crate::email::send_verification_email(&state, user.email.clone(), otp_code);

    let response_data = UserResponse::from(user);

    let response_json = serde_json::to_string(&response_data).unwrap_or_default();

    if let Some(key) = idempotency_key {
        let _ = set_idempotency_completed(
            &mut redis_conn,
            key,
            StatusCode::CREATED.as_u16(),
            &response_json,
        )
        .await;
    }

    crate::webhooks::trigger_webhook(
        state.db.clone(),
        project.id,
        "user.created",
        json!({
            "user_id": response_data.id,
            "email": response_data.email,
        }),
    );

    (StatusCode::CREATED, Json(response_data)).into_response()
}

pub async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Response {
    let project_id = match get_project_id_from_headers(&headers, &state.config) {
        Ok(id) => id,
        Err(err_resp) => return err_resp,
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

    let user_res = login(&state.db, project.id, &payload.email, &payload.password).await;

    let user = match user_res {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Invalid email or password" })),
            )
                .into_response();
        }
    };

    if !user.email_verified {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Email address not verified. Please check logs for OTP code." })),
        )
            .into_response();
    }

    if user.mfa_enabled {
        let ticket = match omni_auth_core::tokens::generate_mfa_ticket(&project, user.id) {
            Ok(t) => t,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Internal server error" })),
                )
                    .into_response();
            }
        };
        return (
            StatusCode::OK,
            Json(json!({
                "mfa_required": true,
                "mfa_ticket": ticket
            })),
        )
            .into_response();
    }

    // Create session
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

    crate::webhooks::trigger_webhook(
        state.db.clone(),
        project.id,
        "session.created",
        json!({
            "session_id": session.id,
            "user_id": user.id,
        }),
    );

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

pub async fn logout_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let refresh_cookie = get_cookie_value(&headers, "refresh_token");

    if let Some(token) = refresh_cookie
        && let Ok(raw_claims) =
            jsonwebtoken::dangerous::insecure_decode::<RefreshTokenClaims>(&token)
        && let Ok(project_id) = Uuid::parse_str(&raw_claims.claims.project_id)
        && let Ok(project) = get_project(&state.db, project_id).await
        && let Ok(claims) = verify_refresh_token(&project, &token)
        && let Ok(session_id) = Uuid::parse_str(&claims.sid)
    {
        let _ = revoke_session(&state.db, session_id).await;
    }

    (
        StatusCode::OK,
        [(header::SET_COOKIE, make_clear_cookie())],
        Json(json!({ "message": "Successfully logged out" })),
    )
        .into_response()
}

pub async fn refresh_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let refresh_cookie = get_cookie_value(&headers, "refresh_token");

    let token = match refresh_cookie {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "Missing refresh token" })),
            )
                .into_response();
        }
    };

    // Insecurely decode token to resolve correct project ID
    let raw_claims = match jsonwebtoken::dangerous::insecure_decode::<RefreshTokenClaims>(&token) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::SET_COOKIE, make_clear_cookie())],
                Json(json!({ "error": "Invalid token format" })),
            )
                .into_response();
        }
    };

    let project_id = match Uuid::parse_str(&raw_claims.claims.project_id) {
        Ok(id) => id,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::SET_COOKIE, make_clear_cookie())],
                Json(json!({ "error": "Invalid project ID in token" })),
            )
                .into_response();
        }
    };

    let project = match get_project(&state.db, project_id).await {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::SET_COOKIE, make_clear_cookie())],
                Json(json!({ "error": "Project not found" })),
            )
                .into_response();
        }
    };

    let mut redis_conn = state.redis.clone();
    let rotation_res = rotate_refresh_token(
        &state.db,
        &mut redis_conn,
        &project,
        &token,
        state.config.access_token_ttl_mins,
        state.config.refresh_token_ttl_days,
    )
    .await;

    match rotation_res {
        Ok((access_token, refresh_token)) => (
            StatusCode::OK,
            [(
                header::SET_COOKIE,
                make_cookie(&refresh_token, state.config.refresh_token_ttl_days),
            )],
            Json(json!({ "access_token": access_token })),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!("Token rotation failed: {:?}", e);
            (
                StatusCode::UNAUTHORIZED,
                [(header::SET_COOKIE, make_clear_cookie())],
                Json(json!({ "error": "Invalid or expired session" })),
            )
                .into_response()
        }
    }
}

pub async fn me_handler(user_ctx: AuthenticatedUser) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "user_id": user_ctx.user_id,
            "session_id": user_ctx.session_id,
            "project_id": user_ctx.project.id,
        })),
    )
}

#[derive(Debug, Deserialize)]
pub struct VerifyEmailRequest {
    pub email: String,
    pub code: String,
}

pub async fn verify_email_handler(
    State(state): State<AppState>,
    Json(payload): Json<VerifyEmailRequest>,
) -> impl IntoResponse {
    let email_normalized = payload.email.trim().to_lowercase();
    let mut redis_conn = state.redis.clone();

    let redis_key = format!("email_verify:{}", email_normalized);
    let attempts_key = format!("email_verify_attempts:{}", email_normalized);

    let cached_code: Option<String> = redis::Cmd::get(&redis_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);

    if cached_code.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Verification code has expired or was not requested." })),
        )
            .into_response();
    }

    let code = cached_code.unwrap();
    if code == payload.code {
        // Delete code and attempts counter from Redis
        let _: () = redis::Cmd::del(&[&redis_key, &attempts_key])
            .query_async(&mut redis_conn)
            .await
            .unwrap_or_default();

        // Update user email_verified = true in PG
        let update_res = sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
            .bind(&email_normalized)
            .execute(&state.db)
            .await;

        match update_res {
            Ok(_) => (
                StatusCode::OK,
                Json(json!({ "message": "Email verified successfully" })),
            )
                .into_response(),
            Err(e) => {
                tracing::error!("Failed to update email_verified: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database update failed").into_response()
            }
        }
    } else {
        // Increment attempts counter
        let attempts: u32 = redis::Cmd::incr(&attempts_key, 1)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or(0);

        // Set expire on attempts key if this was the first failed attempt
        if attempts == 1 {
            let _: () = redis::Cmd::expire(&attempts_key, 900)
                .query_async(&mut redis_conn)
                .await
                .unwrap_or_default();
        }

        if attempts >= 5 {
            // Delete code and attempts from Redis to block further tries
            let _: () = redis::Cmd::del(&[&redis_key, &attempts_key])
                .query_async(&mut redis_conn)
                .await
                .unwrap_or_default();

            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Too many failed verification attempts. This code has been invalidated. Please request a new code."
                })),
            )
                .into_response()
        } else {
            let remaining = 5 - attempts;
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Invalid verification code. {} attempts remaining before code is invalidated.", remaining)
                })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

/// HTTP POST handler to regenerate and resend a 6-digit OTP verification code.
/// Overwrites any existing verification code and resets the verification attempt limit counter.
pub async fn resend_verification_handler(
    State(state): State<AppState>,
    Json(payload): Json<ResendVerificationRequest>,
) -> impl IntoResponse {
    let email_normalized = payload.email.trim().to_lowercase();

    // Check if user exists and is not verified
    let user_opt = match sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at
         FROM users WHERE email = $1"
    )
    .bind(&email_normalized)
    .fetch_optional(&state.db)
    .await {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!("Database error looking up user: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database lookup failed").into_response();
        }
    };

    let user = match user_opt {
        Some(u) => u,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "User not found" })),
            )
                .into_response();
        }
    };

    if user.email_verified {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Email is already verified" })),
        )
            .into_response();
    }

    let mut redis_conn = state.redis.clone();
    let redis_key = format!("email_verify:{}", email_normalized);

    // Generate a fresh code
    use rand::RngExt;
    let otp_code = format!("{:06}", rand::rng().random_range(100000..1000000));
    let _: () = redis::Cmd::set_ex(&redis_key, &otp_code, 900)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();

    crate::email::send_verification_email(&state, email_normalized, otp_code);

    (
        StatusCode::OK,
        Json(json!({ "message": "Verification code resent successfully" })),
    )
        .into_response()
}

// ─── Password Reset ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

/// HTTP POST handler to initiate password recovery.
/// Generates a unique 32-character base64 URL-safe reset token, caches it in Redis,
/// and dispatches a recovery email with a link pointing back to the frontend reset forms.
pub async fn forgot_password_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ForgotPasswordRequest>,
) -> impl IntoResponse {
    let email_normalized = body.email.trim().to_lowercase();
    let project_id = match get_project_id_from_headers(&headers, &state.config) {
        Ok(id) => id,
        Err(err_resp) => return err_resp,
    };

    let mut redis_conn = state.redis.clone();

    // Look up user but don't reveal whether they exist
    let user_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND project_id = $2)",
    )
    .bind(&email_normalized)
    .bind(project_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if user_exists {
        // Generate a secure 64-char hex token
        use rand::RngExt;
        let token: String = (0..64)
            .map(|_| format!("{:x}", rand::rng().random::<u8>() & 0xf))
            .collect();

        let redis_key = format!("pwd_reset:{}", email_normalized);
        let _: () = redis::Cmd::set_ex(&redis_key, &token, 1800)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or_default();

        crate::email::send_password_reset_email(&state, email_normalized, token);
    }

    (
        StatusCode::OK,
        Json(json!({ "message": "If that email is registered, a reset link has been sent" })),
    )
        .into_response()
}

// ─── Reset Password ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
    pub token: String,
    pub new_password: String,
}

/// HTTP POST handler to reset a user's password using a verification token.
/// Verifies the token cache matches the user's email, validates length criteria,
/// updates the password hash in the database, and clears active sessions.
pub async fn reset_password_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ResetPasswordRequest>,
) -> impl IntoResponse {
    let email_normalized = body.email.trim().to_lowercase();
    let project_id = match get_project_id_from_headers(&headers, &state.config) {
        Ok(id) => id,
        Err(err_resp) => return err_resp,
    };

    if body.new_password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Password must be at least 8 characters" })),
        )
            .into_response();
    }

    let mut redis_conn = state.redis.clone();
    let redis_key = format!("pwd_reset:{}", email_normalized);

    let stored_token: Option<String> = redis::Cmd::get(&redis_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);

    let valid = match &stored_token {
        Some(t) => *t == body.token,
        None => false,
    };

    if !valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid or expired reset token" })),
        )
            .into_response();
    }

    // Hash the new password using argon2 (same as signup)
    let new_hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Password hashing error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    // Update password in DB
    let update_res = sqlx::query(
        "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2 AND project_id = $3"
    )
    .bind(&new_hash)
    .bind(&email_normalized)
    .bind(project_id)
    .execute(&state.db)
    .await;

    if let Err(e) = update_res {
        tracing::error!("Failed to update password hash: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Internal server error" })),
        )
            .into_response();
    }

    // Delete the reset token from Redis
    let _: () = redis::Cmd::del(&redis_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();

    // Revoke ALL sessions for this user (security: force re-login everywhere)
    let _ = sqlx::query(
        "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = $1 AND project_id = $2)"
    )
    .bind(&email_normalized)
    .bind(project_id)
    .execute(&state.db)
    .await;

    (
        StatusCode::OK,
        Json(json!({ "message": "Password reset successfully. Please log in with your new password." })),
    )
        .into_response()
}

// ─── Change Password ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// HTTP POST handler to change a logged-in user's password.
/// Validates the caller's active session, matches their current password, and hashes the new one.
pub async fn change_password_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(body): Json<ChangePasswordRequest>,
) -> impl IntoResponse {
    if body.new_password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "New password must be at least 8 characters" })),
        )
            .into_response();
    }

    // Fetch current password hash
    let row = sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = $1")
        .bind(user_ctx.user_id)
        .fetch_optional(&state.db)
        .await;

    let current_hash = match row {
        Ok(Some(h)) => h,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "User not found" })),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("DB error fetching password hash: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    // Verify current password
    let is_valid = match verify_password(&body.current_password, &current_hash) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("Password verification error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    if !is_valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Current password is incorrect" })),
        )
            .into_response();
    }

    // Hash new password
    let new_hash = match hash_password(&body.new_password) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Password hashing error: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    // Update password in DB
    let update_res =
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
            .bind(&new_hash)
            .bind(user_ctx.user_id)
            .execute(&state.db)
            .await;

    if let Err(e) = update_res {
        tracing::error!("Failed to update password: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "Internal server error" })),
        )
            .into_response();
    }

    // Revoke all OTHER sessions — keep the current session active
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND id != $2")
        .bind(user_ctx.user_id)
        .bind(user_ctx.session_id)
        .execute(&state.db)
        .await;

    (
        StatusCode::OK,
        Json(json!({ "message": "Password changed successfully" })),
    )
        .into_response()
}

// ── Magic Link Login ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
}

/// `POST /v1/auth/magic-link`
///
/// Request a magic sign-in link for an existing, verified account.
/// Always returns 200 to prevent email enumeration.
/// The link (or token, in dev) is sent to the user's email.
pub async fn request_magic_link_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MagicLinkRequest>,
) -> impl IntoResponse {
    let email_normalized = body.email.trim().to_lowercase();
    let project_id = match get_project_id_from_headers(&headers, &state.config) {
        Ok(id) => id,
        Err(err_resp) => return err_resp,
    };
    let mut redis_conn = state.redis.clone();

    // Only send link if user exists AND is verified (magic link = login, not signup)
    let user_opt = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE email = $1 AND project_id = $2 AND email_verified = TRUE)"
    )
    .bind(&email_normalized)
    .bind(project_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if user_opt {
        // Generate a 64-char hex token (32 random bytes)
        use rand::RngExt;
        let token: String = (0..64)
            .map(|_| format!("{:x}", rand::rng().random::<u8>() & 0xf))
            .collect();

        let redis_key = format!("magic_link:{}", email_normalized);
        // Single-use, 15-minute TTL
        let _: () = redis::Cmd::set_ex(&redis_key, &token, 900)
            .query_async(&mut redis_conn)
            .await
            .unwrap_or_default();

        crate::email::send_magic_link_email(&state, email_normalized, token);
    }

    (
        StatusCode::OK,
        Json(json!({ "message": "If that email has a verified account, a sign-in link has been sent" })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkRequest {
    pub email: String,
    pub token: String,
}

/// `POST /v1/auth/magic-link/verify`
///
/// Verify a magic link token. On success: creates a full session and returns
/// `{ access_token, user }` with the refresh cookie set — exactly like a normal login.
pub async fn verify_magic_link_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<VerifyMagicLinkRequest>,
) -> Response {
    let email_normalized = body.email.trim().to_lowercase();
    let project_id = match get_project_id_from_headers(&headers, &state.config) {
        Ok(id) => id,
        Err(err_resp) => return err_resp,
    };
    let mut redis_conn = state.redis.clone();

    // Retrieve and validate stored token
    let redis_key = format!("magic_link:{}", email_normalized);
    let stored: Option<String> = redis::Cmd::get(&redis_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or(None);

    if stored.as_deref() != Some(&body.token) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "Invalid or expired magic link" })),
        )
            .into_response();
    }

    // Delete immediately — single-use token
    let _: () = redis::Cmd::del(&redis_key)
        .query_async(&mut redis_conn)
        .await
        .unwrap_or_default();

    // Fetch the user
    let user = match sqlx::query_as::<_, User>(
        "SELECT id, project_id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at
         FROM users WHERE email = $1 AND project_id = $2",
    )
    .bind(&email_normalized)
    .bind(project_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(json!({ "error": "User not found" }))).into_response();
        }
        Err(e) => {
            tracing::error!("DB error in magic link verify: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Internal server error" }))).into_response();
        }
    };

    // Fetch the project for token signing
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

    // Capture session metadata from request headers
    let ip_address = headers
        .get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim().to_string());
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Create a database session
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
            tracing::error!("Session creation error in magic link verify: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response();
        }
    };

    // Generate access + refresh tokens (same as login)
    let (access_token, refresh_token, _jti) = match generate_tokens(
        &project,
        user.id,
        session.id,
        state.config.access_token_ttl_mins,
        state.config.refresh_token_ttl_days,
    ) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Token generation error in magic link verify: {:?}", e);
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
