//! OAuth social authentication route handlers.
//! Directs authorization steps and handles code exchange callbacks for Google and GitHub.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Redirect},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::middleware::{AppState, AuthenticatedUser};
use omni_auth_core::{
    oauth::{get_or_create_oauth_user, link_oauth_account},
    projects::get_project,
    sessions::create_session,
    tokens::generate_tokens,
};

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub project_id: Uuid,
    pub redirect_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OauthState {
    project_id: Uuid,
    redirect_uri: String,
}

// GitHub API JSON models
#[derive(Deserialize)]
struct GithubUser {
    id: i64,
}

#[derive(Deserialize)]
struct GithubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

// Google API JSON models
#[derive(Deserialize)]
struct GoogleUser {
    id: String,
    email: String,
}

/// Helper to format refresh token cookie (same as auth.rs)
fn make_cookie(token: &str, max_age_days: i64) -> String {
    let max_age_seconds = max_age_days * 24 * 60 * 60;
    format!(
        "refresh_token={}; Path=/v1/auth; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        token, max_age_seconds
    )
}

/// HTTP GET handler to redirect the client user to the social provider's consent page (Google or GitHub).
/// Generates and serializes the state parameter containing the tenant project and callback URI.
pub async fn authorize_handler(
    Path(provider): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");
    let state_payload = OauthState {
        project_id: query.project_id,
        redirect_uri: query.redirect_uri,
    };
    let state_bytes = match serde_json::to_vec(&state_payload) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize state",
            )
                .into_response();
        }
    };
    let state_str = BASE64_URL_SAFE_NO_PAD.encode(&state_bytes);

    let redirect_url = match provider.as_str() {
        "github" => {
            let client_id = match &state.config.github_client_id {
                Some(id) => id,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "GitHub OAuth not configured on server",
                    )
                        .into_response();
                }
            };
            let callback = format!("http://{}/v1/auth/oauth/github/callback", host);
            format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
                client_id, callback, state_str
            )
        }
        "google" => {
            let client_id = match &state.config.google_client_id {
                Some(id) => id,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        "Google OAuth not configured on server",
                    )
                        .into_response();
                }
            };
            let callback = format!("http://{}/v1/auth/oauth/google/callback", host);
            format!(
                "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20profile%20email&state={}",
                client_id, callback, state_str
            )
        }
        _ => return (StatusCode::BAD_REQUEST, "Unsupported OAuth provider").into_response(),
    };

    Redirect::to(&redirect_url).into_response()
}

/// HTTP GET callback handler invoked by social OAuth providers.
///
/// Exchanges the query authorization code parameter for an access token, queries user
/// profile data from the provider's API, resolves or creates the corresponding local account mapping,
/// initializes a session, and redirects back to the client's redirect URI with tokens.
pub async fn callback_handler(
    Path(provider): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> impl IntoResponse {
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080");
    // 1. Decode state to retrieve project_id and original redirect_uri
    let state_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&query.state) {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid state format").into_response(),
    };
    let oauth_state: OauthState = match serde_json::from_slice(&state_bytes) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid state payload").into_response(),
    };

    let project = match get_project(&state.db, oauth_state.project_id).await {
        Ok(p) => p,
        Err(_) => return (StatusCode::NOT_FOUND, "Project not found").into_response(),
    };

    let client = reqwest::Client::new();

    let (provider_user_id, user_email) = match provider.as_str() {
        "github" => {
            let client_id = match &state.config.github_client_id {
                Some(id) => id,
                None => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "GitHub config error")
                        .into_response();
                }
            };
            let client_secret = match &state.config.github_client_secret {
                Some(sec) => sec,
                None => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "GitHub config error")
                        .into_response();
                }
            };

            // Exchange code for token
            let token_res = match client
                .post("https://github.com/login/oauth/access_token")
                .header(header::ACCEPT, "application/json")
                .json(&json!({
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": query.code
                }))
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        format!("GitHub exchange error: {:?}", e),
                    )
                        .into_response();
                }
            };

            #[derive(Deserialize)]
            struct GithubTokenResponse {
                access_token: String,
            }
            let token_data: GithubTokenResponse = match token_res.json().await {
                Ok(t) => t,
                Err(_) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        "Failed to parse GitHub token response",
                    )
                        .into_response();
                }
            };

            // Fetch GitHub profile
            let profile_res = match client
                .get("https://api.github.com/user")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", token_data.access_token),
                )
                .header(header::USER_AGENT, "omni-auth")
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to retrieve GitHub profile")
                        .into_response();
                }
            };
            let github_user: GithubUser = match profile_res.json().await {
                Ok(u) => u,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to parse GitHub profile")
                        .into_response();
                }
            };
            let p_id = github_user.id.to_string();

            // Fetch GitHub emails
            let emails_res = match client
                .get("https://api.github.com/user/emails")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", token_data.access_token),
                )
                .header(header::USER_AGENT, "omni-auth")
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to retrieve GitHub emails")
                        .into_response();
                }
            };
            let emails: Vec<GithubEmail> = match emails_res.json().await {
                Ok(e) => e,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to parse GitHub emails")
                        .into_response();
                }
            };

            // Find primary and verified email
            let primary_email = emails
                .iter()
                .find(|e| e.primary && e.verified)
                .or_else(|| emails.iter().find(|e| e.verified))
                .or_else(|| emails.first());

            let u_email = match primary_email {
                Some(e) => e.email.clone(),
                None => {
                    return (StatusCode::BAD_REQUEST, "No email found in GitHub profile")
                        .into_response();
                }
            };
            (p_id, u_email)
        }
        "google" => {
            let client_id = match &state.config.google_client_id {
                Some(id) => id,
                None => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Google config error")
                        .into_response();
                }
            };
            let client_secret = match &state.config.google_client_secret {
                Some(sec) => sec,
                None => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Google config error")
                        .into_response();
                }
            };
            let callback = format!("http://{}/v1/auth/oauth/google/callback", host);

            // Exchange code for token
            let token_res = match client
                .post("https://oauth2.googleapis.com/token")
                .form(&[
                    ("client_id", client_id.as_str()),
                    ("client_secret", client_secret.as_str()),
                    ("code", query.code.as_str()),
                    ("grant_type", "authorization_code"),
                    ("redirect_uri", callback.as_str()),
                ])
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        format!("Google exchange error: {:?}", e),
                    )
                        .into_response();
                }
            };

            #[derive(Deserialize)]
            struct GoogleTokenResponse {
                access_token: String,
            }
            let token_data: GoogleTokenResponse = match token_res.json().await {
                Ok(t) => t,
                Err(_) => {
                    return (
                        StatusCode::BAD_GATEWAY,
                        "Failed to parse Google token response",
                    )
                        .into_response();
                }
            };

            // Fetch Google userinfo
            let userinfo_res = match client
                .get("https://www.googleapis.com/oauth2/v2/userinfo")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {}", token_data.access_token),
                )
                .send()
                .await
            {
                Ok(r) => r,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to retrieve Google profile")
                        .into_response();
                }
            };
            let google_user: GoogleUser = match userinfo_res.json().await {
                Ok(u) => u,
                Err(_) => {
                    return (StatusCode::BAD_GATEWAY, "Failed to parse Google profile")
                        .into_response();
                }
            };
            (google_user.id, google_user.email)
        }
        _ => return (StatusCode::BAD_REQUEST, "Unsupported OAuth provider").into_response(),
    };

    // 2. Fetch or create mapped local user
    let user = match get_or_create_oauth_user(
        &state.db,
        project.id,
        &provider,
        &provider_user_id,
        &user_email,
    )
    .await
    {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to link user: {:?}", e),
            )
                .into_response();
        }
    };

    // If user has MFA enabled, standard redirect won't immediately return tokens; instead return MFA verification page!
    if user.mfa_enabled {
        let ticket = match omni_auth_core::tokens::generate_mfa_ticket(&project, user.id) {
            Ok(t) => t,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "MFA ticket error").into_response();
            }
        };
        // Redirect consumer app to complete 2FA challenge. Pass the MFA ticket.
        let target = format!(
            "{}?mfa_required=true&mfa_ticket={}",
            oauth_state.redirect_uri, ticket
        );
        return Redirect::to(&target).into_response();
    }

    // 3. Create Session & Tokens
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
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Session creation error").into_response();
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
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Token generation error").into_response();
        }
    };

    // 4. Return tokens
    let target = format!("{}?access_token={}", oauth_state.redirect_uri, access_token);
    (
        StatusCode::FOUND,
        [
            (header::LOCATION, target),
            (
                header::SET_COOKIE,
                make_cookie(&refresh_token, state.config.refresh_token_ttl_days),
            ),
        ],
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct LinkOauthRequest {
    pub provider: String,
    pub provider_user_id: String,
}

/// HTTP POST handler to explicitly link a social OAuth account identity to an existing authenticated user.
pub async fn link_handler(
    State(state): State<AppState>,
    user_ctx: AuthenticatedUser,
    Json(payload): Json<LinkOauthRequest>,
) -> impl IntoResponse {
    match link_oauth_account(
        &state.db,
        user_ctx.user_id,
        user_ctx.project.id,
        &payload.provider,
        &payload.provider_user_id,
    )
    .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "message": "OAuth provider linked successfully" })),
        )
            .into_response(),
        Err(omni_auth_core::error::AuthError::UserAlreadyExists) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "This provider account is already linked" })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("OAuth link failed: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Internal server error" })),
            )
                .into_response()
        }
    }
}
