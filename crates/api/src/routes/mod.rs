//! Application router definition and middleware configuration.
//! Orchestrates endpoint nesting, rate limiting, and CORS header controls.

use crate::middleware::AppState;
use axum::{
    Router,
    http::{Method, header},
    routing::post,
};
use std::sync::Arc;
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::cors::CorsLayer;

pub mod admin;
pub mod auth;
pub mod jwks;
pub mod mfa;
pub mod oauth;
mod orgs;
mod sessions;

/// Configures and nests all endpoint routers.
/// Applies the global CORS policies and Governor rate limiting middleware configurations.
pub fn create_router(state: AppState) -> Router {
    // Rate limiter configuration: 5 requests per 10 seconds (0.5 requests per second)
    // with a burst size of 5.
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(2) // 2 requests per second
            .burst_size(5) // burst of 5
            .finish()
            .unwrap(),
    );

    let auth_routes = Router::new()
        .route("/signup", post(auth::signup_handler))
        .route("/login", post(auth::login_handler))
        .route("/logout", post(auth::logout_handler))
        .route("/refresh", post(auth::refresh_handler))
        .route("/me", axum::routing::get(auth::me_handler))
        .route("/verify-email", post(auth::verify_email_handler))
        .route(
            "/resend-verification",
            post(auth::resend_verification_handler),
        )
        .route("/mfa/enroll", post(mfa::enroll_handler))
        .route("/mfa/enable", post(mfa::enable_handler))
        .route("/mfa/disable", post(mfa::disable_handler))
        .route("/mfa/verify", post(mfa::verify_handler))
        .route(
            "/oauth/{provider}/authorize",
            axum::routing::get(oauth::authorize_handler),
        )
        .route(
            "/oauth/{provider}/callback",
            axum::routing::get(oauth::callback_handler),
        )
        .route("/forgot-password", post(auth::forgot_password_handler))
        .route("/reset-password", post(auth::reset_password_handler))
        .route("/change-password", post(auth::change_password_handler))
        .route("/magic-link", post(auth::request_magic_link_handler))
        .route("/magic-link/verify", post(auth::verify_magic_link_handler))
        .layer(GovernorLayer::new(governor_config.clone()));

    let org_routes = Router::new()
        .route(
            "/",
            post(orgs::create_org_handler).get(orgs::list_orgs_handler),
        )
        .route(
            "/{org_id}/members",
            axum::routing::get(orgs::list_members_handler).post(orgs::add_member_handler),
        )
        .route(
            "/{org_id}/members/{user_id}",
            axum::routing::patch(orgs::update_member_handler).delete(orgs::remove_member_handler),
        )
        .layer(GovernorLayer::new(governor_config.clone()));

    let session_routes = Router::new()
        .route(
            "/",
            axum::routing::get(sessions::list_sessions_handler)
                .delete(sessions::revoke_all_sessions_handler),
        )
        .route(
            "/{session_id}",
            axum::routing::delete(sessions::revoke_session_handler),
        )
        .layer(GovernorLayer::new(governor_config.clone()));

    let admin_routes = Router::new()
        .route("/projects", post(admin::create_project_handler))
        .route("/webhooks", post(admin::create_webhook_handler));

    let allowed_origins: Vec<axum::http::HeaderValue> = state
        .config
        .allowed_cors_origins
        .split(',')
        .map(|s| s.trim().parse().unwrap())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::HeaderName::from_static("x-project-id"),
            header::HeaderName::from_static("idempotency-key"),
            header::HeaderName::from_static("x-admin-api-key"),
        ])
        .allow_credentials(true);

    Router::new()
        .nest("/v1/auth", auth_routes)
        .nest("/v1/orgs", org_routes)
        .nest("/v1/sessions", session_routes)
        .nest("/v1/admin", admin_routes)
        .route(
            "/.well-known/jwks.json",
            axum::routing::get(jwks::jwks_handler),
        )
        .layer(cors)
        .with_state(state)
}
