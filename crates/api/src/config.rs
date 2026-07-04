//! System configuration parser.
//! Resolves configuration defaults and overrides environment variables using Figment.

use figment::{
    Figment,
    providers::{Env, Serialized},
};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub access_token_ttl_mins: i64,
    pub refresh_token_ttl_days: i64,

    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,

    pub resend_api_key: Option<String>,
    pub resend_from_email: Option<String>,

    /// Base URL of the frontend app — used to build clickable email links.
    /// Set FRONTEND_URL in your .env for production.
    pub frontend_url: String,

    pub admin_api_key: Option<String>,
    pub allowed_cors_origins: String,
    pub allow_default_project_fallback: bool,
}

impl Config {
    /// Loads configuration variables from environment and default fallbacks.
    #[allow(clippy::result_large_err)]
    pub fn load() -> Result<Self, figment::Error> {
        Figment::new()
            .merge(Serialized::default("host", "0.0.0.0".to_string()))
            .merge(Serialized::default("port", 8080))
            .merge(Serialized::default(
                "redis_url",
                "redis://127.0.0.1:6379".to_string(),
            ))
            .merge(Serialized::default("access_token_ttl_mins", 15))
            .merge(Serialized::default("refresh_token_ttl_days", 7))
            .merge(Serialized::default(
                "frontend_url",
                "http://localhost:3000".to_string(),
            ))
            .merge(Serialized::default(
                "allowed_cors_origins",
                "http://localhost:3000,http://127.0.0.1:3000".to_string(),
            ))
            .merge(Serialized::default("allow_default_project_fallback", true))
            .merge(Env::raw().map(|key| key.as_str().to_lowercase().into()))
            .extract()
    }
}
