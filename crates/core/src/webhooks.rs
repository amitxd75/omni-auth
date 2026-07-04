//! Multi-tenant Webhook registration and cryptographic signature validation.
//! Permits tenant applications to register event-driven hooks and sign outgoing JSON payloads using HMAC-SHA256.

use crate::error::Result;
use ring::hmac;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct WebhookEndpoint {
    pub id: Uuid,
    pub project_id: Uuid,
    pub url: String,
    pub secret: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Serialize)]
pub struct WebhookPayload {
    pub event: String,
    pub data: serde_json::Value,
    pub timestamp: i64,
}

/// Helper function to format binary byte slices into lowercase hex strings.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Computes the HMAC-SHA256 signature hash of a string webhook payload body.
///
/// Used by client backends to verify that incoming webhook payloads are genuine
/// and have not been tampered with or intercepted in transit.
///
/// # Parameters
/// - `secret`: Private webhook signing key.
/// - `payload`: Raw JSON payload string body.
///
/// # Returns
/// A lowercase hex-encoded string of the computed HMAC signature.
pub fn calculate_webhook_signature(secret: &str, payload: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, payload.as_bytes());
    bytes_to_hex(tag.as_ref())
}

/// Inserts a new webhook subscriber URL endpoint record into the database.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `project_id`: ID of the project workspace.
/// - `url`: Destination HTTP URL to dispatch events.
/// - `secret`: Private token used for payload signature creation.
pub async fn register_webhook_endpoint(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    url: &str,
    secret: &str,
) -> Result<WebhookEndpoint> {
    let id = Uuid::now_v7();
    let endpoint = sqlx::query_as::<_, WebhookEndpoint>(
        "INSERT INTO webhook_endpoints (id, project_id, url, secret)
         VALUES ($1, $2, $3, $4)
         RETURNING id, project_id, url, secret, created_at",
    )
    .bind(id)
    .bind(project_id)
    .bind(url)
    .bind(secret)
    .fetch_one(pool)
    .await?;

    Ok(endpoint)
}

/// Retrieves all registered webhook endpoints associated with a project.
pub async fn get_webhook_endpoints(
    pool: &sqlx::PgPool,
    project_id: Uuid,
) -> Result<Vec<WebhookEndpoint>> {
    let endpoints = sqlx::query_as::<_, WebhookEndpoint>(
        "SELECT id, project_id, url, secret, created_at
         FROM webhook_endpoints
         WHERE project_id = $1",
    )
    .bind(project_id)
    .fetch_all(pool)
    .await?;

    Ok(endpoints)
}
