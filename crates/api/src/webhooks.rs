//! Outbound webhook notification dispatcher service.
//! Dispatches event payloads to registered listener endpoints concurrently in the background.

use omni_auth_core::webhooks::{
    WebhookPayload, calculate_webhook_signature, get_webhook_endpoints,
};
use uuid::Uuid;

/// Triggers and sends a webhook event payload to all registered project subscribers.
///
/// Spawns a supervisor task that fetches target hooks from the database, serializes the payload,
/// computes the HMAC-SHA256 signature, and maps concurrent HTTP POST requests on separate green threads.
///
/// # Parameters
/// - `db`: Database pool.
/// - `project_id`: Target tenant project UUID.
/// - `event`: Event tag (e.g. `user.signup`).
/// - `data`: Event payload metadata payload.
pub fn trigger_webhook(
    db: sqlx::PgPool,
    project_id: Uuid,
    event: &'static str,
    data: serde_json::Value,
) {
    tokio::spawn(async move {
        let endpoints = match get_webhook_endpoints(&db, project_id).await {
            Ok(e) => e,
            Err(_) => return,
        };

        if endpoints.is_empty() {
            return;
        }

        let payload = WebhookPayload {
            event: event.to_string(),
            data,
            timestamp: chrono::Utc::now().timestamp(),
        };

        let payload_str = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(_) => return,
        };

        let client = reqwest::Client::new();

        for endpoint in endpoints {
            let signature = calculate_webhook_signature(&endpoint.secret, &payload_str);
            let url = endpoint.url.clone();
            let payload_str_clone = payload_str.clone();
            let client_clone = client.clone();

            tokio::spawn(async move {
                let _ = client_clone
                    .post(&url)
                    .header("X-Omni-Signature", signature)
                    .header("Content-Type", "application/json")
                    .body(payload_str_clone)
                    .send()
                    .await;
            });
        }
    });
}
