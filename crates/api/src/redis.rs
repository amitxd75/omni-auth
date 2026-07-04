//! Redis cache operations for request idempotency keys.
//! Prevents duplicate request processing (e.g. double payments or creations) by storing state for 5 minutes.

use omni_auth_core::error::{AuthError, Result};
use redis::AsyncCommands;
pub use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum IdempotencyStatus {
    InProgress,
    Completed { status: u16, body: String },
}

/// Key prefix for idempotency store
const IDEMPOTENCY_PREFIX: &str = "omni-auth:idempotency:";
/// TTL for idempotency records (5 minutes)
const IDEMPOTENCY_TTL: u64 = 300;

/// Queries Redis to check if a specific idempotency key has already been registered.
pub async fn check_idempotency(
    redis_conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<IdempotencyStatus>> {
    let full_key = format!("{}{}", IDEMPOTENCY_PREFIX, key);
    let val: Option<String> = redis_conn.get(&full_key).await?;

    match val {
        Some(s) => {
            let status = serde_json::from_str(&s).map_err(|e| {
                AuthError::Crypto(format!("Failed to parse idempotency status: {}", e))
            })?;
            Ok(Some(status))
        }
        None => Ok(None),
    }
}

/// Registers a lock in Redis indicating that request processing is in progress.
pub async fn set_idempotency_in_progress(
    redis_conn: &mut ConnectionManager,
    key: &str,
) -> Result<()> {
    let full_key = format!("{}{}", IDEMPOTENCY_PREFIX, key);
    let status = IdempotencyStatus::InProgress;
    let serialized = serde_json::to_string(&status)
        .map_err(|e| AuthError::Crypto(format!("Failed to serialize idempotency status: {}", e)))?;

    let _: () = redis_conn
        .set_ex(&full_key, serialized, IDEMPOTENCY_TTL)
        .await?;
    Ok(())
}

/// Stores the completed HTTP response status and body in Redis against the idempotency key.
pub async fn set_idempotency_completed(
    redis_conn: &mut ConnectionManager,
    key: &str,
    status_code: u16,
    body: &str,
) -> Result<()> {
    let full_key = format!("{}{}", IDEMPOTENCY_PREFIX, key);
    let status = IdempotencyStatus::Completed {
        status: status_code,
        body: body.to_string(),
    };
    let serialized = serde_json::to_string(&status)
        .map_err(|e| AuthError::Crypto(format!("Failed to serialize idempotency status: {}", e)))?;

    let _: () = redis_conn
        .set_ex(&full_key, serialized, IDEMPOTENCY_TTL)
        .await?;
    Ok(())
}
