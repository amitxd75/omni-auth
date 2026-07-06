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

/// Atomically acquires a token from the Redis token-bucket rate limiter.
/// Returns Ok(true) if allowed, Ok(false) if rate-limited.
pub async fn acquire_rate_limit_token(
    redis_conn: &mut ConnectionManager,
    key: &str,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
) -> Result<bool> {
    let redis_key = format!("omni-auth:rate_limit:{}", key);
    let now = chrono::Utc::now().timestamp() as f64;

    let script = redis::Script::new(
        r#"
        local key = KEYS[1]
        local max_tokens = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])

        local data = redis.call('HMGET', key, 'tokens', 'last_updated')
        local tokens = tonumber(data[1])
        local last_updated = tonumber(data[2])

        if not tokens then
            tokens = max_tokens
            last_updated = now
        else
            local elapsed = math.max(0, now - last_updated)
            tokens = math.min(max_tokens, tokens + elapsed * refill_rate)
            last_updated = now
        end

        if tokens >= 1 then
            tokens = tokens - 1
            redis.call('HMSET', key, 'tokens', tokens, 'last_updated', last_updated)
            redis.call('EXPIRE', key, 86400)
            return 1
        else
            return 0
        end
    "#,
    );

    let allowed: i32 = script
        .key(&redis_key)
        .arg(max_tokens)
        .arg(refill_rate)
        .arg(now)
        .invoke_async(redis_conn)
        .await?;

    Ok(allowed == 1)
}
