//! Cryptographic JWT creation, verification, and rotation.
//! Handles access tokens, refresh tokens, MFA tickets, and Redis-based token-reuse (replay attack) protection.

use crate::error::{AuthError, Result};
use crate::projects::Project;
use crate::sessions::{get_session, revoke_session};
use base64::prelude::*;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessTokenClaims {
    pub sub: String, // User ID
    pub sid: String, // Session ID
    pub project_id: String,
    pub exp: usize, // Expiration time (epoch seconds)
    pub iat: usize, // Issued at (epoch seconds)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RefreshTokenClaims {
    pub sub: String, // User ID
    pub jti: String, // Refresh Token ID (UUID v7)
    pub sid: String, // Session ID
    pub project_id: String,
    pub exp: usize, // Expiration time (epoch seconds)
    pub iat: usize, // Issued at (epoch seconds)
}

/// Generates a paired JWT access token and refresh token for an active user session.
/// Access and Refresh tokens are cryptographically signed using the project's private Ed25519 key.
///
/// # Parameters
/// - `project`: Reference to the Project context containing keys.
/// - `user_id`: Target user UUID.
/// - `session_id`: Unique database session ID linking the tokens.
/// - `access_ttl_mins`: Access token lifetime duration in minutes.
/// - `refresh_ttl_days`: Refresh token lifetime duration in days.
///
/// # Returns
/// A tuple of `(access_token_string, refresh_token_string, refresh_token_jti_uuid)`.
pub fn generate_tokens(
    project: &Project,
    user_id: Uuid,
    session_id: Uuid,
    access_ttl_mins: i64,
    refresh_ttl_days: i64,
) -> Result<(String, String, Uuid)> {
    let now = Utc::now();
    let access_exp = now + Duration::minutes(access_ttl_mins);
    let refresh_exp = now + Duration::days(refresh_ttl_days);

    let access_claims = AccessTokenClaims {
        sub: user_id.to_string(),
        sid: session_id.to_string(),
        project_id: project.id.to_string(),
        exp: access_exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let refresh_jti = Uuid::now_v7();
    let refresh_claims = RefreshTokenClaims {
        sub: user_id.to_string(),
        jti: refresh_jti.to_string(),
        sid: session_id.to_string(),
        project_id: project.id.to_string(),
        exp: refresh_exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let priv_key_der = BASE64_STANDARD.decode(&project.jwt_private_key)?;
    let encoding_key = EncodingKey::from_ed_der(&priv_key_der);

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(project.id.to_string());
    let access_token = encode(&header, &access_claims, &encoding_key)?;
    let refresh_token = encode(&header, &refresh_claims, &encoding_key)?;

    Ok((access_token, refresh_token, refresh_jti))
}

/// Verifies an Access Token signature offline using the project's public key.
/// Validates expiration claims and returns the deserialized claims struct.
pub fn verify_access_token(project: &Project, token: &str) -> Result<AccessTokenClaims> {
    let pub_key_der = BASE64_STANDARD.decode(&project.jwt_public_key)?;
    let decoding_key = DecodingKey::from_ed_der(&pub_key_der);
    let validation = Validation::new(Algorithm::EdDSA);

    let token_data = decode::<AccessTokenClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

/// Verifies a Refresh Token signature offline using the project's public key.
/// Validates expiration claims and returns the deserialized claims struct.
pub fn verify_refresh_token(project: &Project, token: &str) -> Result<RefreshTokenClaims> {
    let pub_key_der = BASE64_STANDARD.decode(&project.jwt_public_key)?;
    let decoding_key = DecodingKey::from_ed_der(&pub_key_der);
    let validation = Validation::new(Algorithm::EdDSA);

    let token_data = decode::<RefreshTokenClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

/// Performs Refresh Token Rotation (RTR) and detects token reuse (replay attacks).
///
/// If a client submits a refresh token that has already been rotated (flagged in Redis),
/// this constitutes a potential theft. The server immediately revokes the parent database session,
/// invalidating all active refresh/access tokens in that family.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `redis_conn`: Redis connection manager for tracking used tokens.
/// - `project`: Reference to the tenant project context.
/// - `refresh_token`: The incoming raw refresh token to inspect.
/// - `access_ttl_mins`: Default lifetime for the new access token.
/// - `refresh_ttl_days`: Default lifetime for the new rotated refresh token.
pub async fn rotate_refresh_token(
    pool: &sqlx::PgPool,
    redis_conn: &mut redis::aio::ConnectionManager,
    project: &Project,
    refresh_token: &str,
    access_ttl_mins: i64,
    refresh_ttl_days: i64,
) -> Result<(String, String)> {
    let claims = verify_refresh_token(project, refresh_token)?;

    let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidToken)?;
    let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken)?;
    let jti = claims.jti.clone();

    // Check Redis for token reuse
    let reuse_key = format!("omni-auth:used-token:{}", jti);
    let has_been_used: bool = redis_conn.exists(&reuse_key).await?;

    if has_been_used {
        // REUSE DETECTED!
        // Kill the whole family by revoking the session in Postgres
        let _ = revoke_session(pool, session_id).await;
        return Err(AuthError::TokenReused);
    }

    // Verify session exists and is active in Postgres
    let session = match get_session(pool, session_id).await {
        Ok(s) => s,
        Err(_) => {
            // Session revoked or expired
            return Err(AuthError::SessionNotFound);
        }
    };

    if session.user_id != user_id {
        return Err(AuthError::InvalidToken);
    }

    // Mark current token as used in Redis with TTL = remaining lifetime of token
    let now = Utc::now().timestamp() as usize;
    let remaining_seconds = claims.exp.saturating_sub(now);

    if remaining_seconds > 0 {
        let _: () = redis_conn
            .set_ex(&reuse_key, claims.sid.clone(), remaining_seconds as u64)
            .await?;
    }

    // Generate a new token pair (updates/rotates the token, keeps same session ID)
    let (new_access, new_refresh, _) = generate_tokens(
        project,
        user_id,
        session_id,
        access_ttl_mins,
        refresh_ttl_days,
    )?;

    // We can also extend/update the session expires_at if we want, but for now we'll keep it simple

    Ok((new_access, new_refresh))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MfaTicketClaims {
    pub sub: String, // User ID
    pub project_id: String,
    pub exp: usize,
    pub iat: usize,
}

/// Generates a short-lived (5 minutes) MFA sign-in ticket token.
/// Used to authenticate MFA code verification endpoints after successful password verification.
pub fn generate_mfa_ticket(project: &Project, user_id: Uuid) -> Result<String> {
    let now = Utc::now();
    let exp = now + Duration::minutes(5);

    let claims = MfaTicketClaims {
        sub: user_id.to_string(),
        project_id: project.id.to_string(),
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    let priv_key_der = BASE64_STANDARD.decode(&project.jwt_private_key)?;
    let encoding_key = EncodingKey::from_ed_der(&priv_key_der);
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(project.id.to_string());
    let ticket = encode(&header, &claims, &encoding_key)?;

    Ok(ticket)
}

/// Verifies the signature of an MFA ticket and returns the associated user's UUID.
pub fn verify_mfa_ticket(project: &Project, ticket: &str) -> Result<Uuid> {
    let pub_key_der = BASE64_STANDARD.decode(&project.jwt_public_key)?;
    let decoding_key = DecodingKey::from_ed_der(&pub_key_der);
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;

    let token_data =
        decode::<MfaTicketClaims>(ticket, &decoding_key, &validation).map_err(AuthError::Jwt)?;

    let user_id = Uuid::parse_str(&token_data.claims.sub).map_err(|_| AuthError::InvalidToken)?;

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projects::generate_keypair;
    use uuid::Uuid;

    #[test]
    fn test_token_generation_and_verification() {
        let (priv_key, pub_key) = generate_keypair().unwrap();
        let project = Project {
            id: Uuid::now_v7(),
            name: "Test Project".to_string(),
            jwt_private_key: priv_key,
            jwt_public_key: pub_key,
            api_key: "oa_proj_test_api_key".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let user_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();

        let (access, refresh, jti) = generate_tokens(&project, user_id, session_id, 15, 7).unwrap();

        let access_claims = verify_access_token(&project, &access).unwrap();
        assert_eq!(access_claims.sub, user_id.to_string());
        assert_eq!(access_claims.sid, session_id.to_string());

        let refresh_claims = verify_refresh_token(&project, &refresh).unwrap();
        assert_eq!(refresh_claims.sub, user_id.to_string());
        assert_eq!(refresh_claims.sid, session_id.to_string());
        assert_eq!(refresh_claims.jti, jti.to_string());
    }
}
