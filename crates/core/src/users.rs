//! Multi-tenant User identity and authentication management.
//! Handles password hashing with Argon2id, credentials verification, registration, and MFA settings.

use crate::error::{AuthError, Result};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow, Clone)]
pub struct User {
    pub id: Uuid,
    pub project_id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Hashes a plain-text password using the Argon2id key derivation function.
/// Automatically generates a cryptographically secure salt.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AuthError::PasswordHash(e.to_string()))
        .map(|h| h.to_string())
}

/// Verifies a user password input matches the stored Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| AuthError::PasswordHash(e.to_string()))?;

    let argon2 = Argon2::default();
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Registers a new user account under a specific tenant project.
/// Validates basic email formatting and normalizes input to lowercase.
pub async fn signup(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    email: &str,
    password: &str,
) -> Result<User> {
    let email_normalized = email.trim().to_lowercase();
    if email_normalized.is_empty() || !email_normalized.contains('@') {
        return Err(AuthError::InvalidCredentials);
    }

    let password_hash = hash_password(password)?;
    let user_id = Uuid::now_v7();

    let result = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, project_id, email, password_hash)
         VALUES ($1, $2, $3, $4)
         RETURNING id, project_id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at"
    )
    .bind(user_id)
    .bind(project_id)
    .bind(email_normalized)
    .bind(password_hash)
    .fetch_one(pool)
    .await;

    match result {
        Ok(user) => Ok(user),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            Err(AuthError::UserAlreadyExists)
        }
        Err(e) => Err(AuthError::Database(e)),
    }
}

/// Validates a user's sign-in credentials.
///
/// Implements timing attack mitigation: if the requested email is not found,
/// it still runs a mock password verification step using a dummy hash,
/// ensuring that valid and invalid email lookups take roughly the same time.
///
/// # Parameters
/// - `pool`: The database connection pool.
/// - `project_id`: Target tenant project UUID.
/// - `email`: User's input email.
/// - `password`: User's input password.
pub async fn login(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    email: &str,
    password: &str,
) -> Result<User> {
    let email_normalized = email.trim().to_lowercase();

    let user = sqlx::query_as::<_, User>(
        "SELECT id, project_id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at
         FROM users
         WHERE project_id = $1 AND email = $2"
    )
    .bind(project_id)
    .bind(email_normalized)
    .fetch_optional(pool)
    .await?;

    let user = match user {
        Some(u) => u,
        None => {
            // Mitigate user enumeration timing attack by performing a dummy verification
            let dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$dGVzdHBhc3N3b3Jk";
            let _ = verify_password(password, dummy_hash);
            return Err(AuthError::InvalidCredentials);
        }
    };

    if verify_password(password, &user.password_hash)? {
        Ok(user)
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

/// Fetches a user profile from the database by its primary UUID key.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `user_id`: Target user account UUID.
pub async fn get_user_by_id(pool: &sqlx::PgPool, user_id: Uuid) -> Result<User> {
    let user = sqlx::query_as::<_, User>(
        "SELECT id, project_id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at
         FROM users
         WHERE id = $1"
    )
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(user)
}

/// Updates a user's multi-factor authentication (MFA) parameters (secret key and activation status).
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `user_id`: Target user account UUID.
/// - `mfa_secret`: Optional Base32 encoded TOTP key. Pass `None` to clear MFA settings.
/// - `mfa_enabled`: Activation boolean flag.
pub async fn update_mfa_settings(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    mfa_secret: Option<String>,
    mfa_enabled: bool,
) -> Result<()> {
    sqlx::query(
        "UPDATE users
         SET mfa_secret = $1, mfa_enabled = $2, updated_at = NOW()
         WHERE id = $3",
    )
    .bind(mfa_secret)
    .bind(mfa_enabled)
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "my_secure_password";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }
}
