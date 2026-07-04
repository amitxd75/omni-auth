//! OAuth identity management and mapping.
//! Resolves federated social logins (GitHub, Google, etc.) and links them to local system users.

use crate::error::{AuthError, Result};
use crate::users::{User, signup};
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct OauthAccount {
    pub id: Uuid,
    pub user_id: Uuid,
    pub project_id: Uuid,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Resolves a user associated with an OAuth credential.
///
/// If the social identity is already mapped, returns the existing user.
/// If not, but the email matches an existing account, links them.
/// Otherwise, registers a new user with a random unguessable password and links them.
///
/// # Parameters
/// - `pool`: The database connection pool.
/// - `project_id`: The ID of the tenant project.
/// - `provider`: Name of the social provider (e.g. "github", "google").
/// - `provider_user_id`: The provider's unique user ID.
/// - `email`: The user's verified primary email.
pub async fn get_or_create_oauth_user(
    pool: &sqlx::PgPool,
    project_id: Uuid,
    provider: &str,
    provider_user_id: &str,
    email: &str,
) -> Result<User> {
    // 1. Check if the OAuth identity is already linked to an existing account
    let existing_oauth = sqlx::query_as::<_, OauthAccount>(
        "SELECT id, user_id, project_id, provider, provider_user_id, created_at
         FROM oauth_accounts
         WHERE project_id = $1 AND provider = $2 AND provider_user_id = $3",
    )
    .bind(project_id)
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await?;

    if let Some(oauth) = existing_oauth {
        // Fetch and return the linked user
        let user = sqlx::query_as::<_, User>(
            "SELECT id, project_id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at
             FROM users
             WHERE id = $1"
        )
        .bind(oauth.user_id)
        .fetch_one(pool)
        .await?;
        return Ok(user);
    }

    // 2. No existing OAuth link. Check if a user with the same email already exists in this project
    let email_normalized = email.trim().to_lowercase();
    let existing_user = sqlx::query_as::<_, User>(
        "SELECT id, project_id, email, password_hash, email_verified, mfa_enabled, mfa_secret, created_at, updated_at
         FROM users
         WHERE project_id = $1 AND email = $2"
    )
    .bind(project_id)
    .bind(&email_normalized)
    .fetch_optional(pool)
    .await?;

    let user = match existing_user {
        Some(u) => u,
        None => {
            // Create a new user with a random unguessable password
            let random_password = Uuid::now_v7().to_string();
            signup(pool, project_id, &email_normalized, &random_password).await?
        }
    };

    // 3. Create the OAuth account link
    let oauth_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, project_id, provider, provider_user_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(oauth_id)
    .bind(user.id)
    .bind(project_id)
    .bind(provider)
    .bind(provider_user_id)
    .execute(pool)
    .await?;

    Ok(user)
}

/// Explicitly maps a new social OAuth credential to an existing, authenticated user profile.
///
/// # Parameters
/// - `pool`: The database connection pool.
/// - `user_id`: Target user account UUID.
/// - `project_id`: Target tenant project UUID.
/// - `provider`: Social OAuth provider identifier.
/// - `provider_user_id`: Provider user ID to link.
///
/// # Returns
/// `Ok(())` on success, or an error if the social account is already linked.
pub async fn link_oauth_account(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    project_id: Uuid,
    provider: &str,
    provider_user_id: &str,
) -> Result<()> {
    // Check if the link already exists
    let existing = sqlx::query(
        "SELECT 1 FROM oauth_accounts
         WHERE project_id = $1 AND provider = $2 AND provider_user_id = $3",
    )
    .bind(project_id)
    .bind(provider)
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await?;

    if existing.is_some() {
        return Err(AuthError::UserAlreadyExists); // link already exists
    }

    let oauth_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO oauth_accounts (id, user_id, project_id, provider, provider_user_id)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(oauth_id)
    .bind(user_id)
    .bind(project_id)
    .bind(provider)
    .bind(provider_user_id)
    .execute(pool)
    .await?;

    Ok(())
}
