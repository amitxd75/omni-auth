//! Project tenant workspace configuration and cryptographic key pair management.
//! Every project holds unique Ed25519 asymmetric keys for token signing and verification.

use crate::error::{AuthError, Result};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use rand::RngExt;

pub const DEFAULT_PROJECT_ID: Uuid = Uuid::nil(); // 00000000-0000-0000-0000-000000000000

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub jwt_private_key: String, // Base64 encoded PKCS#8 DER bytes
    pub jwt_public_key: String,  // Base64 encoded raw public key
    pub api_key: String,         // Private API key/secret
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Generates a cryptographically secure random API key for projects.
/// Used for server-to-server connection verification.
pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    rand::rng().fill(&mut bytes);
    format!("oa_proj_{}", BASE64_URL_SAFE_NO_PAD.encode(bytes))
}

/// Generates a new Ed25519 PKCS#8 key pair.
/// The public and private keys are returned as Base64-encoded strings.
///
/// # Returns
/// A tuple of `(private_key_b64, public_key_b64)`.
pub fn generate_keypair() -> Result<(String, String)> {
    let rng = SystemRandom::new();
    let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| AuthError::Crypto("Failed to generate Ed25519 PKCS8 key".to_string()))?;

    let pkcs8_bytes = pkcs8_doc.as_ref();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes)
        .map_err(|e| AuthError::Crypto(format!("Failed to parse generated keypair: {}", e)))?;

    let public_key_bytes = key_pair.public_key().as_ref();

    let priv_b64 = BASE64_STANDARD.encode(pkcs8_bytes);
    let pub_b64 = BASE64_STANDARD.encode(public_key_bytes);

    Ok((priv_b64, pub_b64))
}

/// Verification helper that checks the database for a seeded fallback project workspace.
/// If absent (e.g. fresh environment installation), generates a default project.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
///
/// # Returns
/// The existing or newly bootstrapped default `Project`.
pub async fn ensure_default_project(pool: &sqlx::PgPool) -> Result<Project> {
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at FROM projects WHERE id = $1"
    )
    .bind(DEFAULT_PROJECT_ID)
    .fetch_optional(pool)
    .await?;

    match project {
        Some(p) => Ok(p),
        None => {
            let (priv_key, pub_key) = generate_keypair()?;
            let new_project = sqlx::query_as::<_, Project>(
                "INSERT INTO projects (id, name, jwt_private_key, jwt_public_key, api_key)
                 VALUES ($1, $2, $3, $4, $5)
                 RETURNING id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at",
            )
            .bind(DEFAULT_PROJECT_ID)
            .bind("Default Project")
            .bind(priv_key)
            .bind(pub_key)
            .bind("oa_proj_default_project_api_key_replace_me")
            .fetch_one(pool)
            .await?;

            Ok(new_project)
        }
    }
}

/// Retrieves a project's parameters and keys from the database using its UUID identifier.
///
/// # Parameters
/// - `pool`: PostgreSQL database connection pool.
/// - `id`: The UUID of the project to retrieve.
pub async fn get_project(pool: &sqlx::PgPool, id: Uuid) -> Result<Project> {
    let project = sqlx::query_as::<_, Project>(
        "SELECT id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at FROM projects WHERE id = $1"
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    project.ok_or(AuthError::ProjectNotFound)
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::tokens::{generate_tokens, verify_access_token};
    use sqlx::PgPool;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_db_keys() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@localhost:5432/omni_auth".to_string());
        let pool = PgPool::connect(&db_url).await.unwrap();
        let project = ensure_default_project(&pool).await.unwrap();

        let user_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();

        let tokens = generate_tokens(&project, user_id, session_id, 15, 7);
        assert!(tokens.is_ok(), "generate_tokens failed: {:?}", tokens.err());

        let (access, _, _) = tokens.unwrap();
        let claims = verify_access_token(&project, &access);
        assert!(
            claims.is_ok(),
            "verify_access_token failed: {:?}",
            claims.err()
        );
    }

    #[tokio::test]
    async fn test_project_api_key() {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@localhost:5432/omni_auth".to_string());
        let pool = PgPool::connect(&db_url).await.unwrap();

        let project_id = Uuid::now_v7();
        let api_key = generate_api_key();
        let (priv_key, pub_key) = generate_keypair().unwrap();

        let inserted = sqlx::query_as::<_, Project>(
            "INSERT INTO projects (id, name, jwt_private_key, jwt_public_key, api_key)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at",
        )
        .bind(project_id)
        .bind("Test Auth Key Project")
        .bind(priv_key)
        .bind(pub_key)
        .bind(&api_key)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(inserted.id, project_id);
        assert_eq!(inserted.api_key, api_key);

        // Fetch back by api_key to confirm retrieval works
        let fetched = sqlx::query_as::<_, Project>(
            "SELECT id, name, jwt_private_key, jwt_public_key, api_key, created_at, updated_at 
             FROM projects WHERE api_key = $1",
        )
        .bind(&api_key)
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(fetched.id, project_id);
        assert_eq!(fetched.api_key, api_key);

        // Cleanup
        sqlx::query("DELETE FROM projects WHERE id = $1")
            .bind(project_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
