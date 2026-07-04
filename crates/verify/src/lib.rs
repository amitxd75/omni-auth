//! Fetches JWKS from an omni-auth server and verifies tokens offline.
//! Framework-agnostic — wrap with axum/actix middleware in the consuming app.

use base64::prelude::*;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub project_id: String,
    pub sid: String,
    pub exp: usize,
    pub iat: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("token expired")]
    Expired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("jwks fetch failed: {0}")]
    JwksFetchFailed(String),
    #[error("invalid token claims: {0}")]
    InvalidClaims(String),
    #[error("key not found in jwks")]
    KeyNotFound,
}

#[derive(Debug, Deserialize)]
struct JwkKey {
    kty: String,
    #[serde(rename = "use")]
    _use: String,
    crv: String,
    kid: String,
    x: String,
}

#[derive(Debug, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

struct Cache {
    keys: std::collections::HashMap<String, DecodingKey>,
    expires_at: DateTime<Utc>,
}

/// Token verification client that handles offline validation.
/// Maintains an in-memory thread-safe cache of public JWK keys fetched from the server.
pub struct Verifier {
    jwks_url: String,
    client: reqwest::Client,
    cache: RwLock<Option<Cache>>,
    cache_ttl: Duration,
}

impl Verifier {
    /// Creates a new JWKS token Verifier client.
    ///
    /// # Parameters
    /// - `jwks_url`: URL of the auth server's `/.well-known/jwks.json` endpoint.
    pub fn new(jwks_url: &str) -> Self {
        Self {
            jwks_url: jwks_url.to_string(),
            client: reqwest::Client::new(),
            cache: RwLock::new(None),
            cache_ttl: Duration::hours(1),
        }
    }

    /// Fetches the Ed25519 decoding key matching a key ID (`kid`).
    ///
    /// Implements double-checked locking with a read/write lock cache.
    /// On a cache miss or cache expiration, executes a request to fetch and cache
    /// the fresh JWKS keys from the authorization server.
    ///
    /// # Parameters
    /// - `kid`: Key Identifier string.
    async fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, VerifyError> {
        // Read lock scope
        {
            let cache_opt = self.cache.read().await;
            if let Some(cache) = &*cache_opt
                && Utc::now() < cache.expires_at
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }

        // Cache miss or expired: fetch new keys and acquire write lock
        let mut cache_opt = self.cache.write().await;
        // Double check in case another thread populated it
        if let Some(cache) = &*cache_opt
            && Utc::now() < cache.expires_at
            && let Some(key) = cache.keys.get(kid)
        {
            return Ok(key.clone());
        }

        // Fetch JWKS from auth server
        let response = self
            .client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| VerifyError::JwksFetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(VerifyError::JwksFetchFailed(format!(
                "HTTP status {}",
                response.status()
            )));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| VerifyError::JwksFetchFailed(e.to_string()))?;

        let mut keys = std::collections::HashMap::new();
        for key in jwks.keys {
            if key.kty == "OKP" && key.crv == "Ed25519" {
                let bytes = BASE64_URL_SAFE_NO_PAD.decode(&key.x).map_err(|_| {
                    VerifyError::JwksFetchFailed("Invalid base64url key parameter".to_string())
                })?;
                let dec_key = DecodingKey::from_ed_der(&bytes);
                keys.insert(key.kid, dec_key);
            }
        }

        let new_cache = Cache {
            keys,
            expires_at: Utc::now() + self.cache_ttl,
        };

        let dec_key = new_cache
            .keys
            .get(kid)
            .ok_or(VerifyError::KeyNotFound)?
            .clone();

        *cache_opt = Some(new_cache);

        Ok(dec_key)
    }

    /// Verifies the signature of a JWT access token offline.
    ///
    /// Decodes the token header to retrieve the key ID (`kid`), resolves the Ed25519
    /// decoding key using `get_decoding_key()`, and performs standard cryptographic signature check.
    ///
    /// # Parameters
    /// - `token`: The raw JWT bearer token string.
    pub async fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        let header = decode_header(token).map_err(|_| VerifyError::InvalidSignature)?;
        let kid = header.kid.ok_or(VerifyError::KeyNotFound)?;

        let decoding_key = self.get_decoding_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;

        let token_data =
            decode::<Claims>(token, &decoding_key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => VerifyError::Expired,
                _ => VerifyError::InvalidSignature,
            })?;

        Ok(token_data.claims)
    }
}
