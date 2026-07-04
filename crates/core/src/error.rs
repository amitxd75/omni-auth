//! Custom error types and Result wrapper for the core authentication engine.
//! Maps database, Redis, cryptographic, and JWT validation errors to domain-specific errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("Invalid email or password")]
    InvalidCredentials,

    #[error("User already exists")]
    UserAlreadyExists,

    #[error("Project not found")]
    ProjectNotFound,

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("Token has been reused")]
    TokenReused,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
}

pub type Result<T> = std::result::Result<T, AuthError>;
