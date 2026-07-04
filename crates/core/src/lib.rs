//! Core business logic engine for OmniAuth multi-tenant authentication platform.
//! Declares error types, user schemas, session lifecycle, token signing, organizations, webhooks, and MFA.

pub mod error;
pub mod mfa;
pub mod oauth;
pub mod orgs;
pub mod projects;
pub mod sessions;
pub mod tokens;
pub mod users;
pub mod webhooks;
