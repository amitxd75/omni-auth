//! Standalone binary entry point for OmniAuth API server.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    omni_auth_api::run_standalone().await
}
