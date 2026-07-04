//! Main application bootstrap entry point.
//! Initializes logging, configuration settings, databases connections, migrations execution, and binds the HTTP Axum server listener.

mod config;
mod email;
mod middleware;
mod redis;
mod routes;
mod webhooks;

use config::Config;
use middleware::AppState;
use omni_auth_core::projects::ensure_default_project;

/// Main server execution entry point.
///
/// Performs the following bootstrapping checklist in order:
/// 1. Instantiates environment settings from `.env`.
/// 2. Binds trace/logging console output.
/// 3. Builds and verifies database connections (PostgreSQL & Redis).
/// 4. Dispatches database schema updates via SQLx migration suite.
/// 5. Seeds fallback default project tenant parameters.
/// 6. Configures CORS and HTTP routes before serving the app on the specified port.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load environment variables from .env file
    let _ = dotenvy::dotenv();

    // Initialize logging
    tracing_subscriber::fmt::init();

    // 1. Load config
    let config = Config::load()?;
    tracing::info!("Loaded configuration successfully");

    // 2. Connect to database
    let db_pool = sqlx::PgPool::connect(&config.database_url).await?;
    tracing::info!("Connected to Postgres database");

    // 3. Run database migrations
    // The macro path is relative to crates/api/src/main.rs
    sqlx::migrate!("../migrations/migrations")
        .run(&db_pool)
        .await?;
    tracing::info!("Applied database migrations");

    // 4. Connect to Redis and create ConnectionManager
    let redis_client = ::redis::Client::open(config.redis_url.clone())?;
    let redis_conn = ::redis::aio::ConnectionManager::new(redis_client).await?;
    tracing::info!("Initialized Redis connection manager");

    // 5. Seed default project
    let default_project = ensure_default_project(&db_pool).await?;
    tracing::info!("Default project ensured: ID = {}", default_project.id);

    // 6. Build AppState
    let state = AppState {
        db: db_pool,
        redis: redis_conn,
        config: config.clone(),
    };

    // 7. Initialize router
    let app = routes::create_router(state).route("/health", axum::routing::get(|| async { "ok" }));

    // 8. Start listening
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
