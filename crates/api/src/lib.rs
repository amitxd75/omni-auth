//! Main application bootstrap entry point.
//! Exposes all API sub-modules for consumption as a library and defines the standalone runtime.

pub mod config;
pub mod email;
pub mod middleware;
pub mod redis;
pub mod routes;
pub mod webhooks;

/// Starts the OmniAuth API server in standalone mode.
pub async fn run_standalone() -> anyhow::Result<()> {
    // Load environment variables from .env file
    let _ = dotenvy::dotenv();

    // Initialize logging (try_init to avoid panics if already initialized by parent process)
    let _ = tracing_subscriber::fmt::try_init();

    // 1. Load config
    let config = config::Config::load()?;
    tracing::info!("Loaded configuration successfully");

    // 2. Connect to database
    let db_pool = sqlx::PgPool::connect(&config.database_url).await?;
    tracing::info!("Connected to Postgres database");

    // 3. Run database migrations
    sqlx::migrate!("../migrations/migrations")
        .run(&db_pool)
        .await?;
    tracing::info!("Applied database migrations");

    // 4. Connect to Redis and create ConnectionManager
    let redis_client = ::redis::Client::open(config.redis_url.clone())?;
    let redis_conn = ::redis::aio::ConnectionManager::new(redis_client).await?;
    tracing::info!("Initialized Redis connection manager");

    // 5. Seed default project
    let default_project = omni_auth_core::projects::ensure_default_project(&db_pool).await?;
    tracing::info!("Default project ensured: ID = {}", default_project.id);

    // 6. Build AppState
    let state = middleware::AppState {
        db: db_pool,
        redis: redis_conn,
        config: config.clone(),
    };

    // 7. Initialize router
    let app = routes::create_router(state).route("/health", axum::routing::get(|| async { "ok" }));

    // 8. Start listening
    let addr = format!("{}:{}", config.host, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("OmniAuth server listening standalone on http://{}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
