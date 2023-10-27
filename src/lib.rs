use sqlx::postgres::PgPoolOptions;
mod routes;

pub async fn run(database_url: String) -> Result<(), Box<dyn std::error::Error>> {
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url.as_str())
        .await
        .map_err(|e| format!("DB connection failed: {}", e))?;

    let app = routes::create_routes(db_pool)
        .await
        .expect("Failed to create routes");

    let bind_addr = &"0.0.0.0:8000"
        .parse()
        .map_err(|e| format!("Failed to parse address: {}", e))?;

    axum::Server::bind(bind_addr)
        .serve(app.into_make_service())
        .await
        .map_err(|e| format!("Server error: {}", e))?;

    Ok(())
}
