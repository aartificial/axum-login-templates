mod routes;

use login::run;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url =
        dotenv::var("DATABASE_URL").map_err(|e| format!("Failed to get DATABASE_URL: {}", e))?;
    run(database_url).await
}
