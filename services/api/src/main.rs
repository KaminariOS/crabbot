use std::net::SocketAddr;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = crabbot_api::router();
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
