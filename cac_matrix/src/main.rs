use axum::{http::HeaderMap, response::IntoResponse, routing::get};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let listener = tokio::net::UnixListener::bind("/run/serve")?;
    let router = axum::Router::new().route("/", get(auth));
    axum::serve(listener, router).await?;
    println!("Hello, world!");
    Ok(())
}

async fn auth(headers: HeaderMap) -> impl IntoResponse {
    headers.get("X-CN")
}
