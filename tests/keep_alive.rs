use std::net::SocketAddr;

use axum::{Router, extract::ConnectInfo, routing::get};
use tls_rust::{ClientBuilder, ClientProfile, Request};

async fn remote_addr(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
    addr.to_string()
}

#[tokio::test]
async fn reuses_same_connection_by_default() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route("/", get(remote_addr));
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .build()
        .expect("client should build");

    let url = format!("http://{addr}/");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..5 {
        let response = client
            .execute(Request::get(url.clone()))
            .await
            .expect("request should succeed");
        seen.insert(response.text().await.expect("response body"));
    }

    assert_eq!(seen.len(), 1);
    server.abort();
}

#[tokio::test]
async fn uses_different_connections_when_keep_alive_disabled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route("/", get(remote_addr));
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .disable_keep_alives(true)
        .build()
        .expect("client should build");

    let url = format!("http://{addr}/");
    let mut seen = std::collections::HashSet::new();
    for _ in 0..5 {
        let response = client
            .execute(Request::get(url.clone()))
            .await
            .expect("request should succeed");
        seen.insert(response.text().await.expect("response body"));
    }

    assert_eq!(seen.len(), 5);
    server.abort();
}
