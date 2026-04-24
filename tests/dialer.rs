use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{Router, routing::get};
use tls_rust::{ClientBuilder, ClientProfile, Request};
use tokio::net::TcpListener;

async fn ok() -> &'static str {
    "ok"
}

#[tokio::test]
async fn custom_dial_context_is_used_for_http_requests() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, Router::new().route("/", get(ok)))
            .await
            .expect("serve");
    });

    let dial_count = Arc::new(AtomicUsize::new(0));
    let dial_count_clone = Arc::clone(&dial_count);
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .dial_context(move |host, port| {
            let dial_count = Arc::clone(&dial_count_clone);
            async move {
                dial_count.fetch_add(1, Ordering::SeqCst);
                tokio::net::TcpStream::connect((host.as_str(), port))
                    .await
                    .map_err(|err| tls_rust::ClientError::Http(err.to_string()))
            }
        })
        .build()
        .expect("build client");

    let response = client
        .execute(Request::get(format!("http://{addr}/")))
        .await
        .expect("request");
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(dial_count.load(Ordering::SeqCst), 1);

    server.abort();
}

#[tokio::test]
async fn public_dialer_can_open_plain_tcp_streams() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let accept = tokio::spawn(async move {
        let _ = listener.accept().await.expect("accept");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .build()
        .expect("build client");

    let _stream = client
        .get_dialer()
        .dial(addr.ip().to_string(), addr.port())
        .await
        .expect("dial");

    accept.abort();
}
