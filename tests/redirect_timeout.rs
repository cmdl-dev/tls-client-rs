use std::time::Duration;

use axum::{Router, http::StatusCode, response::Redirect, routing::get};
use tls_rust::{ClientBuilder, ClientError, ClientProfile, Request};

async fn index() -> StatusCode {
    StatusCode::OK
}

async fn redirect() -> Redirect {
    Redirect::permanent("/index")
}

async fn timeout() -> &'static str {
    tokio::time::sleep(Duration::from_secs(5)).await;
    "slow"
}

fn app() -> Router {
    Router::new()
        .route("/index", get(index))
        .route("/redirect", get(redirect))
        .route("/timeout", get(timeout))
}

#[tokio::test]
async fn redirect_follow_switches_at_runtime() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app()).await.expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome105)
        .follow_redirects(false)
        .build()
        .expect("client should build");

    let url = format!("http://{addr}/redirect");
    let response = client
        .execute(Request::get(url.clone()))
        .await
        .expect("first response");
    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);

    client.set_follow_redirects(true);
    let response = client
        .execute(Request::get(url))
        .await
        .expect("second response");
    assert_eq!(response.status(), StatusCode::OK);

    server.abort();
}

#[tokio::test]
async fn timeout_returns_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app()).await.expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome105)
        .timeout(Duration::from_secs(1))
        .build()
        .expect("client should build");

    let url = format!("http://{addr}/timeout");
    let error = client
        .execute(Request::get(url))
        .await
        .expect_err("request should time out");

    match error {
        ClientError::Http(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }

    server.abort();
}
