use std::io::Write;

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Response, StatusCode, header},
    routing::get,
};
use flate2::{Compression, write::GzEncoder};
use tls_rust::{ClientBuilder, ClientProfile, Request};

async fn gzip_handler() -> Response<Body> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(b"hello compressed").expect("write");
    let body = encoder.finish().expect("finish");

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"))
        .body(Body::from(body))
        .expect("response")
}

#[tokio::test]
async fn keeps_compressed_response_when_auto_decompression_is_disabled() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route("/", get(gzip_handler));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .disable_compression(true)
        .build()
        .expect("client should build");

    let response = client
        .execute(
            Request::get(format!("http://{addr}/"))
                .header("Accept-Encoding", "gzip, deflate, br, zstd"),
        )
        .await
        .expect("request should succeed");

    assert_eq!(
        response.headers().get(header::CONTENT_ENCODING),
        Some(&HeaderValue::from_static("gzip"))
    );
    let body = response.bytes().await.expect("body bytes");
    assert!(body.starts_with(&[0x1f, 0x8b]));

    server.abort();
}
