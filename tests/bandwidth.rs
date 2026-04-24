use std::sync::Arc;

use axum::{Router, http::StatusCode, routing::get};
use tls_rust::{BandwidthTracker, ClientBuilder, ClientProfile, NoopBandwidthTracker, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn payload() -> (StatusCode, &'static str) {
    (StatusCode::OK, "payload")
}

#[tokio::test]
async fn bandwidth_tracker_records_http1_traffic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let app = Router::new().route("/payload", get(payload));
        axum::serve(listener, app).await.expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome105)
        .build()
        .expect("client should build");
    let tracker = client.bandwidth_tracker();

    let response = client
        .execute(Request::get(format!("http://{addr}/payload")))
        .await
        .expect("request should succeed");
    assert_eq!(response.status(), StatusCode::OK);

    assert!(
        tracker.write_bytes() > 0,
        "expected request bytes to be tracked"
    );
    assert!(
        tracker.read_bytes() > 0,
        "expected response bytes to be tracked"
    );
    assert!(
        tracker.total_bandwidth() >= tracker.write_bytes() + tracker.read_bytes(),
        "total bandwidth should include read and write bytes"
    );

    tracker.reset();
    assert_eq!(tracker.total_bandwidth(), 0);
    assert_eq!(tracker.read_bytes(), 0);
    assert_eq!(tracker.write_bytes(), 0);

    server.abort();
}

#[tokio::test]
async fn tracked_stream_updates_counts_and_noop_tracker_stays_zero() {
    let (left, mut right) = tokio::io::duplex(64);
    let tracker = Arc::new(BandwidthTracker::new());
    let noop = NoopBandwidthTracker::new();

    let mut tracked = tracker.track_stream(left);
    right.write_all(b"ping").await.expect("write ping");
    let mut read = [0u8; 4];
    tracked.read_exact(&mut read).await.expect("read ping");
    tracked.write_all(b"pong").await.expect("write pong");
    let mut reply = [0u8; 4];
    right.read_exact(&mut reply).await.expect("read pong");

    assert_eq!(&read, b"ping");
    assert_eq!(&reply, b"pong");
    assert!(tracker.read_bytes() >= 4);
    assert!(tracker.write_bytes() >= 4);

    let _ = noop.track_stream(tokio::io::duplex(8).0);
    assert_eq!(noop.total_bandwidth(), 0);
}
