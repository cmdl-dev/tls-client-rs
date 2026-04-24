use std::sync::Arc;

use tls_rust::{ClientBuilder, ClientProfile, Request};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};

async fn spawn_raw_http_server() -> (
    String,
    Arc<Mutex<Option<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let request_text = Arc::new(Mutex::new(None));
    let request_text_clone = request_text.clone();

    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buffer = vec![0u8; 8192];
        let size = stream.read(&mut buffer).await.expect("read request");
        *request_text_clone.lock().await =
            Some(String::from_utf8_lossy(&buffer[..size]).to_string());
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .expect("write response");
    });

    (format!("http://{addr}/"), request_text, handle)
}

#[tokio::test]
async fn preserves_http1_header_order() {
    let (url, captured, handle) = spawn_raw_http_server().await;
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome105)
        .force_http1(true)
        .build()
        .expect("client should build");

    client
        .execute(
            Request::get(url)
                .header("Header4", "value4")
                .header("Header2", "value2")
                .header("Header1", "value1")
                .header("Header3", "value3"),
        )
        .await
        .expect("request should succeed");

    let raw = captured
        .lock()
        .await
        .clone()
        .expect("request should be captured");

    let h1 = raw.find("Header4: value4").expect("Header4 present");
    let h2 = raw.find("Header2: value2").expect("Header2 present");
    let h3 = raw.find("Header1: value1").expect("Header1 present");
    let h4 = raw.find("Header3: value3").expect("Header3 present");
    assert!(h1 < h2 && h2 < h3 && h3 < h4);

    handle.abort();
}

#[tokio::test]
async fn preserves_content_length_position_in_http1_requests() {
    let (url, captured, handle) = spawn_raw_http_server().await;
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome105)
        .force_http1(true)
        .build()
        .expect("client should build");

    client
        .execute(
            Request::post(url)
                .header("Header1", "value1")
                .header("Content-Length", "6")
                .header("Header2", "value2")
                .body("foobar"),
        )
        .await
        .expect("request should succeed");

    let raw = captured
        .lock()
        .await
        .clone()
        .expect("request should be captured");

    let header1 = raw.find("Header1: value1").expect("Header1 present");
    let content_length = raw
        .find("Content-Length: 6")
        .expect("content-length present");
    let header2 = raw.find("Header2: value2").expect("Header2 present");
    assert!(header1 < content_length && content_length < header2);

    handle.abort();
}
