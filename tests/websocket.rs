use futures_util::{SinkExt, StreamExt};
use tls_rust::{ClientBuilder, ClientProfile};
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;

async fn spawn_websocket_server() -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept");
            tokio::spawn(async move {
                let mut websocket = accept_async(stream).await.expect("accept websocket");
                while let Some(message) = websocket.next().await {
                    let message = message.expect("message");
                    websocket.send(message).await.expect("send echo");
                }
            });
        }
    });

    (format!("ws://{addr}"), handle)
}

#[tokio::test]
async fn websocket_echo_works() {
    let (url, handle) = spawn_websocket_server().await;
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .random_tls_extension_order(true)
        .build()
        .expect("client should build");

    let mut websocket = client
        .websocket(url)
        .connect()
        .await
        .expect("websocket should connect");
    websocket
        .send_text("hello world")
        .await
        .expect("send should succeed");
    let message = websocket.recv_text().await.expect("receive should succeed");
    assert_eq!(message.as_deref(), Some("hello world"));

    let _ = websocket.close().await;
    handle.abort();
}
