use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{Router, extract::ConnectInfo, http::HeaderMap, routing::get};
use tls_rust::{ClientBuilder, ClientError, ClientProfile, PreHookErrorMode, Request};

async fn header_echo(headers: HeaderMap) -> String {
    headers
        .get("x-custom-header")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn delayed_ok(ConnectInfo(_addr): ConnectInfo<SocketAddr>) -> &'static str {
    tokio::time::sleep(Duration::from_millis(50)).await;
    "ok"
}

#[tokio::test]
async fn pre_hook_modifies_request_headers() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route("/", get(header_echo));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome124)
        .pre_hook(|request| {
            request.with_header("X-Custom-Header", "test-value");
            Ok(())
        })
        .build()
        .expect("client should build");

    let response = client
        .execute(Request::get(format!("http://{addr}/")))
        .await
        .expect("request should succeed");
    assert_eq!(response.text().await.expect("body"), "test-value");

    server.abort();
}

#[tokio::test]
async fn pre_hook_error_aborts_request() {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome124)
        .pre_hook(|_| Err(PreHookErrorMode::Abort("pre-hook error".to_string())))
        .build()
        .expect("client should build");

    let error = client
        .execute(Request::get("http://127.0.0.1/"))
        .await
        .expect_err("pre-hook should abort request");

    match error {
        ClientError::HookAborted(message) => assert_eq!(message, "pre-hook error"),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[tokio::test]
async fn post_hook_receives_response_metadata() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route("/", get(|| async { "ok" }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let status = Arc::new(Mutex::new(None));
    let error = Arc::new(Mutex::new(None));
    let status_clone = status.clone();
    let error_clone = error.clone();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome124)
        .post_hook(move |context| {
            *status_clone.lock().expect("status lock") = context.status;
            *error_clone.lock().expect("error lock") = context.error.clone();
            Ok(())
        })
        .build()
        .expect("client should build");

    client
        .execute(Request::get(format!("http://{addr}/")))
        .await
        .expect("request should succeed");

    assert_eq!(*status.lock().expect("status lock"), Some(200));
    assert_eq!(*error.lock().expect("error lock"), None);

    server.abort();
}

#[tokio::test]
async fn multiple_hooks_execute_in_order_and_continue_when_requested() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new().route("/", get(|| async { "ok" }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let order = Arc::new(Mutex::new(Vec::new()));
    let first = order.clone();
    let second = order.clone();
    let third = order.clone();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome124)
        .pre_hook(move |_| {
            first.lock().expect("lock").push(1);
            Ok(())
        })
        .pre_hook(move |_| {
            second.lock().expect("lock").push(2);
            Err(PreHookErrorMode::Continue("continue".to_string()))
        })
        .pre_hook(move |_| {
            third.lock().expect("lock").push(3);
            Ok(())
        })
        .build()
        .expect("client should build");

    client
        .execute(Request::get(format!("http://{addr}/")))
        .await
        .expect("request should succeed");
    assert_eq!(*order.lock().expect("lock"), vec![1, 2, 3]);

    server.abort();
}

#[tokio::test]
async fn runtime_hook_registration_is_thread_safe() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new()
        .route("/", get(delayed_ok))
        .into_make_service_with_connect_info::<SocketAddr>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome124)
        .build()
        .expect("client should build");

    let pre_count = Arc::new(AtomicUsize::new(0));
    let post_count = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for _ in 0..10 {
        let client = client.clone();
        let pre_count = pre_count.clone();
        let post_count = post_count.clone();
        tasks.push(tokio::spawn(async move {
            client.add_pre_hook(move |_| {
                pre_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            client.add_post_hook(move |_| {
                post_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
        }));
    }

    for task in tasks {
        task.await.expect("join task");
    }

    client
        .execute(Request::get(format!("http://{addr}/")))
        .await
        .expect("request should succeed");

    assert_eq!(pre_count.load(Ordering::SeqCst), 10);
    assert_eq!(post_count.load(Ordering::SeqCst), 10);

    server.abort();
}

#[tokio::test]
async fn post_hook_not_called_when_pre_hook_aborts() {
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome124)
        .pre_hook(|_| Err(PreHookErrorMode::Abort("stop".to_string())))
        .post_hook(move |_| {
            called_clone.store(true, Ordering::SeqCst);
            Ok(())
        })
        .build()
        .expect("client should build");

    let _ = client.execute(Request::get("http://127.0.0.1/")).await;
    assert!(!called.load(Ordering::SeqCst));
}
