use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use cookie::Cookie;
use tls_rust::{ClientBuilder, ClientProfile, CookieJar, CookieJarOptions};
use url::Url;

#[test]
fn skip_existing_cookies_on_client_set_cookies() {
    let jar = Arc::new(CookieJar::new(CookieJarOptions {
        skip_existing: true,
    }));
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .cookie_jar(jar.clone())
        .build()
        .expect("client should build");

    let url = Url::parse("http://testhost.de/test").expect("valid url");

    assert_eq!(client.get_cookies(&url).len(), 0);

    client.set_cookies(&url, &[Cookie::new("test1", "value1").into_owned()]);
    assert_eq!(client.get_cookies(&url).len(), 1);

    client.set_cookies(&url, &[Cookie::new("test2", "value2").into_owned()]);
    assert_eq!(client.get_cookies(&url).len(), 2);

    client.set_cookies(
        &url,
        &[Cookie::new("test1", "value1-replaced").into_owned()],
    );
    let cookies = client.get_cookies(&url);
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.name() == "test1" && cookie.value() == "value1")
    );
}

#[test]
fn excludes_expired_cookies_from_requests() {
    let jar = Arc::new(CookieJar::new(CookieJarOptions::default()));
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .cookie_jar(jar)
        .build()
        .expect("client should build");

    let url = Url::parse("http://testhost.de/test").expect("valid url");

    let alive = Cookie::build(("alive", "yes"))
        .max_age(cookie::time::Duration::seconds(60))
        .build()
        .into_owned();
    let expired = Cookie::build(("dead", "no"))
        .max_age(cookie::time::Duration::seconds(-1))
        .build()
        .into_owned();

    client.set_cookies(&url, &[alive, expired]);
    let cookies = client.get_cookies(&url);
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies[0].name(), "alive");

    let expire_existing = Cookie::build(("alive", "gone"))
        .max_age(cookie::time::Duration::seconds(-1))
        .build()
        .into_owned();
    client.set_cookies(&url, &[expire_existing]);
    assert!(client.get_cookies(&url).is_empty());
}

#[tokio::test]
async fn skip_existing_cookies_from_response_headers() {
    #[derive(Clone)]
    struct AppState {
        calls: Arc<AtomicUsize>,
    }

    async fn handler(State(state): State<AppState>) -> impl IntoResponse {
        let call = state.calls.fetch_add(1, Ordering::SeqCst);
        let mut headers = HeaderMap::new();
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("session=alpha; Path=/"),
        );
        headers.append(
            header::SET_COOKIE,
            HeaderValue::from_static("theme=dark; Path=/"),
        );
        if call > 0 {
            headers.append(
                header::SET_COOKIE,
                HeaderValue::from_static("session=beta; Path=/"),
            );
        }
        (StatusCode::OK, headers, "ok")
    }

    let state = AppState {
        calls: Arc::new(AtomicUsize::new(0)),
    };
    let app = Router::new().route("/", get(handler)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let jar = Arc::new(CookieJar::new(CookieJarOptions {
        skip_existing: true,
    }));
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .cookie_jar(jar)
        .build()
        .expect("client should build");

    let url = format!("http://{addr}/");
    client
        .execute(tls_rust::Request::get(url.clone()))
        .await
        .expect("first response");
    let parsed = Url::parse(&url).expect("valid url");
    let cookies = client.get_cookies(&parsed);
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.name() == "session" && cookie.value() == "alpha")
    );

    client
        .execute(tls_rust::Request::get(url))
        .await
        .expect("second response");
    let cookies = client.get_cookies(&parsed);
    assert_eq!(cookies.len(), 2);
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.name() == "session" && cookie.value() == "alpha")
    );

    server.abort();
}
