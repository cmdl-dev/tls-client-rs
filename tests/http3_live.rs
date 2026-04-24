use serde_json::Value;
use tls_rust::{ClientBuilder, ClientProfile, Request};

fn ensure_h3_helper() {
    let helper = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates")
        .join("h3-helper")
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "tls-rust-h3-helper.exe"
        } else {
            "tls-rust-h3-helper"
        });
    assert!(
        helper.is_file(),
        "HTTP/3 helper binary is missing at {}",
        helper.display()
    );
    unsafe {
        std::env::set_var("TLS_RUST_H3_HELPER_BIN", helper);
    }
}

fn chrome_headers(request: Request) -> Request {
    request
        .header("accept", "*/*")
        .header("accept-language", "en-US,en;q=0.9")
        .header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        )
}

fn firefox_headers(request: Request) -> Request {
    request
        .header("accept", "*/*")
        .header("accept-language", "en-US,en;q=0.9")
        .header(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        )
}

#[tokio::test]
#[ignore = "Live HTTP/3 test ported from Go http3_test.go"]
async fn http3_uses_quic_when_enabled() {
    ensure_h3_helper();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome144)
        .protocol_racing(true)
        .build()
        .expect("client should build");

    let response = client
        .execute(chrome_headers(Request::get("https://http3.is/")))
        .await
        .expect("request should succeed");
    let body = response.text().await.expect("body text");

    assert!(
        body.contains("it does support HTTP/3!"),
        "expected http3.is to confirm HTTP/3 usage, got: {body}"
    );
}

#[tokio::test]
#[ignore = "Live HTTP/3 direct-path test ported from Go http3_roundtripper_path_test.go"]
async fn http3_direct_path_uses_quic_for_chrome_144() {
    ensure_h3_helper();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome144)
        .build()
        .expect("client should build");

    let response = client
        .execute(chrome_headers(Request::get("https://http3.is/")))
        .await
        .expect("request should succeed");

    assert_eq!(response.version(), http::Version::HTTP_3);
}

#[tokio::test]
#[ignore = "Live HTTP/3 test ported from Go http3_test.go"]
async fn http3_can_be_disabled() {
    ensure_h3_helper();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome144)
        .disable_http3(true)
        .build()
        .expect("client should build");

    let response = client
        .execute(chrome_headers(Request::get("https://http3.is/")))
        .await
        .expect("request should succeed");
    let body = response.text().await.expect("body text");

    assert!(
        body.contains("HTTP/3 (h3-29 or h3-27) was not used to request this page"),
        "expected http3.is to confirm HTTP/3 was disabled, got: {body}"
    );
}

#[tokio::test]
#[ignore = "Live HTTP/3 fingerprint test ported from Go http3_fingerprint_test.go"]
async fn chrome_144_browserleaks_http3_fingerprint_matches_go() {
    ensure_h3_helper();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome144)
        .protocol_racing(true)
        .build()
        .expect("client should build");

    let response = client
        .execute(chrome_headers(Request::get(
            "https://quic.browserleaks.com/",
        )))
        .await
        .expect("request should succeed");
    let body = response.text().await.expect("body text");
    let json: Value = serde_json::from_str(&body).expect("browserleaks JSON");

    assert_eq!(
        json.get("h3_hash").and_then(Value::as_str),
        Some("ba909fc3dc419ea5c5b26c6323ac1879")
    );
    assert_eq!(
        json.get("h3_text").and_then(Value::as_str),
        Some("1:65536;6:262144;7:100;51:1;GREASE|GREASE|984832|m,a,s,p")
    );
}

#[tokio::test]
#[ignore = "Live HTTP/3 fingerprint test ported from Go http3_fingerprint_test.go"]
async fn firefox_147_browserleaks_http3_fingerprint_matches_go() {
    ensure_h3_helper();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Firefox147)
        .protocol_racing(true)
        .build()
        .expect("client should build");

    let response = client
        .execute(firefox_headers(Request::get(
            "https://quic.browserleaks.com/",
        )))
        .await
        .expect("request should succeed");
    let body = response.text().await.expect("body text");
    let json: Value = serde_json::from_str(&body).expect("browserleaks JSON");

    assert_eq!(
        json.get("h3_hash").and_then(Value::as_str),
        Some("d50d4e585c22bb92b6c86b592aa2d586")
    );
    assert_eq!(
        json.get("h3_text").and_then(Value::as_str),
        Some("1:65536;7:20;727725890:0;16765559:1;51:1;8:1|GREASE|m,s,a,p")
    );
}

#[tokio::test]
#[ignore = "Live HTTP/3 Cloudflare test ported from Go http3_chrome_cloudflare_test.go"]
async fn chrome_144_cloudflare_trace_uses_http3_when_racing() {
    ensure_h3_helper();
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome144)
        .protocol_racing(true)
        .build()
        .expect("client should build");

    let response = client
        .execute(chrome_headers(Request::get(
            "https://www.cloudflare.com/cdn-cgi/trace",
        )))
        .await
        .expect("request should succeed");
    let body = response.text().await.expect("body text");

    assert!(
        body.contains("http=http/3"),
        "expected Cloudflare trace to report HTTP/3, got: {body}"
    );
}
