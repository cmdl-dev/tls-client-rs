use std::collections::HashMap;

use tls_rust::{ClientBuilder, ClientError, ClientProfile};

fn assert_invalid_config(builder: ClientBuilder, needle: &str) {
    match builder.build() {
        Err(ClientError::InvalidConfig(message)) => {
            assert!(
                message.contains(needle),
                "expected `{message}` to contain `{needle}`"
            );
        }
        Ok(_) => panic!("expected invalid config error, got successful build"),
        Err(other) => panic!("expected invalid config error, got {other:?}"),
    }
}

#[test]
fn rejects_http3_racing_with_http3_disabled() {
    assert_invalid_config(
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .protocol_racing(true)
            .disable_http3(true),
        "HTTP/3 racing cannot be enabled when HTTP/3 is disabled",
    );
}

#[test]
fn rejects_http3_racing_with_force_http1() {
    assert_invalid_config(
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .protocol_racing(true)
            .force_http1(true),
        "HTTP/3 racing cannot be enabled when HTTP/1 is forced",
    );
}

#[test]
fn rejects_disabling_both_ip_versions() {
    assert_invalid_config(
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .disable_ipv4(true)
            .disable_ipv6(true),
        "cannot disable both IPv4 and IPv6",
    );
}

#[test]
fn rejects_certificate_pinning_with_insecure_skip_verify() {
    let mut pins = HashMap::new();
    pins.insert("example.com".to_string(), vec!["pin1".to_string()]);

    assert_invalid_config(
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .certificate_pinning(pins)
            .insecure_skip_verify(true),
        "certificate pinning cannot be used with insecure skip verify",
    );
}

#[test]
fn rejects_proxy_url_with_custom_proxy_dialer() {
    assert_invalid_config(
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .proxy_url("http://proxy.example.com:8080")
            .custom_proxy_dialer(true),
        "cannot set both proxy URL and custom proxy dialer factory",
    );
}

#[test]
fn accepts_valid_configurations() {
    let variants = [
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .protocol_racing(true),
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .protocol_racing(true)
            .disable_ipv6(true),
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .protocol_racing(true)
            .disable_ipv4(true),
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .force_http1(true)
            .disable_http3(true),
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .disable_http3(true),
        ClientBuilder::new()
            .profile(ClientProfile::Chrome133)
            .server_name_overwrite("example.com")
            .insecure_skip_verify(true),
    ];

    for builder in variants {
        builder.build().expect("builder should be valid");
    }
}
