use tls_rust::{ClientBuilder, ClientProfile, Request};

#[tokio::test]
#[ignore = "Live parity test ported from Go firefox_unsupported_group_test.go"]
async fn firefox_110_can_post_to_web_registration_endpoint() {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Firefox110)
        .build()
        .expect("client should build");

    let response = client
        .execute(
            Request::post("https://registrierung.web.de/account/email-registration")
                .body(Vec::<u8>::new())
                .header("accept", "*/*")
                .header("accept-encoding", "gzip")
                .header("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) chrome/100.0.4896.75 safari/537.36",
                ),
        )
        .await;

    assert!(
        response.is_ok(),
        "firefox_110 POST should not fail: {response:?}"
    );
}
