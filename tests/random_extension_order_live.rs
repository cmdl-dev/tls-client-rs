use std::time::Duration;

use serde_json::Value;
use tls_rust::{ClientBuilder, ClientProfile, Request};

const PEET_API_URL: &str = "https://tls.peet.ws/api/all";

#[tokio::test]
#[ignore = "Live random extension order test ported from Go"]
async fn random_extension_order_keeps_chrome_107_extension_set() {
    let payload = capture_randomized(ClientProfile::Chrome107).await;
    let ja3 = string_at_path(&payload, "tls.ja3");
    let extension_part = ja3
        .split(',')
        .nth(2)
        .expect("ja3 should contain an extension segment");

    let expected_extensions = [
        "5", "0", "35", "16", "18", "10", "23", "65281", "43", "51", "27", "17513", "45", "13",
        "11", "21",
    ];

    for extension in expected_extensions {
        assert!(
            extension_part.split('-').any(|part| part == extension),
            "missing extension {extension} in {extension_part}"
        );
    }

    let actual_extensions: Vec<_> = extension_part.split('-').collect();
    assert_eq!(actual_extensions.last().copied(), Some("21"));
}

async fn capture_randomized(profile: ClientProfile) -> Value {
    let client = ClientBuilder::new()
        .profile(profile)
        .random_tls_extension_order(true)
        .timeout(Duration::from_secs(90))
        .build()
        .expect("build rust client");

    let response = client
        .execute(
            Request::get(PEET_API_URL)
                .header("accept", "*/*")
                .header("accept-encoding", "gzip")
                .header(
                    "user-agent",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) chrome/100.0.4896.75 safari/537.36",
                ),
        )
        .await
        .expect("perform rust capture request");

    let body = response.text().await.expect("read rust capture body");
    serde_json::from_str(&body).expect("decode rust capture response")
}

fn string_at_path<'a>(value: &'a Value, path: &str) -> &'a str {
    let mut current = value;
    for segment in path.split('.') {
        current = current
            .get(segment)
            .unwrap_or_else(|| panic!("missing `{path}` in payload"));
    }
    current
        .as_str()
        .unwrap_or_else(|| panic!("`{path}` was not a string"))
}
