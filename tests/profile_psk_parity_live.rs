use std::{path::PathBuf, process::Command, time::Duration};

use serde_json::Value;
use tls_rust::{ClientBuilder, ClientProfile, Request};

const PEET_API_URL: &str = "https://tls.peet.ws/api/all";

#[derive(Clone, Copy)]
struct PskCase {
    go_name: &'static str,
    rust_profile: ClientProfile,
}

const PSK_CASES: &[PskCase] = &[
    PskCase {
        go_name: "chrome_116_PSK",
        rust_profile: ClientProfile::Chrome116Psk,
    },
    PskCase {
        go_name: "chrome_116_PSK_PQ",
        rust_profile: ClientProfile::Chrome116PskPq,
    },
    PskCase {
        go_name: "chrome_130_PSK",
        rust_profile: ClientProfile::Chrome130Psk,
    },
    PskCase {
        go_name: "chrome_131_PSK",
        rust_profile: ClientProfile::Chrome131Psk,
    },
    PskCase {
        go_name: "chrome_133_PSK",
        rust_profile: ClientProfile::Chrome133Psk,
    },
    PskCase {
        go_name: "chrome_144_PSK",
        rust_profile: ClientProfile::Chrome144Psk,
    },
    PskCase {
        go_name: "firefox_146_PSK",
        rust_profile: ClientProfile::Firefox146Psk,
    },
    PskCase {
        go_name: "firefox_147_PSK",
        rust_profile: ClientProfile::Firefox147Psk,
    },
];

#[tokio::test]
#[ignore = "Live PSK parity test against tls.peet.ws and local Go helper"]
async fn resumed_profiles_match_go_after_warmup_request() {
    let mut mismatches = Vec::new();

    for case in PSK_CASES {
        let go_payload = capture_from_go(case.go_name, 2);
        let rust_payload = capture_from_rust(case.rust_profile, 2).await;

        compare_field(
            case.go_name,
            "http_version",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            case.go_name,
            "tls.ja3",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            case.go_name,
            "tls.ja3_hash",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            case.go_name,
            "http2.akamai_fingerprint",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            case.go_name,
            "http2.akamai_fingerprint_hash",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
    }

    if !mismatches.is_empty() {
        panic!(
            "PSK profile parity mismatches detected:\n{}",
            mismatches.join("\n")
        );
    }
}

fn capture_from_go(profile: &str, repeat: usize) -> Value {
    let tls_client_dir = manifest_dir().join("tls-client");
    let output = Command::new("go")
        .args([
            "run",
            "./cmd/profile_capture",
            "--profile",
            profile,
            "--url",
            PEET_API_URL,
            "--repeat",
            &repeat.to_string(),
        ])
        .current_dir(&tls_client_dir)
        .output()
        .expect("run go profile capture");

    if !output.status.success() {
        panic!(
            "go profile capture failed for {profile}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    serde_json::from_slice(&output.stdout).expect("decode go capture response")
}

async fn capture_from_rust(profile: ClientProfile, repeat: usize) -> Value {
    let client = ClientBuilder::new()
        .profile(profile)
        .timeout(Duration::from_secs(90))
        .build()
        .expect("build rust client");

    let mut payload = None;
    for _ in 0..repeat {
        let response = client
            .execute(
                Request::get(PEET_API_URL)
                    .header("accept", "*/*")
                    .header("accept-encoding", "gzip")
                    .header("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
                    .header(
                        "user-agent",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) chrome/100.0.4896.75 safari/537.36",
                    ),
            )
            .await
            .expect("perform rust capture request");

        let body = response.text().await.expect("read rust capture body");
        payload = Some(serde_json::from_str(&body).expect("decode rust capture response"));
    }

    payload.expect("at least one rust capture payload")
}

fn compare_field(
    profile: &str,
    path: &str,
    left: &Value,
    right: &Value,
    mismatches: &mut Vec<String>,
) {
    let left_value = value_at_path(left, path);
    let right_value = value_at_path(right, path);

    if left_value != right_value {
        mismatches.push(format!(
            "{profile} {path} mismatch\n  go:   {}\n  rust: {}",
            compact_json(left_value),
            compact_json(right_value)
        ));
    }
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> &'a Value {
    let mut current = value;
    for segment in path.split('.') {
        current = current
            .get(segment)
            .unwrap_or_else(|| panic!("missing `{path}` in payload"));
    }
    current
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string(value).expect("serialize mismatch value")
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
