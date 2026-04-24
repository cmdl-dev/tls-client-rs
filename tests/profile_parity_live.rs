use std::{path::PathBuf, process::Command, time::Duration};

use serde_json::Value;
use tls_rust::{ClientBuilder, ClientProfile, Request};

const PEET_API_URL: &str = "https://tls.peet.ws/api/all";

fn is_known_live_transport_limitation(profile: &str) -> bool {
    matches!(profile, "chrome_120")
}

#[tokio::test]
#[ignore = "Live network differential test against tls.peet.ws and local Go helper"]
async fn shared_profiles_match_go_fingerprints_on_tls_peet() {
    let mut mismatches = Vec::new();

    for (go_name, rust_profile) in ClientProfile::registry() {
        if is_known_live_transport_limitation(go_name) {
            continue;
        }
        let go_payload = capture_from_go(go_name);
        let rust_payload = capture_from_rust(*rust_profile).await;

        compare_field(
            go_name,
            "http_version",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            go_name,
            "tls.ja3",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            go_name,
            "tls.ja3_hash",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            go_name,
            "http2.akamai_fingerprint",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_field(
            go_name,
            "http2.akamai_fingerprint_hash",
            &go_payload,
            &rust_payload,
            &mut mismatches,
        );
        compare_normalized_extensions(go_name, &go_payload, &rust_payload, &mut mismatches);
    }

    if !mismatches.is_empty() {
        panic!(
            "profile parity mismatches detected:\n{}",
            mismatches.join("\n")
        );
    }
}

fn capture_from_go(profile: &str) -> Value {
    let tls_client_dir = manifest_dir().join("tls-client");
    let output = Command::new("go")
        .args([
            "run",
            "./cmd/profile_capture",
            "--profile",
            profile,
            "--url",
            PEET_API_URL,
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

async fn capture_from_rust(profile: ClientProfile) -> Value {
    let client = ClientBuilder::new()
        .profile(profile)
        .timeout(Duration::from_secs(90))
        .build()
        .expect("build rust client");

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
    serde_json::from_str(&body).expect("decode rust capture response")
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

fn compare_normalized_extensions(
    profile: &str,
    left: &Value,
    right: &Value,
    mismatches: &mut Vec<String>,
) {
    let left_extensions = normalized_extension_names(value_at_path(left, "tls.extensions"));
    let right_extensions = normalized_extension_names(value_at_path(right, "tls.extensions"));

    if left_extensions != right_extensions {
        mismatches.push(format!(
            "{profile} tls.extensions mismatch\n  go:   {}\n  rust: {}",
            left_extensions.join(", "),
            right_extensions.join(", ")
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

fn normalized_extension_names(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("extensions should be an array")
        .iter()
        .map(|entry| {
            normalize_extension_name(
                entry["name"]
                    .as_str()
                    .expect("extension entry should have a name"),
            )
        })
        .collect()
}

fn normalize_extension_name(name: &str) -> String {
    if name.starts_with("TLS_GREASE") {
        "TLS_GREASE".to_string()
    } else {
        name.to_string()
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
