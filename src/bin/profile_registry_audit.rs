use std::{collections::BTreeSet, fs, path::PathBuf};

use tls_rust::ClientProfile;

fn main() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let go_profiles = extract_go_profile_keys(
        &manifest_dir
            .join("tls-client")
            .join("profiles")
            .join("profiles.go"),
    );
    let rust_profiles: BTreeSet<String> = ClientProfile::registry()
        .iter()
        .map(|(key, _)| (*key).to_string())
        .collect();

    let missing_in_rust: Vec<_> = go_profiles.difference(&rust_profiles).cloned().collect();
    let extra_in_rust: Vec<_> = rust_profiles.difference(&go_profiles).cloned().collect();

    println!("go_profiles={}", go_profiles.len());
    println!("rust_profiles={}", rust_profiles.len());

    if !missing_in_rust.is_empty() {
        println!("missing_in_rust={}", missing_in_rust.join(","));
    }
    if !extra_in_rust.is_empty() {
        println!("extra_in_rust={}", extra_in_rust.join(","));
    }

    if !missing_in_rust.is_empty() || !extra_in_rust.is_empty() {
        std::process::exit(1);
    }
}

fn extract_go_profile_keys(path: &PathBuf) -> BTreeSet<String> {
    let contents = fs::read_to_string(path).expect("read Go profile registry");
    let mut keys = BTreeSet::new();
    let mut in_map = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("var MappedTLSClients") {
            in_map = true;
            continue;
        }
        if in_map && trimmed == "}" {
            break;
        }
        if !in_map || !trimmed.starts_with('"') {
            continue;
        }
        if let Some(end) = trimmed[1..].find('"') {
            keys.insert(trimmed[1..1 + end].to_string());
        }
    }

    keys
}
