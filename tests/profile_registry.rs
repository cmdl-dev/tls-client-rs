use std::collections::HashSet;

use tls_rust::{
    ApplicationProtocol, ClientBuilder, ClientProfile, DEFAULT_CLIENT_PROFILE, PseudoHeader,
};

#[test]
fn default_profile_matches_go_default() {
    assert_eq!(DEFAULT_CLIENT_PROFILE, ClientProfile::Chrome133);
    assert_eq!(ClientProfile::default(), DEFAULT_CLIENT_PROFILE);
}

#[test]
fn profile_registry_round_trips_keys() {
    let mut seen = HashSet::new();

    for &(key, profile) in ClientProfile::registry() {
        assert!(seen.insert(key), "duplicate registry key: {key}");
        assert_eq!(ClientProfile::from_key(key), Some(profile));
        let canonical = profile.as_key();
        assert!(
            canonical == key
                || matches!(
                    (canonical, key),
                    ("mms_ios", "mms_ios_1")
                        | ("mesh_ios", "mesh_ios_1")
                        | ("mesh_android", "mesh_android_1")
                ),
            "unexpected alias mapping: {key} -> {canonical}"
        );
    }

    assert_eq!(ClientProfile::from_key("chrome_999"), None);
}

#[test]
fn ported_profiles_build_emulations() {
    for &(_, profile) in ClientProfile::registry() {
        assert!(
            profile.spec().is_ok(),
            "{} should be ported",
            profile.as_key()
        );
    }
}

#[test]
fn profile_specs_expose_transport_agnostic_metadata() {
    let chrome = ClientProfile::Chrome133.spec().expect("chrome_133 spec");
    assert_eq!(chrome.key, "chrome_133");
    assert_eq!(
        chrome.tls.alpn,
        vec![
            ApplicationProtocol::Http3,
            ApplicationProtocol::Http2,
            ApplicationProtocol::Http1
        ]
    );
    let chrome_h3 = chrome.http3.expect("chrome_133 http3 spec");
    assert_eq!(chrome_h3.settings_order, vec![1, 0x6, 7, 0x33]);
    assert!(chrome_h3.send_grease_frames);

    let firefox = ClientProfile::Firefox147.spec().expect("firefox_147 spec");
    let firefox_h3 = firefox.http3.expect("firefox_147 http3 spec");
    assert_eq!(
        firefox_h3.pseudo_header_order,
        vec![
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Authority,
            PseudoHeader::Path
        ]
    );
}

#[test]
fn all_current_registry_profiles_build() {
    for &(_, profile) in ClientProfile::registry() {
        if let Err(error) = ClientBuilder::new().profile(profile).build() {
            panic!(
                "expected profile {} to build successfully, got {error:?}",
                profile.as_key()
            );
        }
    }
}

#[test]
fn registry_count_matches_go_catalog() {
    assert_eq!(ClientProfile::registry().len(), 79);
}
