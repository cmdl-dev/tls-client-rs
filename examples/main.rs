use std::{collections::HashMap, env, error::Error, fs, path::PathBuf, sync::Arc, time::Duration};

use serde_json::Value;
use tls_rust::{
    ApplicationProtocol, ApplicationSettingsProtocol, ClientBuilder, ClientProfile,
    CompressionAlgorithm, CookieJar, CookieJarOptions, Http2ProfileSpec, Http2Setting,
    Http2SettingId, ProfileSpec, PseudoHeader, Request, TlsProfileSpec, TlsProfileVersion,
    parse_ja3,
};

const PEET_API_URL: &str = "https://tls.peet.ws/api/all";
const BROWSERLEAKS_TLS_URL: &str = "https://tls.browserleaks.com";

#[tokio::main]
async fn main() {
    log_result("sslPinning", ssl_pinning().await);
    log_result(
        "requestToppsAsChrome107Client",
        request_topps_as_chrome107_client().await,
    );
    log_result("postAsTlsClient", post_as_tls_client().await);
    log_result(
        "requestWithFollowRedirectSwitch",
        request_with_follow_redirect_switch().await,
    );
    log_result(
        "requestWithCustomClient",
        request_with_custom_client().await,
    );
    log_result(
        "requestWithJa3CustomClientWithTwoGreaseExtensions",
        request_with_ja3_custom_client_with_two_grease_extensions().await,
    );
    log_result("rotateProxiesOnClient", rotate_proxies_on_client().await);
    log_result(
        "downloadImageWithTlsClient",
        download_image_with_tls_client().await,
    );
    log_result("testPskExtension", test_psk_extension().await);
    log_result("testALPSExtension", test_alps_extension().await);
}

fn log_result(name: &str, result: Result<(), Box<dyn Error>>) {
    if let Err(err) = result {
        eprintln!("{name}: {err}");
    }
}

async fn ssl_pinning() -> Result<(), Box<dyn Error>> {
    let jar = Arc::new(CookieJar::new(CookieJarOptions::default()));
    let mut pins = HashMap::new();
    pins.insert(
        "bstn.com".to_string(),
        vec![
            "NQvy9sFS99nBqk/nZCUF44hFhshrkvxqYtfrZq3i+Ww=".to_string(),
            "4a6cPehI7OG6cuDZka5NDZ7FR8a60d3auda+sKfg4Ng=".to_string(),
            "x4QzPSC810K5/cMjb05Qm4k3Bw5zBn4lTdO/nEW/Td4=".to_string(),
        ],
    );

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .timeout(Duration::from_secs(60))
        .random_tls_extension_order(true)
        .cookie_jar(jar)
        .certificate_pinning(pins)
        .proxy_url("http://127.0.0.1:8888")
        .build()?;

    let url = "https://bstn.com";
    let response = client.execute(chrome107_bstn_request(url)).await?;

    println!("GET {} : {}", url, response.status());
    Ok(())
}

async fn request_topps_as_chrome107_client() -> Result<(), Box<dyn Error>> {
    let jar = Arc::new(CookieJar::new(CookieJarOptions::default()));
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .timeout(Duration::from_secs(30))
        .cookie_jar(jar)
        .build()?;

    let url = "https://www.topps.com/";
    let response = client.execute(chrome105_document_request(url)).await?;
    println!(
        "requesting topps as chrome107 => status code: {}",
        response.status()
    );
    println!(
        "tls client cookies for url {} : {:?}",
        url,
        client.get_cookies(&url::Url::parse(url)?)
    );
    Ok(())
}

async fn post_as_tls_client() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .timeout(Duration::from_secs(30))
        .build()?;

    let url = "https://eonk4gg5hquk0g6.m.pipedream.net";
    let response = client
        .execute(
            Request::post(url)
                .header("accept", "*/*")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
                .header("user-agent", chrome105_macos_user_agent())
                .body("foo=bar&baz=foo".as_bytes().to_vec()),
        )
        .await?;

    println!("POST Request status code: {}", response.status());
    Ok(())
}

async fn request_with_follow_redirect_switch() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .timeout(Duration::from_secs(30))
        .follow_redirects(false)
        .build()?;

    let url =
        "https://currys.co.uk/products/sony-playstation-5-digital-edition-825-gb-10205198.html";
    let request = chrome105_document_request(url).header("Accept-Encoding", "gzip");

    let response = client.execute(request.clone()).await?;
    println!(
        "requesting currys.co.uk => status code: {} (Redirect not followed)",
        response.status()
    );

    client.set_follow_redirects(true);
    let response = client.execute(request).await?;
    println!(
        "requesting currys.co.uk with automatic redirect follow => status code: {} (Redirect Followed)",
        response.status()
    );
    Ok(())
}

async fn request_with_custom_client() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile_spec(custom_client_profile())
        .timeout(Duration::from_secs(60))
        .build()?;

    let response = client
        .execute(chrome105_document_request("https://www.topps.com/"))
        .await?;

    println!(
        "requesting topps as customClient1 => status code: {}",
        response.status()
    );
    Ok(())
}

async fn request_with_ja3_custom_client_with_two_grease_extensions() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile_spec(custom_ja3_profile()?)
        .timeout(Duration::from_secs(60))
        .build()?;

    let response = client
        .execute(Request::get("https://tls.browserleaks.com/tls"))
        .await?;
    let status = response.status();
    let body = response.text().await?;

    println!("{body}");
    println!("status code: {status}");
    Ok(())
}

async fn rotate_proxies_on_client() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .timeout(Duration::from_secs(30))
        .proxy_url("http://user:pass@host:port")
        .build()?;

    let request = chrome105_document_request(PEET_API_URL).header("Accept-Encoding", "gzip");
    let payload = execute_peet_request(&client, request.clone()).await?;
    println!(
        "requesting tls.peet.ws with proxy 1 => ip: {}",
        payload["ip"].as_str().unwrap_or("<missing>")
    );

    client.set_proxy("http://user:pass@host:port")?;
    let payload = execute_peet_request(&client, request).await?;
    println!(
        "requesting tls.peet.ws with proxy 2 => ip: {}",
        payload["ip"].as_str().unwrap_or("<missing>")
    );
    Ok(())
}

async fn download_image_with_tls_client() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome107)
        .timeout(Duration::from_secs(30))
        .follow_redirects(false)
        .build()?;

    let url = "https://avatars.githubusercontent.com/u/17678241?v=4";
    let response = client.execute(Request::get(url)).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    println!("requesting image => status code: {status}");

    let output = example_output_path("example-test.jpg")?;
    fs::write(&output, bytes)?;
    println!("wrote file to: {}", output.display());
    Ok(())
}

async fn test_psk_extension() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile_spec(custom_psk_profile())
        .timeout(Duration::from_secs(60))
        .build()?;

    let first = execute_peet_request(&client, psk_peet_request()).await?;
    print_psk_result(&first);

    let second = execute_peet_request(&client, psk_peet_request()).await?;
    print_psk_result(&second);
    Ok(())
}

async fn test_alps_extension() -> Result<(), Box<dyn Error>> {
    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .timeout(Duration::from_secs(60))
        .build()?;

    let response = client
        .execute(
            Request::get(BROWSERLEAKS_TLS_URL)
                .header("accept", "*/*")
                .header("user-agent", chrome133_linux_user_agent()),
        )
        .await?;
    let body = response.text().await?;
    let payload: Value = serde_json::from_str(&body)?;
    let ja3_text = payload["ja3_text"].as_str().unwrap_or_default();

    if ja3_text.contains("17613") && !ja3_text.contains("17513") {
        println!("profile includes new ALPS extension (17613) and not old one (17513)");
    } else {
        println!("profile does not include new ALPS extension (17613)");
    }
    Ok(())
}

fn chrome107_bstn_request(url: &str) -> Request {
    Request::get(url)
        .header("accept", "*/*")
        .header("accept-encoding", "gzip, deflate, br")
        .header("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
        .header(
            "sec-ch-ua",
            r#""Google Chrome";v="107", "Chromium";v="107", "Not=A?Brand";v="24""#,
        )
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", r#""macOS""#)
        .header("sec-fetch-dest", "empty")
        .header("user-agent", chrome107_macos_user_agent())
}

fn chrome105_document_request(url: &str) -> Request {
    Request::get(url)
        .header(
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        )
        .header("accept-encoding", "gzip")
        .header("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
        .header("cache-control", "max-age=0")
        .header("if-none-match", r#"W/"4d0b1-K9LHIpKrZsvKsqNBKd13iwXkWxQ""#)
        .header(
            "sec-ch-ua",
            r#""Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105""#,
        )
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", r#""macOS""#)
        .header("sec-fetch-dest", "document")
        .header("sec-fetch-mode", "navigate")
        .header("sec-fetch-site", "none")
        .header("sec-fetch-user", "?1")
        .header("upgrade-insecure-requests", "1")
        .header("user-agent", chrome105_macos_user_agent())
}

fn psk_peet_request() -> Request {
    Request::get(PEET_API_URL)
        .header("accept", "*/*")
        .header("user-agent", chrome118_linux_user_agent())
}

fn custom_client_profile() -> ProfileSpec {
    ProfileSpec {
        key: "MyCustomProfile",
        tls: TlsProfileSpec {
            curves: "X25519:P-256:P-384",
            cipher_list: chrome_cipher_list(),
            sigalgs: chrome_signature_algorithms(),
            delegated_credentials: None,
            alpn: vec![ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: vec![ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            grease_enabled: true,
            session_ticket: true,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: true,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            enable_ech_grease: false,
            renegotiation: true,
            key_shares_limit: None,
            certificate_compression: vec![CompressionAlgorithm::Brotli],
            extension_order: vec![
                0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513, 21,
            ],
            include_padding: true,
            permute_extensions: false,
            preserve_tls13_cipher_list: true,
            aes_hw_override: true,
            record_size_limit: None,
            min_tls_version: TlsProfileVersion::Tls10,
            max_tls_version: TlsProfileVersion::Tls13,
        },
        http2: Http2ProfileSpec {
            settings: vec![
                Http2Setting {
                    id: Http2SettingId::HeaderTableSize,
                    value: 65536,
                },
                Http2Setting {
                    id: Http2SettingId::MaxConcurrentStreams,
                    value: 1000,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 6291456,
                },
                Http2Setting {
                    id: Http2SettingId::MaxHeaderListSize,
                    value: 262144,
                },
            ],
            settings_order: vec![
                Http2SettingId::HeaderTableSize,
                Http2SettingId::MaxConcurrentStreams,
                Http2SettingId::InitialWindowSize,
                Http2SettingId::MaxHeaderListSize,
            ],
            pseudo_header_order: chrome_pseudo_header_order(),
            connection_flow: 15663105,
            stream_id: None,
            allow_http: false,
            header_priority: None,
            priorities: Vec::new(),
            max_send_buffer_size: Some(1_048_576),
        },
        http3: None,
    }
}

fn custom_ja3_profile() -> Result<ProfileSpec, Box<dyn Error>> {
    let ja3 = parse_ja3(
        "771,2570-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,2570-18-5-27-11-0-10-35-16-65037-51-13-23-43-17513-65281-45-2570,2570-25497-29-23-24,0",
    )?;
    Ok(ProfileSpec {
        key: "MyCustomProfile",
        tls: TlsProfileSpec {
            curves: "X25519Kyber768Draft00:X25519:P-256:P-384",
            cipher_list: chrome_cipher_list(),
            sigalgs: chrome_signature_algorithms(),
            delegated_credentials: None,
            alpn: vec![ApplicationProtocol::Http2, ApplicationProtocol::Http1],
            alps: vec![ApplicationSettingsProtocol::Http2],
            alps_use_new_codepoint: false,
            grease_enabled: true,
            session_ticket: true,
            pre_shared_key: false,
            psk_skip_session_ticket: false,
            psk_dhe_ke: true,
            enable_ocsp_stapling: true,
            enable_signed_cert_timestamps: true,
            enable_ech_grease: true,
            renegotiation: true,
            key_shares_limit: None,
            certificate_compression: vec![CompressionAlgorithm::Brotli],
            extension_order: ja3.extensions,
            include_padding: false,
            permute_extensions: false,
            preserve_tls13_cipher_list: true,
            aes_hw_override: true,
            record_size_limit: None,
            min_tls_version: TlsProfileVersion::Tls12,
            max_tls_version: TlsProfileVersion::Tls13,
        },
        http2: Http2ProfileSpec {
            settings: vec![
                Http2Setting {
                    id: Http2SettingId::HeaderTableSize,
                    value: 65536,
                },
                Http2Setting {
                    id: Http2SettingId::EnablePush,
                    value: 0,
                },
                Http2Setting {
                    id: Http2SettingId::InitialWindowSize,
                    value: 6291456,
                },
                Http2Setting {
                    id: Http2SettingId::MaxHeaderListSize,
                    value: 262144,
                },
            ],
            settings_order: vec![
                Http2SettingId::HeaderTableSize,
                Http2SettingId::EnablePush,
                Http2SettingId::InitialWindowSize,
                Http2SettingId::MaxHeaderListSize,
            ],
            pseudo_header_order: chrome_pseudo_header_order(),
            connection_flow: 15663105,
            stream_id: None,
            allow_http: false,
            header_priority: None,
            priorities: Vec::new(),
            max_send_buffer_size: Some(1_048_576),
        },
        http3: None,
    })
}

fn custom_psk_profile() -> ProfileSpec {
    let mut profile = custom_client_profile();
    profile.key = "MyCustomProfileWithPSK";
    profile.tls.pre_shared_key = true;
    profile.tls.session_ticket = true;
    profile.tls.extension_order = vec![
        45, 51, 17513, 43, 0, 11, 5, 23, 16, 10, 65281, 27, 18, 35, 13, 21, 41,
    ];
    profile.http2.settings = vec![
        Http2Setting {
            id: Http2SettingId::HeaderTableSize,
            value: 65536,
        },
        Http2Setting {
            id: Http2SettingId::EnablePush,
            value: 0,
        },
        Http2Setting {
            id: Http2SettingId::MaxConcurrentStreams,
            value: 1000,
        },
        Http2Setting {
            id: Http2SettingId::InitialWindowSize,
            value: 6291456,
        },
        Http2Setting {
            id: Http2SettingId::MaxHeaderListSize,
            value: 262144,
        },
    ];
    profile.http2.settings_order = vec![
        Http2SettingId::HeaderTableSize,
        Http2SettingId::EnablePush,
        Http2SettingId::MaxConcurrentStreams,
        Http2SettingId::InitialWindowSize,
        Http2SettingId::MaxHeaderListSize,
    ];
    profile
}

async fn execute_peet_request(
    client: &tls_rust::Client,
    request: Request,
) -> Result<Value, Box<dyn Error>> {
    let response = client.execute(request).await?;
    let body = response.text().await?;
    Ok(serde_json::from_str(&body)?)
}

fn print_psk_result(payload: &Value) {
    let ja3 = payload["tls"]["ja3"].as_str().unwrap_or_default();
    if ja3.contains("-41,") {
        println!("profile includes PSK extension (41)");
    } else {
        println!("profile does not include PSK extension (41)");
    }
}

fn chrome105_macos_user_agent() -> &'static str {
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36"
}

fn chrome107_macos_user_agent() -> &'static str {
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
}

fn chrome118_linux_user_agent() -> &'static str {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
}

fn chrome133_linux_user_agent() -> &'static str {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"
}

fn chrome_cipher_list() -> &'static str {
    concat!(
        "TLS_AES_128_GCM_SHA256:",
        "TLS_AES_256_GCM_SHA384:",
        "TLS_CHACHA20_POLY1305_SHA256:",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:",
        "TLS_RSA_WITH_AES_128_GCM_SHA256:",
        "TLS_RSA_WITH_AES_256_GCM_SHA384:",
        "TLS_RSA_WITH_AES_128_CBC_SHA:",
        "TLS_RSA_WITH_AES_256_CBC_SHA"
    )
}

fn chrome_signature_algorithms() -> &'static str {
    concat!(
        "ecdsa_secp256r1_sha256:",
        "rsa_pss_rsae_sha256:",
        "rsa_pkcs1_sha256:",
        "ecdsa_secp384r1_sha384:",
        "rsa_pss_rsae_sha384:",
        "rsa_pkcs1_sha384:",
        "rsa_pss_rsae_sha512:",
        "rsa_pkcs1_sha512"
    )
}

fn chrome_pseudo_header_order() -> Vec<PseudoHeader> {
    vec![
        PseudoHeader::Method,
        PseudoHeader::Authority,
        PseudoHeader::Scheme,
        PseudoHeader::Path,
    ]
}

fn example_output_path(file_name: &str) -> Result<PathBuf, Box<dyn Error>> {
    let executable = env::current_exe()?;
    let directory = executable
        .parent()
        .ok_or("current executable does not have a parent directory")?;
    Ok(directory.join(file_name))
}
