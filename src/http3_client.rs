use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex, OnceLock},
    time::Duration,
};

use base64::Engine;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, process::Command};
use url::Url;

use crate::{
    bandwidth::BandwidthTracker,
    client::{ClientError, ClientOptions},
    profile::{ProfileSpec, PseudoHeader},
    request::{Request, Response},
};

const HELPER_NAME: &str = "tls-rust-h3-helper";

pub(crate) async fn send_http3(
    request: Request,
    url: Url,
    options: Arc<ClientOptions>,
    profile: Arc<ProfileSpec>,
    tracker: Arc<BandwidthTracker>,
    session_cache: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
) -> Result<Response, ClientError> {
    let helper_path = find_helper_binary()?;
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    let server_name = options
        .server_name_overwrite
        .clone()
        .unwrap_or_else(|| host.to_string());
    let session_key = format!("{}:{server_name}", profile.key);
    let cached_session = session_cache
        .lock()
        .expect("http3 session cache poisoned")
        .get(&session_key)
        .cloned();

    let payload = HelperRequest {
        request: RequestPayload::from_request(&request),
        options: HelperOptions::from_options(&options),
        profile: HelperProfile::from_profile(&profile),
        cached_session: cached_session
            .as_deref()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
    };

    let mut child = Command::new(helper_path)
        .arg("--stdio")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|err| ClientError::Http(format!("failed to spawn HTTP/3 helper: {err}")))?;

    let request_json = serde_json::to_vec(&payload).map_err(|err| {
        ClientError::Http(format!("failed to encode HTTP/3 helper request: {err}"))
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&request_json).await.map_err(|err| {
            ClientError::Http(format!("failed to write HTTP/3 helper request: {err}"))
        })?;
        stdin.shutdown().await.map_err(|err| {
            ClientError::Http(format!("failed to finish HTTP/3 helper request: {err}"))
        })?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|err| ClientError::Http(format!("failed waiting for HTTP/3 helper: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(ClientError::Http(format!(
            "HTTP/3 helper exited with status {} (stdout: {}, stderr: {})",
            output.status,
            stdout.trim(),
            stderr.trim()
        )));
    }

    let helper_response: HelperResponse =
        serde_json::from_slice(&output.stdout).map_err(|err| {
            ClientError::Http(format!("failed to decode HTTP/3 helper response: {err}"))
        })?;

    tracker.add_read(helper_response.bandwidth.read_bytes as usize);
    tracker.add_write(helper_response.bandwidth.write_bytes as usize);

    if let Some(session) = helper_response.cached_session {
        let session = base64::engine::general_purpose::STANDARD
            .decode(session)
            .map_err(|err| {
                ClientError::Http(format!(
                    "failed to decode HTTP/3 session cache entry: {err}"
                ))
            })?;
        session_cache
            .lock()
            .expect("http3 session cache poisoned")
            .insert(session_key, session);
    }

    match helper_response.outcome {
        HelperOutcome::Success(payload) => build_response(payload),
        HelperOutcome::Error(error) => match error.kind {
            ErrorKind::BadPin => Err(ClientError::BadPinDetected(error.message)),
            ErrorKind::Http => Err(ClientError::Http(error.message)),
            ErrorKind::UnsupportedProfile => Err(ClientError::UnsupportedProfile(error.message)),
            ErrorKind::InvalidConfig => Err(ClientError::InvalidConfig(error.message)),
        },
    }
}

fn build_response(payload: ResponsePayload) -> Result<Response, ClientError> {
    let status = StatusCode::from_u16(payload.status).map_err(|err| {
        ClientError::Http(format!("invalid HTTP/3 status code from helper: {err}"))
    })?;
    let version = match payload.version.as_str() {
        "HTTP/3" => Version::HTTP_3,
        "HTTP/2" => Version::HTTP_2,
        "HTTP/1.1" => Version::HTTP_11,
        "HTTP/1.0" => Version::HTTP_10,
        other => {
            return Err(ClientError::Http(format!(
                "invalid HTTP version from helper: {other}"
            )));
        }
    };
    let mut headers = HeaderMap::with_capacity(payload.headers.len());
    for header in payload.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes()).map_err(|err| {
            ClientError::Http(format!(
                "invalid HTTP/3 response header name from helper: {err}"
            ))
        })?;
        let value = HeaderValue::from_bytes(header.value.as_bytes()).map_err(|err| {
            ClientError::Http(format!(
                "invalid HTTP/3 response header value from helper: {err}"
            ))
        })?;
        headers.append(name, value);
    }

    let body = match payload.body {
        Some(body) => base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|err| {
                ClientError::Http(format!("failed to decode HTTP/3 response body: {err}"))
            })?,
        None => Vec::new(),
    };

    Ok(Response::new(status, version, headers, body))
}

fn find_helper_binary() -> Result<PathBuf, ClientError> {
    static HELPER: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    HELPER
        .get_or_init(resolve_helper_binary)
        .as_ref()
        .map(PathBuf::clone)
        .map_err(|message| ClientError::Http(message.clone()))
}

fn resolve_helper_binary() -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os("TLS_RUST_H3_HELPER_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(format!(
            "TLS_RUST_H3_HELPER_BIN points to `{}` but no file exists there",
            path.display()
        ));
    }

    let mut candidates = Vec::new();
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(dir) = current_exe.parent() {
            candidates.push(dir.join(helper_filename()));
            if let Some(parent) = dir.parent() {
                candidates.push(parent.join(helper_filename()));
            }
        }
    }
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("debug")
            .join(helper_filename()),
    );
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("release")
            .join(helper_filename()),
    );
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates")
            .join("h3-helper")
            .join("target")
            .join("debug")
            .join(helper_filename()),
    );
    candidates.push(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates")
            .join("h3-helper")
            .join("target")
            .join("release")
            .join(helper_filename()),
    );

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            format!(
                "HTTP/3 helper binary `{}` was not found. Build it with `cargo build --manifest-path crates/h3-helper/Cargo.toml`
or set TLS_RUST_H3_HELPER_BIN.",
                helper_filename(),
            )
        })
}

fn helper_filename() -> String {
    if cfg!(windows) {
        format!("{HELPER_NAME}.exe")
    } else {
        HELPER_NAME.to_string()
    }
}

#[derive(Serialize)]
struct HelperRequest {
    request: RequestPayload,
    options: HelperOptions,
    profile: HelperProfile,
    cached_session: Option<String>,
}

#[derive(Serialize)]
struct RequestPayload {
    method: String,
    url: String,
    headers: Vec<HeaderPayload>,
    body: Option<String>,
}

impl RequestPayload {
    fn from_request(request: &Request) -> Self {
        Self {
            method: request.method.as_str().to_string(),
            url: request.url.clone(),
            headers: request
                .headers
                .iter()
                .map(|header| HeaderPayload {
                    name: header.name.clone(),
                    value: header.value.clone(),
                })
                .collect(),
            body: request
                .body
                .as_deref()
                .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
        }
    }
}

#[derive(Serialize)]
struct HelperOptions {
    timeout_ms: u64,
    disable_ipv4: bool,
    disable_ipv6: bool,
    insecure_skip_verify: bool,
    certificate_pins: HashMap<String, Vec<String>>,
    server_name_overwrite: Option<String>,
}

impl HelperOptions {
    fn from_options(options: &ClientOptions) -> Self {
        Self {
            timeout_ms: duration_millis(options.timeout),
            disable_ipv4: options.disable_ipv4,
            disable_ipv6: options.disable_ipv6,
            insecure_skip_verify: options.insecure_skip_verify,
            certificate_pins: options.certificate_pins.clone(),
            server_name_overwrite: options.server_name_overwrite.clone(),
        }
    }
}

#[derive(Serialize)]
struct HelperProfile {
    key: String,
    pre_shared_key: bool,
    http3: Option<Http3ProfilePayload>,
}

impl HelperProfile {
    fn from_profile(profile: &ProfileSpec) -> Self {
        Self {
            key: profile.key.to_string(),
            pre_shared_key: profile.tls.pre_shared_key,
            http3: profile.http3.as_ref().map(Http3ProfilePayload::from_spec),
        }
    }
}

#[derive(Serialize)]
struct Http3ProfilePayload {
    settings: Vec<Http3SettingPayload>,
    settings_order: Vec<u64>,
    pseudo_header_order: Vec<String>,
    priority_param: u32,
    send_grease_frames: bool,
}

impl Http3ProfilePayload {
    fn from_spec(profile: &crate::profile::Http3ProfileSpec) -> Self {
        Self {
            settings: profile
                .settings
                .iter()
                .map(|setting| Http3SettingPayload {
                    id: setting.id,
                    value: setting.value,
                })
                .collect(),
            settings_order: profile.settings_order.clone(),
            pseudo_header_order: profile
                .pseudo_header_order
                .iter()
                .map(|pseudo| match pseudo {
                    PseudoHeader::Method => ":method".to_string(),
                    PseudoHeader::Authority => ":authority".to_string(),
                    PseudoHeader::Scheme => ":scheme".to_string(),
                    PseudoHeader::Path => ":path".to_string(),
                })
                .collect(),
            priority_param: profile.priority_param,
            send_grease_frames: profile.send_grease_frames,
        }
    }
}

#[derive(Serialize)]
struct Http3SettingPayload {
    id: u64,
    value: u64,
}

#[derive(Serialize, Deserialize)]
struct HeaderPayload {
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct HelperResponse {
    outcome: HelperOutcome,
    cached_session: Option<String>,
    bandwidth: BandwidthPayload,
}

#[derive(Deserialize)]
#[serde(tag = "status", content = "payload")]
enum HelperOutcome {
    Success(ResponsePayload),
    Error(HelperError),
}

#[derive(Deserialize)]
struct ResponsePayload {
    status: u16,
    version: String,
    headers: Vec<HeaderPayload>,
    body: Option<String>,
}

#[derive(Deserialize)]
struct HelperError {
    kind: ErrorKind,
    message: String,
}

#[derive(Clone, Deserialize)]
enum ErrorKind {
    Http,
    BadPin,
    UnsupportedProfile,
    InvalidConfig,
}

#[derive(Deserialize)]
struct BandwidthPayload {
    read_bytes: u64,
    write_bytes: u64,
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
