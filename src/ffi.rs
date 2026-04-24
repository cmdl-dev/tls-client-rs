use std::{
    collections::HashMap,
    ffi::{CStr, CString, c_char},
    sync::{Mutex, OnceLock},
    time::Duration,
};

use base64::Engine;
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::runtime::Runtime;
use url::Url;
use uuid::Uuid;

use crate::{Client, ClientBuilder, ClientProfile, Request};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static SESSIONS: OnceLock<Mutex<HashMap<String, Client>>> = OnceLock::new();
static RESPONSES: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("failed to initialize FFI runtime"))
}

fn sessions() -> &'static Mutex<HashMap<String, Client>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn responses() -> &'static Mutex<HashMap<String, usize>> {
    RESPONSES.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct FfiRequestInput {
    #[serde(rename = "certificatePinningHosts")]
    certificate_pinning_hosts: HashMap<String, Vec<String>>,
    #[serde(rename = "customTlsClient")]
    custom_tls_client: Option<Value>,
    headers: HashMap<String, String>,
    #[serde(rename = "defaultHeaders")]
    default_headers: HashMap<String, Vec<String>>,
    #[serde(rename = "serverNameOverwrite")]
    server_name_overwrite: Option<String>,
    #[serde(rename = "proxyUrl")]
    proxy_url: Option<String>,
    #[serde(rename = "requestBody")]
    request_body: Option<String>,
    #[serde(rename = "requestHostOverride")]
    request_host_override: Option<String>,
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    #[serde(rename = "requestMethod")]
    request_method: String,
    #[serde(rename = "requestUrl")]
    request_url: String,
    #[serde(rename = "tlsClientIdentifier")]
    tls_client_identifier: String,
    #[serde(rename = "headerOrder")]
    header_order: Vec<String>,
    #[serde(rename = "requestCookies")]
    request_cookies: Vec<FfiCookie>,
    #[serde(rename = "timeoutMilliseconds")]
    timeout_milliseconds: u64,
    #[serde(rename = "timeoutSeconds")]
    timeout_seconds: u64,
    #[serde(rename = "followRedirects")]
    follow_redirects: bool,
    #[serde(rename = "forceHttp1")]
    force_http1: bool,
    #[serde(rename = "disableHttp3")]
    disable_http3: bool,
    #[serde(rename = "withProtocolRacing")]
    with_protocol_racing: bool,
    #[serde(rename = "insecureSkipVerify")]
    insecure_skip_verify: bool,
    #[serde(rename = "isByteRequest")]
    is_byte_request: bool,
    #[serde(rename = "isByteResponse")]
    is_byte_response: bool,
    #[serde(rename = "isRotatingProxy")]
    is_rotating_proxy: bool,
    #[serde(rename = "disableIPV6")]
    disable_ipv6: bool,
    #[serde(rename = "disableIPV4")]
    disable_ipv4: bool,
    #[serde(rename = "withoutCookieJar")]
    without_cookie_jar: bool,
    #[serde(rename = "withRandomTLSExtensionOrder")]
    with_random_tls_extension_order: bool,
}

#[derive(Debug, Deserialize)]
struct DestroySessionInput {
    #[serde(rename = "sessionId")]
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct SessionCookiesInput {
    #[serde(rename = "sessionId")]
    session_id: String,
    url: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
struct FfiCookie {
    #[serde(default)]
    name: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    expires: i64,
    #[serde(rename = "maxAge", default)]
    max_age: i64,
    #[serde(default)]
    secure: bool,
    #[serde(rename = "httpOnly", default)]
    http_only: bool,
}

#[derive(Debug, Deserialize)]
struct AddCookiesInput {
    #[serde(rename = "sessionId")]
    session_id: String,
    url: String,
    cookies: Vec<FfiCookie>,
}

#[derive(Debug, Serialize)]
struct FfiResponse {
    id: String,
    status: u16,
    body: String,
    headers: Option<HashMap<String, Vec<String>>>,
    cookies: Option<HashMap<String, String>>,
    target: String,
    #[serde(rename = "usedProtocol")]
    used_protocol: String,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct DestroyOutput {
    id: String,
    success: bool,
}

#[derive(Debug, Serialize)]
struct CookiesOutput {
    id: String,
    cookies: Vec<FfiCookie>,
}

fn parse_json<T: for<'de> Deserialize<'de>>(input: *const c_char) -> Result<T, String> {
    if input.is_null() {
        return Err("null input pointer".to_string());
    }
    let json = unsafe { CStr::from_ptr(input) }
        .to_str()
        .map_err(|err| format!("invalid utf-8 input: {err}"))?;
    serde_json::from_str(json).map_err(|err| format!("invalid json: {err}"))
}

fn encode_json<T: Serialize>(value: &T, id: &str) -> *mut c_char {
    let json = serde_json::to_string(value).unwrap_or_else(|err| {
        serde_json::json!({
            "id": id,
            "status": 0,
            "body": format!("failed to serialize ffi response: {err}"),
            "headers": Value::Null,
            "cookies": Value::Null,
            "target": "",
            "usedProtocol": ""
        })
        .to_string()
    });
    let c_string = CString::new(json).expect("ffi response contains null byte");
    let ptr = c_string.into_raw();
    responses()
        .lock()
        .expect("ffi response map poisoned")
        .insert(id.to_string(), ptr as usize);
    ptr
}

fn error_response(err: impl Into<String>, session_id: Option<String>) -> *mut c_char {
    let id = Uuid::new_v4().to_string();
    let payload = FfiResponse {
        id: id.clone(),
        status: 0,
        body: err.into(),
        headers: None,
        cookies: None,
        target: String::new(),
        used_protocol: String::new(),
        session_id,
    };
    encode_json(&payload, &id)
}

fn create_or_reuse_client(input: &FfiRequestInput) -> Result<(Client, Option<String>), String> {
    let session_id = input.session_id.clone().filter(|value| !value.is_empty());

    if let Some(custom) = &input.custom_tls_client
        && !custom.is_null()
    {
        return Err("customTlsClient is not implemented in the Rust FFI yet".to_string());
    }

    if let Some(session_id_value) = &session_id {
        let mut guard = sessions().lock().expect("ffi session map poisoned");
        if let Some(existing) = guard.get(session_id_value).cloned() {
            if input.is_rotating_proxy
                || existing.get_proxy() != normalize_proxy_option(input.proxy_url.clone())
            {
                existing
                    .set_proxy(input.proxy_url.clone().unwrap_or_default())
                    .map_err(|err| err.to_string())?;
            }
            if existing.get_follow_redirects() != input.follow_redirects {
                existing.set_follow_redirects(input.follow_redirects);
            }
            return Ok((existing, Some(session_id_value.clone())));
        }

        let client = build_client(input)?;
        guard.insert(session_id_value.clone(), client.clone());
        return Ok((client, Some(session_id_value.clone())));
    }

    Ok((build_client(input)?, None))
}

fn build_client(input: &FfiRequestInput) -> Result<Client, String> {
    if input.timeout_seconds != 0 && input.timeout_milliseconds != 0 {
        return Err("cannot set both timeoutSeconds and timeoutMilliseconds".to_string());
    }

    let profile = if input.tls_client_identifier.is_empty() {
        ClientProfile::default()
    } else {
        ClientProfile::from_key(&input.tls_client_identifier).ok_or_else(|| {
            format!(
                "unsupported tlsClientIdentifier `{}`",
                input.tls_client_identifier
            )
        })?
    };

    let mut builder = ClientBuilder::new()
        .profile(profile)
        .follow_redirects(input.follow_redirects)
        .force_http1(input.force_http1)
        .disable_http3(input.disable_http3)
        .protocol_racing(input.with_protocol_racing)
        .random_tls_extension_order(input.with_random_tls_extension_order)
        .disable_ipv4(input.disable_ipv4)
        .disable_ipv6(input.disable_ipv6)
        .insecure_skip_verify(input.insecure_skip_verify);

    if input.without_cookie_jar {
        builder = builder.without_cookie_jar();
    }
    if !input.certificate_pinning_hosts.is_empty() {
        builder = builder.certificate_pinning(input.certificate_pinning_hosts.clone());
    }
    if let Some(server_name) = &input.server_name_overwrite {
        builder = builder.server_name_overwrite(server_name.clone());
    }
    if let Some(proxy_url) = &input.proxy_url
        && !proxy_url.is_empty()
    {
        builder = builder.proxy_url(proxy_url.clone());
    }

    let timeout = if input.timeout_milliseconds != 0 {
        Duration::from_millis(input.timeout_milliseconds)
    } else if input.timeout_seconds != 0 {
        Duration::from_secs(input.timeout_seconds)
    } else {
        Duration::from_secs(30)
    };
    builder
        .timeout(timeout)
        .build()
        .map_err(|err| err.to_string())
}

fn build_request(input: &FfiRequestInput) -> Result<Request, String> {
    if input.request_url.is_empty() || input.request_method.is_empty() {
        return Err("requestUrl and requestMethod are required".to_string());
    }

    let method = input
        .request_method
        .parse()
        .map_err(|err| format!("invalid requestMethod: {err}"))?;
    let mut request = Request::new(method, input.request_url.clone());

    let mut headers = if input.headers.is_empty() {
        input
            .default_headers
            .iter()
            .filter_map(|(key, values)| values.first().map(|value| (key.clone(), value.clone())))
            .collect::<HashMap<_, _>>()
    } else {
        input.headers.clone()
    };

    if let Some(host) = &input.request_host_override {
        headers.insert("Host".to_string(), host.clone());
    }

    let ordered = !input.header_order.is_empty();
    if ordered {
        for key in &input.header_order {
            if let Some(value) = headers.remove(key) {
                request = request.header(key.clone(), value);
            }
        }
    }
    for (key, value) in headers {
        request = request.header(key, value);
    }

    if let Some(body) = &input.request_body {
        let bytes = if input.is_byte_request {
            base64::engine::general_purpose::STANDARD
                .decode(body)
                .map_err(|err| format!("failed to decode requestBody: {err}"))?
        } else {
            body.as_bytes().to_vec()
        };
        if !bytes.is_empty() {
            request = request.body(bytes);
        }
    }

    Ok(request)
}

fn apply_request_cookies(client: &Client, input: &FfiRequestInput) -> Result<(), String> {
    if input.request_cookies.is_empty() {
        return Ok(());
    }
    let url = Url::parse(&input.request_url).map_err(|err| format!("invalid requestUrl: {err}"))?;
    let cookies = input
        .request_cookies
        .iter()
        .map(to_cookie)
        .collect::<Vec<_>>();
    client.set_cookies(&url, &cookies);
    Ok(())
}

fn to_cookie(cookie: &FfiCookie) -> Cookie<'static> {
    let mut built = Cookie::new(cookie.name.clone(), cookie.value.clone());
    if !cookie.path.is_empty() {
        built.set_path(cookie.path.clone());
    }
    if !cookie.domain.is_empty() {
        built.set_domain(cookie.domain.clone());
    }
    if cookie.max_age != 0 {
        built.set_max_age(cookie::time::Duration::seconds(cookie.max_age));
    }
    if cookie.expires > 0 {
        built.set_expires(cookie::time::OffsetDateTime::from_unix_timestamp(cookie.expires).ok());
    }
    built.set_secure(cookie.secure);
    built.set_http_only(cookie.http_only);
    built.into_owned()
}

fn from_cookie(cookie: &Cookie<'static>) -> FfiCookie {
    FfiCookie {
        name: cookie.name().to_string(),
        value: cookie.value().to_string(),
        path: cookie.path().unwrap_or_default().to_string(),
        domain: cookie.domain().unwrap_or_default().to_string(),
        expires: cookie
            .expires()
            .and_then(|expiry| expiry.datetime())
            .map(|value| value.unix_timestamp())
            .unwrap_or_default(),
        max_age: cookie
            .max_age()
            .map(|value| value.whole_seconds())
            .unwrap_or_default(),
        secure: cookie.secure().unwrap_or(false),
        http_only: cookie.http_only().unwrap_or(false),
    }
}

fn map_headers(headers: &http::HeaderMap) -> HashMap<String, Vec<String>> {
    let mut out = HashMap::new();
    for (name, value) in headers {
        let entry = out
            .entry(name.as_str().to_string())
            .or_insert_with(Vec::new);
        entry.push(value.to_str().unwrap_or_default().to_string());
    }
    out
}

fn normalize_proxy_option(value: Option<String>) -> Option<String> {
    value.filter(|proxy| !proxy.trim().is_empty())
}

fn request_impl(input: FfiRequestInput) -> Result<FfiResponse, String> {
    let (client, session_id) = create_or_reuse_client(&input)?;
    apply_request_cookies(&client, &input)?;
    let request = build_request(&input)?;
    let request_url = input.request_url.clone();

    let response = runtime()
        .block_on(client.execute(request))
        .map_err(|err| format!("failed to do request: {err}"))?;
    let status = response.status().as_u16();
    let used_protocol = format!("{:?}", response.version());
    let headers = map_headers(response.headers());
    let body_bytes = runtime()
        .block_on(response.bytes())
        .map_err(|err| format!("failed to read response body: {err}"))?;
    let body = if input.is_byte_response {
        base64::engine::general_purpose::STANDARD.encode(&body_bytes)
    } else {
        String::from_utf8(body_bytes)
            .map_err(|err| format!("response body was not valid utf-8: {err}"))?
    };

    let cookies = if let Some(jar) = client.cookie_jar() {
        let url = Url::parse(&request_url).map_err(|err| format!("invalid requestUrl: {err}"))?;
        jar.get_cookies(&url)
            .into_iter()
            .map(|cookie| (cookie.name().to_string(), cookie.value().to_string()))
            .collect()
    } else {
        HashMap::new()
    };

    Ok(FfiResponse {
        id: Uuid::new_v4().to_string(),
        status,
        body,
        headers: Some(headers),
        cookies: Some(cookies),
        target: request_url,
        used_protocol,
        session_id,
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn freeMemory(response_id: *const c_char) {
    if response_id.is_null() {
        return;
    }
    let Ok(id) = (unsafe { CStr::from_ptr(response_id) }).to_str() else {
        return;
    };

    if let Some(ptr) = responses()
        .lock()
        .expect("ffi response map poisoned")
        .remove(id)
    {
        unsafe {
            let _ = CString::from_raw(ptr as *mut c_char);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn destroyAll() -> *mut c_char {
    let cleared = {
        let mut guard = sessions().lock().expect("ffi session map poisoned");
        let count = guard.len();
        guard.clear();
        count
    };
    let id = Uuid::new_v4().to_string();
    let payload = serde_json::json!({
        "id": id,
        "success": true,
        "clearedSessions": cleared
    });
    encode_json(&payload, &id)
}

#[unsafe(no_mangle)]
pub extern "C" fn destroySession(input: *const c_char) -> *mut c_char {
    let payload: DestroySessionInput = match parse_json(input) {
        Ok(value) => value,
        Err(err) => return error_response(err, None),
    };
    sessions()
        .lock()
        .expect("ffi session map poisoned")
        .remove(&payload.session_id);
    let id = Uuid::new_v4().to_string();
    encode_json(
        &DestroyOutput {
            id: id.clone(),
            success: true,
        },
        &id,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn getCookiesFromSession(input: *const c_char) -> *mut c_char {
    let payload: SessionCookiesInput = match parse_json(input) {
        Ok(value) => value,
        Err(err) => return error_response(err, None),
    };
    let Some(client) = sessions()
        .lock()
        .expect("ffi session map poisoned")
        .get(&payload.session_id)
        .cloned()
    else {
        return error_response(
            format!("no client found for sessionId: {}", payload.session_id),
            Some(payload.session_id),
        );
    };

    let url = match Url::parse(&payload.url) {
        Ok(url) => url,
        Err(err) => return error_response(format!("invalid url: {err}"), Some(payload.session_id)),
    };
    let cookies = client
        .get_cookies(&url)
        .into_iter()
        .map(|cookie| from_cookie(&cookie))
        .collect::<Vec<_>>();
    let id = Uuid::new_v4().to_string();
    encode_json(
        &CookiesOutput {
            id: id.clone(),
            cookies,
        },
        &id,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn addCookiesToSession(input: *const c_char) -> *mut c_char {
    let payload: AddCookiesInput = match parse_json(input) {
        Ok(value) => value,
        Err(err) => return error_response(err, None),
    };
    let Some(client) = sessions()
        .lock()
        .expect("ffi session map poisoned")
        .get(&payload.session_id)
        .cloned()
    else {
        return error_response(
            format!("no client found for sessionId: {}", payload.session_id),
            Some(payload.session_id),
        );
    };
    let url = match Url::parse(&payload.url) {
        Ok(url) => url,
        Err(err) => return error_response(format!("invalid url: {err}"), Some(payload.session_id)),
    };
    let cookies = payload.cookies.iter().map(to_cookie).collect::<Vec<_>>();
    client.set_cookies(&url, &cookies);
    let current = client
        .get_cookies(&url)
        .into_iter()
        .map(|cookie| from_cookie(&cookie))
        .collect::<Vec<_>>();
    let id = Uuid::new_v4().to_string();
    encode_json(
        &CookiesOutput {
            id: id.clone(),
            cookies: current,
        },
        &id,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn request(input: *const c_char) -> *mut c_char {
    let payload: FfiRequestInput = match parse_json(input) {
        Ok(value) => value,
        Err(err) => return error_response(err, None),
    };
    match request_impl(payload) {
        Ok(response) => {
            let id = response.id.clone();
            encode_json(&response, &id)
        }
        Err(err) => error_response(err, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::get};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    async fn ok() -> &'static str {
        "ffi-ok"
    }

    #[test]
    fn request_impl_runs_basic_http_flow() {
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let listener = runtime()
            .block_on(TcpListener::bind("127.0.0.1:0"))
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        runtime().spawn(async move {
            let app = Router::new().route(
                "/",
                get(move || {
                    let hits = hits_clone.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        ok().await
                    }
                }),
            );
            axum::serve(listener, app).await.expect("serve");
        });

        let payload = FfiRequestInput {
            request_method: "GET".to_string(),
            request_url: format!("http://{addr}/"),
            tls_client_identifier: "chrome_133".to_string(),
            follow_redirects: true,
            ..Default::default()
        };

        let response = request_impl(payload).expect("ffi request");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "ffi-ok");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
