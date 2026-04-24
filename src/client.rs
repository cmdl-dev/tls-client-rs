use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex, Once, OnceLock, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use base64::Engine;
use boring2::ssl::{
    CertCompressionAlgorithm, ExtensionType, NameType, Ssl, SslConnector, SslMethod, SslSession,
    SslSessionCacheMode, SslVerifyMode, SslVersion, StatusType,
};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, lookup_host},
    sync::Mutex,
};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use url::Url;

use crate::{
    bandwidth::BandwidthTracker,
    cookie_jar::{CookieJar, CookieJarOptions},
    http2::send_http2,
    http3_client::send_http3,
    profile::{
        ApplicationProtocol, ApplicationSettingsProtocol, ClientProfile, CompressionAlgorithm,
        ProfileSpec, TlsProfileVersion,
    },
    request::{HeaderEntry, Request, Response},
    websocket::{WebSocket, WebSocketBuilder, WebSocketError},
};

pub(crate) trait AsyncIo:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin
{
}

impl<T> AsyncIo for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

pub(crate) type BoxedIo = Box<dyn AsyncIo>;
type DialFuture<T> = Pin<Box<dyn Future<Output = Result<T, ClientError>> + Send>>;
type CustomDialContextFn = Arc<dyn Fn(String, u16) -> DialFuture<TcpStream> + Send + Sync>;

#[derive(Clone)]
pub struct ClientOptions {
    pub profile: ClientProfile,
    pub timeout: Duration,
    pub follow_redirects: bool,
    pub force_http1: bool,
    pub disable_http3: bool,
    pub protocol_racing: bool,
    pub disable_compression: bool,
    pub disable_keep_alives: bool,
    pub random_tls_extension_order: bool,
    pub disable_ipv4: bool,
    pub disable_ipv6: bool,
    pub insecure_skip_verify: bool,
    pub certificate_pins: HashMap<String, Vec<String>>,
    pub server_name_overwrite: Option<String>,
    pub proxy_url: Option<String>,
    pub use_custom_proxy_dialer: bool,
    pub cookie_jar: Option<Arc<CookieJar>>,
    dial_context: Option<CustomDialContextFn>,
}

impl std::fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOptions")
            .field("profile", &self.profile)
            .field("timeout", &self.timeout)
            .field("follow_redirects", &self.follow_redirects)
            .field("force_http1", &self.force_http1)
            .field("disable_http3", &self.disable_http3)
            .field("protocol_racing", &self.protocol_racing)
            .field("disable_compression", &self.disable_compression)
            .field("disable_keep_alives", &self.disable_keep_alives)
            .field(
                "random_tls_extension_order",
                &self.random_tls_extension_order,
            )
            .field("disable_ipv4", &self.disable_ipv4)
            .field("disable_ipv6", &self.disable_ipv6)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("certificate_pins", &self.certificate_pins)
            .field("server_name_overwrite", &self.server_name_overwrite)
            .field("proxy_url", &self.proxy_url)
            .field("use_custom_proxy_dialer", &self.use_custom_proxy_dialer)
            .field("cookie_jar", &self.cookie_jar)
            .field(
                "dial_context",
                &self.dial_context.as_ref().map(|_| "<custom>"),
            )
            .finish()
    }
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            profile: ClientProfile::default(),
            timeout: Duration::from_secs(30),
            follow_redirects: false,
            force_http1: false,
            disable_http3: false,
            protocol_racing: false,
            disable_compression: false,
            disable_keep_alives: false,
            random_tls_extension_order: false,
            disable_ipv4: false,
            disable_ipv6: false,
            insecure_skip_verify: false,
            certificate_pins: HashMap::new(),
            server_name_overwrite: None,
            proxy_url: None,
            use_custom_proxy_dialer: false,
            cookie_jar: Some(Arc::new(CookieJar::new(CookieJarOptions::default()))),
            dial_context: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ContinueHooks(pub String);

#[derive(Clone, Debug)]
pub enum PreHookErrorMode {
    Abort(String),
    Continue(String),
}

#[derive(Clone, Debug)]
pub enum PostHookErrorMode {
    Abort(String),
    Continue(String),
}

pub type PreHookFn = Arc<dyn Fn(&mut Request) -> Result<(), PreHookErrorMode> + Send + Sync>;
pub type PostHookFn = Arc<dyn Fn(&PostHookContext) -> Result<(), PostHookErrorMode> + Send + Sync>;
pub type BadPinHandlerFn = Arc<dyn Fn(&Request) + Send + Sync>;

pub struct ClientStream {
    inner: ClientStreamInner,
}

enum ClientStreamInner {
    Plain(BoxedIo),
    Tls(tokio_boring2::SslStream<BoxedIo>),
}

impl ClientStream {
    fn plain(inner: BoxedIo) -> Self {
        Self {
            inner: ClientStreamInner::Plain(inner),
        }
    }

    fn tls(inner: tokio_boring2::SslStream<BoxedIo>) -> Self {
        Self {
            inner: ClientStreamInner::Tls(inner),
        }
    }
}

impl tokio::io::AsyncRead for ClientStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        unsafe {
            match &mut self.get_unchecked_mut().inner {
                ClientStreamInner::Plain(stream) => {
                    Pin::new_unchecked(stream.as_mut()).poll_read(cx, buf)
                }
                ClientStreamInner::Tls(stream) => Pin::new_unchecked(stream).poll_read(cx, buf),
            }
        }
    }
}

impl tokio::io::AsyncWrite for ClientStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        unsafe {
            match &mut self.get_unchecked_mut().inner {
                ClientStreamInner::Plain(stream) => {
                    Pin::new_unchecked(stream.as_mut()).poll_write(cx, buf)
                }
                ClientStreamInner::Tls(stream) => Pin::new_unchecked(stream).poll_write(cx, buf),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        unsafe {
            match &mut self.get_unchecked_mut().inner {
                ClientStreamInner::Plain(stream) => {
                    Pin::new_unchecked(stream.as_mut()).poll_flush(cx)
                }
                ClientStreamInner::Tls(stream) => Pin::new_unchecked(stream).poll_flush(cx),
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        unsafe {
            match &mut self.get_unchecked_mut().inner {
                ClientStreamInner::Plain(stream) => {
                    Pin::new_unchecked(stream.as_mut()).poll_shutdown(cx)
                }
                ClientStreamInner::Tls(stream) => Pin::new_unchecked(stream).poll_shutdown(cx),
            }
        }
    }
}

#[derive(Clone)]
pub struct ClientDialer {
    client: Client,
}

impl ClientDialer {
    pub async fn dial(
        &self,
        host: impl Into<String>,
        port: u16,
    ) -> Result<ClientStream, ClientError> {
        let host = host.into();
        let proxy_url = self.client.get_proxy();
        let stream =
            connect_target(&host, port, &self.client.options, proxy_url.as_deref()).await?;
        Ok(ClientStream::plain(stream))
    }
}

#[derive(Clone)]
pub struct ClientTlsDialer {
    client: Client,
}

impl ClientTlsDialer {
    pub async fn dial(
        &self,
        url: impl AsRef<str>,
        force_http1: bool,
    ) -> Result<ClientStream, ClientError> {
        let url = Url::parse(url.as_ref()).map_err(ClientError::Url)?;
        let mut profile = (*self.client.profile_spec).clone();
        if force_http1 {
            profile.tls.alpn = vec![ApplicationProtocol::Http1];
        }
        let proxy_url = self.client.get_proxy();
        let stream = connect_tls(
            &url,
            &self.client.options,
            proxy_url.as_deref(),
            &self.client.tls_connector,
            &profile,
            &self.client.tls_session_cache,
        )
        .await?;
        Ok(ClientStream::tls(stream))
    }
}

#[derive(Clone, Debug)]
pub struct PostHookContext {
    pub request: Request,
    pub status: Option<u16>,
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct Client {
    options: Arc<ClientOptions>,
    profile_spec: Arc<ProfileSpec>,
    tls_connector: Arc<SslConnector>,
    proxy_url: Arc<RwLock<Option<String>>>,
    bad_pin_handler: Option<BadPinHandlerFn>,
    follow_redirects: Arc<AtomicBool>,
    pre_hooks: Arc<RwLock<Vec<PreHookFn>>>,
    post_hooks: Arc<RwLock<Vec<PostHookFn>>>,
    http1_pool: Arc<Mutex<HashMap<String, Vec<TcpStream>>>>,
    tls_session_cache: Arc<StdMutex<HashMap<String, SslSession>>>,
    http3_session_cache: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
    bandwidth_tracker: Arc<BandwidthTracker>,
}

pub struct ClientBuilder {
    options: ClientOptions,
    custom_profile_spec: Option<ProfileSpec>,
    pre_hooks: Vec<PreHookFn>,
    post_hooks: Vec<PostHookFn>,
    bad_pin_handler: Option<BadPinHandlerFn>,
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            options: ClientOptions::default(),
            custom_profile_spec: None,
            pre_hooks: Vec::new(),
            post_hooks: Vec::new(),
            bad_pin_handler: None,
        }
    }

    pub fn profile(mut self, profile: ClientProfile) -> Self {
        self.options.profile = profile;
        self.custom_profile_spec = None;
        self
    }

    pub fn profile_spec(mut self, profile_spec: ProfileSpec) -> Self {
        self.custom_profile_spec = Some(profile_spec);
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }

    pub fn follow_redirects(mut self, enabled: bool) -> Self {
        self.options.follow_redirects = enabled;
        self
    }

    pub fn force_http1(mut self, enabled: bool) -> Self {
        self.options.force_http1 = enabled;
        self
    }

    pub fn disable_http3(mut self, enabled: bool) -> Self {
        self.options.disable_http3 = enabled;
        self
    }

    pub fn protocol_racing(mut self, enabled: bool) -> Self {
        self.options.protocol_racing = enabled;
        self
    }

    pub fn disable_compression(mut self, enabled: bool) -> Self {
        self.options.disable_compression = enabled;
        self
    }

    pub fn disable_keep_alives(mut self, enabled: bool) -> Self {
        self.options.disable_keep_alives = enabled;
        self
    }

    pub fn random_tls_extension_order(mut self, enabled: bool) -> Self {
        self.options.random_tls_extension_order = enabled;
        self
    }

    pub fn disable_ipv4(mut self, enabled: bool) -> Self {
        self.options.disable_ipv4 = enabled;
        self
    }

    pub fn disable_ipv6(mut self, enabled: bool) -> Self {
        self.options.disable_ipv6 = enabled;
        self
    }

    pub fn insecure_skip_verify(mut self, enabled: bool) -> Self {
        self.options.insecure_skip_verify = enabled;
        self
    }

    pub fn certificate_pinning(mut self, pins: impl Into<HashMap<String, Vec<String>>>) -> Self {
        self.options.certificate_pins = pins.into();
        self
    }

    pub fn server_name_overwrite(mut self, server_name: impl Into<String>) -> Self {
        self.options.server_name_overwrite = Some(server_name.into());
        self
    }

    pub fn proxy_url(mut self, proxy_url: impl Into<String>) -> Self {
        self.options.proxy_url = Some(proxy_url.into());
        self
    }

    pub fn custom_proxy_dialer(mut self, enabled: bool) -> Self {
        self.options.use_custom_proxy_dialer = enabled;
        self
    }

    pub fn cookie_jar(mut self, jar: Arc<CookieJar>) -> Self {
        self.options.cookie_jar = Some(jar);
        self
    }

    pub fn without_cookie_jar(mut self) -> Self {
        self.options.cookie_jar = None;
        self
    }

    pub fn dial_context<F, Fut>(mut self, dialer: F) -> Self
    where
        F: Fn(String, u16) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<TcpStream, ClientError>> + Send + 'static,
    {
        self.options.dial_context = Some(Arc::new(move |host, port| Box::pin(dialer(host, port))));
        self
    }

    pub fn pre_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&mut Request) -> Result<(), PreHookErrorMode> + Send + Sync + 'static,
    {
        self.pre_hooks.push(Arc::new(hook));
        self
    }

    pub fn post_hook<F>(mut self, hook: F) -> Self
    where
        F: Fn(&PostHookContext) -> Result<(), PostHookErrorMode> + Send + Sync + 'static,
    {
        self.post_hooks.push(Arc::new(hook));
        self
    }

    pub fn bad_pin_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&Request) + Send + Sync + 'static,
    {
        self.bad_pin_handler = Some(Arc::new(handler));
        self
    }

    pub fn build(self) -> Result<Client, ClientError> {
        self.validate()?;
        let normalized_proxy_url = match &self.options.proxy_url {
            Some(proxy_url) => normalize_proxy_url(proxy_url)?,
            None => None,
        };
        let mut profile_spec = match self.custom_profile_spec {
            Some(profile_spec) => profile_spec,
            None => self
                .options
                .profile
                .spec()
                .map_err(|message| ClientError::UnsupportedProfile(message.to_string()))?,
        };
        if self.options.random_tls_extension_order {
            profile_spec.tls.permute_extensions = true;
        }
        let tls_session_cache = Arc::new(StdMutex::new(HashMap::new()));
        let http3_session_cache = Arc::new(StdMutex::new(HashMap::new()));
        let tls_connector = build_tls_connector(&self.options, &profile_spec, &tls_session_cache)?;

        Ok(Client {
            options: Arc::new(self.options.clone()),
            profile_spec: Arc::new(profile_spec),
            tls_connector: Arc::new(tls_connector),
            proxy_url: Arc::new(RwLock::new(normalized_proxy_url)),
            bad_pin_handler: self.bad_pin_handler,
            follow_redirects: Arc::new(AtomicBool::new(self.options.follow_redirects)),
            pre_hooks: Arc::new(RwLock::new(self.pre_hooks)),
            post_hooks: Arc::new(RwLock::new(self.post_hooks)),
            http1_pool: Arc::new(Mutex::new(HashMap::new())),
            tls_session_cache,
            http3_session_cache,
            bandwidth_tracker: Arc::new(BandwidthTracker::new()),
        })
    }

    fn validate(&self) -> Result<(), ClientError> {
        if self.options.protocol_racing && self.options.disable_http3 {
            return Err(ClientError::InvalidConfig(
                "HTTP/3 racing cannot be enabled when HTTP/3 is disabled".to_string(),
            ));
        }

        if self.options.protocol_racing && self.options.force_http1 {
            return Err(ClientError::InvalidConfig(
                "HTTP/3 racing cannot be enabled when HTTP/1 is forced".to_string(),
            ));
        }

        if self.options.disable_ipv4 && self.options.disable_ipv6 {
            return Err(ClientError::InvalidConfig(
                "cannot disable both IPv4 and IPv6".to_string(),
            ));
        }

        if !self.options.certificate_pins.is_empty() && self.options.insecure_skip_verify {
            return Err(ClientError::InvalidConfig(
                "certificate pinning cannot be used with insecure skip verify".to_string(),
            ));
        }

        if self.options.proxy_url.is_some() && self.options.use_custom_proxy_dialer {
            return Err(ClientError::InvalidConfig(
                "cannot set both proxy URL and custom proxy dialer factory".to_string(),
            ));
        }

        if self.options.dial_context.is_some()
            && (self.options.proxy_url.is_some() || self.options.use_custom_proxy_dialer)
        {
            return Err(ClientError::InvalidConfig(
                "custom dial context overrides built-in proxy logic".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn set_follow_redirects(&self, enabled: bool) {
        self.follow_redirects.store(enabled, Ordering::Relaxed);
    }

    pub fn get_follow_redirects(&self) -> bool {
        self.follow_redirects.load(Ordering::Relaxed)
    }

    pub fn get_proxy(&self) -> Option<String> {
        self.proxy_url.read().expect("proxy lock poisoned").clone()
    }

    pub fn set_proxy(&self, proxy_url: impl Into<String>) -> Result<(), ClientError> {
        let proxy_url = proxy_url.into();
        let normalized = normalize_proxy_url(&proxy_url)?;
        *self.proxy_url.write().expect("proxy lock poisoned") = normalized;
        Ok(())
    }

    pub fn add_pre_hook<F>(&self, hook: F)
    where
        F: Fn(&mut Request) -> Result<(), PreHookErrorMode> + Send + Sync + 'static,
    {
        self.pre_hooks
            .write()
            .expect("pre-hooks poisoned")
            .push(Arc::new(hook));
    }

    pub fn add_post_hook<F>(&self, hook: F)
    where
        F: Fn(&PostHookContext) -> Result<(), PostHookErrorMode> + Send + Sync + 'static,
    {
        self.post_hooks
            .write()
            .expect("post-hooks poisoned")
            .push(Arc::new(hook));
    }

    pub fn reset_pre_hooks(&self) {
        self.pre_hooks.write().expect("pre-hooks poisoned").clear();
    }

    pub fn reset_post_hooks(&self) {
        self.post_hooks
            .write()
            .expect("post-hooks poisoned")
            .clear();
    }

    pub fn cookie_jar(&self) -> Option<Arc<CookieJar>> {
        self.options.cookie_jar.clone()
    }

    pub fn bandwidth_tracker(&self) -> Arc<BandwidthTracker> {
        self.bandwidth_tracker.clone()
    }

    pub fn get_bandwidth_tracker(&self) -> Arc<BandwidthTracker> {
        self.bandwidth_tracker()
    }

    pub fn get_dialer(&self) -> ClientDialer {
        ClientDialer {
            client: self.clone(),
        }
    }

    pub fn get_tls_dialer(&self) -> ClientTlsDialer {
        ClientTlsDialer {
            client: self.clone(),
        }
    }

    pub fn get_cookies(&self, url: &Url) -> Vec<cookie::Cookie<'static>> {
        self.cookie_jar()
            .map(|jar| jar.get_cookies(url))
            .unwrap_or_default()
    }

    pub fn set_cookies(&self, url: &Url, cookies: &[cookie::Cookie<'static>]) {
        if let Some(jar) = self.cookie_jar() {
            jar.set_cookies(url, cookies);
        }
    }

    pub async fn execute(&self, mut request: Request) -> Result<Response, ClientError> {
        self.run_pre_hooks(&mut request)?;

        let url = Url::parse(&request.url).map_err(ClientError::Url)?;
        if let Some(jar) = self.cookie_jar() {
            if let Some(value) = jar.cookie_header_value(&url) {
                request.headers.push(HeaderEntry::new("Cookie", value));
            }
        }

        let request_for_hooks = request.clone();
        let result = tokio::time::timeout(
            self.options.timeout,
            self.execute_with_redirects(request, 0),
        )
        .await
        .map_err(|_| ClientError::Http("request timed out".to_string()))?;

        if let (Ok(response), Some(jar)) = (&result, self.cookie_jar()) {
            jar.set_from_response_headers(&url, response.headers());
        }
        if matches!(&result, Err(ClientError::BadPinDetected(_))) {
            if let Some(handler) = &self.bad_pin_handler {
                handler(&request_for_hooks);
            }
        }

        self.run_post_hooks(&request_for_hooks, &result);
        result
    }

    pub fn websocket(&self, url: impl Into<String>) -> WebSocketBuilder {
        WebSocketBuilder::new(self.clone(), url)
    }

    pub(crate) async fn connect_websocket(
        &self,
        builder: WebSocketBuilder,
    ) -> Result<WebSocket, WebSocketError> {
        let websocket_config = builder.websocket_config();
        let mut request = builder.request;
        self.run_pre_hooks(&mut request)?;

        let url = Url::parse(&request.url).map_err(ClientError::Url)?;
        if let Some(jar) = self.cookie_jar() {
            if let Some(value) = jar.cookie_header_value(&url) {
                request.headers.push(HeaderEntry::new("Cookie", value));
            }
        }

        let mut ws_request = request
            .url
            .clone()
            .into_client_request()
            .map_err(WebSocketError::Http)?;
        for entry in &request.headers {
            let name = HeaderName::from_bytes(entry.name.as_bytes()).map_err(|err| {
                ClientError::InvalidHeaderName(entry.name.clone(), err.to_string())
            })?;
            let value = HeaderValue::from_str(&entry.value).map_err(|err| {
                ClientError::InvalidHeaderValue(entry.name.clone(), err.to_string())
            })?;
            ws_request.headers_mut().append(name, value);
        }

        let stream = match url.scheme() {
            "ws" => {
                let host = url
                    .host_str()
                    .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
                let port = url.port_or_known_default().unwrap_or(80);
                connect_target(host, port, &self.options, self.get_proxy().as_deref()).await?
            }
            "wss" => {
                let mut websocket_profile = (*self.profile_spec).clone();
                websocket_profile.tls.alpn = vec![ApplicationProtocol::Http1];
                let tls_stream = connect_tls(
                    &url,
                    &self.options,
                    self.get_proxy().as_deref(),
                    &self.tls_connector,
                    &websocket_profile,
                    &self.tls_session_cache,
                )
                .await?;
                Box::new(tls_stream) as BoxedIo
            }
            scheme => {
                return Err(WebSocketError::Client(ClientError::Http(format!(
                    "unsupported websocket URL scheme `{scheme}`"
                ))));
            }
        };

        let (socket, response) =
            tokio_tungstenite::client_async_with_config(ws_request, stream, websocket_config)
                .await
                .map_err(WebSocketError::Http)?;

        if let Some(jar) = self.cookie_jar() {
            jar.set_from_response_headers(&url, response.headers());
        }

        Ok(WebSocket::new(socket))
    }

    async fn execute_with_redirects(
        &self,
        mut request: Request,
        mut depth: usize,
    ) -> Result<Response, ClientError> {
        loop {
            let response = self.send_once(&request).await?;
            if !self.follow_redirects.load(Ordering::Relaxed) || depth >= 10 {
                return Ok(response);
            }

            let status = response.status();
            if !matches!(
                status,
                StatusCode::MOVED_PERMANENTLY
                    | StatusCode::FOUND
                    | StatusCode::SEE_OTHER
                    | StatusCode::TEMPORARY_REDIRECT
                    | StatusCode::PERMANENT_REDIRECT
            ) {
                return Ok(response);
            }

            let Some(location) = response.headers().get(http::header::LOCATION) else {
                return Ok(response);
            };
            let location = location
                .to_str()
                .map_err(|err| ClientError::Http(format!("invalid redirect location: {err}")))?;
            let base = Url::parse(&request.url).map_err(ClientError::Url)?;
            let redirect_url = base.join(location).map_err(ClientError::Url)?;

            request.url = redirect_url.to_string();
            if status == StatusCode::SEE_OTHER {
                request.method = http::Method::GET;
                request.body = None;
            }

            depth += 1;
        }
    }

    async fn send_once(&self, request: &Request) -> Result<Response, ClientError> {
        let url = Url::parse(&request.url).map_err(ClientError::Url)?;
        match url.scheme() {
            "http" => self.send_http1_plain(request, &url).await,
            "https" => self.send_https(request, &url, &self.profile_spec).await,
            scheme => Err(ClientError::Http(format!(
                "unsupported URL scheme `{scheme}`"
            ))),
        }
    }

    async fn send_http1_plain(
        &self,
        request: &Request,
        url: &Url,
    ) -> Result<Response, ClientError> {
        let proxy_url = self.get_proxy();
        let authority = authority_for_pool(url)?;
        let use_direct_pool = !self.options.disable_keep_alives && proxy_url.is_none();
        let mut direct_stream = if proxy_url.is_none() && use_direct_pool {
            self.take_pooled_http1(&authority)
                .await?
                .or(Some(connect_plain(url, &self.options).await?))
        } else if proxy_url.is_none() {
            Some(connect_plain(url, &self.options).await?)
        } else {
            None
        };
        let mut proxy_stream = if let Some(proxy_url) = proxy_url.as_deref() {
            Some(connect_plain_via_proxy(url, &self.options, proxy_url).await?)
        } else {
            None
        };
        let stream: &mut dyn AsyncIo = match (direct_stream.as_mut(), proxy_stream.as_mut()) {
            (Some(stream), None) => stream,
            (None, Some(stream)) => stream.as_mut(),
            _ => unreachable!("either direct or proxy stream must exist"),
        };

        let keep_alive = use_direct_pool;
        let request_bytes = build_http1_request(request, url, keep_alive)?;
        stream
            .write_all(&request_bytes)
            .await
            .map_err(|err| ClientError::Http(format!("failed to write request: {err}")))?;
        self.bandwidth_tracker.add_write(request_bytes.len());
        stream
            .flush()
            .await
            .map_err(|err| ClientError::Http(format!("failed to flush request: {err}")))?;

        let parsed = read_http1_response(stream, &self.bandwidth_tracker).await?;
        let response = Response::new(
            parsed.status,
            parsed.version,
            parsed.headers.clone(),
            parsed.body,
        );

        if keep_alive && !parsed.connection_close {
            if let Some(stream) = direct_stream.take() {
                self.return_pooled_http1(authority, stream).await;
            }
        }

        Ok(response)
    }

    async fn send_https(
        &self,
        request: &Request,
        url: &Url,
        profile: &ProfileSpec,
    ) -> Result<Response, ClientError> {
        let proxy_url = self.get_proxy();
        if !self.http3_eligible(proxy_url.as_deref(), profile) {
            return self
                .send_https_via_tls(request, url, profile, proxy_url.as_deref())
                .await;
        }

        if self.options.protocol_racing {
            return self
                .send_https_racing(request, url, profile, proxy_url)
                .await;
        }

        match send_http3(
            request.clone(),
            url.clone(),
            self.options.clone(),
            Arc::new(profile.clone()),
            self.bandwidth_tracker.clone(),
            self.http3_session_cache.clone(),
        )
        .await
        {
            Ok(response) => Ok(response),
            Err(err) => {
                if std::env::var_os("TLS_RUST_HTTP3_STRICT").is_some() {
                    return Err(err);
                }
                self.send_https_via_tls(request, url, profile, proxy_url.as_deref())
                    .await
            }
        }
    }

    fn http3_eligible(&self, proxy_url: Option<&str>, profile: &ProfileSpec) -> bool {
        !self.options.force_http1
            && !self.options.disable_http3
            && proxy_url.is_none()
            && profile.http3.is_some()
    }

    async fn send_https_racing(
        &self,
        request: &Request,
        url: &Url,
        profile: &ProfileSpec,
        proxy_url: Option<String>,
    ) -> Result<Response, ClientError> {
        let h3_client = self.clone();
        let h3_request = request.clone();
        let h3_url = url.clone();
        let h3_profile = Arc::new(profile.clone());
        let mut h3_task = tokio::spawn(async move {
            send_http3(
                h3_request,
                h3_url,
                h3_client.options.clone(),
                h3_profile,
                h3_client.bandwidth_tracker.clone(),
                h3_client.http3_session_cache.clone(),
            )
            .await
        });

        let tls_client = self.clone();
        let tls_request = request.clone();
        let tls_url = url.clone();
        let tls_profile = profile.clone();
        let proxy_url_for_tls = proxy_url.clone();
        let mut tls_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            tls_client
                .send_https_via_tls(
                    &tls_request,
                    &tls_url,
                    &tls_profile,
                    proxy_url_for_tls.as_deref(),
                )
                .await
        });

        let (first_is_h3, first_result) = tokio::select! {
            result = &mut h3_task => (true, result),
            result = &mut tls_task => (false, result),
        };

        let other_task = if first_is_h3 {
            &mut tls_task
        } else {
            &mut h3_task
        };
        match flatten_race_result(first_result, if first_is_h3 { "http3" } else { "tls" }) {
            Ok(response) => {
                other_task.abort();
                Ok(response)
            }
            Err(err) => {
                if first_is_h3 && std::env::var_os("TLS_RUST_HTTP3_STRICT").is_some() {
                    other_task.abort();
                    return Err(err);
                }
                flatten_race_result(other_task.await, if first_is_h3 { "tls" } else { "http3" })
            }
        }
    }

    async fn send_https_via_tls(
        &self,
        request: &Request,
        url: &Url,
        profile: &ProfileSpec,
        proxy_url: Option<&str>,
    ) -> Result<Response, ClientError> {
        let mut stream = connect_tls(
            url,
            &self.options,
            proxy_url,
            &self.tls_connector,
            profile,
            &self.tls_session_cache,
        )
        .await?;
        let selected_alpn = stream
            .ssl()
            .selected_alpn_protocol()
            .map(|value| value.to_vec())
            .unwrap_or_default();
        if !self.options.force_http1 && selected_alpn.as_slice() == b"h2" {
            let (response, _stream) =
                send_http2(stream, request, url, profile, &self.bandwidth_tracker).await?;
            return Ok(response);
        }

        let keep_alive = false;
        let request_bytes = build_http1_request(request, url, keep_alive)?;
        stream
            .write_all(&request_bytes)
            .await
            .map_err(|err| ClientError::Http(format!("failed to write TLS request: {err}")))?;
        self.bandwidth_tracker.add_write(request_bytes.len());
        stream
            .flush()
            .await
            .map_err(|err| ClientError::Http(format!("failed to flush TLS request: {err}")))?;

        let parsed = read_http1_response(&mut stream, &self.bandwidth_tracker).await?;
        Ok(Response::new(
            parsed.status,
            parsed.version,
            parsed.headers,
            parsed.body,
        ))
    }

    async fn take_pooled_http1(&self, key: &str) -> Result<Option<TcpStream>, ClientError> {
        let mut pool = self.http1_pool.lock().await;
        Ok(pool.get_mut(key).and_then(|streams| streams.pop()))
    }

    async fn return_pooled_http1(&self, key: String, stream: TcpStream) {
        let mut pool = self.http1_pool.lock().await;
        pool.entry(key).or_default().push(stream);
    }

    fn run_pre_hooks(&self, request: &mut Request) -> Result<(), ClientError> {
        let hooks = self.pre_hooks.read().expect("pre-hooks poisoned").clone();
        for hook in hooks {
            let outcome = catch_unwind(AssertUnwindSafe(|| (hook)(request)))
                .map_err(|_| ClientError::HookPanic("pre hook panicked".to_string()))?;
            match outcome {
                Ok(()) => {}
                Err(PreHookErrorMode::Continue(_)) => continue,
                Err(PreHookErrorMode::Abort(message)) => {
                    return Err(ClientError::HookAborted(message));
                }
            }
        }

        Ok(())
    }

    fn run_post_hooks(&self, request: &Request, result: &Result<Response, ClientError>) {
        let hooks = self.post_hooks.read().expect("post-hooks poisoned").clone();
        let context = PostHookContext {
            request: request.clone(),
            status: result
                .as_ref()
                .ok()
                .map(|response| response.status().as_u16()),
            error: result.as_ref().err().map(ToString::to_string),
        };

        for hook in hooks {
            let outcome = catch_unwind(AssertUnwindSafe(|| (hook)(&context)));
            match outcome {
                Ok(Ok(())) | Ok(Err(PostHookErrorMode::Continue(_))) => {}
                Ok(Err(PostHookErrorMode::Abort(_))) | Err(_) => break,
            }
        }
    }
}

fn flatten_race_result(
    result: Result<Result<Response, ClientError>, tokio::task::JoinError>,
    label: &str,
) -> Result<Response, ClientError> {
    match result {
        Ok(inner) => inner,
        Err(err) => Err(ClientError::Http(format!(
            "{label} request task failed to join: {err}"
        ))),
    }
}

#[derive(Debug)]
struct ParsedHttp1Response {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Vec<u8>,
    connection_close: bool,
}

fn build_http1_request(
    request: &Request,
    url: &Url,
    keep_alive: bool,
) -> Result<Vec<u8>, ClientError> {
    let mut bytes = Vec::new();
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    bytes.extend_from_slice(request.method.as_str().as_bytes());
    bytes.extend_from_slice(b" ");
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(b" HTTP/1.1\r\n");

    if !request.has_header("Host") {
        bytes.extend_from_slice(b"Host: ");
        bytes.extend_from_slice(host_header_value(url)?.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }

    for header in &request.headers {
        validate_header_entry(header)?;
        bytes.extend_from_slice(header.name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(header.value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }

    if request.body.is_some() && !request.has_header("Content-Length") {
        let len = request.body.as_ref().expect("body checked").len();
        bytes.extend_from_slice(format!("Content-Length: {len}\r\n").as_bytes());
    }

    if !request.has_header("Connection") {
        if keep_alive {
            bytes.extend_from_slice(b"Connection: keep-alive\r\n");
        } else {
            bytes.extend_from_slice(b"Connection: close\r\n");
        }
    }

    bytes.extend_from_slice(b"\r\n");

    if let Some(body) = &request.body {
        bytes.extend_from_slice(body);
    }

    Ok(bytes)
}

fn validate_header_entry(header: &HeaderEntry) -> Result<(), ClientError> {
    HeaderName::from_bytes(header.name.as_bytes())
        .map_err(|err| ClientError::InvalidHeaderName(header.name.clone(), err.to_string()))?;
    HeaderValue::from_str(&header.value)
        .map_err(|err| ClientError::InvalidHeaderValue(header.name.clone(), err.to_string()))?;
    Ok(())
}

async fn connect_plain(url: &Url, options: &ClientOptions) -> Result<TcpStream, ClientError> {
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    let port = url.port_or_known_default().unwrap_or(80);
    connect_direct_tcp(host, port, options).await
}

async fn connect_plain_via_proxy(
    url: &Url,
    options: &ClientOptions,
    proxy_url: &str,
) -> Result<BoxedIo, ClientError> {
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    let port = url.port_or_known_default().unwrap_or(80);
    connect_target(host, port, options, Some(proxy_url)).await
}

fn authority_for_pool(url: &Url) -> Result<String, ClientError> {
    let authority = url.authority();
    if authority.is_empty() {
        return Err(ClientError::Http("URL missing authority".to_string()));
    }

    Ok(format!("{}://{}", url.scheme(), authority))
}

fn host_header_value(url: &Url) -> Result<String, ClientError> {
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    let port = url.port();
    let include_port = match (url.scheme(), port) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => false,
        _ => true,
    };

    if include_port {
        Ok(format!("{host}:{}", url.port().expect("port checked")))
    } else {
        Ok(host.to_string())
    }
}

#[derive(Clone, Copy)]
enum ProxyScheme {
    Http,
    Https,
    Socks4,
    Socks4a,
    Socks5,
    Socks5h,
}

struct ProxyConfig {
    scheme: ProxyScheme,
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
}

fn normalize_proxy_url(proxy_url: &str) -> Result<Option<String>, ClientError> {
    if proxy_url.trim().is_empty() {
        return Ok(None);
    }

    parse_proxy_config(proxy_url)?;
    Ok(Some(proxy_url.to_string()))
}

fn parse_proxy_config(proxy_url: &str) -> Result<ProxyConfig, ClientError> {
    let parsed = Url::parse(proxy_url)
        .map_err(|err| ClientError::Http(format!("invalid proxy URL `{proxy_url}`: {err}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| ClientError::Http(format!("proxy URL `{proxy_url}` is missing a host")))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| ClientError::Http(format!("proxy URL `{proxy_url}` is missing a port")))?;
    let scheme = match parsed.scheme() {
        "http" => ProxyScheme::Http,
        "https" => ProxyScheme::Https,
        "socks4" => ProxyScheme::Socks4,
        "socks4a" => ProxyScheme::Socks4a,
        "socks5" => ProxyScheme::Socks5,
        "socks5h" => ProxyScheme::Socks5h,
        scheme => {
            return Err(ClientError::Http(format!(
                "unsupported proxy scheme `{scheme}`"
            )));
        }
    };

    let username = if parsed.username().is_empty() {
        None
    } else {
        Some(parsed.username().to_string())
    };
    let password = parsed.password().map(ToString::to_string);

    Ok(ProxyConfig {
        scheme,
        host: host.to_string(),
        port,
        username,
        password,
    })
}

async fn connect_via_http_proxy(
    target_host: &str,
    target_port: u16,
    options: &ClientOptions,
    proxy: &ProxyConfig,
) -> Result<BoxedIo, ClientError> {
    let proxy_stream = connect_direct_tcp(&proxy.host, proxy.port, options).await?;
    let mut proxy_stream: BoxedIo = match proxy.scheme {
        ProxyScheme::Http => Box::new(proxy_stream),
        ProxyScheme::Https => Box::new(connect_tls_to_proxy(proxy_stream, proxy, options).await?),
        _ => unreachable!("invalid HTTP proxy scheme"),
    };

    write_http_connect(&mut proxy_stream, target_host, target_port, proxy).await?;
    read_http_connect_response(&mut proxy_stream).await?;
    Ok(proxy_stream)
}

async fn connect_tls_to_proxy(
    stream: TcpStream,
    proxy: &ProxyConfig,
    options: &ClientOptions,
) -> Result<tokio_boring2::SslStream<TcpStream>, ClientError> {
    let mut builder = if options.insecure_skip_verify {
        SslConnector::no_default_verify_builder(SslMethod::tls())
    } else {
        SslConnector::builder(SslMethod::tls())
    }
    .map_err(|err| {
        ClientError::Http(format!(
            "failed to initialize HTTPS proxy TLS connector: {err}"
        ))
    })?;

    if options.insecure_skip_verify {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        configure_ca_roots(&mut builder)?;
    }

    let connector = builder.build();
    let mut config = connector.configure().map_err(|err| {
        ClientError::Http(format!(
            "failed to configure HTTPS proxy TLS connector: {err}"
        ))
    })?;
    if options.insecure_skip_verify {
        config.set_verify_hostname(false);
    }
    let ssl = config.into_ssl(&proxy.host).map_err(|err| {
        ClientError::Http(format!("failed to build HTTPS proxy TLS session: {err}"))
    })?;

    tokio_boring2::SslStreamBuilder::new(ssl, stream)
        .connect()
        .await
        .map_err(|err| ClientError::Http(format!("HTTPS proxy TLS handshake failed: {err}")))
}

async fn write_http_connect(
    stream: &mut BoxedIo,
    target_host: &str,
    target_port: u16,
    proxy: &ProxyConfig,
) -> Result<(), ClientError> {
    let authority = format!("{target_host}:{target_port}");
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(username) = &proxy.username {
        let password = proxy.password.as_deref().unwrap_or_default();
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {credentials}\r\n"));
    }
    request.push_str("\r\n");

    stream.write_all(request.as_bytes()).await.map_err(|err| {
        ClientError::Http(format!("failed to write proxy CONNECT request: {err}"))
    })?;
    stream.flush().await.map_err(|err| {
        ClientError::Http(format!("failed to flush proxy CONNECT request: {err}"))
    })?;
    Ok(())
}

async fn read_http_connect_response(stream: &mut BoxedIo) -> Result<(), ClientError> {
    let mut buffer = Vec::with_capacity(1024);
    let headers_end = loop {
        if let Some(index) = find_headers_end(&buffer) {
            break index;
        }

        let mut chunk = [0u8; 512];
        let read = stream.read(&mut chunk).await.map_err(|err| {
            ClientError::Http(format!("failed to read proxy CONNECT response: {err}"))
        })?;
        if read == 0 {
            return Err(ClientError::Http(
                "proxy closed connection before CONNECT response completed".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut headers);
    response.parse(&buffer[..headers_end]).map_err(|err| {
        ClientError::Http(format!("failed to parse proxy CONNECT response: {err}"))
    })?;
    let status = response.code.unwrap_or_default();
    if status != 200 {
        return Err(ClientError::Http(format!(
            "proxy CONNECT failed with status {status}"
        )));
    }

    Ok(())
}

async fn connect_via_socks4_proxy(
    target_host: &str,
    target_port: u16,
    options: &ClientOptions,
    proxy: &ProxyConfig,
) -> Result<BoxedIo, ClientError> {
    let mut stream = connect_direct_tcp(&proxy.host, proxy.port, options).await?;
    let user_id = proxy.username.as_deref().unwrap_or("");
    let mut request = Vec::with_capacity(128);
    request.push(0x04);
    request.push(0x01);
    request.extend_from_slice(&target_port.to_be_bytes());

    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => request.extend_from_slice(&ipv4.octets()),
        Ok(IpAddr::V6(_)) if matches!(proxy.scheme, ProxyScheme::Socks4a) => {
            request.extend_from_slice(&[0, 0, 0, 1]);
        }
        Ok(IpAddr::V6(_)) => {
            return Err(ClientError::Http(
                "SOCKS4 does not support IPv6 targets".to_string(),
            ));
        }
        Err(_) if matches!(proxy.scheme, ProxyScheme::Socks4a) => {
            request.extend_from_slice(&[0, 0, 0, 1]);
        }
        Err(_) => {
            return Err(ClientError::Http(
                "SOCKS4 requires an IPv4 target or a socks4a proxy".to_string(),
            ));
        }
    }

    request.extend_from_slice(user_id.as_bytes());
    request.push(0);
    if matches!(proxy.scheme, ProxyScheme::Socks4a) && target_host.parse::<IpAddr>().is_err() {
        request.extend_from_slice(target_host.as_bytes());
        request.push(0);
    }

    stream
        .write_all(&request)
        .await
        .map_err(|err| ClientError::Http(format!("failed to write SOCKS4 request: {err}")))?;
    stream
        .flush()
        .await
        .map_err(|err| ClientError::Http(format!("failed to flush SOCKS4 request: {err}")))?;

    let mut response = [0u8; 8];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|err| ClientError::Http(format!("failed to read SOCKS4 response: {err}")))?;
    if response[1] != 0x5a {
        return Err(ClientError::Http(format!(
            "SOCKS4 proxy rejected the connection with status 0x{:02x}",
            response[1]
        )));
    }

    Ok(Box::new(stream))
}

async fn connect_via_socks5_proxy(
    target_host: &str,
    target_port: u16,
    options: &ClientOptions,
    proxy: &ProxyConfig,
) -> Result<BoxedIo, ClientError> {
    let mut stream = connect_direct_tcp(&proxy.host, proxy.port, options).await?;
    let methods = if proxy.username.is_some() {
        [0x00_u8, 0x02_u8]
    } else {
        [0x00_u8, 0x00_u8]
    };
    let greeting = if proxy.username.is_some() {
        vec![0x05, 0x02, methods[0], methods[1]]
    } else {
        vec![0x05, 0x01, methods[0]]
    };
    stream
        .write_all(&greeting)
        .await
        .map_err(|err| ClientError::Http(format!("failed to write SOCKS5 greeting: {err}")))?;
    let mut method_response = [0u8; 2];
    stream
        .read_exact(&mut method_response)
        .await
        .map_err(|err| {
            ClientError::Http(format!("failed to read SOCKS5 greeting response: {err}"))
        })?;
    if method_response[0] != 0x05 {
        return Err(ClientError::Http(
            "SOCKS5 proxy returned an invalid greeting response".to_string(),
        ));
    }
    match method_response[1] {
        0x00 => {}
        0x02 => {
            let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
            let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
            let mut auth_request = Vec::with_capacity(3 + username.len() + password.len());
            auth_request.push(0x01);
            auth_request.push(username.len() as u8);
            auth_request.extend_from_slice(username);
            auth_request.push(password.len() as u8);
            auth_request.extend_from_slice(password);
            stream.write_all(&auth_request).await.map_err(|err| {
                ClientError::Http(format!("failed to write SOCKS5 auth request: {err}"))
            })?;
            let mut auth_response = [0u8; 2];
            stream.read_exact(&mut auth_response).await.map_err(|err| {
                ClientError::Http(format!("failed to read SOCKS5 auth response: {err}"))
            })?;
            if auth_response != [0x01, 0x00] {
                return Err(ClientError::Http(
                    "SOCKS5 proxy rejected username/password authentication".to_string(),
                ));
            }
        }
        0xff => {
            return Err(ClientError::Http(
                "SOCKS5 proxy does not accept any supported authentication method".to_string(),
            ));
        }
        method => {
            return Err(ClientError::Http(format!(
                "SOCKS5 proxy selected unsupported authentication method 0x{method:02x}"
            )));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            request.push(0x01);
            request.extend_from_slice(&ipv4.octets());
        }
        Ok(IpAddr::V6(ipv6)) => {
            request.push(0x04);
            request.extend_from_slice(&ipv6.octets());
        }
        Err(_) => {
            request.push(0x03);
            request.push(target_host.len() as u8);
            request.extend_from_slice(target_host.as_bytes());
        }
    }
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request).await.map_err(|err| {
        ClientError::Http(format!("failed to write SOCKS5 connect request: {err}"))
    })?;
    stream.flush().await.map_err(|err| {
        ClientError::Http(format!("failed to flush SOCKS5 connect request: {err}"))
    })?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|err| {
        ClientError::Http(format!("failed to read SOCKS5 connect response: {err}"))
    })?;
    if header[0] != 0x05 {
        return Err(ClientError::Http(
            "SOCKS5 proxy returned an invalid connect response".to_string(),
        ));
    }
    if header[1] != 0x00 {
        return Err(ClientError::Http(format!(
            "SOCKS5 proxy rejected the connection with status 0x{:02x}",
            header[1]
        )));
    }

    let addr_len = match header[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(|err| {
                ClientError::Http(format!("failed to read SOCKS5 address length: {err}"))
            })?;
            usize::from(len[0])
        }
        atyp => {
            return Err(ClientError::Http(format!(
                "SOCKS5 proxy returned unsupported address type 0x{atyp:02x}"
            )));
        }
    };
    let mut discard = vec![0u8; addr_len + 2];
    stream.read_exact(&mut discard).await.map_err(|err| {
        ClientError::Http(format!("failed to finish reading SOCKS5 response: {err}"))
    })?;

    Ok(Box::new(stream))
}

async fn read_http1_response<T>(
    stream: &mut T,
    tracker: &BandwidthTracker,
) -> Result<ParsedHttp1Response, ClientError>
where
    T: tokio::io::AsyncRead + Unpin + ?Sized,
{
    let mut buffer = Vec::with_capacity(4096);
    let headers_end = loop {
        if let Some(index) = find_headers_end(&buffer) {
            break index;
        }

        let mut chunk = [0u8; 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|err| ClientError::Http(format!("failed to read response: {err}")))?;
        if read == 0 {
            return Err(ClientError::Http(
                "connection closed before response headers were received".to_string(),
            ));
        }
        tracker.add_read(read);
        buffer.extend_from_slice(&chunk[..read]);
    };

    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let status = response
        .parse(&buffer[..headers_end])
        .map_err(|err| ClientError::Http(format!("failed to parse response headers: {err}")))?;
    let header_bytes = match status {
        httparse::Status::Complete(bytes) => bytes,
        httparse::Status::Partial => {
            return Err(ClientError::Http(
                "response headers were incomplete".to_string(),
            ));
        }
    };

    let version = match response.version.unwrap_or(1) {
        0 => Version::HTTP_10,
        _ => Version::HTTP_11,
    };
    let status = StatusCode::from_u16(response.code.unwrap_or(200))
        .map_err(|err| ClientError::Http(format!("invalid status code: {err}")))?;
    let header_map = parse_headers(response.headers)?;

    let mut body = buffer[header_bytes..].to_vec();
    let content_length = header_map
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok());

    if let Some(expected) = content_length {
        while body.len() < expected {
            let mut chunk = vec![0u8; expected - body.len()];
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|err| ClientError::Http(format!("failed to read response body: {err}")))?;
            if read == 0 {
                break;
            }
            tracker.add_read(read);
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(expected);
    }

    let connection_close = header_map
        .get(http::header::CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("close"))
        .unwrap_or(version == Version::HTTP_10);

    Ok(ParsedHttp1Response {
        status,
        version,
        headers: header_map,
        body,
        connection_close,
    })
}

fn parse_headers(headers: &[httparse::Header<'_>]) -> Result<HeaderMap, ClientError> {
    let mut map = HeaderMap::with_capacity(headers.len());
    for header in headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|err| ClientError::Http(format!("invalid response header name: {err}")))?;
        let value = HeaderValue::from_bytes(header.value)
            .map_err(|err| ClientError::Http(format!("invalid response header value: {err}")))?;
        map.append(name, value);
    }
    Ok(map)
}

fn find_headers_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

async fn connect_tls(
    url: &Url,
    options: &ClientOptions,
    proxy_url: Option<&str>,
    connector: &SslConnector,
    profile: &ProfileSpec,
    session_cache: &Arc<StdMutex<HashMap<String, SslSession>>>,
) -> Result<tokio_boring2::SslStream<BoxedIo>, ClientError> {
    init_openssl_cert_env();

    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    let tcp = connect_target(
        host,
        url.port_or_known_default().unwrap_or(443),
        options,
        proxy_url,
    )
    .await?;
    let mut config = connector
        .configure()
        .map_err(|err| ClientError::Http(format!("failed to configure TLS connector: {err}")))?;
    if options.insecure_skip_verify {
        config.set_verify_hostname(false);
    }
    apply_tls_profile_connection(&mut config, &profile.tls)?;

    let server_name = options.server_name_overwrite.as_deref().unwrap_or(host);
    let mut ssl = config
        .into_ssl(server_name)
        .map_err(|err| ClientError::Http(format!("failed to construct TLS session: {err}")))?;
    let session_key = tls_session_cache_key(profile.key, server_name);
    ssl.set_ex_data(tls_session_key_ex_index(), session_key.clone());
    if profile.tls.pre_shared_key {
        if let Some(session) = session_cache
            .lock()
            .expect("tls session cache poisoned")
            .get(&session_key)
            .cloned()
        {
            unsafe {
                ssl.set_session(&session).map_err(|err| {
                    ClientError::Http(format!("failed to reuse TLS session: {err}"))
                })?;
            }
        }
    }

    let stream = tokio_boring2::SslStreamBuilder::new(ssl, tcp)
        .connect()
        .await
        .map_err(|err| ClientError::Http(format!("TLS handshake failed: {err}")))?;
    verify_certificate_pins(&stream, host, &options.certificate_pins)?;
    Ok(stream)
}

fn tls_session_cache_key(profile_key: &str, server_name: &str) -> String {
    format!("{profile_key}:{server_name}")
}

fn build_tls_connector(
    options: &ClientOptions,
    profile: &ProfileSpec,
    session_cache: &Arc<StdMutex<HashMap<String, SslSession>>>,
) -> Result<SslConnector, ClientError> {
    init_openssl_cert_env();

    let mut builder = if options.insecure_skip_verify {
        SslConnector::no_default_verify_builder(SslMethod::tls())
    } else {
        SslConnector::builder(SslMethod::tls())
    }
    .map_err(|err| ClientError::Http(format!("failed to initialize TLS connector: {err}")))?;

    if options.insecure_skip_verify {
        builder.set_verify(SslVerifyMode::NONE);
    } else {
        configure_ca_roots(&mut builder)?;
    }

    apply_tls_profile_context(&mut builder, &profile.tls)?;
    if profile.tls.pre_shared_key {
        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
        let session_cache = Arc::clone(session_cache);
        let profile_key = profile.key.to_string();
        builder.set_new_session_callback(move |ssl, session| {
            let Some(key) = ssl
                .ex_data(tls_session_key_ex_index())
                .cloned()
                .or_else(|| {
                    ssl.servername(NameType::HOST_NAME)
                        .map(|server_name| tls_session_cache_key(&profile_key, server_name))
                })
            else {
                return;
            };

            session_cache
                .lock()
                .expect("tls session cache poisoned")
                .insert(key, session);
        });
    }
    Ok(builder.build())
}

fn tls_session_key_ex_index() -> boring2::ex_data::Index<Ssl, String> {
    static INDEX: OnceLock<boring2::ex_data::Index<Ssl, String>> = OnceLock::new();
    *INDEX.get_or_init(|| {
        Ssl::new_ex_index::<String>().expect("create TLS session-key ex_data index")
    })
}

async fn connect_target(
    host: &str,
    port: u16,
    options: &ClientOptions,
    proxy_url: Option<&str>,
) -> Result<BoxedIo, ClientError> {
    let Some(proxy_url) = proxy_url else {
        return Ok(Box::new(connect_direct_tcp(host, port, options).await?));
    };

    let proxy = parse_proxy_config(proxy_url)?;
    match proxy.scheme {
        ProxyScheme::Http | ProxyScheme::Https => {
            connect_via_http_proxy(host, port, options, &proxy).await
        }
        ProxyScheme::Socks4 | ProxyScheme::Socks4a => {
            connect_via_socks4_proxy(host, port, options, &proxy).await
        }
        ProxyScheme::Socks5 | ProxyScheme::Socks5h => {
            connect_via_socks5_proxy(host, port, options, &proxy).await
        }
    }
}

async fn connect_direct_tcp(
    host: &str,
    port: u16,
    options: &ClientOptions,
) -> Result<TcpStream, ClientError> {
    if let Some(dial_context) = &options.dial_context {
        return dial_context(host.to_string(), port).await;
    }

    let addrs = resolve_socket_addrs(host, port, options).await?;
    let mut last_error = None;

    for addr in addrs {
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }
        .map_err(|err| ClientError::Http(format!("failed to create TCP socket: {err}")))?;

        match socket.connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_error = Some(err),
        }
    }

    let message = last_error
        .map(|err| format!("failed to connect to {host}:{port}: {err}"))
        .unwrap_or_else(|| format!("failed to connect to {host}:{port}"));
    Err(ClientError::Http(message))
}

async fn resolve_socket_addrs(
    host: &str,
    port: u16,
    options: &ClientOptions,
) -> Result<Vec<SocketAddr>, ClientError> {
    let resolved = lookup_host((host, port))
        .await
        .map_err(|err| ClientError::Http(format!("failed to resolve {host}:{port}: {err}")))?;
    let filtered = filter_socket_addrs(resolved.collect(), options);
    if filtered.is_empty() {
        return Err(ClientError::Http(format!(
            "no socket addresses remain for {host}:{port} after IP family filtering"
        )));
    }
    Ok(filtered)
}

fn filter_socket_addrs(addrs: Vec<SocketAddr>, options: &ClientOptions) -> Vec<SocketAddr> {
    addrs
        .into_iter()
        .filter(|addr| {
            (!options.disable_ipv4 || !addr.is_ipv4()) && (!options.disable_ipv6 || !addr.is_ipv6())
        })
        .collect()
}

fn verify_certificate_pins<S>(
    stream: &tokio_boring2::SslStream<S>,
    host: &str,
    pins: &HashMap<String, Vec<String>>,
) -> Result<(), ClientError> {
    let Some(expected) = pins_for_host(pins, host) else {
        return Ok(());
    };

    let mut actual = Vec::new();
    if let Some(cert) = stream.ssl().peer_certificate() {
        actual.push(certificate_pin(&cert)?);
    }
    if let Some(chain) = stream.ssl().peer_cert_chain() {
        for cert in chain {
            actual.push(certificate_pin(cert)?);
        }
    }

    if actual
        .iter()
        .any(|pin| expected.iter().any(|expected| expected == pin))
    {
        return Ok(());
    }

    Err(ClientError::BadPinDetected(format!(
        "bad ssl pin detected for {host}, expected one of {:?}, found {:?}",
        expected, actual
    )))
}

fn certificate_pin(cert: &boring2::x509::X509Ref) -> Result<String, ClientError> {
    let public_key = cert
        .public_key()
        .map_err(|err| ClientError::Http(format!("failed to read peer public key: {err}")))?;
    let public_key_der = public_key
        .public_key_to_der()
        .map_err(|err| ClientError::Http(format!("failed to encode peer public key: {err}")))?;
    let digest = Sha256::digest(public_key_der);
    Ok(base64::engine::general_purpose::STANDARD.encode(digest))
}

fn pins_for_host<'a>(
    pins: &'a HashMap<String, Vec<String>>,
    host: &str,
) -> Option<&'a Vec<String>> {
    if let Some(exact) = pins.get(host) {
        return Some(exact);
    }

    let host = host.to_ascii_lowercase();
    pins.iter()
        .filter_map(|(pattern, expected)| {
            wildcard_pin_base(pattern).and_then(|base| {
                (host == base || host.ends_with(&format!(".{base}")))
                    .then_some((base.len(), expected))
            })
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, expected)| expected)
}

fn wildcard_pin_base(pattern: &str) -> Option<String> {
    pattern
        .strip_prefix("*.")
        .map(|base| base.to_ascii_lowercase())
}

fn apply_tls_profile_context(
    builder: &mut boring2::ssl::SslConnectorBuilder,
    tls: &crate::profile::TlsProfileSpec,
) -> Result<(), ClientError> {
    builder
        .set_cipher_list(tls.cipher_list)
        .map_err(|err| ClientError::Http(format!("failed to set cipher list: {err}")))?;
    builder
        .set_curves_list(tls.curves)
        .map_err(|err| ClientError::Http(format!("failed to set curves list: {err}")))?;
    builder
        .set_sigalgs_list(tls.sigalgs)
        .map_err(|err| ClientError::Http(format!("failed to set signature algorithms: {err}")))?;
    if let Some(delegated_credentials) = tls.delegated_credentials {
        builder
            .set_delegated_credentials(delegated_credentials)
            .map_err(|err| {
                ClientError::Http(format!("failed to set delegated credentials: {err}"))
            })?;
    }

    builder
        .set_min_proto_version(Some(map_tls_version(tls.min_tls_version)))
        .map_err(|err| ClientError::Http(format!("failed to set minimum TLS version: {err}")))?;
    builder
        .set_max_proto_version(Some(map_tls_version(tls.max_tls_version)))
        .map_err(|err| ClientError::Http(format!("failed to set maximum TLS version: {err}")))?;
    builder
        .set_alpn_protos(&encode_alpn_protocols(&tls.alpn))
        .map_err(|err| ClientError::Http(format!("failed to set ALPN protocols: {err}")))?;

    builder.set_grease_enabled(tls.grease_enabled);
    builder.set_aes_hw_override(tls.aes_hw_override);
    builder.set_permute_extensions(tls.permute_extensions);
    if let Some(limit) = tls.key_shares_limit {
        builder.set_key_shares_limit(limit);
    }
    if let Some(limit) = tls.record_size_limit {
        builder.set_record_size_limit(limit as u16);
    }
    if tls.enable_ocsp_stapling {
        builder.enable_ocsp_stapling();
    }
    if tls.enable_signed_cert_timestamps {
        builder.enable_signed_cert_timestamps();
    }
    for algorithm in &tls.certificate_compression {
        builder
            .add_cert_compression_alg(map_cert_compression(*algorithm))
            .map_err(|err| {
                ClientError::Http(format!(
                    "failed to configure certificate compression algorithms: {err}"
                ))
            })?;
    }

    let permutation = tls
        .extension_order
        .iter()
        .copied()
        .map(ExtensionType::from)
        .collect::<Vec<_>>();
    builder
        .set_extension_permutation(&permutation)
        .map_err(|err| ClientError::Http(format!("failed to set TLS extension order: {err}")))?;

    Ok(())
}

fn apply_tls_profile_connection(
    config: &mut boring2::ssl::ConnectConfiguration,
    tls: &crate::profile::TlsProfileSpec,
) -> Result<(), ClientError> {
    config.set_enable_ech_grease(tls.enable_ech_grease);
    config.set_alps_use_new_codepoint(tls.alps_use_new_codepoint);
    if tls.enable_ocsp_stapling {
        config.set_status_type(StatusType::OCSP).map_err(|err| {
            ClientError::Http(format!("failed to configure OCSP status type: {err}"))
        })?;
    }

    for protocol in &tls.alps {
        let alpn = match protocol {
            ApplicationSettingsProtocol::Http2 => b"h2".as_slice(),
            ApplicationSettingsProtocol::Http3 => b"h3".as_slice(),
        };
        config
            .add_application_settings(alpn)
            .map_err(|err| ClientError::Http(format!("failed to configure ALPS: {err}")))?;
    }

    Ok(())
}

fn map_tls_version(version: TlsProfileVersion) -> SslVersion {
    match version {
        TlsProfileVersion::Tls10 => SslVersion::TLS1,
        TlsProfileVersion::Tls11 => SslVersion::TLS1_1,
        TlsProfileVersion::Tls12 => SslVersion::TLS1_2,
        TlsProfileVersion::Tls13 => SslVersion::TLS1_3,
    }
}

fn map_cert_compression(algorithm: CompressionAlgorithm) -> CertCompressionAlgorithm {
    match algorithm {
        CompressionAlgorithm::Brotli => CertCompressionAlgorithm::Brotli,
        CompressionAlgorithm::Zlib => CertCompressionAlgorithm::Zlib,
        CompressionAlgorithm::Zstd => CertCompressionAlgorithm::Zstd,
    }
}

fn encode_alpn_protocols(protocols: &[ApplicationProtocol]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for protocol in protocols {
        let value = match protocol {
            ApplicationProtocol::Http1 => b"http/1.1".as_slice(),
            ApplicationProtocol::Http2 => b"h2".as_slice(),
            ApplicationProtocol::Http3 => b"h3".as_slice(),
        };
        bytes.push(value.len() as u8);
        bytes.extend_from_slice(value);
    }
    bytes
}

fn init_openssl_cert_env() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = unsafe { openssl_probe::try_init_openssl_env_vars() };
    });
}

fn configure_ca_roots(builder: &mut boring2::ssl::SslConnectorBuilder) -> Result<(), ClientError> {
    let probe = openssl_probe::probe();
    let cert_file = probe.cert_file.or_else(find_fallback_ca_file);

    let Some(cert_file) = cert_file else {
        return Ok(());
    };

    builder
        .set_ca_file(&cert_file)
        .map_err(|err| ClientError::Http(format!("failed to load CA roots: {err}")))
}

fn find_fallback_ca_file() -> Option<PathBuf> {
    const CANDIDATES: &[&str] = &[
        "C:\\Program Files\\Git\\mingw64\\etc\\ssl\\certs\\ca-bundle.crt",
        "C:\\Program Files\\Git\\mingw64\\etc\\ssl\\cert.pem",
        "C:\\Program Files\\Git\\usr\\ssl\\certs\\ca-bundle.crt",
        "C:\\Program Files\\Git\\usr\\ssl\\cert.pem",
    ];

    CANDIDATES
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("http error: {0}")]
    Http(String),
    #[error(transparent)]
    Url(#[from] url::ParseError),
    #[error("unsupported profile: {0}")]
    UnsupportedProfile(String),
    #[error("invalid header name `{0}`: {1}")]
    InvalidHeaderName(String, String),
    #[error("invalid header value for `{0}`: {1}")]
    InvalidHeaderValue(String, String),
    #[error("hook aborted request: {0}")]
    HookAborted(String),
    #[error("hook panicked: {0}")]
    HookPanic(String),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("{0}")]
    BadPinDetected(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_pins_match_root_and_subdomains() {
        let mut pins = HashMap::new();
        pins.insert("*.example.com".to_string(), vec!["pin".to_string()]);
        pins.insert("api.example.com".to_string(), vec!["exact".to_string()]);

        assert_eq!(
            pins_for_host(&pins, "api.example.com"),
            Some(&vec!["exact".to_string()])
        );
        assert_eq!(
            pins_for_host(&pins, "example.com"),
            Some(&vec!["pin".to_string()])
        );
        assert_eq!(
            pins_for_host(&pins, "www.example.com"),
            Some(&vec!["pin".to_string()])
        );
        assert_eq!(pins_for_host(&pins, "example.net"), None);
    }

    #[test]
    fn ip_filtering_respects_disabled_families() {
        let addrs = vec![
            "127.0.0.1:443".parse::<SocketAddr>().expect("ipv4 addr"),
            "[::1]:443".parse::<SocketAddr>().expect("ipv6 addr"),
        ];

        let mut options = ClientOptions::default();
        options.disable_ipv4 = true;
        let filtered = filter_socket_addrs(addrs.clone(), &options);
        assert_eq!(filtered, vec!["[::1]:443".parse().expect("ipv6 addr")]);

        let mut options = ClientOptions::default();
        options.disable_ipv6 = true;
        let filtered = filter_socket_addrs(addrs, &options);
        assert_eq!(filtered, vec!["127.0.0.1:443".parse().expect("ipv4 addr")]);
    }
}
