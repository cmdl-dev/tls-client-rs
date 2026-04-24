use std::{
    collections::{HashMap, HashSet},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use boring2::x509::X509;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version};
use quiche::{
    Config, ConnectionId, RecvInfo, h3,
    h3::{Config as H3Config, Header, NameValue, Priority},
};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    bandwidth::BandwidthTracker,
    client::{ClientError, ClientOptions},
    profile::{Http3ProfileSpec, ProfileSpec, PseudoHeader},
    request::{Request, Response},
};

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 262_144;
const DGRAM_QUEUE_LEN: usize = 32;
const PRIORITY_HEADER_VALUE: &str = "u=0, i";

pub async fn send_http3(
    request: Request,
    url: Url,
    options: Arc<ClientOptions>,
    profile: Arc<ProfileSpec>,
    tracker: Arc<BandwidthTracker>,
    session_cache: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
) -> Result<Response, ClientError> {
    tokio::task::spawn_blocking(move || {
        send_http3_blocking(request, url, &options, &profile, &tracker, &session_cache)
    })
    .await
    .map_err(|err| ClientError::Http(format!("HTTP/3 task failed: {err}")))?
}

fn send_http3_blocking(
    request: Request,
    url: Url,
    options: &ClientOptions,
    profile: &ProfileSpec,
    tracker: &BandwidthTracker,
    session_cache: &Arc<StdMutex<HashMap<String, Vec<u8>>>>,
) -> Result<Response, ClientError> {
    let h3_profile = profile
        .http3
        .as_ref()
        .ok_or_else(|| ClientError::Http(format!("profile `{}` does not support HTTP/3", profile.key)))?;
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let peer_addr = resolve_udp_addr(host, port, options)?;
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|err| ClientError::Http(format!("failed to bind UDP socket: {err}")))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| ClientError::Http(format!("failed to read UDP local address: {err}")))?;

    let server_name = options
        .server_name_overwrite
        .as_deref()
        .unwrap_or(host);
    let session_key = format!("{}:{server_name}", profile.key);
    let mut config = build_quiche_config(options, h3_profile)?;
    let scid_bytes = generate_connection_id();
    let scid = ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(server_name), &scid, local_addr, peer_addr, &mut config)
        .map_err(|err| ClientError::Http(format!("failed to initiate QUIC connection: {err}")))?;

    if profile.tls.pre_shared_key {
        if let Some(session) = session_cache
            .lock()
            .expect("http3 session cache poisoned")
            .get(&session_key)
            .cloned()
        {
            conn.set_session(&session)
                .map_err(|err| ClientError::Http(format!("failed to reuse QUIC session: {err}")))?;
        }
    }

    let mut h3_config = build_h3_config(h3_profile)?;
    let mut h3_conn = None;
    let mut req_stream_id = None;
    let mut request_sent = false;
    let mut verified_pins = false;
    let mut response_status = None;
    let mut response_headers = HeaderMap::new();
    let mut response_body = Vec::new();
    let mut saw_finished = false;
    let request_headers = build_request_headers(&request, &url, h3_profile)?;
    let overall_deadline = Instant::now() + options.timeout;
    let mut recv_buf = [0u8; 65535];
    let mut send_buf = [0u8; MAX_DATAGRAM_SIZE];

    flush_outgoing(&socket, &mut conn, &mut send_buf, tracker)?;

    loop {
        if Instant::now() >= overall_deadline {
            return Err(ClientError::Http("HTTP/3 request timed out".to_string()));
        }

        if conn.is_closed() {
            return Err(ClientError::Http(format!(
                "HTTP/3 connection closed before response completed for {} ({})",
                url,
                describe_connection_close(&conn)
            )));
        }

        if conn.is_established() && !verified_pins {
            verify_certificate_pins(&conn, host, &options.certificate_pins)?;
            verified_pins = true;
            if let Some(session) = conn.session() {
                session_cache
                    .lock()
                    .expect("http3 session cache poisoned")
                    .insert(session_key.clone(), session.to_vec());
            }
        }

        if conn.is_established() && h3_conn.is_none() {
            h3_conn = Some(
                h3::Connection::with_transport(&mut conn, &mut h3_config).map_err(|err| {
                    ClientError::Http(format!("failed to establish HTTP/3 session: {err}"))
                })?,
            );
        }

        if let Some(h3_conn) = &mut h3_conn {
            if !request_sent {
                let fin = request.body.as_deref().unwrap_or_default().is_empty();
                let stream_id = h3_conn
                    .send_request(&mut conn, &request_headers, fin)
                    .map_err(|err| ClientError::Http(format!("failed to send HTTP/3 request: {err}")))?;
                if let Some(body) = &request.body {
                    if !body.is_empty() {
                        h3_conn.send_body(&mut conn, stream_id, body, true).map_err(|err| {
                            ClientError::Http(format!("failed to send HTTP/3 request body: {err}"))
                        })?;
                    }
                }
                if h3_profile.priority_param > 0 {
                    let priority = Priority::new(0, true);
                    h3_conn
                        .send_priority_update_for_request(&mut conn, stream_id, &priority)
                        .map_err(|err| {
                            ClientError::Http(format!(
                                "failed to send HTTP/3 priority update for stream {stream_id}: {err}"
                            ))
                        })?;
                }
                req_stream_id = Some(stream_id);
                request_sent = true;
                flush_outgoing(&socket, &mut conn, &mut send_buf, tracker)?;
            }

            loop {
                match h3_conn.poll(&mut conn) {
                    Ok((stream_id, h3::Event::Headers { list, .. })) => {
                        if Some(stream_id) != req_stream_id {
                            continue;
                        }

                        let (status, headers) = parse_response_headers(&list)?;
                        if (100..200).contains(&status.as_u16()) && status != StatusCode::SWITCHING_PROTOCOLS
                        {
                            continue;
                        }

                        response_status = Some(status);
                        response_headers = headers;
                    }
                    Ok((stream_id, h3::Event::Data)) => {
                        if Some(stream_id) != req_stream_id {
                            continue;
                        }

                        loop {
                            match h3_conn.recv_body(&mut conn, stream_id, &mut recv_buf) {
                                Ok(read) => response_body.extend_from_slice(&recv_buf[..read]),
                                Err(h3::Error::Done) => break,
                                Err(err) => {
                                    return Err(ClientError::Http(format!(
                                        "failed to read HTTP/3 response body: {err}"
                                    )));
                                }
                            }
                        }
                    }
                    Ok((stream_id, h3::Event::Finished)) => {
                        if Some(stream_id) == req_stream_id {
                            saw_finished = true;
                            break;
                        }
                    }
                    Ok((_stream_id, h3::Event::Reset(code))) => {
                        return Err(ClientError::Http(format!(
                            "HTTP/3 stream reset by peer with code {code}"
                        )));
                    }
                    Ok((_stream_id, h3::Event::PriorityUpdate)) => {}
                    Ok((_stream_id, h3::Event::GoAway)) => {}
                    Err(h3::Error::Done) => break,
                    Err(err) => {
                        return Err(ClientError::Http(format!("HTTP/3 processing failed: {err}")));
                    }
                }
            }
        }

        if saw_finished {
            let status = response_status.ok_or_else(|| {
                ClientError::Http("HTTP/3 response finished before headers were received".to_string())
            })?;
            if let Some(session) = conn.session() {
                session_cache
                    .lock()
                    .expect("http3 session cache poisoned")
                    .insert(session_key.clone(), session.to_vec());
            }
            conn.close(true, 0x100, b"kthxbye").ok();
            return Ok(Response::new(
                status,
                Version::HTTP_3,
                response_headers,
                response_body,
            ));
        }

        flush_outgoing(&socket, &mut conn, &mut send_buf, tracker)?;

        let timeout = conn
            .timeout()
            .unwrap_or_else(|| Duration::from_millis(50))
            .min(remaining(overall_deadline));
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|err| ClientError::Http(format!("failed to set UDP read timeout: {err}")))?;

        match socket.recv_from(&mut recv_buf) {
            Ok((read, from)) => {
                tracker.add_read(read);
                let info = RecvInfo {
                    from,
                    to: local_addr,
                };
                conn.recv(&mut recv_buf[..read], info)
                    .map_err(|err| ClientError::Http(format!("QUIC receive failed: {err}")))?;
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                conn.on_timeout();
            }
            Err(err) => {
                return Err(ClientError::Http(format!("failed to receive UDP datagram: {err}")));
            }
        }
    }
}

fn build_quiche_config(
    options: &ClientOptions,
    h3_profile: &Http3ProfileSpec,
) -> Result<Config, ClientError> {
    let mut config = Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|err| ClientError::Http(format!("failed to create QUIC config: {err}")))?;
    if options.insecure_skip_verify {
        config.verify_peer(false);
    } else if let Some(cert_file) = probe_ca_file() {
        config
            .load_verify_locations_from_file(cert_file.to_string_lossy().as_ref())
            .map_err(|err| ClientError::Http(format!("failed to load CA roots for QUIC: {err}")))?;
    }

    config
        .set_application_protos(h3::APPLICATION_PROTOCOL)
        .map_err(|err| ClientError::Http(format!("failed to set HTTP/3 ALPNs: {err}")))?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    Ok(config)
}

fn build_h3_config(h3_profile: &Http3ProfileSpec) -> Result<H3Config, ClientError> {
    let mut config =
        H3Config::new().map_err(|err| ClientError::Http(format!("failed to create H3 config: {err}")))?;
    let ordered_ids = ordered_setting_ids(h3_profile);
    let settings = h3_profile
        .settings
        .iter()
        .map(|setting| (setting.id, setting.value))
        .collect::<HashMap<_, _>>();
    let mut additional = Vec::new();
    let mut handled = HashSet::new();

    for id in ordered_ids {
        let Some(value) = settings.get(&id).copied().or_else(|| default_setting_value(id, h3_profile))
        else {
            continue;
        };

        match id {
            0x1 => config.set_qpack_max_table_capacity(value),
            0x6 => config.set_max_field_section_size(value),
            0x7 => config.set_qpack_blocked_streams(value),
            0x8 => config.enable_extended_connect(value > 0),
            0x33 => {}
            _ => additional.push((id, value)),
        }
        handled.insert(id);
    }

    for (id, value) in &settings {
        if handled.contains(id) {
            continue;
        }

        match *id {
            0x1 => config.set_qpack_max_table_capacity(*value),
            0x6 => config.set_max_field_section_size(*value),
            0x7 => config.set_qpack_blocked_streams(*value),
            0x8 => config.enable_extended_connect(*value > 0),
            0x33 => {}
            _ => additional.push((*id, *value)),
        }
    }

    if !additional.is_empty() {
        config
            .set_additional_settings(additional)
            .map_err(|err| ClientError::Http(format!("failed to configure H3 settings: {err}")))?;
    }

    Ok(config)
}

fn build_request_headers(
    request: &Request,
    url: &Url,
    profile: &Http3ProfileSpec,
) -> Result<Vec<Header>, ClientError> {
    let mut headers = Vec::with_capacity(request.headers.len() + 8);
    let authority = authority_for_h3(url)?;
    let path = request_path(url);
    let pseudo_headers = [
        (PseudoHeader::Method, request.method.as_str().as_bytes().to_vec()),
        (PseudoHeader::Authority, authority.into_bytes()),
        (PseudoHeader::Scheme, url.scheme().as_bytes().to_vec()),
        (PseudoHeader::Path, path.into_bytes()),
    ]
    .into_iter()
    .collect::<HashMap<_, _>>();

    for pseudo in &profile.pseudo_header_order {
        if let Some(value) = pseudo_headers.get(pseudo) {
            headers.push(Header::new(pseudo_name(*pseudo).as_bytes(), value.as_slice()));
        }
    }

    if profile.priority_param > 0
        && !request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("priority"))
    {
        headers.push(Header::new(b"priority", PRIORITY_HEADER_VALUE.as_bytes()));
    }

    for entry in &request.headers {
        if entry.name.starts_with(':') {
            continue;
        }
        if entry.name.eq_ignore_ascii_case("host") {
            continue;
        }

        headers.push(Header::new(
            entry.name.to_ascii_lowercase().as_bytes(),
            entry.value.as_bytes(),
        ));
    }

    if let Some(body) = &request.body {
        if !body.is_empty()
            && !request
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("content-length"))
        {
            headers.push(Header::new(
                b"content-length",
                body.len().to_string().as_bytes(),
            ));
        }
    }

    Ok(headers)
}

fn parse_response_headers(headers: &[Header]) -> Result<(StatusCode, HeaderMap), ClientError> {
    let mut status = None;
    let mut map = HeaderMap::with_capacity(headers.len());

    for header in headers {
        let name = std::str::from_utf8(header.name())
            .map_err(|err| ClientError::Http(format!("invalid HTTP/3 header name: {err}")))?;
        let value = header.value();
        if name == ":status" {
            let value = std::str::from_utf8(value)
                .map_err(|err| ClientError::Http(format!("invalid HTTP/3 status value: {err}")))?;
            status = Some(
                StatusCode::from_u16(value.parse::<u16>().map_err(|err| {
                    ClientError::Http(format!("invalid HTTP/3 status code `{value}`: {err}"))
                })?)
                .map_err(|err| ClientError::Http(format!("invalid HTTP/3 status code: {err}")))?,
            );
            continue;
        }

        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
            ClientError::Http(format!("invalid HTTP/3 response header name `{name}`: {err}"))
        })?;
        let value = HeaderValue::from_bytes(value).map_err(|err| {
            ClientError::Http(format!("invalid HTTP/3 response header value for `{name}`: {err}"))
        })?;
        map.append(name, value);
    }

    let status = status.ok_or_else(|| {
        ClientError::Http("HTTP/3 response omitted required :status header".to_string())
    })?;
    Ok((status, map))
}

fn flush_outgoing(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    send_buf: &mut [u8],
    tracker: &BandwidthTracker,
) -> Result<(), ClientError> {
    loop {
        match conn.send(send_buf) {
            Ok((written, info)) => {
                socket
                    .send_to(&send_buf[..written], info.to)
                    .map_err(|err| ClientError::Http(format!("failed to send QUIC datagram: {err}")))?;
                tracker.add_write(written);
            }
            Err(quiche::Error::Done) => break,
            Err(err) => {
                return Err(ClientError::Http(format!("failed to produce QUIC packet: {err}")));
            }
        }
    }

    Ok(())
}

fn resolve_udp_addr(host: &str, port: u16, options: &ClientOptions) -> Result<SocketAddr, ClientError> {
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|err| ClientError::Http(format!("failed to resolve {host}:{port}: {err}")))?;
    resolved
        .filter(|addr| (!options.disable_ipv4 || !addr.is_ipv4()) && (!options.disable_ipv6 || !addr.is_ipv6()))
        .next()
        .ok_or_else(|| {
            ClientError::Http(format!(
                "no UDP addresses remain for {host}:{port} after IP family filtering"
            ))
        })
}

fn verify_certificate_pins(
    conn: &quiche::Connection,
    host: &str,
    pins: &HashMap<String, Vec<String>>,
) -> Result<(), ClientError> {
    let Some(expected) = pins_for_host(pins, host) else {
        return Ok(());
    };

    let mut actual = Vec::new();
    if let Some(cert) = conn.peer_cert() {
        actual.push(certificate_pin_from_der(cert)?);
    }
    if let Some(chain) = conn.peer_cert_chain() {
        for cert in chain {
            actual.push(certificate_pin_from_der(cert)?);
        }
    }

    if actual.iter().any(|pin| expected.iter().any(|expected| expected == pin)) {
        return Ok(());
    }

    Err(ClientError::BadPinDetected(format!(
        "bad ssl pin detected for {host}, expected one of {:?}, found {:?}",
        expected, actual
    )))
}

fn certificate_pin_from_der(cert_der: &[u8]) -> Result<String, ClientError> {
    let cert = X509::from_der(cert_der)
        .map_err(|err| ClientError::Http(format!("failed to parse peer certificate: {err}")))?;
    let public_key = cert
        .public_key()
        .map_err(|err| ClientError::Http(format!("failed to read peer public key: {err}")))?;
    let public_key_der = public_key
        .public_key_to_der()
        .map_err(|err| ClientError::Http(format!("failed to encode peer public key: {err}")))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(public_key_der)))
}

fn pins_for_host<'a>(pins: &'a HashMap<String, Vec<String>>, host: &str) -> Option<&'a Vec<String>> {
    if let Some(exact) = pins.get(host) {
        return Some(exact);
    }

    let host = host.to_ascii_lowercase();
    pins.iter()
        .filter_map(|(pattern, expected)| {
            pattern.strip_prefix("*.").and_then(|base| {
                let base = base.to_ascii_lowercase();
                (host == base || host.ends_with(&format!(".{base}"))).then_some((base.len(), expected))
            })
        })
        .max_by_key(|(len, _)| *len)
        .map(|(_, expected)| expected)
}

fn probe_ca_file() -> Option<PathBuf> {
    let probe = openssl_probe::probe();
    probe.cert_file.or_else(find_fallback_ca_file)
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

fn ordered_setting_ids(h3_profile: &Http3ProfileSpec) -> Vec<u64> {
    if !h3_profile.settings_order.is_empty() {
        return h3_profile.settings_order.clone();
    }

    h3_profile.settings.iter().map(|setting| setting.id).collect()
}

fn default_setting_value(id: u64, h3_profile: &Http3ProfileSpec) -> Option<u64> {
    match id {
        0x6 => Some(DEFAULT_MAX_FIELD_SECTION_SIZE),
        0x33 if advertises_h3_datagram(h3_profile) => Some(1),
        _ => None,
    }
}

fn advertises_h3_datagram(h3_profile: &Http3ProfileSpec) -> bool {
    h3_profile.settings.iter().any(|setting| setting.id == 0x33 && setting.value > 0)
        || h3_profile.settings_order.contains(&0x33)
}

fn pseudo_name(pseudo: PseudoHeader) -> &'static str {
    match pseudo {
        PseudoHeader::Method => ":method",
        PseudoHeader::Authority => ":authority",
        PseudoHeader::Scheme => ":scheme",
        PseudoHeader::Path => ":path",
    }
}

fn authority_for_h3(url: &Url) -> Result<String, ClientError> {
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Http("URL missing host".to_string()))?;
    Ok(match url.port() {
        Some(port) if Some(port) != url.port_or_known_default() => format!("{host}:{port}"),
        _ => match url.port() {
            Some(port) if matches!(url.scheme(), "http" | "https") && !is_default_port(url.scheme(), port) => {
                format!("{host}:{port}")
            }
            _ => {
                if let Some(port) = url.port() {
                    if is_default_port(url.scheme(), port) {
                        host.to_string()
                    } else {
                        format!("{host}:{port}")
                    }
                } else {
                    host.to_string()
                }
            }
        },
    })
}

fn is_default_port(scheme: &str, port: u16) -> bool {
    matches!((scheme, port), ("http", 80) | ("https", 443))
}

fn request_path(url: &Url) -> String {
    let mut path = url.path().to_string();
    if path.is_empty() {
        path.push('/');
    }
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

fn generate_connection_id() -> [u8; quiche::MAX_CONN_ID_LEN] {
    let mut bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_nanos()
        .to_le_bytes();
    let pid = std::process::id().to_le_bytes();
    let now_len = now.len().min(bytes.len());
    bytes[..now_len].copy_from_slice(&now[..now_len]);
    let offset = now_len.saturating_sub(4);
    let pid_len = pid.len().min(bytes.len() - offset);
    bytes[offset..offset + pid_len].copy_from_slice(&pid[..pid_len]);
    bytes
}

fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

fn describe_connection_close(conn: &quiche::Connection) -> String {
    let mut details = Vec::new();

    if let Some(error) = conn.peer_error() {
        details.push(format!("peer_error={error:?}"));
    }

    if let Some(error) = conn.local_error() {
        details.push(format!("local_error={error:?}"));
    }

    let app_proto = conn.application_proto();
    if !app_proto.is_empty() {
        details.push(format!(
            "alpn={}",
            String::from_utf8_lossy(app_proto)
        ));
    }

    details.push(format!("stats={:?}", conn.stats()));

    if details.is_empty() {
        "no close details available".to_string()
    } else {
        details.join(", ")
    }
}
