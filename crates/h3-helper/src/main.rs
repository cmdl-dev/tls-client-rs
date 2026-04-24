use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use boring::x509::X509;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Version};
use quiche::{
    Config, ConnectionId, RecvInfo, h3,
    h3::{Header, NameValue},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

const MAX_DATAGRAM_SIZE: usize = 1350;
const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 262_144;
const PRIORITY_HEADER_VALUE: &str = "u=0, i";
const STREAM_TYPE_CONTROL: u64 = 0x0;
const STREAM_TYPE_QPACK_ENCODER: u64 = 0x2;
const STREAM_TYPE_QPACK_DECODER: u64 = 0x3;
const CLIENT_REQUEST_STREAM_ID: u64 = 0;
const CLIENT_CONTROL_STREAM_ID: u64 = 2;
const CLIENT_QPACK_ENCODER_STREAM_ID: u64 = 6;
const CLIENT_QPACK_DECODER_STREAM_ID: u64 = 10;

fn main() {
    let response = match run() {
        Ok(response) => response,
        Err(error) => HelperResponse {
            outcome: HelperOutcome::Error(HelperError::from_error(error)),
            cached_session: None,
            bandwidth: BandwidthPayload::default(),
        },
    };

    let mut stdout = std::io::stdout().lock();
    let json = serde_json::to_vec(&response).expect("serialize helper response");
    stdout.write_all(&json).expect("write helper response");
}

fn run() -> Result<HelperResponse, HelperErrorKind> {
    let mut stdin = String::new();
    std::io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|err| HelperErrorKind::Http(format!("failed to read helper stdin: {err}")))?;
    let payload: HelperRequest = serde_json::from_str(&stdin)
        .map_err(|err| HelperErrorKind::Http(format!("failed to parse helper request: {err}")))?;

    let request = payload.request.into_request()?;
    let url = Url::parse(&request.url)
        .map_err(|err| HelperErrorKind::Http(format!("invalid helper URL: {err}")))?;

    let (response, cached_session, bandwidth) =
        send_http3_blocking(request, url, payload.options, payload.profile, payload.cached_session)?;

    Ok(HelperResponse {
        outcome: HelperOutcome::Success(ResponsePayload::from_response(response)?),
        cached_session: cached_session
            .as_deref()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes)),
        bandwidth,
    })
}

fn send_http3_blocking(
    request: RequestPayloadResolved,
    url: Url,
    options: HelperOptions,
    profile: HelperProfile,
    cached_session: Option<String>,
) -> Result<(ResponsePayloadResolved, Option<Vec<u8>>, BandwidthPayload), HelperErrorKind> {
    let h3_profile = profile.http3.ok_or_else(|| {
        HelperErrorKind::UnsupportedProfile(format!(
            "profile `{}` does not support HTTP/3",
            profile.key
        ))
    })?;
    if options.disable_ipv4 && options.disable_ipv6 {
        return Err(HelperErrorKind::InvalidConfig(
            "cannot disable both IPv4 and IPv6".to_string(),
        ));
    }

    let host = url
        .host_str()
        .ok_or_else(|| HelperErrorKind::Http("URL missing host".to_string()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let peer_addr = resolve_udp_addr(host, port, &options)?;
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)
        .map_err(|err| HelperErrorKind::Http(format!("failed to bind UDP socket: {err}")))?;
    let local_addr = socket
        .local_addr()
        .map_err(|err| HelperErrorKind::Http(format!("failed to read UDP local address: {err}")))?;

    let server_name = options
        .server_name_overwrite
        .as_deref()
        .unwrap_or(host);
    let mut config = build_quiche_config(&options)?;
    if advertises_h3_datagram(&h3_profile) {
        config.enable_dgram(true, 32, 32);
    }
    let scid_bytes = generate_connection_id();
    let scid = ConnectionId::from_ref(&scid_bytes);
    let mut conn = quiche::connect(Some(server_name), &scid, local_addr, peer_addr, &mut config)
        .map_err(|err| HelperErrorKind::Http(format!("failed to initiate QUIC connection: {err}")))?;

    if profile.pre_shared_key {
        if let Some(session) = cached_session {
            let session = base64::engine::general_purpose::STANDARD
                .decode(session)
                .map_err(|err| HelperErrorKind::Http(format!("failed to decode cached QUIC session: {err}")))?;
            conn.set_session(&session)
                .map_err(|err| HelperErrorKind::Http(format!("failed to reuse QUIC session: {err}")))?;
        }
    }

    let request_headers = build_request_headers(&request, &url, &h3_profile)?;
    let mut qpack_encoder = h3::qpack::Encoder::new();
    let mut qpack_decoder = h3::qpack::Decoder::new();
    let mut inbound = InboundState::default();
    let mut control_sent = false;
    let mut request_sent = false;
    let mut verified_pins = false;
    let mut response_status = None;
    let mut response_headers = HeaderMap::new();
    let mut response_body = Vec::new();
    let mut saw_finished = false;
    let overall_deadline = Instant::now() + Duration::from_millis(options.timeout_ms);
    let mut recv_buf = [0u8; 65535];
    let mut send_buf = [0u8; MAX_DATAGRAM_SIZE];
    let mut bandwidth = BandwidthPayload::default();

    flush_outgoing(&socket, &mut conn, &mut send_buf, &mut bandwidth)?;

    loop {
        if Instant::now() >= overall_deadline {
            return Err(HelperErrorKind::Http("HTTP/3 request timed out".to_string()));
        }

        if conn.is_closed() {
            return Err(HelperErrorKind::Http(format!(
                "HTTP/3 connection closed before response completed for {} ({})",
                url,
                describe_connection_close(&conn)
            )));
        }

        if conn.is_established() && !verified_pins {
            verify_certificate_pins(&conn, host, &options.certificate_pins)?;
            verified_pins = true;
        }

        if conn.is_established() && !control_sent {
            send_control_stream(&mut conn, &h3_profile)?;
            control_sent = true;
            flush_outgoing(&socket, &mut conn, &mut send_buf, &mut bandwidth)?;
        }

        if conn.is_established() && control_sent && !request_sent {
            send_request_stream(
                &mut conn,
                &request_headers,
                request.body.as_deref(),
                &mut qpack_encoder,
            )?;
            request_sent = true;
            flush_outgoing(&socket, &mut conn, &mut send_buf, &mut bandwidth)?;
        }

        if request_sent {
            drain_readable_streams(
                &mut conn,
                &mut recv_buf,
                &mut inbound,
                &mut qpack_decoder,
                &mut response_status,
                &mut response_headers,
                &mut response_body,
                &mut saw_finished,
            )?;
        }

        if saw_finished {
            let status = response_status.ok_or_else(|| {
                HelperErrorKind::Http(
                    "HTTP/3 response finished before headers were received".to_string(),
                )
            })?;
            let cached_session = conn.session().map(|session| session.to_vec());
            conn.close(true, 0x100, b"kthxbye").ok();
            return Ok((
                ResponsePayloadResolved {
                    status,
                    version: Version::HTTP_3,
                    headers: response_headers,
                    body: response_body,
                },
                cached_session,
                bandwidth,
            ));
        }

        flush_outgoing(&socket, &mut conn, &mut send_buf, &mut bandwidth)?;

        let timeout = conn
            .timeout()
            .unwrap_or_else(|| Duration::from_millis(50))
            .min(remaining(overall_deadline));
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|err| HelperErrorKind::Http(format!("failed to set UDP read timeout: {err}")))?;

        match socket.recv_from(&mut recv_buf) {
            Ok((read, from)) => {
                bandwidth.read_bytes += read as u64;
                let info = RecvInfo { from, to: local_addr };
                conn.recv(&mut recv_buf[..read], info)
                    .map_err(|err| HelperErrorKind::Http(format!("QUIC receive failed: {err}")))?;
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::TimedOut
                    || err.kind() == std::io::ErrorKind::WouldBlock =>
            {
                conn.on_timeout();
            }
            Err(err) => {
                return Err(HelperErrorKind::Http(format!("failed to receive UDP datagram: {err}")));
            }
        }
    }
}

fn build_quiche_config(options: &HelperOptions) -> Result<Config, HelperErrorKind> {
    let mut config = Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|err| HelperErrorKind::Http(format!("failed to create QUIC config: {err}")))?;
    if options.insecure_skip_verify {
        config.verify_peer(false);
    } else if let Some(cert_file) = probe_ca_file() {
        config
            .load_verify_locations_from_file(cert_file.to_string_lossy().as_ref())
            .map_err(|err| HelperErrorKind::Http(format!("failed to load CA roots for QUIC: {err}")))?;
    }

    config
        .set_application_protos(h3::APPLICATION_PROTOCOL)
        .map_err(|err| HelperErrorKind::Http(format!("failed to set HTTP/3 ALPNs: {err}")))?;
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

fn send_control_stream(
    conn: &mut quiche::Connection,
    h3_profile: &HelperHttp3Profile,
) -> Result<(), HelperErrorKind> {
    let mut payload = encode_varint(STREAM_TYPE_CONTROL);
    payload.extend_from_slice(&encode_settings_frame(h3_profile)?);
    if h3_profile.send_grease_frames {
        payload.extend_from_slice(&encode_grease_frame());
    }
    if h3_profile.priority_param > 0 {
        payload.extend_from_slice(&encode_priority_update_frame(h3_profile.priority_param));
    }

    conn.stream_send(CLIENT_CONTROL_STREAM_ID, &payload, false)
        .map_err(|err| HelperErrorKind::Http(format!("failed to send HTTP/3 control stream: {err}")))?;

    conn.stream_send(CLIENT_QPACK_ENCODER_STREAM_ID, &encode_varint(STREAM_TYPE_QPACK_ENCODER), false)
        .map_err(|err| HelperErrorKind::Http(format!("failed to open QPACK encoder stream: {err}")))?;
    conn.stream_send(CLIENT_QPACK_DECODER_STREAM_ID, &encode_varint(STREAM_TYPE_QPACK_DECODER), false)
        .map_err(|err| HelperErrorKind::Http(format!("failed to open QPACK decoder stream: {err}")))?;

    Ok(())
}

fn send_request_stream(
    conn: &mut quiche::Connection,
    headers: &[Header],
    body: Option<&[u8]>,
    encoder: &mut h3::qpack::Encoder,
) -> Result<(), HelperErrorKind> {
    let header_block = encode_header_block(encoder, headers)?;
    let mut payload = encode_headers_frame(&header_block)?;

    if let Some(body) = body {
        if !body.is_empty() {
            payload.extend_from_slice(&encode_data_frame(body)?);
        }
    }

    conn.stream_send(CLIENT_REQUEST_STREAM_ID, &payload, true)
        .map_err(|err| HelperErrorKind::Http(format!("failed to send HTTP/3 request stream: {err}")))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drain_readable_streams(
    conn: &mut quiche::Connection,
    recv_buf: &mut [u8],
    inbound: &mut InboundState,
    qpack_decoder: &mut h3::qpack::Decoder,
    response_status: &mut Option<StatusCode>,
    response_headers: &mut HeaderMap,
    response_body: &mut Vec<u8>,
    saw_finished: &mut bool,
) -> Result<(), HelperErrorKind> {
    let readable = conn.readable().collect::<Vec<_>>();
    for stream_id in readable {
        loop {
            match conn.stream_recv(stream_id, recv_buf) {
                Ok((read, fin)) => {
                    let state = inbound.streams.entry(stream_id).or_default();
                    state.buffer.extend_from_slice(&recv_buf[..read]);
                    if fin {
                        state.fin = true;
                    }
                }
                Err(quiche::Error::InvalidStreamState(_)) => break,
                Err(quiche::Error::Done) => break,
                Err(err) => {
                    return Err(HelperErrorKind::Http(format!(
                        "failed to read HTTP/3 stream {stream_id}: {err}"
                    )));
                }
            }
        }

        if stream_id == CLIENT_REQUEST_STREAM_ID {
            process_response_stream(
                inbound.streams.get_mut(&stream_id).expect("response stream state"),
                qpack_decoder,
                response_status,
                response_headers,
                response_body,
                saw_finished,
            )?;
        } else {
            process_uni_stream(
                inbound.streams.get_mut(&stream_id).expect("uni stream state"),
                qpack_decoder,
            )?;
        }
    }

    Ok(())
}

fn process_response_stream(
    state: &mut StreamState,
    qpack_decoder: &mut h3::qpack::Decoder,
    response_status: &mut Option<StatusCode>,
    response_headers: &mut HeaderMap,
    response_body: &mut Vec<u8>,
    saw_finished: &mut bool,
) -> Result<(), HelperErrorKind> {
    while let Some((consumed, frame)) = decode_next_frame(&state.buffer)? {
        match frame {
            ParsedFrame::Headers(header_block) => {
                let headers = qpack_decoder
                    .decode(&header_block, u64::MAX)
                    .map_err(|err| HelperErrorKind::Http(format!("failed to decode QPACK headers: {err}")))?;
                let (status, parsed_headers) = parse_response_headers(&headers)?;
                if (100..200).contains(&status.as_u16()) && status != StatusCode::SWITCHING_PROTOCOLS {
                    state.buffer.drain(0..consumed);
                    continue;
                }
                *response_status = Some(status);
                *response_headers = parsed_headers;
            }
            ParsedFrame::Data(payload) => {
                response_body.extend_from_slice(&payload);
            }
            ParsedFrame::Other => {}
        }

        state.buffer.drain(0..consumed);
    }

    if state.fin && state.buffer.is_empty() {
        *saw_finished = true;
    }

    Ok(())
}

fn process_uni_stream(
    state: &mut StreamState,
    qpack_decoder: &mut h3::qpack::Decoder,
) -> Result<(), HelperErrorKind> {
    if state.kind.is_none() {
        let Some((stream_type, consumed)) = decode_varint_prefix(&state.buffer)? else {
            return Ok(());
        };

        state.kind = Some(match stream_type {
            STREAM_TYPE_CONTROL => UniStreamKind::Control,
            STREAM_TYPE_QPACK_ENCODER => UniStreamKind::QpackEncoder,
            STREAM_TYPE_QPACK_DECODER => UniStreamKind::QpackDecoder,
            _ => UniStreamKind::Ignored(()),
        });
        state.buffer.drain(0..consumed);
    }

    match state.kind {
        Some(UniStreamKind::Control) => {
            while let Some((consumed, _frame)) = decode_next_frame(&state.buffer)? {
                state.buffer.drain(0..consumed);
            }
        }
        Some(UniStreamKind::QpackEncoder) => {
            qpack_decoder
                .control(&mut state.buffer)
                .map_err(|err| HelperErrorKind::Http(format!("failed to process QPACK encoder stream: {err}")))?;
            state.buffer.clear();
        }
        Some(UniStreamKind::QpackDecoder) | Some(UniStreamKind::Ignored(_)) | None => {
            state.buffer.clear();
        }
    }

    Ok(())
}

fn encode_settings_frame(h3_profile: &HelperHttp3Profile) -> Result<Vec<u8>, HelperErrorKind> {
    let mut ordered = ordered_settings(h3_profile);
    if h3_profile.priority_param > 0 {
        ordered.push((generate_grease_setting_id(), generate_grease_setting_value()));
    }
    let mut payload = Vec::new();
    for (id, value) in ordered {
        payload.extend_from_slice(&encode_varint(id));
        payload.extend_from_slice(&encode_varint(value));
    }
    Ok(encode_frame_bytes(0x4, &payload))
}

fn encode_headers_frame(header_block: &[u8]) -> Result<Vec<u8>, HelperErrorKind> {
    Ok(encode_frame_bytes(0x1, header_block))
}

fn encode_data_frame(body: &[u8]) -> Result<Vec<u8>, HelperErrorKind> {
    Ok(encode_frame_bytes(0x0, body))
}

fn encode_frame_bytes(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = encode_varint(frame_type);
    out.extend_from_slice(&encode_varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

fn encode_header_block(
    encoder: &mut h3::qpack::Encoder,
    headers: &[Header],
) -> Result<Vec<u8>, HelperErrorKind> {
    let capacity = headers
        .iter()
        .fold(64usize, |acc, header| acc + header.name().len() + header.value().len() + 32);
    let mut header_block = vec![0u8; capacity];
    let written = encoder
        .encode(headers, &mut header_block)
        .map_err(|err| HelperErrorKind::Http(format!("failed to encode QPACK headers: {err}")))?;
    header_block.truncate(written);
    Ok(header_block)
}

fn encode_grease_frame() -> Vec<u8> {
    let mut out = encode_varint(generate_grease_frame_type());
    out.extend_from_slice(&encode_varint(0));
    out
}

fn encode_priority_update_frame(priority_param: u32) -> Vec<u8> {
    let mut payload = encode_varint(CLIENT_REQUEST_STREAM_ID);
    payload.extend_from_slice(PRIORITY_HEADER_VALUE.as_bytes());

    let mut out = encode_varint(priority_param as u64);
    out.extend_from_slice(&encode_varint(payload.len() as u64));
    out.extend_from_slice(&payload);
    out
}

fn encode_varint(value: u64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let mut octets = octets::OctetsMut::with_slice(&mut bytes);
    let written = octets.put_varint(value).expect("encode varint").len();
    bytes[..written].to_vec()
}

fn decode_varint_prefix(bytes: &[u8]) -> Result<Option<(u64, usize)>, HelperErrorKind> {
    let mut octets = octets::Octets::with_slice(bytes);
    match octets.get_varint() {
        Ok(value) => Ok(Some((value, bytes.len() - octets.cap()))),
        Err(_) => Ok(None),
    }
}

fn decode_next_frame(
    bytes: &[u8],
) -> Result<Option<(usize, ParsedFrame)>, HelperErrorKind> {
    let mut octets = octets::Octets::with_slice(bytes);
    let frame_type = match octets.get_varint() {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let frame_len = match octets.get_varint() {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let header_len = bytes.len() - octets.cap();
    let frame_len = frame_len as usize;
    if octets.cap() < frame_len {
        return Ok(None);
    }

    let payload = &bytes[header_len..header_len + frame_len];
    let frame = match frame_type {
        0x0 => ParsedFrame::Data(payload.to_vec()),
        0x1 => ParsedFrame::Headers(payload.to_vec()),
        _ => ParsedFrame::Other,
    };
    Ok(Some((header_len + frame_len, frame)))
}

fn ordered_settings(h3_profile: &HelperHttp3Profile) -> Vec<(u64, u64)> {
    let ordered_ids = ordered_setting_ids(h3_profile);
    let settings = h3_profile
        .settings
        .iter()
        .map(|setting| (setting.id, setting.value))
        .collect::<HashMap<_, _>>();
    let mut ordered = Vec::new();
    let mut handled = HashSet::new();

    for id in ordered_ids {
        let Some(value) = settings.get(&id).copied().or_else(|| default_setting_value(id, h3_profile))
        else {
            continue;
        };
        ordered.push((id, value));
        handled.insert(id);
    }

    for (id, value) in settings {
        if !handled.contains(&id) {
            ordered.push((id, value));
        }
    }

    ordered
}

fn generate_grease_setting_id() -> u64 {
    0x1f * 1_000_000_000 + 0x21
}

fn generate_grease_setting_value() -> u64 {
    1
}

fn generate_grease_frame_type() -> u64 {
    0x1f * 1_000_000_000 + 0x21
}

fn build_request_headers(
    request: &RequestPayloadResolved,
    url: &Url,
    profile: &HelperHttp3Profile,
) -> Result<Vec<Header>, HelperErrorKind> {
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

fn parse_response_headers(headers: &[Header]) -> Result<(StatusCode, HeaderMap), HelperErrorKind> {
    let mut status = None;
    let mut map = HeaderMap::with_capacity(headers.len());

    for header in headers {
        let name = std::str::from_utf8(header.name())
            .map_err(|err| HelperErrorKind::Http(format!("invalid HTTP/3 header name: {err}")))?;
        let value = header.value();
        if name == ":status" {
            let value = std::str::from_utf8(value)
                .map_err(|err| HelperErrorKind::Http(format!("invalid HTTP/3 status value: {err}")))?;
            status = Some(
                StatusCode::from_u16(value.parse::<u16>().map_err(|err| {
                    HelperErrorKind::Http(format!("invalid HTTP/3 status code `{value}`: {err}"))
                })?)
                .map_err(|err| HelperErrorKind::Http(format!("invalid HTTP/3 status code: {err}")))?,
            );
            continue;
        }

        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|err| {
            HelperErrorKind::Http(format!("invalid HTTP/3 response header name `{name}`: {err}"))
        })?;
        let value = HeaderValue::from_bytes(value).map_err(|err| {
            HelperErrorKind::Http(format!("invalid HTTP/3 response header value for `{name}`: {err}"))
        })?;
        map.append(name, value);
    }

    let status = status.ok_or_else(|| {
        HelperErrorKind::Http("HTTP/3 response omitted required :status header".to_string())
    })?;
    Ok((status, map))
}

fn flush_outgoing(
    socket: &UdpSocket,
    conn: &mut quiche::Connection,
    send_buf: &mut [u8],
    bandwidth: &mut BandwidthPayload,
) -> Result<(), HelperErrorKind> {
    loop {
        match conn.send(send_buf) {
            Ok((written, info)) => {
                socket
                    .send_to(&send_buf[..written], info.to)
                    .map_err(|err| HelperErrorKind::Http(format!("failed to send QUIC datagram: {err}")))?;
                bandwidth.write_bytes += written as u64;
            }
            Err(quiche::Error::Done) => break,
            Err(err) => {
                return Err(HelperErrorKind::Http(format!("failed to produce QUIC packet: {err}")));
            }
        }
    }

    Ok(())
}

fn resolve_udp_addr(host: &str, port: u16, options: &HelperOptions) -> Result<SocketAddr, HelperErrorKind> {
    let resolved = (host, port)
        .to_socket_addrs()
        .map_err(|err| HelperErrorKind::Http(format!("failed to resolve {host}:{port}: {err}")))?;
    resolved
        .filter(|addr| (!options.disable_ipv4 || !addr.is_ipv4()) && (!options.disable_ipv6 || !addr.is_ipv6()))
        .next()
        .ok_or_else(|| {
            HelperErrorKind::Http(format!(
                "no UDP addresses remain for {host}:{port} after IP family filtering"
            ))
        })
}

fn verify_certificate_pins(
    conn: &quiche::Connection,
    host: &str,
    pins: &HashMap<String, Vec<String>>,
) -> Result<(), HelperErrorKind> {
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

    Err(HelperErrorKind::BadPin(format!(
        "bad ssl pin detected for {host}, expected one of {:?}, found {:?}",
        expected, actual
    )))
}

fn certificate_pin_from_der(cert_der: &[u8]) -> Result<String, HelperErrorKind> {
    let cert = X509::from_der(cert_der)
        .map_err(|err| HelperErrorKind::Http(format!("failed to parse peer certificate: {err}")))?;
    let public_key = cert
        .public_key()
        .map_err(|err| HelperErrorKind::Http(format!("failed to read peer public key: {err}")))?;
    let public_key_der = public_key
        .public_key_to_der()
        .map_err(|err| HelperErrorKind::Http(format!("failed to encode peer public key: {err}")))?;
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

fn ordered_setting_ids(h3_profile: &HelperHttp3Profile) -> Vec<u64> {
    if !h3_profile.settings_order.is_empty() {
        return h3_profile.settings_order.clone();
    }

    h3_profile.settings.iter().map(|setting| setting.id).collect()
}

fn default_setting_value(id: u64, h3_profile: &HelperHttp3Profile) -> Option<u64> {
    match id {
        0x6 => Some(DEFAULT_MAX_FIELD_SECTION_SIZE),
        0x33 if advertises_h3_datagram(h3_profile) => Some(1),
        _ => None,
    }
}

fn advertises_h3_datagram(h3_profile: &HelperHttp3Profile) -> bool {
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

fn authority_for_h3(url: &Url) -> Result<String, HelperErrorKind> {
    let host = url
        .host_str()
        .ok_or_else(|| HelperErrorKind::Http("URL missing host".to_string()))?;
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
        details.push(format!("alpn={}", String::from_utf8_lossy(app_proto)));
    }

    details.push(format!("stats={:?}", conn.stats()));

    details.join(", ")
}

#[derive(Default)]
struct InboundState {
    streams: HashMap<u64, StreamState>,
}

#[derive(Default)]
struct StreamState {
    buffer: Vec<u8>,
    kind: Option<UniStreamKind>,
    fin: bool,
}

#[derive(Clone, Copy)]
enum UniStreamKind {
    Control,
    QpackEncoder,
    QpackDecoder,
    Ignored(()),
}

enum ParsedFrame {
    Data(Vec<u8>),
    Headers(Vec<u8>),
    Other,
}

#[derive(Deserialize)]
struct HelperRequest {
    request: RequestPayload,
    options: HelperOptions,
    profile: HelperProfile,
    cached_session: Option<String>,
}

#[derive(Deserialize)]
struct RequestPayload {
    method: String,
    url: String,
    headers: Vec<HeaderPayload>,
    body: Option<String>,
}

impl RequestPayload {
    fn into_request(self) -> Result<RequestPayloadResolved, HelperErrorKind> {
        let method = self
            .method
            .parse::<Method>()
            .map_err(|err| HelperErrorKind::Http(format!("invalid helper HTTP method `{}`: {err}", self.method)))?;
        let body = match self.body {
            Some(body) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|err| HelperErrorKind::Http(format!("invalid helper request body: {err}")))?,
            ),
            None => None,
        };
        Ok(RequestPayloadResolved {
            method,
            url: self.url,
            headers: self.headers,
            body,
        })
    }
}

struct RequestPayloadResolved {
    method: Method,
    url: String,
    headers: Vec<HeaderPayload>,
    body: Option<Vec<u8>>,
}

#[derive(Clone, Deserialize)]
struct HelperOptions {
    timeout_ms: u64,
    disable_ipv4: bool,
    disable_ipv6: bool,
    insecure_skip_verify: bool,
    certificate_pins: HashMap<String, Vec<String>>,
    server_name_overwrite: Option<String>,
}

#[derive(Deserialize)]
struct HelperProfile {
    key: String,
    pre_shared_key: bool,
    http3: Option<HelperHttp3Profile>,
}

#[derive(Clone, Deserialize)]
struct HelperHttp3Profile {
    settings: Vec<Http3SettingPayload>,
    settings_order: Vec<u64>,
    pseudo_header_order: Vec<PseudoHeader>,
    priority_param: u32,
    #[allow(dead_code)]
    send_grease_frames: bool,
}

#[derive(Clone, Deserialize)]
struct Http3SettingPayload {
    id: u64,
    value: u64,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq, Hash)]
enum PseudoHeader {
    #[serde(rename = ":method")]
    Method,
    #[serde(rename = ":authority")]
    Authority,
    #[serde(rename = ":scheme")]
    Scheme,
    #[serde(rename = ":path")]
    Path,
}

#[derive(Clone, Serialize, Deserialize)]
struct HeaderPayload {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct HelperResponse {
    outcome: HelperOutcome,
    cached_session: Option<String>,
    bandwidth: BandwidthPayload,
}

#[derive(Serialize)]
#[serde(tag = "status", content = "payload")]
enum HelperOutcome {
    Success(ResponsePayload),
    Error(HelperError),
}

struct ResponsePayloadResolved {
    status: StatusCode,
    version: Version,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Serialize)]
struct ResponsePayload {
    status: u16,
    version: String,
    headers: Vec<HeaderPayload>,
    body: Option<String>,
}

impl ResponsePayload {
    fn from_response(response: ResponsePayloadResolved) -> Result<Self, HelperErrorKind> {
        let version = match response.version {
            Version::HTTP_3 => "HTTP/3",
            Version::HTTP_2 => "HTTP/2",
            Version::HTTP_11 => "HTTP/1.1",
            Version::HTTP_10 => "HTTP/1.0",
            other => {
                return Err(HelperErrorKind::Http(format!(
                    "unexpected HTTP version from helper response: {other:?}"
                )))
            }
        }
        .to_string();

        let headers = response
            .headers
            .iter()
            .map(|(name, value)| HeaderPayload {
                name: name.as_str().to_string(),
                value: String::from_utf8_lossy(value.as_bytes()).to_string(),
            })
            .collect();

        Ok(Self {
            status: response.status.as_u16(),
            version,
            headers,
            body: Some(base64::engine::general_purpose::STANDARD.encode(response.body)),
        })
    }
}

#[derive(Serialize)]
struct HelperError {
    kind: ErrorKind,
    message: String,
}

impl HelperError {
    fn from_error(error: HelperErrorKind) -> Self {
        match error {
            HelperErrorKind::Http(message) => Self {
                kind: ErrorKind::Http,
                message,
            },
            HelperErrorKind::BadPin(message) => Self {
                kind: ErrorKind::BadPin,
                message,
            },
            HelperErrorKind::UnsupportedProfile(message) => Self {
                kind: ErrorKind::UnsupportedProfile,
                message,
            },
            HelperErrorKind::InvalidConfig(message) => Self {
                kind: ErrorKind::InvalidConfig,
                message,
            },
        }
    }
}

#[derive(Serialize)]
enum ErrorKind {
    Http,
    BadPin,
    UnsupportedProfile,
    InvalidConfig,
}

#[derive(Default, Serialize)]
struct BandwidthPayload {
    read_bytes: u64,
    write_bytes: u64,
}

enum HelperErrorKind {
    Http(String),
    BadPin(String),
    UnsupportedProfile(String),
    InvalidConfig(String),
}
