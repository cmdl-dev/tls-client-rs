use hpack::{Decoder, Encoder};
use http::{StatusCode, Version};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::Url;

use crate::{
    bandwidth::BandwidthTracker,
    client::ClientError,
    profile::{Http2SettingId, ProfileSpec, PseudoHeader},
    request::{HeaderEntry, Request, Response, headers_to_map},
};

const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_PRIORITY: u8 = 0x2;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

pub(crate) async fn send_http2<S>(
    mut stream: tokio_boring2::SslStream<S>,
    request: &Request,
    url: &Url,
    profile: &ProfileSpec,
    tracker: &BandwidthTracker,
) -> Result<(Response, tokio_boring2::SslStream<S>), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let stream_id = profile.http2.stream_id.unwrap_or(1);

    stream
        .write_all(CONNECTION_PREFACE)
        .await
        .map_err(|err| ClientError::Http(format!("failed to write HTTP/2 preface: {err}")))?;
    tracker.add_write(CONNECTION_PREFACE.len());
    write_settings(&mut stream, profile, tracker).await?;

    if profile.http2.connection_flow > 0 {
        write_window_update(&mut stream, 0, profile.http2.connection_flow, tracker).await?;
    }

    for priority in &profile.http2.priorities {
        write_priority(
            &mut stream,
            priority.stream_id,
            priority.stream_dependency,
            priority.exclusive,
            priority.weight,
            tracker,
        )
        .await?;
    }

    write_headers(&mut stream, stream_id, request, url, profile, tracker).await?;
    if let Some(body) = &request.body {
        write_data(&mut stream, stream_id, body, tracker).await?;
    }
    stream
        .flush()
        .await
        .map_err(|err| ClientError::Http(format!("failed to flush HTTP/2 request: {err}")))?;

    let response = read_response(&mut stream, stream_id, tracker).await?;
    Ok((response, stream))
}

async fn write_settings<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    profile: &ProfileSpec,
    tracker: &BandwidthTracker,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    for setting_id in &profile.http2.settings_order {
        let Some(setting) = profile
            .http2
            .settings
            .iter()
            .find(|entry| &entry.id == setting_id)
        else {
            continue;
        };
        payload.extend_from_slice(&setting_id_to_wire(setting.id).to_be_bytes());
        payload.extend_from_slice(&setting.value.to_be_bytes());
    }
    write_frame(stream, FRAME_SETTINGS, 0, 0, &payload, tracker).await
}

async fn write_window_update<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    stream_id: u32,
    increment: u32,
    tracker: &BandwidthTracker,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let payload = (increment & 0x7fff_ffff).to_be_bytes();
    write_frame(stream, FRAME_WINDOW_UPDATE, 0, stream_id, &payload, tracker).await
}

async fn write_priority<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    stream_id: u32,
    dependency: u32,
    exclusive: bool,
    weight: u8,
    tracker: &BandwidthTracker,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut payload = Vec::with_capacity(5);
    payload.extend_from_slice(&dependency_bytes(dependency, exclusive));
    payload.push(weight);
    write_frame(stream, FRAME_PRIORITY, 0, stream_id, &payload, tracker).await
}

async fn write_headers<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    stream_id: u32,
    request: &Request,
    url: &Url,
    profile: &ProfileSpec,
    tracker: &BandwidthTracker,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let headers = build_request_headers(request, url, profile)?;
    let mut encoder = Encoder::new();
    let borrowed = headers
        .iter()
        .map(|(name, value)| (&name[..], &value[..]))
        .collect::<Vec<_>>();
    let block = encoder.encode(borrowed);

    let mut payload = Vec::new();
    let mut flags = FLAG_END_HEADERS;
    if request.body.is_none() {
        flags |= FLAG_END_STREAM;
    }
    if let Some(priority) = profile.http2.header_priority {
        flags |= FLAG_PRIORITY;
        payload.extend_from_slice(&dependency_bytes(
            priority.stream_dependency,
            priority.exclusive,
        ));
        payload.push(priority.weight);
    }
    payload.extend_from_slice(&block);

    write_frame(stream, FRAME_HEADERS, flags, stream_id, &payload, tracker).await
}

async fn write_data<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    stream_id: u32,
    body: &[u8],
    tracker: &BandwidthTracker,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_frame(
        stream,
        FRAME_DATA,
        FLAG_END_STREAM,
        stream_id,
        body,
        tracker,
    )
    .await
}

async fn read_response<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    target_stream_id: u32,
    tracker: &BandwidthTracker,
) -> Result<Response, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut decoder = Decoder::new();
    let mut status = None;
    let mut headers = Vec::new();
    let mut body = Vec::new();

    loop {
        let frame = read_frame(stream, tracker).await?;
        match frame.kind {
            FRAME_SETTINGS => {
                if frame.flags & FLAG_ACK == 0 {
                    write_frame(stream, FRAME_SETTINGS, FLAG_ACK, 0, &[], tracker).await?;
                }
            }
            FRAME_PING => {
                if frame.flags & FLAG_ACK == 0 {
                    write_frame(stream, FRAME_PING, FLAG_ACK, 0, &frame.payload, tracker).await?;
                }
            }
            FRAME_HEADERS | FRAME_CONTINUATION => {
                if frame.stream_id != target_stream_id {
                    continue;
                }

                let mut block = extract_header_block(&frame)?;
                let mut end_headers = frame.flags & FLAG_END_HEADERS != 0;
                while !end_headers {
                    let continuation = read_frame(stream, tracker).await?;
                    if continuation.kind != FRAME_CONTINUATION
                        || continuation.stream_id != target_stream_id
                    {
                        return Err(ClientError::Http(
                            "received unexpected frame while reading continuation".to_string(),
                        ));
                    }
                    block.extend_from_slice(&extract_continuation_block(&continuation)?);
                    end_headers = continuation.flags & FLAG_END_HEADERS != 0;
                }

                for (name, value) in decoder.decode(&block).map_err(|err| {
                    ClientError::Http(format!("failed to decode HPACK block: {err:?}"))
                })? {
                    if name == b":status" {
                        let code = std::str::from_utf8(&value).map_err(|err| {
                            ClientError::Http(format!("invalid :status value: {err}"))
                        })?;
                        status = Some(
                            StatusCode::from_u16(code.parse::<u16>().map_err(|err| {
                                ClientError::Http(format!("invalid :status code: {err}"))
                            })?)
                            .map_err(|err| {
                                ClientError::Http(format!("invalid :status code: {err}"))
                            })?,
                        );
                    } else {
                        headers.push(HeaderEntry::new(
                            String::from_utf8(name).map_err(|err| {
                                ClientError::Http(format!("invalid header name bytes: {err}"))
                            })?,
                            String::from_utf8(value).map_err(|err| {
                                ClientError::Http(format!("invalid header value bytes: {err}"))
                            })?,
                        ));
                    }
                }

                if frame.flags & FLAG_END_STREAM != 0 {
                    return build_response(status, headers, body);
                }
            }
            FRAME_DATA => {
                if frame.stream_id != target_stream_id {
                    continue;
                }
                let chunk = extract_data_payload(&frame)?;
                body.extend_from_slice(&chunk);
                if frame.flags & FLAG_END_STREAM != 0 {
                    return build_response(status, headers, body);
                }
            }
            FRAME_RST_STREAM => {
                return Err(ClientError::Http(format!(
                    "HTTP/2 stream reset with payload {:?}",
                    frame.payload
                )));
            }
            FRAME_GOAWAY => {
                return Err(ClientError::Http(
                    "HTTP/2 connection closed by server".to_string(),
                ));
            }
            _ => {}
        }
    }
}

fn build_response(
    status: Option<StatusCode>,
    headers: Vec<HeaderEntry>,
    body: Vec<u8>,
) -> Result<Response, ClientError> {
    Ok(Response::new(
        status.unwrap_or(StatusCode::OK),
        Version::HTTP_2,
        headers_to_map(&headers)?,
        body,
    ))
}

fn build_request_headers(
    request: &Request,
    url: &Url,
    profile: &ProfileSpec,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, ClientError> {
    let mut headers = Vec::new();
    let authority = authority_value(url)?;
    let path = path_and_query(url);

    for pseudo in &profile.http2.pseudo_header_order {
        let value = match pseudo {
            PseudoHeader::Method => request.method.as_str().as_bytes().to_vec(),
            PseudoHeader::Authority => authority.as_bytes().to_vec(),
            PseudoHeader::Scheme => url.scheme().as_bytes().to_vec(),
            PseudoHeader::Path => path.as_bytes().to_vec(),
        };
        headers.push((pseudo_name(*pseudo).as_bytes().to_vec(), value));
    }

    let mut saw_content_length = false;
    for header in &request.headers {
        if is_h2_connection_header(&header.name) {
            continue;
        }
        if header.name.eq_ignore_ascii_case("host") {
            continue;
        }
        saw_content_length |= header.name.eq_ignore_ascii_case("content-length");
        headers.push((
            header.name.to_ascii_lowercase().into_bytes(),
            header.value.as_bytes().to_vec(),
        ));
    }

    if let Some(body) = &request.body {
        if !saw_content_length {
            headers.push((
                b"content-length".to_vec(),
                body.len().to_string().into_bytes(),
            ));
        }
    }

    Ok(headers)
}

fn pseudo_name(pseudo: PseudoHeader) -> &'static str {
    match pseudo {
        PseudoHeader::Method => ":method",
        PseudoHeader::Authority => ":authority",
        PseudoHeader::Scheme => ":scheme",
        PseudoHeader::Path => ":path",
    }
}

fn setting_id_to_wire(setting: Http2SettingId) -> u16 {
    match setting {
        Http2SettingId::HeaderTableSize => 1,
        Http2SettingId::EnablePush => 2,
        Http2SettingId::MaxConcurrentStreams => 3,
        Http2SettingId::InitialWindowSize => 4,
        Http2SettingId::MaxFrameSize => 5,
        Http2SettingId::MaxHeaderListSize => 6,
        Http2SettingId::Raw(value) => value,
    }
}

fn dependency_bytes(stream_dependency: u32, exclusive: bool) -> [u8; 4] {
    let mut value = stream_dependency & 0x7fff_ffff;
    if exclusive {
        value |= 1 << 31;
    }
    value.to_be_bytes()
}

fn path_and_query(url: &Url) -> String {
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

fn authority_value(url: &Url) -> Result<String, ClientError> {
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

fn is_h2_connection_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}

async fn write_frame<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
    tracker: &BandwidthTracker,
) -> Result<(), ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 9];
    let len = payload.len();
    header[0] = ((len >> 16) & 0xff) as u8;
    header[1] = ((len >> 8) & 0xff) as u8;
    header[2] = (len & 0xff) as u8;
    header[3] = kind;
    header[4] = flags;
    header[5..9].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());

    stream
        .write_all(&header)
        .await
        .map_err(|err| ClientError::Http(format!("failed to write HTTP/2 frame header: {err}")))?;
    tracker.add_write(header.len());
    stream
        .write_all(payload)
        .await
        .map_err(|err| ClientError::Http(format!("failed to write HTTP/2 frame payload: {err}")))?;
    tracker.add_write(payload.len());
    Ok(())
}

async fn read_frame<S>(
    stream: &mut tokio_boring2::SslStream<S>,
    tracker: &BandwidthTracker,
) -> Result<Http2Frame, ClientError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut header = [0u8; 9];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| ClientError::Http(format!("failed to read HTTP/2 frame header: {err}")))?;
    tracker.add_read(header.len());
    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .map_err(|err| ClientError::Http(format!("failed to read HTTP/2 frame payload: {err}")))?;
    tracker.add_read(payload.len());

    Ok(Http2Frame {
        kind: header[3],
        flags: header[4],
        stream_id: u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff,
        payload,
    })
}

fn extract_header_block(frame: &Http2Frame) -> Result<Vec<u8>, ClientError> {
    let mut payload = frame.payload.as_slice();
    let padding = if frame.flags & FLAG_PADDED != 0 {
        let Some((&pad_len, rest)) = payload.split_first() else {
            return Err(ClientError::Http(
                "HEADERS frame missing padding length".to_string(),
            ));
        };
        payload = rest;
        usize::from(pad_len)
    } else {
        0
    };

    if frame.flags & FLAG_PRIORITY != 0 {
        if payload.len() < 5 {
            return Err(ClientError::Http(
                "HEADERS frame missing priority payload".to_string(),
            ));
        }
        payload = &payload[5..];
    }

    if padding > payload.len() {
        return Err(ClientError::Http(
            "HEADERS frame padding exceeded payload".to_string(),
        ));
    }
    Ok(payload[..payload.len() - padding].to_vec())
}

fn extract_continuation_block(frame: &Http2Frame) -> Result<Vec<u8>, ClientError> {
    let payload = if frame.flags & FLAG_PADDED != 0 {
        return Err(ClientError::Http(
            "CONTINUATION frame must not be padded".to_string(),
        ));
    } else {
        frame.payload.clone()
    };
    Ok(payload)
}

fn extract_data_payload(frame: &Http2Frame) -> Result<Vec<u8>, ClientError> {
    if frame.flags & FLAG_PADDED == 0 {
        return Ok(frame.payload.clone());
    }

    let Some((&pad_len, rest)) = frame.payload.split_first() else {
        return Err(ClientError::Http(
            "DATA frame missing padding length".to_string(),
        ));
    };
    let padding = usize::from(pad_len);
    if padding > rest.len() {
        return Err(ClientError::Http(
            "DATA frame padding exceeded payload".to_string(),
        ));
    }
    Ok(rest[..rest.len() - padding].to_vec())
}

struct Http2Frame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}
