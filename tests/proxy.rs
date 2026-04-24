use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{Router, http::StatusCode, routing::get};
use base64::Engine;
use tls_rust::{ClientBuilder, ClientProfile, Request};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn ok() -> &'static str {
    "ok"
}

fn app() -> Router {
    Router::new().route("/", get(ok))
}

async fn spawn_target_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind target");
    let addr = listener.local_addr().expect("target addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app()).await.expect("serve target");
    });
    (addr, server)
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    loop {
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            return buffer;
        }

        let mut chunk = [0u8; 512];
        let read = stream.read(&mut chunk).await.expect("read headers");
        assert!(read > 0, "connection closed before headers completed");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

async fn proxy_relay(stream: TcpStream, target: TcpStream) {
    let mut client = stream;
    let mut upstream = target;
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

async fn spawn_http_connect_proxy(
    expected_auth: Option<&'static str>,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");
    let connect_count = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&connect_count);
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept proxy");
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let request = read_headers(&mut stream).await;
                let request = String::from_utf8(request).expect("proxy request utf8");
                let mut lines = request.split("\r\n");
                let request_line = lines.next().expect("request line");
                let authority = request_line
                    .strip_prefix("CONNECT ")
                    .and_then(|line| line.strip_suffix(" HTTP/1.1"))
                    .expect("CONNECT line");

                if let Some(expected_auth) = expected_auth {
                    let auth_header = format!("Proxy-Authorization: Basic {expected_auth}");
                    assert!(
                        request
                            .lines()
                            .any(|line| line.eq_ignore_ascii_case(&auth_header)),
                        "missing proxy auth header in request: {request}"
                    );
                }

                let target = TcpStream::connect(authority).await.expect("connect target");
                counter.fetch_add(1, Ordering::SeqCst);
                stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .expect("write CONNECT response");
                proxy_relay(stream, target).await;
            });
        }
    });
    (addr, connect_count, server)
}

async fn spawn_socks5_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks5");
    let addr = listener.local_addr().expect("socks5 addr");
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept socks5");
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                stream
                    .read_exact(&mut greeting)
                    .await
                    .expect("read greeting");
                assert_eq!(greeting[0], 0x05);
                let mut methods = vec![0u8; usize::from(greeting[1])];
                stream.read_exact(&mut methods).await.expect("read methods");
                let auth_method = if methods.contains(&0x02) { 0x02 } else { 0x00 };
                stream
                    .write_all(&[0x05, auth_method])
                    .await
                    .expect("write auth method");
                if auth_method == 0x02 {
                    let mut auth_version = [0u8; 1];
                    stream
                        .read_exact(&mut auth_version)
                        .await
                        .expect("read auth version");
                    assert_eq!(auth_version[0], 0x01);
                    let mut user_len = [0u8; 1];
                    stream.read_exact(&mut user_len).await.expect("user len");
                    let mut username = vec![0u8; usize::from(user_len[0])];
                    stream.read_exact(&mut username).await.expect("username");
                    let mut pass_len = [0u8; 1];
                    stream.read_exact(&mut pass_len).await.expect("pass len");
                    let mut password = vec![0u8; usize::from(pass_len[0])];
                    stream.read_exact(&mut password).await.expect("password");
                    assert_eq!(str::from_utf8(&username).expect("utf8 username"), "user");
                    assert_eq!(str::from_utf8(&password).expect("utf8 password"), "pass");
                    stream
                        .write_all(&[0x01, 0x00])
                        .await
                        .expect("write auth success");
                }

                let mut request_head = [0u8; 4];
                stream
                    .read_exact(&mut request_head)
                    .await
                    .expect("read request head");
                assert_eq!(request_head[0], 0x05);
                assert_eq!(request_head[1], 0x01);

                let target_host = match request_head[3] {
                    0x01 => {
                        let mut ip = [0u8; 4];
                        stream.read_exact(&mut ip).await.expect("ipv4 addr");
                        IpAddr::V4(Ipv4Addr::from(ip)).to_string()
                    }
                    0x03 => {
                        let mut len = [0u8; 1];
                        stream.read_exact(&mut len).await.expect("domain len");
                        let mut host = vec![0u8; usize::from(len[0])];
                        stream.read_exact(&mut host).await.expect("domain");
                        String::from_utf8(host).expect("utf8 host")
                    }
                    atyp => panic!("unsupported socks5 atyp {atyp:#x}"),
                };
                let mut port = [0u8; 2];
                stream.read_exact(&mut port).await.expect("target port");
                let target_addr = format!("{target_host}:{}", u16::from_be_bytes(port));
                let target = TcpStream::connect(target_addr)
                    .await
                    .expect("connect target");
                stream
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .expect("write socks5 success");
                proxy_relay(stream, target).await;
            });
        }
    });
    (addr, server)
}

async fn spawn_socks4a_proxy() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind socks4");
    let addr = listener.local_addr().expect("socks4 addr");
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept socks4");
            tokio::spawn(async move {
                let mut header = [0u8; 8];
                stream
                    .read_exact(&mut header)
                    .await
                    .expect("read socks4 header");
                assert_eq!(header[0], 0x04);
                assert_eq!(header[1], 0x01);
                let port = u16::from_be_bytes([header[2], header[3]]);
                let ip = [header[4], header[5], header[6], header[7]];

                let mut user = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    stream
                        .read_exact(&mut byte)
                        .await
                        .expect("read socks4 user");
                    if byte[0] == 0 {
                        break;
                    }
                    user.push(byte[0]);
                }

                let host = if ip == [0, 0, 0, 1] {
                    let mut domain = Vec::new();
                    loop {
                        let mut byte = [0u8; 1];
                        stream
                            .read_exact(&mut byte)
                            .await
                            .expect("read socks4a domain");
                        if byte[0] == 0 {
                            break;
                        }
                        domain.push(byte[0]);
                    }
                    String::from_utf8(domain).expect("utf8 domain")
                } else {
                    IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_string()
                };

                let target = TcpStream::connect(format!("{host}:{port}"))
                    .await
                    .expect("connect target");
                stream
                    .write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0])
                    .await
                    .expect("write socks4 success");
                proxy_relay(stream, target).await;
            });
        }
    });
    (addr, server)
}

#[tokio::test]
async fn http_proxy_url_tunnels_requests_and_can_change_at_runtime() {
    let (target_addr, target_server) = spawn_target_server().await;
    let auth = base64::engine::general_purpose::STANDARD.encode("user:pass");
    let (proxy_addr, connect_count, proxy_server) =
        spawn_http_connect_proxy(Some(Box::leak(auth.into_boxed_str()))).await;

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .build()
        .expect("build client");

    let direct_response = client
        .execute(Request::get(format!("http://{target_addr}/")))
        .await
        .expect("direct response");
    assert_eq!(direct_response.status(), StatusCode::OK);
    assert_eq!(connect_count.load(Ordering::SeqCst), 0);
    assert_eq!(client.get_proxy(), None);

    client
        .set_proxy(format!("http://user:pass@{proxy_addr}"))
        .expect("set proxy");
    assert_eq!(
        client.get_proxy(),
        Some(format!("http://user:pass@{proxy_addr}"))
    );

    let proxied_response = client
        .execute(Request::get(format!("http://{target_addr}/")))
        .await
        .expect("proxied response");
    assert_eq!(proxied_response.status(), StatusCode::OK);
    assert_eq!(connect_count.load(Ordering::SeqCst), 1);

    client.set_proxy("").expect("clear proxy");
    assert_eq!(client.get_proxy(), None);

    let direct_response = client
        .execute(Request::get(format!("http://{target_addr}/")))
        .await
        .expect("direct response after clearing proxy");
    assert_eq!(direct_response.status(), StatusCode::OK);
    assert_eq!(connect_count.load(Ordering::SeqCst), 1);

    proxy_server.abort();
    target_server.abort();
}

#[tokio::test]
async fn socks5_proxy_url_supports_username_password_auth() {
    let (target_addr, target_server) = spawn_target_server().await;
    let (proxy_addr, proxy_server) = spawn_socks5_proxy().await;

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .proxy_url(format!("socks5://user:pass@{proxy_addr}"))
        .build()
        .expect("build client");

    let response = client
        .execute(Request::get(format!("http://{target_addr}/")))
        .await
        .expect("socks5 response");
    assert_eq!(response.status(), StatusCode::OK);

    proxy_server.abort();
    target_server.abort();
}

#[tokio::test]
async fn socks4a_proxy_url_supports_domain_targets() {
    let (target_addr, target_server) = spawn_target_server().await;
    let (proxy_addr, proxy_server) = spawn_socks4a_proxy().await;

    let client = ClientBuilder::new()
        .profile(ClientProfile::Chrome133)
        .proxy_url(format!("socks4a://{proxy_addr}"))
        .build()
        .expect("build client");

    let response = client
        .execute(Request::get(format!(
            "http://localhost:{}/",
            target_addr.port()
        )))
        .await
        .expect("socks4a response");
    assert_eq!(response.status(), StatusCode::OK);

    proxy_server.abort();
    target_server.abort();
}
