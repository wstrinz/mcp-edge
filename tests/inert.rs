use mcp_edge::{
    deny_all::{serve, CONNECTION_DEADLINE, MAX_CONNECTIONS},
    Mode,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

struct Fixture {
    addr: SocketAddr,
    stop: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}
impl Fixture {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(serve(listener, stop.clone()));
        Self { addr, stop, task }
    }
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
    async fn raw(&self, bytes: &[u8]) -> Vec<u8> {
        let mut socket = TcpStream::connect(self.addr).await.unwrap();
        socket.write_all(bytes).await.unwrap();
        let mut output = Vec::new();
        let _ = timeout(
            Duration::from_secs(2),
            socket.take(4096).read_to_end(&mut output),
        )
        .await
        .unwrap();
        output
    }
    async fn finish(self) {
        self.stop.cancel();
        self.task.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn alive_does_not_mean_ready_or_mcp_and_secrets_are_not_reflected() {
    let f = Fixture::start().await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let alive = client.get(f.url("/healthz")).send().await.unwrap();
    assert_eq!(alive.status(), 200);
    assert_eq!(alive.headers()["cache-control"], "no-store");
    assert_eq!(alive.headers()["x-content-type-options"], "nosniff");
    assert!(alive.text().await.unwrap().contains("deny-all"));
    let head = client.head(f.url("/healthz")).send().await.unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.bytes().await.unwrap().len(), 0);
    for path in ["/readyz", "/mcp"] {
        assert_eq!(client.get(f.url(path)).send().await.unwrap().status(), 503);
    }
    let denied = client
        .post(f.url("/mcp"))
        .header("authorization", "Bearer SYNTHETIC_DO_NOT_REFLECT")
        .header("cookie", "SYNTHETIC_DO_NOT_REFLECT")
        .body("SYNTHETIC_DO_NOT_REFLECT")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 503);
    assert!(denied.headers().get("www-authenticate").is_none());
    let body = denied.text().await.unwrap();
    assert_eq!(body, "{\"error\":\"forwarding_disabled\"}");
    assert!(!body.contains("SYNTHETIC_DO_NOT_REFLECT"));
    for path in [
        "/.well-known/oauth-authorization-server",
        "/authorize",
        "/token",
        "/register",
        "/approve",
        "/admin",
        "/healthz?access_token=SYNTHETIC_DO_NOT_REFLECT",
    ] {
        let denied = client.get(f.url(path)).send().await.unwrap();
        assert_eq!(denied.status(), 404);
        assert!(!denied
            .text()
            .await
            .unwrap()
            .contains("SYNTHETIC_DO_NOT_REFLECT"));
    }
    f.finish().await;
}

#[tokio::test]
async fn absolute_destinations_connect_duplicate_hosts_and_oversize_headers_are_rejected() {
    let f = Fixture::start().await;
    for input in [
        "GET http://127.0.0.1:9/healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nHost: other.invalid\r\n\r\n",
        "GET /healthz HTTP/1.1\r\n\r\n",
    ] {
        let output = f.raw(input.as_bytes()).await;
        assert!(
            output.starts_with(b"HTTP/1.1 400 "),
            "request must be rejected"
        );
    }
    let huge = format!(
        "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Huge: {}\r\n\r\n",
        "a".repeat(32 * 1024)
    );
    let output = f.raw(huge.as_bytes()).await;
    // The server stops reading at its buffer limit and closes. Depending on
    // timing (notably on Windows) the client sees the 431/400 or a reset that
    // discards it; it must never see the request served.
    assert!(
        output.starts_with(b"HTTP/1.1 431 ")
            || output.starts_with(b"HTTP/1.1 400 ")
            || output.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output[..output.len().min(80)])
    );
    f.finish().await;
}

#[tokio::test]
async fn denied_body_is_not_awaited_and_unread_body_cannot_pipeline_health() {
    let f = Fixture::start().await;
    // Advertise an unfinished large body. A denial must not wait for it.
    let output = f
        .raw(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\n\r\n")
        .await;
    assert!(output.starts_with(b"HTTP/1.1 503 "));
    let output = f.raw(b"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nHELLOGET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n").await;
    assert!(output.starts_with(b"HTTP/1.1 503 "));
    assert_eq!(output.windows(9).filter(|w| *w == b"HTTP/1.1 ").count(), 1);
    f.finish().await;
}

#[tokio::test]
async fn slow_headers_have_a_deadline_and_shutdown_closes_pending_connections() {
    let f = Fixture::start().await;
    let mut socket = TcpStream::connect(f.addr).await.unwrap();
    socket
        .write_all(b"GET /healthz HTTP/1.1\r\n")
        .await
        .unwrap();
    let mut output = Vec::new();
    let _ = timeout(
        CONNECTION_DEADLINE + Duration::from_secs(2),
        socket.read_to_end(&mut output),
    )
    .await
    .unwrap();
    let mut pending = TcpStream::connect(f.addr).await.unwrap();
    pending.write_all(b"GET ").await.unwrap();
    f.finish().await;
    let mut output = [0u8; 1];
    let result = timeout(Duration::from_secs(1), pending.read(&mut output))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
}

#[tokio::test]
async fn connection_capacity_is_bounded_and_capacity_returns_on_shutdown() {
    let f = Fixture::start().await;
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let mut socket = TcpStream::connect(f.addr).await.unwrap();
        socket.write_all(b"GET ").await.unwrap();
        held.push(socket);
    }
    let mut extra = TcpStream::connect(f.addr).await.unwrap();
    extra
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut output = [0u8; 1];
    let result = timeout(Duration::from_secs(1), extra.read(&mut output))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    f.finish().await;
    for mut socket in held {
        let result = timeout(Duration::from_secs(1), socket.read(&mut output))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
    }
}

#[test]
fn mode_defaults_to_deny_all_and_only_known_modes_parse() {
    assert_eq!(Mode::parse(None).unwrap(), Mode::DenyAll);
    assert_eq!(Mode::parse(Some("deny-all")).unwrap(), Mode::DenyAll);
    assert_eq!(Mode::parse(Some("edge")).unwrap(), Mode::Edge);
    for value in ["forward", "mock", "production", "", "true", "EDGE", "proxy"] {
        assert!(Mode::parse(Some(value)).is_err());
    }
}
