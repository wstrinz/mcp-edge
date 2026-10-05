//! Synthetic, loopback-only transport experiment. No Wiskit data or credentials.
//! The iroh ALPN is a narrow RPC envelope, never a general-purpose HTTP proxy.
use anyhow::{bail, Result};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, Limited, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{CONTENT_TYPE, HOST},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use iroh::{
    endpoint::{presets, Connection, QuicTransportConfig, RecvStream, SendStream, VarInt},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    error::Error,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const ALPN: &[u8] = b"wiskit-mcp-poc/1";
pub const HOSTNAME: &str = "poc.invalid";
pub const MAX_REQUEST: usize = 16 * 1024;
pub const MAX_RESPONSE: usize = 1024 * 1024;
pub const MAX_META: usize = 1024;
pub const MAX_CHUNK: usize = 8 * 1024;
pub const MAX_ACTIVE: usize = 2;
pub const MAX_HTTP_CONNECTIONS: usize = 8;
const PHASE_TIMEOUT: Duration = Duration::from_secs(2);
const STREAM_IDLE: Duration = Duration::from_secs(2);
const STREAM_TOTAL: Duration = Duration::from_secs(15);
type BoxError = Box<dyn Error + Send + Sync>;
type HttpBody = UnsyncBoxBody<Bytes, BoxError>;
type ByteStream = Pin<Box<dyn Stream<Item = std::result::Result<Bytes, BoxError>> + Send>>;

#[derive(Default, Debug)]
pub struct Metrics {
    pub dials: AtomicUsize,
    pub rejected_peers: AtomicUsize,
    pub origin_requests: AtomicUsize,
    pub active_origin: AtomicUsize,
    pub cancelled: AtomicUsize,
    pub wire_chunks: AtomicUsize,
    pub mock_requests: AtomicUsize,
    pub active_mock: AtomicUsize,
    pub cancelled_mock: AtomicUsize,
    pub trap_requests: AtomicUsize,
}
impl Metrics {
    pub fn get(counter: &AtomicUsize) -> usize {
        counter.load(Ordering::SeqCst)
    }
}

fn full(bytes: impl Into<Bytes>) -> HttpBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}
fn reply(status: StatusCode, message: &'static str) -> Response<HttpBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(full(format!("{{\"error\":\"{message}\"}}")))
        .unwrap()
}
fn boxed_error(message: &'static str) -> BoxError {
    std::io::Error::other(message).into()
}

/// Body and metadata are independent length-prefixed fields. This type has no
/// destination authority, URL, port, headers, upgrade, or alternate method field.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u8,
    pub path: String,
    pub content_type: String,
}
impl Envelope {
    fn valid(&self) -> bool {
        self.version == 1 && self.path == "/mcp" && self.content_type == "application/json"
    }
    pub fn mcp() -> Self {
        Self {
            version: 1,
            path: "/mcp".into(),
            content_type: "application/json".into(),
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseMeta {
    pub status: u16,
    pub content_type: String,
}

pub async fn write_field(send: &mut SendStream, bytes: &[u8], cap: usize) -> Result<()> {
    if bytes.len() > cap {
        bail!("field size limit");
    }
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}
pub async fn read_field(recv: &mut RecvStream, cap: usize) -> Result<Vec<u8>> {
    let mut length = [0u8; 4];
    recv.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > cap {
        bail!("field size limit");
    }
    let mut data = vec![0; length];
    recv.read_exact(&mut data).await?;
    Ok(data)
}

pub async fn loopback_endpoint() -> Result<Endpoint> {
    let transport = QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(4))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(16 * 1024))
        .receive_window(VarInt::from_u32(64 * 1024))
        .send_window(16 * 1024)
        .max_idle_timeout(Some(VarInt::from_u32(5_000).into()))
        .build();
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .clear_relay_transports()
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .transport_config(transport)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    // Fail closed even if a dependency changes address enumeration behavior.
    checked_addr(&endpoint)?;
    Ok(endpoint)
}
pub fn checked_addr(endpoint: &Endpoint) -> Result<EndpointAddr> {
    let addr = endpoint.addr();
    if addr.addrs.is_empty() {
        bail!("no loopback address");
    }
    for a in &addr.addrs {
        match a {
            TransportAddr::Ip(a) if a.ip().is_loopback() => (),
            _ => bail!("non-loopback endpoint address"),
        }
    }
    Ok(addr)
}

#[derive(Clone, Debug)]
struct Origin {
    admitted_gateway: EndpointId,
    fixed_mcp_url: String,
    client: reqwest::Client,
    slots: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}
struct ActiveOrigin {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<Metrics>,
    upstream_incomplete: bool,
}
impl Drop for ActiveOrigin {
    fn drop(&mut self) {
        // Also observe Router aborts when the entire QUIC connection closes.
        // The task may be dropped before send.stopped() is polled again.
        if self.upstream_incomplete {
            self.metrics.cancelled.fetch_add(1, Ordering::SeqCst);
        }
        self.metrics.active_origin.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Origin {
    fn new(
        admitted_gateway: EndpointId,
        destination: SocketAddr,
        metrics: Arc<Metrics>,
    ) -> Result<Self> {
        if !destination.ip().is_loopback() {
            bail!("destination must be loopback");
        }
        // Do not inherit HTTP_PROXY/ALL_PROXY, redirects, cookies, or credentials.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(PHASE_TIMEOUT)
            .build()?;
        Ok(Self {
            admitted_gateway,
            fixed_mcp_url: format!("http://{destination}/mcp"),
            client,
            slots: Arc::new(Semaphore::new(MAX_ACTIVE)),
            connections: Arc::new(Semaphore::new(MAX_HTTP_CONNECTIONS)),
            metrics,
        })
    }
    async fn error(send: &mut SendStream, status: u16) -> Result<()> {
        let meta = serde_json::to_vec(&ResponseMeta {
            status,
            content_type: "application/json".into(),
        })?;
        write_field(send, &meta, MAX_META).await?;
        write_field(send, b"{\"error\":\"origin refused request\"}", MAX_CHUNK).await?;
        write_field(send, &[], MAX_CHUNK).await?;
        send.finish()?;
        Ok(())
    }
    async fn forward(&self, mut send: SendStream, mut recv: RecvStream) -> Result<()> {
        let permit = match self.slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return Self::error(&mut send, 429).await,
        };
        self.metrics.active_origin.fetch_add(1, Ordering::SeqCst);
        let mut active = ActiveOrigin {
            _permit: permit,
            metrics: self.metrics.clone(),
            upstream_incomplete: false,
        };
        let intake = timeout(PHASE_TIMEOUT, async {
            let raw = read_field(&mut recv, MAX_META).await?;
            let envelope: Envelope = serde_json::from_slice(&raw)?;
            if !envelope.valid() {
                bail!("invalid fixed-service envelope");
            }
            let body = read_field(&mut recv, MAX_REQUEST).await?;
            if body.is_empty() {
                bail!("empty body");
            }
            // Reject trailing bytes; a request cannot smuggle another envelope.
            let mut tail = [0u8; 1];
            if recv.read(&mut tail).await?.is_some() {
                bail!("trailing request bytes");
            }
            Ok::<_, anyhow::Error>(body)
        })
        .await;
        let body = match intake {
            Ok(Ok(body)) => body,
            _ => return Self::error(&mut send, 400).await,
        };
        self.metrics.origin_requests.fetch_add(1, Ordering::SeqCst);
        active.upstream_incomplete = true;
        let response = tokio::select! {
            stopped = send.stopped() => { let _ = stopped; return Ok(()); }
            response = timeout(PHASE_TIMEOUT, self.client.post(&self.fixed_mcp_url).header(CONTENT_TYPE, "application/json").body(body).send()) => {
                match response { Ok(Ok(r)) => r, _ => return Self::error(&mut send, 502).await }
            }
        };
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !matches!(content_type, "application/json" | "text/event-stream") {
            return Self::error(&mut send, 502).await;
        }
        let meta = serde_json::to_vec(&ResponseMeta {
            status: response.status().as_u16(),
            content_type: content_type.into(),
        })?;
        write_field(&mut send, &meta, MAX_META).await?;
        let mut stream = response.bytes_stream();
        let end = tokio::time::Instant::now() + STREAM_TOTAL;
        let mut total = 0;
        loop {
            let bytes = tokio::select! {
                stopped = send.stopped() => { let _ = stopped; return Ok(()); }
                _ = tokio::time::sleep_until(end) => bail!("stream total deadline"),
                item = timeout(STREAM_IDLE, stream.next()) => match item { Ok(Some(bytes)) => bytes?, Ok(None) => break, Err(_) => bail!("stream idle deadline") }
            };
            total += bytes.len();
            if total > MAX_RESPONSE {
                bail!("response size limit");
            }
            for chunk in bytes.chunks(MAX_CHUNK) {
                match timeout(STREAM_IDLE, write_field(&mut send, chunk, MAX_CHUNK)).await {
                    Ok(Ok(())) => {
                        self.metrics.wire_chunks.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => {
                        bail!("stream stopped or stalled");
                    }
                }
            }
        }
        write_field(&mut send, &[], MAX_CHUNK).await?;
        send.finish()?;
        active.upstream_incomplete = false;
        Ok(())
    }
}
impl ProtocolHandler for Origin {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        if connection.remote_id() != self.admitted_gateway {
            self.metrics.rejected_peers.fetch_add(1, Ordering::SeqCst);
            connection.close(VarInt::from_u32(1), b"peer not admitted");
            return Ok(());
        }
        let Ok(_connection_permit) = self.connections.clone().try_acquire_owned() else {
            connection.close(VarInt::from_u32(2), b"origin connection limit");
            return Ok(());
        };
        // Per-origin global slots cover every admitted connection, not just one.
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                incoming = connection.accept_bi() => match incoming {
                    Ok((send, recv)) => { let origin = self.clone(); tasks.spawn(async move {
                        // Drop resets unfinished streams. Only sanitized counters are recorded.
                        let _ = origin.forward(send, recv).await;
                    }); }
                    Err(_) => break,
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => (),
            }
        }
        tasks.abort_all();
        Ok(())
    }
}

#[derive(Clone)]
struct Edge {
    gateway: Endpoint,
    origin: EndpointAddr,
    slots: Arc<Semaphore>,
    metrics: Arc<Metrics>,
}
struct ResponseReader {
    recv: RecvStream,
    _connection: Connection,
    _permit: OwnedSemaphorePermit,
    total: usize,
    deadline: tokio::time::Instant,
}
impl Drop for ResponseReader {
    fn drop(&mut self) {
        let _ = self.recv.stop(VarInt::from_u32(7));
    }
}

impl Edge {
    async fn handle(&self, request: Request<Incoming>) -> Response<HttpBody> {
        // All routing/admission checks happen before dial and before body buffering.
        if request.uri().scheme().is_some() || request.uri().authority().is_some() {
            return reply(StatusCode::BAD_REQUEST, "proxy-form request refused");
        }
        if request.method() != Method::POST {
            return reply(StatusCode::METHOD_NOT_ALLOWED, "only POST");
        }
        if request.uri().path() != "/mcp" || request.uri().query().is_some() {
            return reply(StatusCode::NOT_FOUND, "unknown path");
        }
        let hosts: Vec<_> = request.headers().get_all(HOST).iter().collect();
        if hosts.len() != 1 || hosts[0].to_str().ok() != Some(HOSTNAME) {
            return reply(StatusCode::FORBIDDEN, "host not admitted");
        }
        // Fixed header surface. In particular, arbitrary endpoint/target headers,
        // forwarded headers, cookies, upgrade, and proxy auth never cross iroh.
        for name in request.headers().keys() {
            if !matches!(
                name.as_str(),
                "host" | "content-type" | "content-length" | "accept" | "user-agent"
            ) {
                return reply(StatusCode::BAD_REQUEST, "header refused");
            }
        }
        if request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/json")
        {
            return reply(StatusCode::UNSUPPORTED_MEDIA_TYPE, "JSON required");
        }
        let permit = match self.slots.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return reply(StatusCode::TOO_MANY_REQUESTS, "edge busy"),
        };
        let body = match timeout(
            PHASE_TIMEOUT,
            Limited::new(request.into_body(), MAX_REQUEST).collect(),
        )
        .await
        {
            Ok(Ok(b)) => b.to_bytes(),
            Ok(Err(_)) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "body limit"),
            Err(_) => return reply(StatusCode::REQUEST_TIMEOUT, "body deadline"),
        };
        if body.is_empty() {
            return reply(StatusCode::BAD_REQUEST, "empty body");
        }
        self.metrics.dials.fetch_add(1, Ordering::SeqCst);
        let exchange = timeout(PHASE_TIMEOUT, async {
            let connection = self.gateway.connect(self.origin.clone(), ALPN).await?;
            if connection.remote_id() != self.origin.id {
                bail!("wrong origin identity");
            }
            let (mut send, mut recv) = connection.open_bi().await?;
            write_field(&mut send, &serde_json::to_vec(&Envelope::mcp())?, MAX_META).await?;
            write_field(&mut send, &body, MAX_REQUEST).await?;
            send.finish()?;
            let meta: ResponseMeta =
                serde_json::from_slice(&read_field(&mut recv, MAX_META).await?)?;
            if !matches!(
                meta.content_type.as_str(),
                "application/json" | "text/event-stream"
            ) {
                bail!("response type refused");
            }
            let status = StatusCode::from_u16(meta.status)?;
            Ok::<_, anyhow::Error>((connection, recv, meta.content_type, status))
        })
        .await;
        let (connection, recv, content_type, status) = match exchange {
            Ok(Ok(v)) => v,
            Ok(Err(_)) => return reply(StatusCode::BAD_GATEWAY, "origin unavailable"),
            Err(_) => return reply(StatusCode::GATEWAY_TIMEOUT, "origin deadline"),
        };
        let reader = ResponseReader {
            recv,
            _connection: connection,
            _permit: permit,
            total: 0,
            deadline: tokio::time::Instant::now() + STREAM_TOTAL,
        };
        let stream = futures_util::stream::unfold(Some(reader), |state| async move {
            let mut reader = state?;
            let read = timeout(STREAM_IDLE, read_field(&mut reader.recv, MAX_CHUNK));
            let result = tokio::select! { _ = tokio::time::sleep_until(reader.deadline) => Err(boxed_error("stream total deadline")), result = read => match result { Ok(Ok(bytes)) => Ok(bytes), _ => Err(boxed_error("origin stream interrupted")) } };
            match result {
                Ok(bytes) if bytes.is_empty() => None,
                Ok(bytes) => {
                    reader.total += bytes.len();
                    if reader.total > MAX_RESPONSE {
                        Some((Err(boxed_error("response limit")), None))
                    } else {
                        Some((Ok(Frame::data(Bytes::from(bytes))), Some(reader)))
                    }
                }
                Err(e) => Some((Err(e), None)),
            }
        });
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, content_type)
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .body(StreamBody::new(stream).boxed_unsync())
            .unwrap()
    }
}

pub struct HttpServer {
    pub addr: SocketAddr,
    shutdown: CancellationToken,
    task: JoinHandle<()>,
}
impl HttpServer {
    pub async fn stop(mut self) {
        self.shutdown.cancel();
        let _ = (&mut self.task).await;
    }
}
impl Drop for HttpServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}
async fn http_server<F, Fut>(handler: F) -> Result<HttpServer>
where
    F: Fn(Request<Incoming>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<HttpBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let shutdown = CancellationToken::new();
    let stopping = shutdown.clone();
    let task = tokio::spawn(async move {
        let slots = Arc::new(Semaphore::new(MAX_HTTP_CONNECTIONS));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = stopping.cancelled() => break,
                accepted = listener.accept() => if let Ok((socket, _)) = accepted {
                    let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
                    if socket2::SockRef::from(&socket).set_send_buffer_size(8192).is_err() { continue; }
                    let handler = handler.clone();
                    let stopping = stopping.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let service = service_fn(move |request| { let handler = handler.clone(); async move { Ok::<_, Infallible>(handler(request).await) } });
                        let mut builder = http1::Builder::new();
                        builder.timer(TokioTimer::new()).header_read_timeout(PHASE_TIMEOUT).max_headers(16).max_buf_size(16 * 1024);
                        let connection = builder.serve_connection(TokioIo::new(socket), service);
                        tokio::select! { _ = stopping.cancelled() => (), _ = connection => () }
                    });
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => (),
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });
    Ok(HttpServer {
        addr,
        shutdown,
        task,
    })
}

/// Loopback sink for proving that proxy environment variables are ignored.
pub async fn proxy_trap(metrics: Arc<Metrics>) -> Result<HttpServer> {
    http_server(move |_| {
        let metrics = metrics.clone();
        async move {
            metrics.trap_requests.fetch_add(1, Ordering::SeqCst);
            reply(StatusCode::OK, "synthetic proxy trap")
        }
    })
    .await
}

/// All listeners, test keys, and admission policy are created in this process.
/// Nothing is persisted; there are no command-line destination/credential inputs.
pub struct Poc {
    pub edge_addr: SocketAddr,
    pub mock_addr: SocketAddr,
    pub trap_addr: SocketAddr,
    pub origin_addr: EndpointAddr,
    pub gateway: Endpoint,
    pub metrics: Arc<Metrics>,
    router: Option<Router>,
    origin_endpoint: Endpoint,
    servers: Vec<HttpServer>,
}
impl Poc {
    pub async fn start() -> Result<Self> {
        let metrics = Arc::new(Metrics::default());
        let trap_metrics = metrics.clone();
        let trap = http_server(move |_| {
            let metrics = trap_metrics.clone();
            async move {
                metrics.trap_requests.fetch_add(1, Ordering::SeqCst);
                reply(StatusCode::OK, "trap visited")
            }
        })
        .await?;
        let trap_addr = trap.addr;
        let mock_metrics = metrics.clone();
        let mock = http_server(move |request| {
            let metrics = mock_metrics.clone();
            async move { mock_mcp(request, metrics, trap_addr).await }
        })
        .await?;
        let gateway = loopback_endpoint().await?;
        let origin_endpoint = loopback_endpoint().await?;
        let origin_addr = checked_addr(&origin_endpoint)?;
        let origin = Origin::new(gateway.id(), mock.addr, metrics.clone())?;
        let router = Router::builder(origin_endpoint.clone())
            .accept(ALPN, origin)
            .spawn();
        let edge_handler = Edge {
            gateway: gateway.clone(),
            origin: origin_addr.clone(),
            slots: Arc::new(Semaphore::new(MAX_ACTIVE)),
            metrics: metrics.clone(),
        };
        let edge = http_server(move |request| {
            let handler = edge_handler.clone();
            async move { handler.handle(request).await }
        })
        .await?;
        Ok(Self {
            edge_addr: edge.addr,
            mock_addr: mock.addr,
            trap_addr,
            origin_addr,
            gateway,
            metrics,
            router: Some(router),
            origin_endpoint,
            servers: vec![edge, mock, trap],
        })
    }
    pub async fn stop_origin(&mut self) {
        if let Some(router) = self.router.take() {
            let _ = router.shutdown().await;
        }
        self.origin_endpoint.close().await;
    }
    pub async fn shutdown(mut self) {
        self.stop_origin().await;
        self.gateway.close().await;
        for server in self.servers.drain(..) {
            server.stop().await;
        }
    }
    pub fn url(&self) -> String {
        format!("http://{}/mcp", self.edge_addr)
    }
    pub fn client() -> Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?)
    }
}

struct MockStream {
    index: usize,
    name: String,
    metrics: Arc<Metrics>,
    complete: bool,
}
impl MockStream {
    fn mark_complete(&mut self) {
        self.complete = true;
    }
}
impl Drop for MockStream {
    fn drop(&mut self) {
        if !self.complete {
            self.metrics.cancelled_mock.fetch_add(1, Ordering::SeqCst);
        }
        self.metrics.active_mock.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn mock_mcp(
    request: Request<Incoming>,
    metrics: Arc<Metrics>,
    trap: SocketAddr,
) -> Response<HttpBody> {
    if request.method() != Method::POST || request.uri().path() != "/mcp" {
        return reply(StatusCode::NOT_FOUND, "mock path");
    }
    metrics.mock_requests.fetch_add(1, Ordering::SeqCst);
    let body = match Limited::new(request.into_body(), MAX_REQUEST)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes(),
        Err(_) => return reply(StatusCode::PAYLOAD_TOO_LARGE, "mock body"),
    };
    let json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(j) => j,
        Err(_) => return reply(StatusCode::BAD_REQUEST, "mock JSON"),
    };
    let name = json
        .pointer("/params/name")
        .and_then(|s| s.as_str())
        .unwrap_or("");
    if name == "synthetic_redirect" {
        return Response::builder()
            .status(302)
            .header(CONTENT_TYPE, "application/json")
            .header("location", format!("http://{trap}/must-not-visit"))
            .body(full("{\"synthetic\":\"redirect\"}"))
            .unwrap();
    }
    if matches!(
        name,
        "synthetic_stream" | "synthetic_flood" | "synthetic_quiet"
    ) {
        metrics.active_mock.fetch_add(1, Ordering::SeqCst);
        let stream: ByteStream = Box::pin(futures_util::stream::unfold(
            MockStream {
                index: 0,
                name: name.to_owned(),
                metrics,
                complete: false,
            },
            |mut state| async move {
                if state.name == "synthetic_quiet" {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                } else if state.name == "synthetic_stream" {
                    tokio::time::sleep(Duration::from_millis(120)).await;
                }
                if state.name == "synthetic_stream" && state.index >= 4 {
                    state.mark_complete();
                    return None;
                }
                if state.name == "synthetic_quiet" && state.index >= 1 {
                    state.mark_complete();
                    return None;
                }
                let index = state.index;
                let bytes = if state.name == "synthetic_flood" {
                    Bytes::from(vec![b'x'; MAX_CHUNK])
                } else {
                    Bytes::from(format!(
                        "data: {{\"jsonrpc\":\"2.0\",\"id\":1,\"synthetic_chunk\":{index}}}\n\n"
                    ))
                };
                state.index += 1;
                Some((Ok(bytes), state))
            },
        ));
        return Response::builder()
            .header(CONTENT_TYPE, "text/event-stream")
            .body(StreamBody::new(stream.map(|bytes| bytes.map(Frame::data))).boxed_unsync())
            .unwrap();
    }
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": json.get("id").cloned().unwrap_or(serde_json::Value::Null), "result": { "synthetic": true, "echo": json } });
    Response::builder()
        .header(CONTENT_TYPE, "application/json")
        .body(full(body.to_string()))
        .unwrap()
}

pub fn synthetic_request(name: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":{}}})
}
