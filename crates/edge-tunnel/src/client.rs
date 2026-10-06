//! Edge side of `mcp-edge/1` (PHASE4.md §2.2, §2.6, §2.8).
//!
//! [`OriginClient`] dials exactly one origin EndpointId, configured when it is
//! built; nothing in a request can select or add a peer. It keeps one cached
//! connection, opens one bidirectional stream per request, enforces the edge's
//! in-flight limits and deadlines, and reports every failure as a typed
//! [`TunnelError`] that maps onto the edge's HTTP contract via
//! [`TunnelError::edge_failure`].
//!
//! Offline behaviour: a dial that fails or exceeds 3 s marks the origin offline
//! for 15 s; requests in that window fail immediately with
//! [`TunnelError::Offline`]. The client never retries a request, except the
//! single re-dial after the origin closed a fresh connection with
//! `connection_limit` (nothing was processed then).

use crate::{
    codes::{CloseCode, EdgeFailure, ErrorCode},
    frame::{self, FrameError},
    ids, limits,
    meta::{
        self, Accept, ConsentRequestMeta, ConsentResponseMeta, ContentType, GrantRef,
        GrantRevokeMeta, GrantRevokeResponseMeta, GrantSyncEntry, GrantSyncMeta,
        GrantSyncResponseMeta, McpPostMeta, McpPostResponseMeta, McpProtocolVersion, PingMeta,
        PingResponseMeta, RemoteState, RequestMeta, ResponseMeta, RevokeReason,
    },
    timing, Op, ALPN, PROTOCOL_VERSION,
};
use bytes::Bytes;
use futures_util::Stream;
use iroh::{
    endpoint::{Connection, ConnectionError, RecvStream, VarInt},
    Endpoint, EndpointAddr, EndpointId,
};
use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{watch, Mutex, OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at, Instant},
};

/// Application code the edge uses when it stops reading a response stream.
pub const STOP_CANCELLED: u32 = 0;

/// Typed failure of one tunnel request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelError {
    /// Dial failed or timed out, offline window active, or the connection was
    /// lost (not closed with a known application code).
    Offline,
    /// The origin closed the connection with an application close code.
    Closed(CloseCode),
    /// The edge's own in-flight limit (route, grant or pending consent) is full.
    EdgeBusy,
    /// A deadline passed (write, first byte, idle, total).
    Timeout,
    /// The origin sent something that is not valid `mcp-edge/1`.
    Protocol(&'static str),
    /// The response ended without its terminator (or the stream was reset).
    Truncated,
    /// The response exceeded its total cap.
    ResponseTooLarge,
    /// The request body exceeds the op's cap (refused before any dial).
    RequestTooLarge,
    /// The edge built invalid metadata (refused before any dial).
    InvalidRequest(&'static str),
}

impl TunnelError {
    /// The edge's HTTP answer for this failure.
    pub fn edge_failure(self) -> EdgeFailure {
        match self {
            TunnelError::Offline => EdgeFailure::OriginOffline,
            TunnelError::Closed(code) => code.edge_failure(),
            TunnelError::EdgeBusy => EdgeFailure::TooManyRequests,
            TunnelError::Timeout => EdgeFailure::GatewayTimeout,
            TunnelError::Protocol(_) | TunnelError::Truncated | TunnelError::ResponseTooLarge => {
                EdgeFailure::BackendProtocol
            }
            TunnelError::RequestTooLarge => EdgeFailure::PayloadTooLarge,
            TunnelError::InvalidRequest(_) => EdgeFailure::Internal,
        }
    }
}

impl fmt::Display for TunnelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunnelError::Offline => f.write_str("origin offline"),
            TunnelError::Closed(c) => write!(
                f,
                "origin closed the connection: {}",
                String::from_utf8_lossy(c.reason())
            ),
            TunnelError::EdgeBusy => f.write_str("edge in-flight limit reached"),
            TunnelError::Timeout => f.write_str("tunnel deadline passed"),
            TunnelError::Protocol(what) => write!(f, "origin protocol error: {what}"),
            TunnelError::Truncated => f.write_str("origin response truncated"),
            TunnelError::ResponseTooLarge => f.write_str("origin response too large"),
            TunnelError::RequestTooLarge => f.write_str("request exceeds tunnel limit"),
            TunnelError::InvalidRequest(what) => write!(f, "invalid tunnel request: {what}"),
        }
    }
}
impl std::error::Error for TunnelError {}

/// A transport/authorization refusal from the origin (`error` present).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: u16,
    pub error: ErrorCode,
    pub retry_after: Option<u16>,
}

impl Refusal {
    pub fn edge_failure(&self) -> EdgeFailure {
        self.error.edge_failure()
    }
}

/// Result of a request the origin answered.
#[derive(Debug)]
pub enum Reply<T> {
    Ok(T),
    Refused(Refusal),
}

/// Edge client limits and deadlines. Defaults are the spec values.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub dial_timeout: Duration,
    pub offline_backoff: Duration,
    pub connection_limit_retry: Duration,
    pub request_write: Duration,
    pub first_byte: Duration,
    pub chunk_idle: Duration,
    /// Upper bound of an `mcp_post` budget (25 s).
    pub total: Duration,
    /// In-flight `mcp_post` for this route (8).
    pub max_in_flight: usize,
    /// In-flight `mcp_post` per grant (4).
    pub max_in_flight_per_grant: usize,
    /// Pending `consent_request` for this route (4).
    pub max_pending_consent: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            dial_timeout: timing::DIAL,
            offline_backoff: timing::OFFLINE_BACKOFF,
            connection_limit_retry: timing::CONNECTION_LIMIT_RETRY,
            request_write: timing::REQUEST_IO,
            first_byte: timing::FIRST_BYTE,
            chunk_idle: timing::CHUNK_IDLE,
            total: timing::TOTAL,
            max_in_flight: 8,
            max_in_flight_per_grant: 4,
            max_pending_consent: 4,
        }
    }
}

/// One `mcp_post`. The edge builds it from scratch; no client header crosses.
#[derive(Clone, Debug)]
pub struct McpPostRequest {
    /// Grant the assertion was minted for (local per-grant limit only; the
    /// origin reads the grant from the signed assertion).
    pub grant_id: String,
    pub accept: Accept,
    pub mcp_protocol_version: Option<McpProtocolVersion>,
    /// The minted `Edge-Assertion` (≤ 8 KiB), bound to `POST /mcp` + `body`.
    pub assertion: String,
    /// 16 random bytes, base64url; see [`new_request_id`].
    pub request_id: String,
    /// One JSON-RPC message (≤ 64 KiB, non-empty).
    pub body: Bytes,
    /// Remaining budget; clamped to 25 s. Sent as `deadline_ms`.
    pub budget: Duration,
}

/// A fresh non-secret correlation id (16 random bytes, base64url).
pub fn new_request_id() -> String {
    ids::random_b64url::<16>().expect("OS random source")
}

/// `ping` answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PingInfo {
    pub remote: RemoteState,
    pub enrolled_fingerprint: String,
    pub origin_version: String,
}

struct ConnSlot {
    conn: Option<Connection>,
    offline_until: Option<Instant>,
}

struct Inner {
    endpoint: Endpoint,
    origin: EndpointAddr,
    config: ClientConfig,
    slot: Mutex<ConnSlot>,
    mcp_slots: Arc<Semaphore>,
    consent_slots: Arc<Semaphore>,
    per_grant: StdMutex<HashMap<String, usize>>,
    connects: watch::Sender<u64>,
}

/// Edge-side client for one origin. Cheap to clone.
#[derive(Clone)]
pub struct OriginClient {
    inner: Arc<Inner>,
}

impl fmt::Debug for OriginClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginClient")
            .field("origin", &self.inner.origin.id.fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

struct GrantPermit {
    inner: Arc<Inner>,
    grant: String,
}

impl Drop for GrantPermit {
    fn drop(&mut self) {
        let mut map = self
            .inner
            .per_grant
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.grant) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.grant);
            }
        }
    }
}

/// Permits held for the lifetime of a response.
struct Permits {
    _route: Option<OwnedSemaphorePermit>,
    _grant: Option<GrantPermit>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What a dropped/failed connection means for the caller.
fn classify(conn: &Connection) -> TunnelError {
    match conn.close_reason() {
        Some(ConnectionError::ApplicationClosed(close)) => {
            CloseCode::from_u64(close.error_code.into_inner())
                .map(TunnelError::Closed)
                .unwrap_or(TunnelError::Offline)
        }
        _ => TunnelError::Offline,
    }
}

fn frame_err(conn: &Connection, e: FrameError, before_meta: bool) -> TunnelError {
    if conn.close_reason().is_some() {
        return classify(conn);
    }
    match e {
        FrameError::TooLarge if before_meta => TunnelError::Protocol("response metadata too large"),
        FrameError::TooLarge => TunnelError::Protocol("response chunk too large"),
        FrameError::TrailingBytes => TunnelError::Protocol("bytes after terminator"),
        FrameError::Truncated | FrameError::Io => {
            if before_meta {
                TunnelError::Protocol("stream ended before response metadata")
            } else {
                TunnelError::Truncated
            }
        }
    }
}

/// An opened exchange: request written, response metadata read.
struct Exchange {
    conn: Connection,
    recv: RecvStream,
    meta: Vec<u8>,
}

impl OriginClient {
    /// `origin` must be the single configured origin. In production it is
    /// `EndpointAddr::new(id)` (address lookup through the endpoint's
    /// discovery); tests pass direct loopback addresses.
    pub fn new(endpoint: Endpoint, origin: EndpointAddr, config: ClientConfig) -> Self {
        let (connects, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                endpoint,
                origin,
                mcp_slots: Arc::new(Semaphore::new(config.max_in_flight)),
                consent_slots: Arc::new(Semaphore::new(config.max_pending_consent)),
                config,
                slot: Mutex::new(ConnSlot {
                    conn: None,
                    offline_until: None,
                }),
                per_grant: StdMutex::new(HashMap::new()),
                connects,
            }),
        }
    }

    pub fn origin_id(&self) -> EndpointId {
        self.inner.origin.id
    }

    /// Increments on every new connection to the origin; the gateway runs
    /// `grant_sync` when it changes (§3.6).
    pub fn subscribe_connections(&self) -> watch::Receiver<u64> {
        self.inner.connects.subscribe()
    }

    /// Whether the offline window is active right now.
    pub async fn is_offline(&self) -> bool {
        let slot = self.inner.slot.lock().await;
        slot.offline_until.is_some_and(|t| Instant::now() < t)
    }

    /// Close the cached connection (`shutting_down`).
    pub async fn close(&self) {
        let mut slot = self.inner.slot.lock().await;
        if let Some(c) = slot.conn.take() {
            c.close(
                CloseCode::ShuttingDown.varint(),
                CloseCode::ShuttingDown.reason(),
            );
        }
    }

    async fn connection(&self) -> Result<(Connection, bool), TunnelError> {
        let inner = &self.inner;
        let mut slot = inner.slot.lock().await;
        if let Some(c) = &slot.conn {
            if c.close_reason().is_none() {
                return Ok((c.clone(), false));
            }
            slot.conn = None;
        }
        if let Some(until) = slot.offline_until {
            if Instant::now() < until {
                return Err(TunnelError::Offline);
            }
            slot.offline_until = None;
        }
        let dial = timeout(
            inner.config.dial_timeout,
            inner.endpoint.connect(inner.origin.clone(), ALPN),
        )
        .await;
        match dial {
            Ok(Ok(conn)) if conn.remote_id() == inner.origin.id => {
                slot.conn = Some(conn.clone());
                inner.connects.send_modify(|n| *n += 1);
                Ok((conn, true))
            }
            Ok(Ok(conn)) => {
                // Cannot happen with iroh's TLS binding; fail closed anyway.
                conn.close(CloseCode::ShuttingDown.varint(), b"wrong peer");
                slot.offline_until = Some(Instant::now() + inner.config.offline_backoff);
                Err(TunnelError::Offline)
            }
            _ => {
                slot.offline_until = Some(Instant::now() + inner.config.offline_backoff);
                Err(TunnelError::Offline)
            }
        }
    }

    /// Open a stream, write `meta` + `body` + FIN, read the response metadata
    /// before `first_byte`. Re-dials once if a fresh connection was closed with
    /// `connection_limit`.
    async fn exchange(
        &self,
        op: Op,
        meta: &[u8],
        body: &[u8],
        first_byte: Instant,
    ) -> Result<Exchange, TunnelError> {
        let mut retried = false;
        loop {
            let (conn, fresh) = self.connection().await?;
            match self.try_exchange(&conn, op, meta, body, first_byte).await {
                Err(TunnelError::Closed(CloseCode::ConnectionLimit)) if fresh && !retried => {
                    retried = true;
                    tokio::time::sleep(self.inner.config.connection_limit_retry).await;
                }
                other => return other,
            }
        }
    }

    async fn try_exchange(
        &self,
        conn: &Connection,
        op: Op,
        meta: &[u8],
        body: &[u8],
        first_byte: Instant,
    ) -> Result<Exchange, TunnelError> {
        let write = async {
            let (mut send, recv) = conn.open_bi().await.map_err(|_| classify(conn))?;
            frame::write_field(&mut send, meta, limits::REQUEST_META)
                .await
                .map_err(|e| frame_err(conn, e, true))?;
            frame::write_field(&mut send, body, op.body_cap())
                .await
                .map_err(|e| frame_err(conn, e, true))?;
            send.finish().map_err(|_| classify(conn))?;
            Ok::<_, TunnelError>(recv)
        };
        let write_deadline = (Instant::now() + self.inner.config.request_write).min(first_byte);
        let mut recv = match timeout_at(write_deadline, write).await {
            Ok(r) => r?,
            Err(_) => return Err(TunnelError::Timeout),
        };
        let meta = match timeout_at(
            first_byte,
            frame::read_field(&mut recv, op.response_meta_cap()),
        )
        .await
        {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                let _ = recv.stop(VarInt::from_u32(STOP_CANCELLED));
                return Err(frame_err(conn, e, true));
            }
            Err(_) => {
                let _ = recv.stop(VarInt::from_u32(STOP_CANCELLED));
                return Err(TunnelError::Timeout);
            }
        };
        Ok(Exchange {
            conn: conn.clone(),
            recv,
            meta,
        })
    }

    /// Read the terminator and FIN that must follow a refusal or a control
    /// response.
    async fn finish_empty(&self, ex: &mut Exchange) -> Result<(), TunnelError> {
        let deadline = Instant::now() + self.inner.config.chunk_idle;
        let r = timeout_at(deadline, async {
            let t = frame::read_field(&mut ex.recv, 0).await?;
            debug_assert!(t.is_empty());
            frame::expect_end(&mut ex.recv).await
        })
        .await;
        match r {
            Ok(Ok(())) => Ok(()),
            Ok(Err(FrameError::TooLarge)) => {
                let _ = ex.recv.stop(VarInt::from_u32(STOP_CANCELLED));
                Err(TunnelError::Protocol("unexpected response body"))
            }
            Ok(Err(e)) => Err(frame_err(&ex.conn, e, false)),
            Err(_) => {
                let _ = ex.recv.stop(VarInt::from_u32(STOP_CANCELLED));
                Err(TunnelError::Timeout)
            }
        }
    }

    fn acquire_mcp(&self, grant: &str) -> Result<Permits, TunnelError> {
        let route = self
            .inner
            .mcp_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| TunnelError::EdgeBusy)?;
        let mut map = self
            .inner
            .per_grant
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let n = map.entry(grant.to_owned()).or_insert(0);
        if *n >= self.inner.config.max_in_flight_per_grant {
            return Err(TunnelError::EdgeBusy);
        }
        *n += 1;
        Ok(Permits {
            _route: Some(route),
            _grant: Some(GrantPermit {
                inner: self.inner.clone(),
                grant: grant.to_owned(),
            }),
        })
    }

    /// Forward one MCP POST. On `Ok(Reply::Ok(response))` the body streams
    /// from [`McpResponse::body`]; dropping it stops the origin's work.
    pub async fn mcp_post(&self, req: McpPostRequest) -> Result<Reply<McpResponse>, TunnelError> {
        if req.body.is_empty() {
            return Err(TunnelError::InvalidRequest("empty body"));
        }
        if req.body.len() > limits::MCP_BODY {
            return Err(TunnelError::RequestTooLarge);
        }
        let start = Instant::now();
        let budget = req.budget.min(self.inner.config.total);
        let total_deadline = start + budget;
        let deadline_ms = budget.as_millis().min(timing::DEADLINE_MS_MAX as u128) as u32;
        if deadline_ms < timing::DEADLINE_MS_MIN {
            return Err(TunnelError::Timeout);
        }
        let meta = RequestMeta::McpPost(McpPostMeta {
            v: PROTOCOL_VERSION,
            path: meta::MCP_PATH.into(),
            content_type: meta::JSON.into(),
            accept: req.accept,
            mcp_protocol_version: req.mcp_protocol_version,
            assertion: req.assertion,
            request_id: req.request_id,
            deadline_ms,
        })
        .encode()
        .map_err(|e| match e {
            meta::MetaError::Invalid(what) => TunnelError::InvalidRequest(what),
            meta::MetaError::VersionUnsupported => TunnelError::InvalidRequest("v"),
        })?;
        let permits = self.acquire_mcp(&req.grant_id)?;
        let first_byte = (start + self.inner.config.first_byte).min(total_deadline);
        let mut ex = self
            .exchange(Op::McpPost, &meta, &req.body, first_byte)
            .await?;
        let rmeta: McpPostResponseMeta = match meta::parse_response(&ex.meta) {
            Ok(m) => m,
            Err(_) => {
                let _ = ex.recv.stop(VarInt::from_u32(STOP_CANCELLED));
                return Err(TunnelError::Protocol("response metadata"));
            }
        };
        if let Some(error) = rmeta.error {
            self.finish_empty(&mut ex).await?;
            return Ok(Reply::Refused(Refusal {
                status: rmeta.status,
                error,
                retry_after: rmeta.retry_after,
            }));
        }
        Ok(Reply::Ok(McpResponse {
            status: rmeta.status,
            content_type: rmeta.content_type,
            body: ResponseBody {
                recv: Some(ex.recv),
                conn: ex.conn,
                total: 0,
                cap: limits::MCP_RESPONSE,
                idle: self.inner.config.chunk_idle,
                deadline: total_deadline,
                done: false,
                _permits: permits,
            },
        }))
    }

    async fn control<T: ResponseMeta>(
        &self,
        meta: RequestMeta,
        first_byte: Instant,
    ) -> Result<T, TunnelError> {
        let op = meta.op();
        let bytes = meta.encode().map_err(|e| match e {
            meta::MetaError::Invalid(what) => TunnelError::InvalidRequest(what),
            meta::MetaError::VersionUnsupported => TunnelError::InvalidRequest("v"),
        })?;
        let mut ex = self.exchange(op, &bytes, &[], first_byte).await?;
        let parsed: T = match meta::parse_response(&ex.meta) {
            Ok(m) => m,
            Err(_) => {
                let _ = ex.recv.stop(VarInt::from_u32(STOP_CANCELLED));
                return Err(TunnelError::Protocol("response metadata"));
            }
        };
        self.finish_empty(&mut ex).await?;
        Ok(parsed)
    }

    /// Ask the app owner to approve a grant. The stream stays open until the
    /// owner decides or `expires_at` (≤ 180 s). Dropping the future stops the
    /// stream, which makes the origin drop its prompt (`cancelled`). Returns
    /// the compact approval string; verify it with
    /// [`crate::approval::verify`] before acting on it.
    pub async fn consent_request(
        &self,
        req: ConsentRequestMeta,
    ) -> Result<Reply<String>, TunnelError> {
        let _permit = self
            .inner
            .consent_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| TunnelError::EdgeBusy)?;
        let remaining = req
            .expires_at
            .saturating_sub(unix_now())
            .min(timing::CONSENT.as_secs());
        if remaining == 0 {
            return Err(TunnelError::Timeout);
        }
        let first_byte = Instant::now() + Duration::from_secs(remaining + timing::SKEW_SECS as u64);
        let r: ConsentResponseMeta = self
            .control(RequestMeta::ConsentRequest(req), first_byte)
            .await?;
        Ok(match (r.approval, r.error) {
            (Some(a), None) => Reply::Ok(a),
            (_, Some(error)) => Reply::Refused(Refusal {
                status: r.status,
                error,
                retry_after: r.retry_after,
            }),
            (None, None) => return Err(TunnelError::Protocol("consent response")),
        })
    }

    /// Reconcile the edge's active grants (≤ 64) after (re)connect. The answer
    /// covers exactly the grants sent.
    pub async fn grant_sync(
        &self,
        grants: Vec<GrantRef>,
    ) -> Result<Reply<Vec<GrantSyncEntry>>, TunnelError> {
        let sent: BTreeSet<String> = grants.iter().map(|g| g.grant_id.clone()).collect();
        let first_byte = Instant::now() + self.inner.config.first_byte;
        let r: GrantSyncResponseMeta = self
            .control(
                RequestMeta::GrantSync(GrantSyncMeta {
                    v: PROTOCOL_VERSION,
                    grants,
                }),
                first_byte,
            )
            .await?;
        match (r.grants, r.error) {
            (Some(entries), None) => {
                let got: BTreeSet<String> = entries.iter().map(|e| e.grant_id.clone()).collect();
                if got != sent || got.len() != entries.len() {
                    return Err(TunnelError::Protocol("grant_sync answer does not match"));
                }
                Ok(Reply::Ok(entries))
            }
            (_, Some(error)) => Ok(Reply::Refused(Refusal {
                status: r.status,
                error,
                retry_after: r.retry_after,
            })),
            (None, None) => Err(TunnelError::Protocol("grant_sync response")),
        }
    }

    /// Tell the origin a grant ended (best effort).
    pub async fn grant_revoke(
        &self,
        grant_id: &str,
        gen: u64,
        reason: RevokeReason,
    ) -> Result<Reply<()>, TunnelError> {
        let first_byte = Instant::now() + self.inner.config.first_byte;
        let r: GrantRevokeResponseMeta = self
            .control(
                RequestMeta::GrantRevoke(GrantRevokeMeta {
                    v: PROTOCOL_VERSION,
                    grant_id: grant_id.to_owned(),
                    gen,
                    reason,
                }),
                first_byte,
            )
            .await?;
        Ok(match r.error {
            None => Reply::Ok(()),
            Some(error) => Reply::Refused(Refusal {
                status: r.status,
                error,
                retry_after: r.retry_after,
            }),
        })
    }

    /// Liveness and enrollment status.
    pub async fn ping(&self) -> Result<Reply<PingInfo>, TunnelError> {
        let first_byte = Instant::now() + self.inner.config.first_byte;
        let r: PingResponseMeta = self
            .control(
                RequestMeta::Ping(PingMeta {
                    v: PROTOCOL_VERSION,
                }),
                first_byte,
            )
            .await?;
        Ok(
            match (r.remote, r.enrolled_fingerprint, r.origin_version, r.error) {
                (Some(remote), Some(enrolled_fingerprint), Some(origin_version), None) => {
                    Reply::Ok(PingInfo {
                        remote,
                        enrolled_fingerprint,
                        origin_version,
                    })
                }
                (_, _, _, Some(error)) => Reply::Refused(Refusal {
                    status: r.status,
                    error,
                    retry_after: r.retry_after,
                }),
                _ => return Err(TunnelError::Protocol("ping response")),
            },
        )
    }
}

/// A successful `mcp_post` response: status, content type and a streaming body.
#[derive(Debug)]
pub struct McpResponse {
    /// One of [`meta::MCP_STATUSES`].
    pub status: u16,
    /// Absent only for 202.
    pub content_type: Option<ContentType>,
    pub body: ResponseBody,
}

/// Streaming response body. Enforces the chunk cap, the 1 MiB total, 5 s idle
/// between chunks and the request's total deadline; ends only at the explicit
/// terminator followed by FIN. Dropping it before the end stops the stream
/// (the origin cancels the work) and releases the in-flight permits.
pub struct ResponseBody {
    recv: Option<RecvStream>,
    conn: Connection,
    total: usize,
    cap: usize,
    idle: Duration,
    deadline: Instant,
    done: bool,
    _permits: Permits,
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponseBody")
            .field("total", &self.total)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl ResponseBody {
    fn fail(&mut self, e: TunnelError) -> Option<Result<Bytes, TunnelError>> {
        self.done = true;
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(VarInt::from_u32(STOP_CANCELLED));
        }
        Some(Err(e))
    }

    /// Next chunk; `None` once the terminator and FIN were received.
    pub async fn next_chunk(&mut self) -> Option<Result<Bytes, TunnelError>> {
        if self.done {
            return None;
        }
        let recv = self.recv.as_mut()?;
        let idle = Instant::now() + self.idle;
        let read = timeout_at(
            idle.min(self.deadline),
            frame::read_field(recv, limits::CHUNK),
        )
        .await;
        let chunk = match read {
            Err(_) => return self.fail(TunnelError::Timeout),
            Ok(Err(e)) => {
                let err = frame_err(&self.conn, e, false);
                return self.fail(err);
            }
            Ok(Ok(c)) => c,
        };
        if chunk.is_empty() {
            let end = timeout_at(idle.min(self.deadline), frame::expect_end(recv)).await;
            return match end {
                Ok(Ok(())) => {
                    self.done = true;
                    self.recv = None;
                    None
                }
                Ok(Err(e)) => {
                    let err = frame_err(&self.conn, e, false);
                    self.fail(err)
                }
                Err(_) => self.fail(TunnelError::Timeout),
            };
        }
        self.total += chunk.len();
        if self.total > self.cap {
            return self.fail(TunnelError::ResponseTooLarge);
        }
        Some(Ok(Bytes::from(chunk)))
    }

    /// Read the whole body (bounded by the cap).
    pub async fn collect(mut self) -> Result<Vec<u8>, TunnelError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.next_chunk().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    /// As a `Stream` (e.g. for an HTTP response body). Ends after the first
    /// error.
    pub fn into_stream(self) -> impl Stream<Item = Result<Bytes, TunnelError>> + Send + 'static {
        futures_util::stream::unfold(self, |mut body| async move {
            body.next_chunk().await.map(|item| (item, body))
        })
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        if let Some(mut recv) = self.recv.take() {
            let _ = recv.stop(VarInt::from_u32(STOP_CANCELLED));
        }
    }
}
