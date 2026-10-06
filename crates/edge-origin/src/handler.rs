//! The iroh `ProtocolHandler` for `mcp-edge/1`.

use crate::{
    consent::ConsentResponder, unix_now, Body, McpRequest, McpResponse, OriginApp, Refusal,
    VerifiedGrant,
};
use bytes::Bytes;
use edge_tunnel::{
    approval::ApprovalBinding,
    enrollment::Enrollment,
    frame::{self, FrameError},
    limits,
    meta::{
        self, ConsentRequestMeta, ConsentResponseMeta, ContentType, GrantRevokeResponseMeta,
        GrantState, GrantSyncEntry, GrantSyncResponseMeta, McpPostMeta, McpPostResponseMeta,
        MetaError, PingResponseMeta, RemoteState, RequestMeta, ResponseMeta, MCP_PATH,
    },
    timing, CloseCode, ErrorCode, Op, PROTOCOL_VERSION,
};
use futures_util::StreamExt;
use iroh::{
    endpoint::{Connection, RecvStream, SendStream, VarInt},
    protocol::{AcceptError, ProtocolHandler},
    EndpointId, SecretKey,
};
use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::{timeout, timeout_at, Instant},
};
use tokio_util::sync::CancellationToken;

/// Reset code when the origin aborts a response mid-stream.
pub const RESET_ABORTED: u32 = 1;
/// Stop code when the origin refuses to read (more of) a request.
pub const STOP_REFUSED: u32 = 1;

/// Origin limits. Defaults are the spec values (§2.2, §2.6, §4.1).
#[derive(Clone, Debug)]
pub struct OriginConfig {
    /// Concurrent admitted connections (2); the next is closed `connection_limit`.
    pub max_connections: usize,
    /// Concurrent streams per connection (8); extra streams are reset.
    pub max_streams_per_connection: usize,
    /// In-flight `mcp_post` across all connections (4) → `busy`.
    pub max_in_flight: usize,
    /// In-flight `mcp_post` per grant (2) → `busy`.
    pub max_in_flight_per_grant: usize,
    /// `mcp_post` per grant per minute (120) → `busy`.
    pub max_requests_per_grant_per_minute: u32,
    /// Pending `consent_request` (1) → `consent_busy`.
    pub max_pending_consent: usize,
    /// `jti` replay cache (10 000; full of live entries → reject).
    pub replay_capacity: usize,
    /// Reading the whole request (2 s).
    pub intake_timeout: Duration,
    /// A response write that makes no progress (5 s) → abort.
    pub write_stall: Duration,
    /// `retry_after` sent with `busy` (2 s).
    pub busy_retry_after: u16,
    /// Assertions with `iat` before this (minus 5 s skew) are refused (§4.7:
    /// a restarted origin never accepts assertions minted before it started).
    /// Defaults to the handler's creation time.
    pub started_at_unix: i64,
}

impl Default for OriginConfig {
    fn default() -> Self {
        Self {
            max_connections: 2,
            max_streams_per_connection: 8,
            max_in_flight: 4,
            max_in_flight_per_grant: 2,
            max_requests_per_grant_per_minute: 120,
            max_pending_consent: 1,
            replay_capacity: 10_000,
            intake_timeout: timing::REQUEST_IO,
            write_stall: timing::CHUNK_IDLE,
            busy_retry_after: 2,
            started_at_unix: unix_now(),
        }
    }
}

struct EnrolledEdge {
    enrollment: Enrollment,
    edge_id: EndpointId,
    fingerprint: String,
    verifier: edge_assert::Verifier,
    scopes_sorted: Vec<String>,
}

struct Inner<A> {
    app: Arc<A>,
    key: SecretKey,
    config: OriginConfig,
    enrolled: RwLock<Option<Arc<EnrolledEdge>>>,
    connections: Arc<Semaphore>,
    live: Mutex<HashMap<u64, Connection>>,
    next_conn: AtomicU64,
    mcp_slots: Arc<Semaphore>,
    consent_slots: Arc<Semaphore>,
    per_grant: Mutex<HashMap<String, usize>>,
    rate: Mutex<HashMap<String, (i64, u32)>>,
    shutdown: CancellationToken,
}

/// `mcp-edge/1` protocol handler. Clone it freely; register one instance on
/// the endpoint's Router with `.accept(edge_tunnel::ALPN, handler)`.
pub struct OriginHandler<A: OriginApp> {
    inner: Arc<Inner<A>>,
}

impl<A: OriginApp> Clone for OriginHandler<A> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<A: OriginApp> fmt::Debug for OriginHandler<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginHandler")
            .field("enrolled", &self.enrollment().map(|e| e.fingerprint()))
            .finish_non_exhaustive()
    }
}

/// Removes a connection from the live map when its accept task ends.
struct LiveGuard<A: OriginApp> {
    inner: Arc<Inner<A>>,
    id: u64,
}
impl<A: OriginApp> Drop for LiveGuard<A> {
    fn drop(&mut self) {
        self.inner
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);
    }
}

struct GrantSlot<A: OriginApp> {
    inner: Arc<Inner<A>>,
    grant: String,
}
impl<A: OriginApp> Drop for GrantSlot<A> {
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

impl<A: OriginApp> OriginHandler<A> {
    /// `key` is the origin endpoint's secret key (the transport key behind its
    /// EndpointId); it signs consent approvals under the
    /// `mcp-edge-approval.v1.` domain prefix (D2). Starts unenrolled: every
    /// peer is refused until [`set_enrollment`](Self::set_enrollment).
    pub fn new(app: Arc<A>, key: SecretKey, config: OriginConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                app,
                key,
                connections: Arc::new(Semaphore::new(config.max_connections)),
                mcp_slots: Arc::new(Semaphore::new(config.max_in_flight)),
                consent_slots: Arc::new(Semaphore::new(config.max_pending_consent)),
                config,
                enrolled: RwLock::new(None),
                live: Mutex::new(HashMap::new()),
                next_conn: AtomicU64::new(0),
                per_grant: Mutex::new(HashMap::new()),
                rate: Mutex::new(HashMap::new()),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    /// Replace (or clear) the enrollment. Closes every live connection with
    /// `peer_not_admitted` and starts a fresh replay cache. The app drops its
    /// remote grants itself (§1.3).
    pub fn set_enrollment(
        &self,
        enrollment: Option<Enrollment>,
    ) -> Result<(), crate::EnrollmentError> {
        let next = match enrollment {
            Some(e) => {
                e.validate()?;
                let mut scopes_sorted = e.scopes.clone();
                scopes_sorted.sort();
                Some(Arc::new(EnrolledEdge {
                    edge_id: e.edge_endpoint_id(),
                    fingerprint: e.fingerprint(),
                    verifier: e.assertion_verifier(self.inner.config.replay_capacity),
                    scopes_sorted,
                    enrollment: e,
                }))
            }
            None => None,
        };
        *self
            .inner
            .enrolled
            .write()
            .unwrap_or_else(|e| e.into_inner()) = next;
        self.close_all(CloseCode::PeerNotAdmitted);
        Ok(())
    }

    pub fn enrollment(&self) -> Option<Enrollment> {
        self.current().map(|e| e.enrollment.clone())
    }

    fn current(&self) -> Option<Arc<EnrolledEdge>> {
        self.inner
            .enrolled
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Close every live connection with `code` (remote off →
    /// `RemoteDisabled`, enrollment stale → `EnrollmentStale`, ...).
    /// In-flight requests are cancelled.
    pub fn close_all(&self, code: CloseCode) {
        let live: Vec<Connection> = self
            .inner
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        for c in live {
            c.close(code.varint(), code.reason());
        }
    }

    /// Number of admitted connections right now.
    pub fn live_connections(&self) -> usize {
        self.inner
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Pending consent prompts (0 or 1).
    pub fn pending_consents(&self) -> usize {
        self.inner.config.max_pending_consent - self.inner.consent_slots.available_permits()
    }

    /// In-flight `mcp_post` requests.
    pub fn in_flight(&self) -> usize {
        self.inner.config.max_in_flight - self.inner.mcp_slots.available_permits()
    }
}

impl<A: OriginApp> ProtocolHandler for OriginHandler<A> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let inner = self.inner.clone();
        // 1. Peer admission, before any stream is read.
        let Some(edge) = self
            .current()
            .filter(|e| e.edge_id == connection.remote_id())
        else {
            let c = CloseCode::PeerNotAdmitted;
            connection.close(c.varint(), c.reason());
            return Ok(());
        };
        // 2. Remote mode / enrollment state.
        match inner.app.remote_state() {
            RemoteState::Off => {
                let c = CloseCode::RemoteDisabled;
                connection.close(c.varint(), c.reason());
                return Ok(());
            }
            RemoteState::Stale => {
                let c = CloseCode::EnrollmentStale;
                connection.close(c.varint(), c.reason());
                return Ok(());
            }
            RemoteState::On | RemoteState::Paused => {}
        }
        let Ok(_conn_permit) = inner.connections.clone().try_acquire_owned() else {
            let c = CloseCode::ConnectionLimit;
            connection.close(c.varint(), c.reason());
            return Ok(());
        };
        let id = inner.next_conn.fetch_add(1, Ordering::Relaxed);
        inner
            .live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, connection.clone());
        let _live = LiveGuard {
            inner: inner.clone(),
            id,
        };
        // A shutdown or enrollment change racing the insert above.
        if inner.shutdown.is_cancelled() || !self.current().is_some_and(|e| Arc::ptr_eq(&e, &edge))
        {
            let c = CloseCode::PeerNotAdmitted;
            connection.close(c.varint(), c.reason());
            return Ok(());
        }
        let conn_cancel = inner.shutdown.child_token();
        let streams = Arc::new(Semaphore::new(inner.config.max_streams_per_connection));
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _ = conn_cancel.cancelled() => {
                    let c = CloseCode::ShuttingDown;
                    connection.close(c.varint(), c.reason());
                    break;
                }
                accepted = connection.accept_bi() => match accepted {
                    Ok((mut send, mut recv)) => {
                        let Ok(permit) = streams.clone().try_acquire_owned() else {
                            let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
                            let _ = recv.stop(VarInt::from_u32(STOP_REFUSED));
                            continue;
                        };
                        let inner = inner.clone();
                        let edge = edge.clone();
                        let cancel = conn_cancel.child_token();
                        tasks.spawn(async move {
                            let _permit = permit;
                            handle_stream(inner, edge, send, recv, cancel).await;
                        });
                    }
                    Err(_) => break,
                },
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        conn_cancel.cancel();
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn shutdown(&self) {
        self.inner.shutdown.cancel();
        self.close_all(CloseCode::ShuttingDown);
    }
}

// ------------------------------------------------------------------ streams

/// Fires `cancel` when the edge stops our send side or the connection dies.
fn watch_stop(send: &SendStream, cancel: CancellationToken) -> tokio_util::sync::DropGuard {
    let done = CancellationToken::new();
    let stopped = send.stopped();
    let guard = done.clone().drop_guard();
    tokio::spawn(async move {
        tokio::select! {
            r = stopped => {
                if !matches!(r, Ok(None)) {
                    cancel.cancel();
                }
            }
            _ = done.cancelled() => {}
        }
    });
    guard
}

/// Write a refusal in the shape the op's receiver expects, then the
/// terminator and FIN.
async fn send_refusal(send: &mut SendStream, op: Option<Op>, refusal: Refusal, stall: Duration) {
    let status = refusal.code.status();
    let bytes = match op.unwrap_or(Op::McpPost) {
        Op::McpPost => encode(
            &McpPostResponseMeta {
                v: PROTOCOL_VERSION,
                status,
                content_type: Some(ContentType::Json),
                error: Some(refusal.code),
                retry_after: refusal.retry_after,
            },
            Op::McpPost,
        ),
        Op::ConsentRequest => encode(
            &ConsentResponseMeta {
                v: PROTOCOL_VERSION,
                status,
                approval: None,
                error: Some(refusal.code),
                retry_after: refusal.retry_after,
            },
            Op::ConsentRequest,
        ),
        Op::GrantSync => encode(
            &GrantSyncResponseMeta {
                v: PROTOCOL_VERSION,
                status,
                grants: None,
                error: Some(refusal.code),
                retry_after: refusal.retry_after,
            },
            Op::GrantSync,
        ),
        Op::GrantRevoke => encode(
            &GrantRevokeResponseMeta {
                v: PROTOCOL_VERSION,
                status,
                error: Some(refusal.code),
                retry_after: refusal.retry_after,
            },
            Op::GrantRevoke,
        ),
        Op::Ping => encode(
            &PingResponseMeta {
                v: PROTOCOL_VERSION,
                status,
                remote: None,
                enrolled_fingerprint: None,
                origin_version: None,
                error: Some(refusal.code),
                retry_after: refusal.retry_after,
            },
            Op::Ping,
        ),
    };
    let Some(bytes) = bytes else {
        let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
        return;
    };
    send_complete(send, &bytes, op.unwrap_or(Op::McpPost), stall).await;
}

fn encode<T: ResponseMeta>(meta: &T, op: Op) -> Option<Vec<u8>> {
    meta::encode_response(meta, op.response_meta_cap()).ok()
}

/// meta + terminator + FIN, bounded by the write-stall deadline.
async fn send_complete(send: &mut SendStream, meta_bytes: &[u8], op: Op, stall: Duration) {
    let r = timeout(stall, async {
        frame::write_field(send, meta_bytes, op.response_meta_cap()).await?;
        frame::write_terminator(send).await?;
        send.finish().map_err(|_| FrameError::Io)
    })
    .await;
    if !matches!(r, Ok(Ok(()))) {
        let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
    }
}

struct Intake {
    meta: RequestMeta,
    body: Vec<u8>,
}

/// Read meta + body + FIN. Errors carry the op when it was known.
async fn read_request(recv: &mut RecvStream) -> Result<Intake, (Option<Op>, ErrorCode)> {
    let raw = frame::read_field(recv, limits::REQUEST_META)
        .await
        .map_err(|_| (None, ErrorCode::BadRequest))?;
    let meta = meta::parse_request_meta(&raw).map_err(|e: MetaError| (None, e.code()))?;
    let op = meta.op();
    // §2.4: the path (and every other meta rule) is checked before the body is
    // read; parse_request_meta already did.
    let body = frame::read_field(recv, op.body_cap())
        .await
        .map_err(|_| (Some(op), ErrorCode::BadRequest))?;
    if op == Op::McpPost && body.is_empty() {
        return Err((Some(op), ErrorCode::BadRequest));
    }
    frame::expect_end(recv)
        .await
        .map_err(|_| (Some(op), ErrorCode::BadRequest))?;
    Ok(Intake { meta, body })
}

async fn handle_stream<A: OriginApp>(
    inner: Arc<Inner<A>>,
    edge: Arc<EnrolledEdge>,
    mut send: SendStream,
    mut recv: RecvStream,
    cancel: CancellationToken,
) {
    let _watch = watch_stop(&send, cancel.clone());
    let stall = inner.config.write_stall;
    let intake = match timeout(inner.config.intake_timeout, read_request(&mut recv)).await {
        Ok(Ok(i)) => i,
        Ok(Err((op, code))) => {
            let _ = recv.stop(VarInt::from_u32(STOP_REFUSED));
            send_refusal(&mut send, op, code.into(), stall).await;
            return;
        }
        Err(_) => {
            let _ = recv.stop(VarInt::from_u32(STOP_REFUSED));
            send_refusal(&mut send, None, ErrorCode::BadRequest.into(), stall).await;
            return;
        }
    };
    drop(recv);
    match intake.meta {
        RequestMeta::McpPost(m) => mcp_post(&inner, &edge, send, m, intake.body, cancel).await,
        RequestMeta::ConsentRequest(m) => consent(&inner, &edge, send, m, cancel).await,
        RequestMeta::GrantSync(m) => {
            let refs = m.grants.clone();
            let r = tokio::select! {
                _ = cancel.cancelled() => return,
                r = inner.app.grant_sync(m.grants) => r,
            };
            match r {
                Ok(entries) => {
                    // Exactly the grants asked about; omitted → unknown.
                    let by_id: HashMap<String, GrantState> =
                        entries.into_iter().map(|e| (e.grant_id, e.state)).collect();
                    let grants = refs
                        .into_iter()
                        .map(|g| GrantSyncEntry {
                            state: by_id
                                .get(&g.grant_id)
                                .copied()
                                .unwrap_or(GrantState::Unknown),
                            grant_id: g.grant_id,
                        })
                        .collect();
                    let resp = GrantSyncResponseMeta {
                        v: PROTOCOL_VERSION,
                        status: 200,
                        grants: Some(grants),
                        error: None,
                        retry_after: None,
                    };
                    match encode(&resp, Op::GrantSync) {
                        Some(b) => send_complete(&mut send, &b, Op::GrantSync, stall).await,
                        None => {
                            let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
                        }
                    }
                }
                Err(refusal) => send_refusal(&mut send, Some(Op::GrantSync), refusal, stall).await,
            }
        }
        RequestMeta::GrantRevoke(m) => {
            let r = tokio::select! {
                _ = cancel.cancelled() => return,
                r = inner.app.grant_revoke(m) => r,
            };
            match r {
                Ok(()) => {
                    let resp = GrantRevokeResponseMeta {
                        v: PROTOCOL_VERSION,
                        status: 200,
                        error: None,
                        retry_after: None,
                    };
                    if let Some(b) = encode(&resp, Op::GrantRevoke) {
                        send_complete(&mut send, &b, Op::GrantRevoke, stall).await;
                    }
                }
                Err(refusal) => {
                    send_refusal(&mut send, Some(Op::GrantRevoke), refusal, stall).await
                }
            }
        }
        RequestMeta::Ping(_) => {
            let resp = PingResponseMeta {
                v: PROTOCOL_VERSION,
                status: 200,
                remote: Some(inner.app.remote_state()),
                enrolled_fingerprint: Some(edge.fingerprint.clone()),
                origin_version: Some(inner.app.origin_version()),
                error: None,
                retry_after: None,
            };
            match encode(&resp, Op::Ping) {
                Some(b) => send_complete(&mut send, &b, Op::Ping, stall).await,
                // An invalid origin_version is an app bug; never send it.
                None => {
                    let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
                }
            }
        }
    }
}

fn remote_refusal(state: RemoteState) -> Option<Refusal> {
    match state {
        RemoteState::On => None,
        RemoteState::Off => Some(ErrorCode::RemoteDisabled.into()),
        RemoteState::Stale => Some(ErrorCode::EnrollmentStale.into()),
        RemoteState::Paused => Some(ErrorCode::AuditUnavailable.into()),
    }
}

/// Assertion checks of §4.1 step 4 beyond edge-assert's own.
fn verify_assertion(
    edge: &EnrolledEdge,
    started_at: i64,
    m: &McpPostMeta,
    body: &[u8],
) -> Option<VerifiedGrant> {
    let now = unix_now();
    let claims = edge
        .verifier
        .verify(
            &m.assertion,
            edge_assert::RequestBinding {
                method: "POST",
                path: MCP_PATH,
                body,
            },
            now,
        )
        .ok()?;
    if claims.sub != edge.enrollment.sub {
        return None;
    }
    let mut scope = claims.scope.clone();
    scope.sort();
    if scope != edge.scopes_sorted {
        return None;
    }
    if claims.iat < started_at - timing::SKEW_SECS {
        return None;
    }
    Some(VerifiedGrant {
        grant_id: claims.grant_id,
        client_id: claims.client_id,
        sub: claims.sub,
        scope: claims.scope,
        resource_scope: claims.resource_scope,
        gen: claims.gen,
        iat: claims.iat,
        exp: claims.exp,
    })
}

impl<A: OriginApp> Inner<A> {
    fn rate_ok(&self, grant: &str) -> Result<(), u16> {
        let now = unix_now();
        let mut map = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() > 256 {
            map.retain(|_, (start, _)| now - *start < 60);
        }
        let entry = map.entry(grant.to_owned()).or_insert((now, 0));
        if now - entry.0 >= 60 {
            *entry = (now, 0);
        }
        if entry.1 >= self.config.max_requests_per_grant_per_minute {
            return Err((60 - (now - entry.0)).clamp(1, 60) as u16);
        }
        entry.1 += 1;
        Ok(())
    }

    fn acquire(self: &Arc<Self>, grant: &str) -> Option<(OwnedSemaphorePermit, GrantSlot<A>)> {
        let global = self.mcp_slots.clone().try_acquire_owned().ok()?;
        let mut map = self.per_grant.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(grant.to_owned()).or_insert(0);
        if *n >= self.config.max_in_flight_per_grant {
            return None;
        }
        *n += 1;
        Some((
            global,
            GrantSlot {
                inner: self.clone(),
                grant: grant.to_owned(),
            },
        ))
    }
}

async fn mcp_post<A: OriginApp>(
    inner: &Arc<Inner<A>>,
    edge: &EnrolledEdge,
    mut send: SendStream,
    m: McpPostMeta,
    body: Vec<u8>,
    cancel: CancellationToken,
) {
    let stall = inner.config.write_stall;
    let refuse = |r: Refusal| (Some(Op::McpPost), r);
    let deadline = Instant::now() + Duration::from_millis(m.deadline_ms as u64);
    let checks = (|| {
        if let Some(r) = remote_refusal(inner.app.remote_state()) {
            return Err(refuse(r));
        }
        let grant = verify_assertion(edge, inner.config.started_at_unix, &m, &body)
            .ok_or(refuse(ErrorCode::AssertionInvalid.into()))?;
        if let Err(secs) = inner.rate_ok(&grant.grant_id) {
            return Err(refuse(Refusal::with_retry_after(ErrorCode::Busy, secs)));
        }
        let slots = inner
            .acquire(&grant.grant_id)
            .ok_or(refuse(Refusal::with_retry_after(
                ErrorCode::Busy,
                inner.config.busy_retry_after,
            )))?;
        Ok((grant, slots))
    })();
    let (grant, _slots) = match checks {
        Ok(v) => v,
        Err((op, r)) => return send_refusal(&mut send, op, r, stall).await,
    };
    let req = McpRequest {
        grant,
        accept: m.accept,
        mcp_protocol_version: m.mcp_protocol_version,
        request_id: m.request_id,
        body: Bytes::from(body),
        deadline,
        cancel: cancel.clone(),
    };
    // Deadline also cancels the app's out-of-band work.
    let deadline_task = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => cancel.cancel(),
                _ = cancel.cancelled() => {}
            }
        })
    };
    struct AbortOnDrop(tokio::task::JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _deadline_task = AbortOnDrop(deadline_task);

    let response = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            if Instant::now() >= deadline {
                send_refusal(&mut send, Some(Op::McpPost), ErrorCode::Deadline.into(), stall).await;
            } else {
                let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
            }
            return;
        }
        r = inner.app.mcp_post(req) => r,
    };
    let response = match response {
        Ok(r) => r,
        Err(refusal) => return send_refusal(&mut send, Some(Op::McpPost), refusal, stall).await,
    };
    stream_response(&mut send, response, deadline, &cancel, stall).await;
}

/// Write an app response: meta, chunks (≤ 16 KiB, ≤ 1 MiB total), terminator,
/// FIN. Any violation, stall, deadline or cancellation resets the stream.
async fn stream_response(
    send: &mut SendStream,
    response: McpResponse,
    deadline: Instant,
    cancel: &CancellationToken,
    stall: Duration,
) {
    let abort = |send: &mut SendStream| {
        let _ = send.reset(VarInt::from_u32(RESET_ABORTED));
    };
    let meta = McpPostResponseMeta {
        v: PROTOCOL_VERSION,
        status: response.status,
        content_type: response.content_type,
        error: None,
        retry_after: None,
    };
    let Some(meta_bytes) = encode(&meta, Op::McpPost) else {
        return abort(send);
    };
    // A full body over the cap is refused before anything is written.
    if matches!(&response.body, Body::Full(b) if b.len() > limits::MCP_RESPONSE) {
        return abort(send);
    }
    let write_deadline = |now: Instant| (now + stall).min(deadline);
    macro_rules! write_or_abort {
        ($bytes:expr, $cap:expr) => {{
            let r = tokio::select! {
                _ = cancel.cancelled() => None,
                r = timeout_at(write_deadline(Instant::now()), frame::write_field(send, $bytes, $cap)) => Some(r),
            };
            if !matches!(r, Some(Ok(Ok(())))) {
                return abort(send);
            }
        }};
    }
    write_or_abort!(&meta_bytes, limits::RESPONSE_META);
    let mut total = 0usize;
    let mut write_bytes = |bytes: Bytes| {
        total += bytes.len();
        (total <= limits::MCP_RESPONSE).then_some(bytes)
    };
    match response.body {
        Body::Empty => {}
        Body::Full(bytes) => {
            let Some(bytes) = write_bytes(bytes) else {
                return abort(send);
            };
            for chunk in bytes.chunks(limits::CHUNK) {
                write_or_abort!(chunk, limits::CHUNK);
            }
        }
        Body::Stream(mut stream) => loop {
            let next = tokio::select! {
                _ = cancel.cancelled() => return abort(send),
                _ = tokio::time::sleep_until(deadline) => return abort(send),
                n = stream.next() => n,
            };
            match next {
                None => break,
                Some(Err(_)) => return abort(send),
                Some(Ok(bytes)) => {
                    if bytes.is_empty() {
                        continue;
                    }
                    let Some(bytes) = write_bytes(bytes) else {
                        return abort(send);
                    };
                    for chunk in bytes.chunks(limits::CHUNK) {
                        write_or_abort!(chunk, limits::CHUNK);
                    }
                }
            }
        },
    }
    write_or_abort!(&[], 0);
    if send.finish().is_err() {
        abort(send);
    }
}

async fn consent<A: OriginApp>(
    inner: &Arc<Inner<A>>,
    edge: &EnrolledEdge,
    mut send: SendStream,
    m: ConsentRequestMeta,
    cancel: CancellationToken,
) {
    let stall = inner.config.write_stall;
    if let Some(r) = remote_refusal(inner.app.remote_state()) {
        return send_refusal(&mut send, Some(Op::ConsentRequest), r, stall).await;
    }
    let now = unix_now();
    let max_end = now + timing::CONSENT.as_secs() as i64 + timing::SKEW_SECS;
    if (m.expires_at as i64) <= now || (m.expires_at as i64) > max_end {
        return send_refusal(
            &mut send,
            Some(Op::ConsentRequest),
            ErrorCode::BadRequest.into(),
            stall,
        )
        .await;
    }
    let Ok(_slot) = inner.consent_slots.clone().try_acquire_owned() else {
        return send_refusal(
            &mut send,
            Some(Op::ConsentRequest),
            ErrorCode::ConsentBusy.into(),
            stall,
        )
        .await;
    };
    let expires = Instant::now() + Duration::from_secs((m.expires_at as i64 - now) as u64);
    let binding = ApprovalBinding {
        origin_id: inner.key.public(),
        edge_id: edge.edge_id,
        issuer: edge.enrollment.iss.clone(),
        backend: edge.enrollment.aud.clone(),
        tx: m.tx.clone(),
        grant_id: m.grant_id.clone(),
        nonce: m.nonce.clone(),
        client_id: m.client_id.clone(),
        max_lifetime_secs: m.max_lifetime_secs,
    };
    // Expiry cancels the prompt like an edge cancel does.
    let expiry = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep_until(expires) => cancel.cancel(),
                _ = cancel.cancelled() => {}
            }
        })
    };
    let responder =
        ConsentResponder::new(m, binding, inner.key.clone(), send, cancel.clone(), expires);
    // The app must finish shortly after cancellation; bound it regardless.
    let grace = expires + timing::CHUNK_IDLE + crate::CONSENT_DELIVERY;
    let _ = timeout_at(grace, inner.app.consent_request(responder)).await;
    expiry.abort();
}
