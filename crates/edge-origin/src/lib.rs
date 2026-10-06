//! Embeddable origin side of `mcp-edge/1` (PHASE4.md §2, §3.4, §4.1).
//!
//! Register [`OriginHandler`] on an iroh `Router` for [`edge_tunnel::ALPN`]
//! and implement [`OriginApp`]. The handler:
//!
//! 1. admits only the enrolled edge EndpointId (else closes with
//!    `peer_not_admitted`), closes with `remote_disabled` / `enrollment_stale`
//!    when the app says so, caps admitted connections (2) and streams per
//!    connection (8);
//! 2. reads and validates every frame within the intake deadline (caps checked
//!    before allocation, no trailing bytes);
//! 3. verifies the `Edge-Assertion` of every `mcp_post` (signature, `iss`,
//!    `aud`, lifetime, `req` over the exact `POST /mcp` body, `jti` replay,
//!    `sub`, `scope`, `iat` not before process start);
//! 4. enforces the origin's in-flight and per-grant limits;
//! 5. dispatches to the app (one method per operation) with a cancellation
//!    token that fires when the edge stops the stream, the deadline passes or
//!    the connection ends;
//! 6. streams the app's response within the size/idle limits, and maps
//!    refusals to the spec's error codes.
//!
//! The app owns grant records, consent UI and MCP. Nothing here is specific to
//! Wiskit.
#![forbid(unsafe_code)]

mod consent;
mod handler;

pub use consent::{ConsentError, ConsentResponder};
pub use edge_tunnel;
pub use edge_tunnel::{
    approval::{self, ApprovalBinding, ApprovalClaims, ApprovalError, Decision, ResourceScope},
    enrollment::{Enrollment, EnrollmentError},
    meta::{
        Accept, ConsentRequestMeta, ContentType, GrantRef, GrantRevokeMeta, GrantState,
        GrantSyncEntry, McpProtocolVersion, RemoteState, RevokeReason,
    },
    CloseCode, ErrorCode, ALPN,
};
pub use handler::{OriginConfig, OriginHandler};
pub use tokio_util::sync::CancellationToken;

use bytes::Bytes;
use futures_util::Stream;
use std::{future::Future, pin::Pin, time::Duration};

/// A refusal at transport/authorization level (§2.7). The handler sends it as
/// `{status: code.status(), error: code, retry_after}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: ErrorCode,
    /// 1..=300 seconds; becomes `Retry-After` at the edge.
    pub retry_after: Option<u16>,
}

impl Refusal {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            retry_after: None,
        }
    }

    pub fn with_retry_after(code: ErrorCode, secs: u16) -> Self {
        Self {
            code,
            retry_after: Some(secs.clamp(1, 300)),
        }
    }
}

impl From<ErrorCode> for Refusal {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

/// Claims of the verified `Edge-Assertion`. Identity and grant id come from
/// here; what the grant *allows* must come from the app's own record (§4.2),
/// never from `resource_scope`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGrant {
    pub grant_id: String,
    pub client_id: String,
    pub sub: String,
    pub scope: Vec<String>,
    /// As signed by the edge (the approved scope); compare with the record.
    pub resource_scope: serde_json::Value,
    pub gen: u64,
    pub iat: i64,
    pub exp: i64,
}

/// One verified `mcp_post`.
#[derive(Debug)]
pub struct McpRequest {
    pub grant: VerifiedGrant,
    pub accept: Accept,
    pub mcp_protocol_version: Option<McpProtocolVersion>,
    /// Non-secret correlation id (logs only).
    pub request_id: String,
    /// The exact JSON-RPC body the assertion was bound to.
    pub body: Bytes,
    /// When the edge stops waiting (`deadline_ms` from intake).
    pub deadline: tokio::time::Instant,
    /// Fires when the edge stops the stream (client disconnected), the
    /// deadline passes, the connection ends or the handler shuts down. The
    /// handler also drops the app's future/stream then; the token is for work
    /// the app runs elsewhere (e.g. a WebView bridge request).
    pub cancel: CancellationToken,
}

/// The app aborted a response stream; the handler resets the QUIC stream, so
/// the edge reports a truncated response (never a fabricated success).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyAborted;

/// A streamed response body.
pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, BodyAborted>> + Send>>;

/// Response body. The handler splits it into ≤ 16 KiB chunks and enforces the
/// 1 MiB total (exceeding it resets the stream).
pub enum Body {
    Empty,
    Full(Bytes),
    Stream(BodyStream),
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Body::Empty => f.write_str("Body::Empty"),
            Body::Full(b) => write!(f, "Body::Full({} bytes)", b.len()),
            Body::Stream(_) => f.write_str("Body::Stream"),
        }
    }
}

/// An MCP-level answer (status 200/202/4xx/5xx with a JSON-RPC body). MCP
/// errors are ordinary bodies here, not [`Refusal`]s.
#[derive(Debug)]
pub struct McpResponse {
    /// One of 200, 202, 400, 401, 403, 404, 413, 429, 500, 503, 504. Any other
    /// value is an app bug: the handler resets the stream.
    pub status: u16,
    /// `None` only with 202.
    pub content_type: Option<ContentType>,
    pub body: Body,
}

impl McpResponse {
    /// `200 application/json`.
    pub fn json(body: impl Into<Bytes>) -> Self {
        Self {
            status: 200,
            content_type: Some(ContentType::Json),
            body: Body::Full(body.into()),
        }
    }

    /// `202` without a body (notifications).
    pub fn accepted() -> Self {
        Self {
            status: 202,
            content_type: None,
            body: Body::Empty,
        }
    }

    /// `200 text/event-stream`, streamed as produced.
    pub fn event_stream(stream: BodyStream) -> Self {
        Self {
            status: 200,
            content_type: Some(ContentType::EventStream),
            body: Body::Stream(stream),
        }
    }
}

/// The app side of the origin: one method per operation.
///
/// Implement with `async fn` in the impl block; the futures must be `Send`.
pub trait OriginApp: Send + Sync + 'static {
    /// Current remote-access state (§4.6), read synchronously at accept time
    /// and per request. `Off` closes new connections with `remote_disabled`,
    /// `Stale` with `enrollment_stale`; `Paused` admits the connection but
    /// refuses `mcp_post` and `consent_request` with `audit_unavailable`.
    fn remote_state(&self) -> RemoteState;

    /// Version string reported by `ping` (≤ 64 printable chars).
    fn origin_version(&self) -> String;

    /// A verified MCP POST. Steps 5–8, 10, 11 of §4.1 (grant record, scope,
    /// audit, context from the record, broker, re-check before emitting) are
    /// the app's. Return `Err` for transport/authorization refusals
    /// (`unknown_grant`, `grant_revoked`, `scope_mismatch`, `origin_locked`,
    /// `audit_unavailable`, ...).
    fn mcp_post(
        &self,
        req: McpRequest,
    ) -> impl Future<Output = Result<McpResponse, Refusal>> + Send;

    /// A consent request (§3.4). The app shows its prompt and answers through
    /// the responder (approve / deny / refuse). Write the grant record before
    /// calling [`ConsentResponder::approve`] and drop it if that returns
    /// `Err`. Returning without answering closes the stream without a decision
    /// (the edge shows "no decision"). Watch [`ConsentResponder::cancelled`]:
    /// it fires when the edge cancels or `expires_at` passes.
    fn consent_request(&self, responder: ConsentResponder) -> impl Future<Output = ()> + Send;

    /// Report the state of each grant the edge believes is active. Grants the
    /// app omits are reported `unknown` (the edge then revokes them).
    fn grant_sync(
        &self,
        grants: Vec<GrantRef>,
    ) -> impl Future<Output = Result<Vec<GrantSyncEntry>, Refusal>> + Send;

    /// The edge ended a grant: tombstone it and cancel its in-flight work.
    fn grant_revoke(
        &self,
        revoke: GrantRevokeMeta,
    ) -> impl Future<Output = Result<(), Refusal>> + Send;
}

/// Unix seconds now.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Default delivery-confirmation wait after writing a consent answer.
pub(crate) const CONSENT_DELIVERY: Duration = Duration::from_secs(5);
