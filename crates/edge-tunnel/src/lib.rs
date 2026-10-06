//! Wire protocol for `mcp-edge/1`, the iroh ALPN between `mcp-edge` and a local
//! origin app (PHASE4.md §2), plus the edge-side client.
//!
//! * [`frame`]: `u32` big-endian length-prefixed fields, bounded before
//!   allocation; request ends with FIN (no trailing bytes), response ends with an
//!   explicit zero-length terminator.
//! * [`meta`]: request/response metadata per operation, `deny_unknown_fields`,
//!   validated against the spec's bounds.
//! * [`codes`]: origin error codes, QUIC close codes and their edge mapping (§2.7).
//! * [`approval`]: signed consent approvals (§3.5, D2): signed with the origin's
//!   iroh transport key under the `mcp-edge-approval.v1.` domain prefix.
//! * [`enrollment`]: the `mcp-edge-enroll:1:` string and its fingerprint (§1.3).
//! * [`client`]: [`client::OriginClient`], the edge side (dial exactly one
//!   configured origin, one bidirectional stream per request, fast offline
//!   failure, typed errors).
//!
//! The crate carries no HTTP and no Wiskit logic. See the README for the wire
//! format.
#![forbid(unsafe_code)]

pub mod approval;
pub mod client;
pub mod codes;
pub mod enrollment;
pub mod frame;
pub mod ids;
pub mod meta;

pub use codes::{CloseCode, EdgeFailure, ErrorCode};
/// Re-exported so dependants use exactly the iroh this crate was built against.
pub use iroh;

use std::time::Duration;

/// The five operations on the tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Op {
    McpPost,
    ConsentRequest,
    GrantSync,
    GrantRevoke,
    Ping,
}

/// The ALPN. An incompatible change becomes `mcp-edge/2`.
pub const ALPN: &[u8] = b"mcp-edge/1";
/// In-band protocol version (`v` in every metadata object).
pub const PROTOCOL_VERSION: u8 = 1;

/// Size limits (§2.3). Every length prefix is checked against these before any
/// allocation.
pub mod limits {
    /// Request metadata JSON.
    pub const REQUEST_META: usize = 12 * 1024;
    /// `mcp_post` request body.
    pub const MCP_BODY: usize = 64 * 1024;
    /// `mcp_post` response metadata JSON.
    pub const RESPONSE_META: usize = 2 * 1024;
    /// One response chunk.
    pub const CHUNK: usize = 16 * 1024;
    /// `mcp_post` response total (sum of chunks).
    pub const MCP_RESPONSE: usize = 1024 * 1024;
    /// `Edge-Assertion` carried in `mcp_post` metadata.
    pub const ASSERTION: usize = 8 * 1024;
    /// `consent_request` response (the whole response metadata JSON).
    pub const CONSENT_RESPONSE: usize = 4 * 1024;
    /// `grant_sync` response.
    pub const GRANT_SYNC_RESPONSE: usize = 16 * 1024;
    /// `grant_revoke` response.
    pub const GRANT_REVOKE_RESPONSE: usize = 1024;
    /// `ping` response.
    pub const PING_RESPONSE: usize = 1024;
    /// Compact approval string.
    pub const APPROVAL: usize = 3 * 1024;
    /// Grants per `grant_sync`.
    pub const GRANT_SYNC_ENTRIES: usize = 64;
}

/// Deadlines and policy timings (§2.6, §2.8).
pub mod timing {
    use super::Duration;
    /// Edge: dial (connect + handshake) before fast-fail.
    pub const DIAL: Duration = Duration::from_secs(3);
    /// Edge: how long a failed dial marks the origin offline.
    pub const OFFLINE_BACKOFF: Duration = Duration::from_secs(15);
    /// Edge: wait before the single re-dial after `connection_limit`.
    pub const CONNECTION_LIMIT_RETRY: Duration = Duration::from_secs(1);
    /// Edge: writing the request; origin: reading it (intake).
    pub const REQUEST_IO: Duration = Duration::from_secs(2);
    /// Edge: first response byte.
    pub const FIRST_BYTE: Duration = Duration::from_secs(15);
    /// Both: idle between chunks / write stall.
    pub const CHUNK_IDLE: Duration = Duration::from_secs(5);
    /// Edge: total per `mcp_post` (under the edge's 30 s request deadline).
    pub const TOTAL: Duration = Duration::from_secs(25);
    /// Consent prompt lifetime (`expires_at - requested_at` upper bound).
    pub const CONSENT: Duration = Duration::from_secs(180);
    /// `deadline_ms` bounds.
    pub const DEADLINE_MS_MIN: u32 = 1_000;
    pub const DEADLINE_MS_MAX: u32 = 25_000;
    /// QUIC keep-alive and idle timeout for the edge's cached connection.
    pub const KEEP_ALIVE: Duration = Duration::from_secs(5);
    pub const IDLE_TIMEOUT: Duration = Duration::from_secs(20);
    /// Tolerated clock skew for approvals and assertions.
    pub const SKEW_SECS: i64 = 5;
}

/// QUIC transport settings from §2.2 (8 bidi streams, no uni streams, 64 KiB
/// stream / 256 KiB connection receive windows, 64 KiB send window, 5 s
/// keep-alive, 20 s idle timeout). Intended for the edge's endpoint; an origin
/// that shares an existing endpoint (Wiskit) keeps its own settings and relies
/// on `edge-origin`'s software limits instead.
pub fn transport_config() -> iroh::endpoint::QuicTransportConfig {
    use iroh::endpoint::{QuicTransportConfig, VarInt};
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(8))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(64 * 1024))
        .receive_window(VarInt::from_u32(256 * 1024))
        .send_window(64 * 1024)
        .keep_alive_interval(timing::KEEP_ALIVE)
        .max_idle_timeout(Some(
            VarInt::from_u32(timing::IDLE_TIMEOUT.as_millis() as u32).into(),
        ))
        .build()
}
