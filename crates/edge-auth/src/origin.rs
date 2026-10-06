//! Port to the origin of a `consent = "origin"` backend (PHASE4.md §3, §5).
//!
//! `edge-auth` stays transport-free: the gateway implements [`OriginPort`]
//! over the iroh tunnel and does every cryptographic check of the origin's
//! answer (signature, binding, lifetime) before it reports
//! [`ConsentOutcome::Approved`]. This crate only drives the owner-facing state
//! machine and issues codes for approvals the port vouches for.

use serde_json::Value;
use std::{future::Future, pin::Pin};

/// What the edge sends the origin for one consent attempt (§3.3). Nothing from
/// the browser (IP, user agent, cookies) is included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentAsk {
    /// Route id.
    pub backend: String,
    /// Pending-request id (bound into the approval).
    pub tx: String,
    /// The grant id the edge will create (`g_` + random).
    pub grant_id: String,
    /// 32 random bytes, base64url, echoed in the approval.
    pub nonce: String,
    /// 6 Crockford base32 characters the owner types in the app.
    pub pairing_code: String,
    pub client_id: String,
    /// Self-reported by the OAuth client (control characters already stripped).
    pub client_name: String,
    pub client_registered_at: u64,
    /// Host of the redirect URI only.
    pub redirect_host: String,
    pub requested_at: u64,
    pub scopes: Vec<String>,
    /// The route's grant lifetime (the most the app may approve).
    pub max_lifetime_secs: u64,
    pub expires_at: u64,
}

/// The origin's answer, already verified by the port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentOutcome {
    /// A valid signed approval. `resource_scope` is the approved scope object
    /// (goes into every assertion), `lifetime_secs` ≤ the route maximum.
    Approved {
        resource_scope: Value,
        lifetime_secs: u64,
        /// The compact signed approval, stored on the grant as evidence.
        approval: String,
    },
    /// A valid signed deny.
    Denied,
    /// No decision before the deadline.
    Timeout,
    /// The origin is showing another prompt (`consent_busy`).
    Busy,
    /// Dial/stream failure, a refusal, or an answer that failed verification
    /// (never treated as an approval). The reason is a fixed machine string
    /// such as `origin_offline` or `approval_invalid`.
    Unreachable(&'static str),
}

/// Why the edge ended a grant (sent to the origin as `grant_revoke.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevokeReason {
    /// The owner, at `/owner`.
    Owner,
    /// The client (RFC 7009 `/revoke`, or a code exchange that failed).
    Client,
    /// Refresh-token or code replay.
    Replay,
    /// The absolute lifetime passed (or the code was never exchanged).
    Expired,
}

/// Enrollment and status of one origin backend, for the owner page (§1.2,
/// §1.3). All values are public identifiers; none is a secret.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginPanel {
    pub backend: String,
    pub display_name: String,
    /// `mcp-edge-enroll:1:...`, to paste into the app.
    pub enrollment: String,
    /// `XXXX-XXXX-XXXX-XXXX`, shown on both sides.
    pub fingerprint: String,
    pub edge_id: String,
    pub assertion_key: String,
    pub issuer: String,
    pub owner_id: String,
    pub scopes: Vec<String>,
    /// The configured origin EndpointId (64 hex).
    pub origin_id: String,
    /// The same as `first 8 … last 4`, for comparison with the app.
    pub origin_short: String,
    /// Last known reachability / enrollment state, plain language.
    pub status: String,
}

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Implemented by the gateway for every `consent = "origin"` backend.
pub trait OriginPort: Send + Sync {
    /// Ask the origin's owner (≤ `expires_at`). Dropping the future cancels
    /// the request at the origin.
    fn consent(&self, ask: ConsentAsk) -> BoxFuture<ConsentOutcome>;

    /// Best-effort notice that the edge ended a grant (`gen` = the value its
    /// assertions carried). Must not block.
    fn revoked(&self, backend: &str, grant_id: &str, gen: u64, reason: RevokeReason);

    /// Owner-page panels for the origin backends.
    fn panels(&self) -> Vec<OriginPanel>;
}
