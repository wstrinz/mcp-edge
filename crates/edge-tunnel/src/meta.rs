//! Request and response metadata for every operation (PHASE4.md §2.4, §2.5,
//! §3.3). All objects use `deny_unknown_fields`; `validate()` enforces the
//! spec's bounds. Parsing never trusts the peer: every received object goes
//! through [`parse_request_meta`] or `parse_response::<T>` before use.

use crate::{codes::ErrorCode, ids, limits, timing, Op, PROTOCOL_VERSION};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;

/// Why metadata was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    /// `v` is an integer other than 1 (→ `version_unsupported`).
    VersionUnsupported,
    /// Anything else (→ `bad_request`). The text names the field, never its value.
    Invalid(&'static str),
}

impl fmt::Display for MetaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetaError::VersionUnsupported => f.write_str("unsupported protocol version"),
            MetaError::Invalid(what) => write!(f, "invalid metadata: {what}"),
        }
    }
}
impl std::error::Error for MetaError {}

impl MetaError {
    pub fn code(self) -> ErrorCode {
        match self {
            MetaError::VersionUnsupported => ErrorCode::VersionUnsupported,
            MetaError::Invalid(_) => ErrorCode::BadRequest,
        }
    }
}

fn check(ok: bool, what: &'static str) -> Result<(), MetaError> {
    if ok {
        Ok(())
    } else {
        Err(MetaError::Invalid(what))
    }
}

fn check_v(v: u8) -> Result<(), MetaError> {
    if v == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(MetaError::VersionUnsupported)
    }
}

// ---------------------------------------------------------------- operations

impl Op {
    /// Request body cap (§2.3). Control ops carry no body.
    pub fn body_cap(self) -> usize {
        match self {
            Op::McpPost => limits::MCP_BODY,
            _ => 0,
        }
    }

    /// Cap of the response metadata field. For `mcp_post` the metadata is
    /// small (2 KiB) and the payload follows in chunks; a control op's whole
    /// response is its metadata object, bounded by the op's response cap.
    pub fn response_meta_cap(self) -> usize {
        match self {
            Op::McpPost => limits::RESPONSE_META,
            Op::ConsentRequest => limits::CONSENT_RESPONSE,
            Op::GrantSync => limits::GRANT_SYNC_RESPONSE,
            Op::GrantRevoke => limits::GRANT_REVOKE_RESPONSE,
            Op::Ping => limits::PING_RESPONSE,
        }
    }

    /// Cap of the response chunks (sum). Zero for control ops: their response
    /// is the metadata followed directly by the terminator.
    pub fn response_body_cap(self) -> usize {
        match self {
            Op::McpPost => limits::MCP_RESPONSE,
            _ => 0,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Op::McpPost => "mcp_post",
            Op::ConsentRequest => "consent_request",
            Op::GrantSync => "grant_sync",
            Op::GrantRevoke => "grant_revoke",
            Op::Ping => "ping",
        }
    }
}

// ---------------------------------------------------------------- requests

/// `accept`, derived by the edge from the client's `Accept` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accept {
    Json,
    JsonOrSse,
}

/// MCP protocol versions the edge forwards (as an enum, never a free string).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpProtocolVersion {
    #[serde(rename = "2025-03-26")]
    V2025_03_26,
    #[serde(rename = "2025-06-18")]
    V2025_06_18,
    #[serde(rename = "2025-11-25")]
    V2025_11_25,
}

impl McpProtocolVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            McpProtocolVersion::V2025_03_26 => "2025-03-26",
            McpProtocolVersion::V2025_06_18 => "2025-06-18",
            McpProtocolVersion::V2025_11_25 => "2025-11-25",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "2025-03-26" => McpProtocolVersion::V2025_03_26,
            "2025-06-18" => McpProtocolVersion::V2025_06_18,
            "2025-11-25" => McpProtocolVersion::V2025_11_25,
            _ => return None,
        })
    }
}

/// The only path `mcp_post` may carry.
pub const MCP_PATH: &str = "/mcp";
/// The only request content type.
pub const JSON: &str = "application/json";

/// `mcp_post` request metadata (§2.4). There is no header map, URL, host,
/// port, method, cookie or `Authorization` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpPostMeta {
    pub v: u8,
    pub path: String,
    pub content_type: String,
    pub accept: Accept,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_protocol_version: Option<McpProtocolVersion>,
    pub assertion: String,
    pub request_id: String,
    pub deadline_ms: u32,
}

impl McpPostMeta {
    pub fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check(self.path == MCP_PATH, "path")?;
        check(self.content_type == JSON, "content_type")?;
        check(
            !self.assertion.is_empty()
                && self.assertion.len() <= limits::ASSERTION
                && self.assertion.is_ascii(),
            "assertion",
        )?;
        check(
            ids::b64url_fixed::<16>(&self.request_id).is_some(),
            "request_id",
        )?;
        check(
            (timing::DEADLINE_MS_MIN..=timing::DEADLINE_MS_MAX).contains(&self.deadline_ms),
            "deadline_ms",
        )
    }
}

/// `consent_request` metadata (§3.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestMeta {
    pub v: u8,
    /// Edge pending-transaction id, `[A-Za-z0-9_-]{1,32}`.
    pub tx: String,
    /// Shared grant id: `g_` + `[A-Za-z0-9_-]`, at most 40 bytes.
    pub grant_id: String,
    /// 32 random bytes, base64url (echoed in the approval).
    pub nonce: String,
    /// 6 Crockford base32 characters; the owner types it in the app.
    pub pairing_code: String,
    pub client_id: String,
    /// Self-reported by the OAuth client; no control characters, ≤ 80 chars.
    pub client_name: String,
    pub client_registered_at: u64,
    /// Host only (`claude.ai`).
    pub redirect_host: String,
    pub requested_at: u64,
    pub scopes: Vec<String>,
    pub max_lifetime_secs: u64,
    pub expires_at: u64,
}

/// Longest grant lifetime the wire accepts (the route's `grant_lifetime_secs`
/// is the real ceiling; this only bounds the field).
pub const MAX_GRANT_LIFETIME_SECS: u64 = 30 * 24 * 3600;
/// Shortest grant lifetime an approval may carry (§3.5).
pub const MIN_GRANT_LIFETIME_SECS: u64 = 300;

pub(crate) fn valid_grant_id(s: &str) -> bool {
    s.len() <= 40 && s.starts_with("g_") && ids::is_token(&s[2..], 1, 38)
}

pub(crate) fn valid_scope(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'.' | b'_' | b'-')
        })
}

pub(crate) fn valid_pairing_code(s: &str) -> bool {
    s.len() == 6 && s.bytes().all(|c| ids::CROCKFORD.contains(&c))
}

fn valid_host(s: &str) -> bool {
    (1..=253).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-')
        && !s.starts_with('.')
        && !s.starts_with('-')
}

impl ConsentRequestMeta {
    pub fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check(ids::is_token(&self.tx, 1, 32), "tx")?;
        check(valid_grant_id(&self.grant_id), "grant_id")?;
        check(ids::b64url_fixed::<32>(&self.nonce).is_some(), "nonce")?;
        check(valid_pairing_code(&self.pairing_code), "pairing_code")?;
        check(ids::is_display_text(&self.client_id, 64), "client_id")?;
        check(self.client_id.len() <= 64, "client_id")?;
        check(ids::is_display_text(&self.client_name, 80), "client_name")?;
        check(valid_host(&self.redirect_host), "redirect_host")?;
        check(
            (1..=4).contains(&self.scopes.len()) && self.scopes.iter().all(|s| valid_scope(s)),
            "scopes",
        )?;
        check(
            (MIN_GRANT_LIFETIME_SECS..=MAX_GRANT_LIFETIME_SECS).contains(&self.max_lifetime_secs),
            "max_lifetime_secs",
        )?;
        check(
            self.expires_at > self.requested_at
                && self.expires_at - self.requested_at <= timing::CONSENT.as_secs(),
            "expires_at",
        )
    }
}

/// One grant in `grant_sync`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRef {
    pub grant_id: String,
    pub gen: u64,
}

/// `grant_sync` request: the edge's active grants for the route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSyncMeta {
    pub v: u8,
    pub grants: Vec<GrantRef>,
}

impl GrantSyncMeta {
    pub fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check(self.grants.len() <= limits::GRANT_SYNC_ENTRIES, "grants")?;
        let mut seen = std::collections::BTreeSet::new();
        for g in &self.grants {
            check(valid_grant_id(&g.grant_id), "grants.grant_id")?;
            check(seen.insert(g.grant_id.as_str()), "grants (duplicate)")?;
        }
        Ok(())
    }
}

/// Why the edge ended a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevokeReason {
    Owner,
    Client,
    Replay,
    Expired,
}

/// `grant_revoke` request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevokeMeta {
    pub v: u8,
    pub grant_id: String,
    pub gen: u64,
    pub reason: RevokeReason,
}

impl GrantRevokeMeta {
    pub fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check(valid_grant_id(&self.grant_id), "grant_id")
    }
}

/// `ping` request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingMeta {
    pub v: u8,
}

impl PingMeta {
    pub fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)
    }
}

/// Request metadata, tagged by `op`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RequestMeta {
    McpPost(McpPostMeta),
    ConsentRequest(ConsentRequestMeta),
    GrantSync(GrantSyncMeta),
    GrantRevoke(GrantRevokeMeta),
    Ping(PingMeta),
}

impl RequestMeta {
    pub fn op(&self) -> Op {
        match self {
            RequestMeta::McpPost(_) => Op::McpPost,
            RequestMeta::ConsentRequest(_) => Op::ConsentRequest,
            RequestMeta::GrantSync(_) => Op::GrantSync,
            RequestMeta::GrantRevoke(_) => Op::GrantRevoke,
            RequestMeta::Ping(_) => Op::Ping,
        }
    }

    pub fn validate(&self) -> Result<(), MetaError> {
        match self {
            RequestMeta::McpPost(m) => m.validate(),
            RequestMeta::ConsentRequest(m) => m.validate(),
            RequestMeta::GrantSync(m) => m.validate(),
            RequestMeta::GrantRevoke(m) => m.validate(),
            RequestMeta::Ping(m) => m.validate(),
        }
    }

    /// Validate and encode (sender side). Refuses metadata over 12 KiB.
    pub fn encode(&self) -> Result<Vec<u8>, MetaError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| MetaError::Invalid("encode"))?;
        check(bytes.len() <= limits::REQUEST_META, "size")?;
        Ok(bytes)
    }
}

#[derive(Deserialize)]
struct VersionProbe {
    v: Option<serde_json::Value>,
}

fn probe_version(bytes: &[u8]) -> Result<(), MetaError> {
    let probe: VersionProbe =
        serde_json::from_slice(bytes).map_err(|_| MetaError::Invalid("json"))?;
    match probe.v {
        Some(serde_json::Value::Number(n)) => match n.as_u64() {
            Some(1) => Ok(()),
            Some(_) => Err(MetaError::VersionUnsupported),
            None => Err(MetaError::Invalid("v")),
        },
        _ => Err(MetaError::Invalid("v")),
    }
}

/// Parse and validate request metadata (receiver side). A `v` other than 1 is
/// reported as [`MetaError::VersionUnsupported`] before the strict parse, so a
/// future version with new fields gets the right error.
pub fn parse_request_meta(bytes: &[u8]) -> Result<RequestMeta, MetaError> {
    check(bytes.len() <= limits::REQUEST_META, "size")?;
    probe_version(bytes)?;
    let meta: RequestMeta =
        serde_json::from_slice(bytes).map_err(|_| MetaError::Invalid("schema"))?;
    meta.validate()?;
    Ok(meta)
}

// ---------------------------------------------------------------- responses

/// Response content type for `mcp_post`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    #[serde(rename = "application/json")]
    Json,
    #[serde(rename = "text/event-stream")]
    EventStream,
}

impl ContentType {
    pub fn as_str(self) -> &'static str {
        match self {
            ContentType::Json => "application/json",
            ContentType::EventStream => "text/event-stream",
        }
    }
}

/// Statuses an `mcp_post` response may carry; anything else is a transport
/// error at the edge.
pub const MCP_STATUSES: [u16; 11] = [200, 202, 400, 401, 403, 404, 413, 429, 500, 503, 504];

fn check_refusal(
    status: u16,
    error: Option<ErrorCode>,
    retry_after: Option<u16>,
) -> Result<(), MetaError> {
    if let Some(e) = error {
        check(status == e.status(), "status (does not match error)")?;
    }
    if let Some(r) = retry_after {
        check((1..=300).contains(&r), "retry_after")?;
    }
    Ok(())
}

/// Common shape of every response object.
pub trait ResponseMeta: Serialize + DeserializeOwned {
    fn validate(&self) -> Result<(), MetaError>;
}

/// `mcp_post` response metadata (§2.4). A refusal (`error` present) is followed
/// directly by the terminator: it carries no chunks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpPostResponseMeta {
    pub v: u8,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<ContentType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u16>,
}

impl ResponseMeta for McpPostResponseMeta {
    fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check(MCP_STATUSES.contains(&self.status), "status")?;
        check(
            self.content_type.is_some() || self.status == 202,
            "content_type (absent only with 202)",
        )?;
        check(
            self.error.is_none() || self.content_type == Some(ContentType::Json),
            "content_type (refusals are application/json)",
        )?;
        check_refusal(self.status, self.error, self.retry_after)
    }
}

/// `consent_request` response: `{v, status: 200, approval}` or
/// `{v, status, error}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentResponseMeta {
    pub v: u8,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u16>,
}

fn check_ok_or_error(
    status: u16,
    has_payload: bool,
    error: Option<ErrorCode>,
) -> Result<(), MetaError> {
    match (status, has_payload, error) {
        (200, true, None) => Ok(()),
        (s, false, Some(_)) if s != 200 => Ok(()),
        _ => Err(MetaError::Invalid("status/payload/error combination")),
    }
}

impl ResponseMeta for ConsentResponseMeta {
    fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check_ok_or_error(self.status, self.approval.is_some(), self.error)?;
        if let Some(a) = &self.approval {
            check(
                !a.is_empty() && a.len() <= limits::APPROVAL && a.is_ascii(),
                "approval",
            )?;
        }
        check_refusal(self.status, self.error, self.retry_after)
    }
}

/// Origin-side state of one grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Active,
    Revoked,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSyncEntry {
    pub grant_id: String,
    pub state: GrantState,
}

/// `grant_sync` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantSyncResponseMeta {
    pub v: u8,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grants: Option<Vec<GrantSyncEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u16>,
}

impl ResponseMeta for GrantSyncResponseMeta {
    fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check_ok_or_error(self.status, self.grants.is_some(), self.error)?;
        if let Some(g) = &self.grants {
            check(g.len() <= limits::GRANT_SYNC_ENTRIES, "grants")?;
            check(
                g.iter().all(|e| valid_grant_id(&e.grant_id)),
                "grants.grant_id",
            )?;
        }
        check_refusal(self.status, self.error, self.retry_after)
    }
}

/// `grant_revoke` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRevokeResponseMeta {
    pub v: u8,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u16>,
}

impl ResponseMeta for GrantRevokeResponseMeta {
    fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        check_ok_or_error(self.status, self.error.is_none(), self.error)?;
        check_refusal(self.status, self.error, self.retry_after)
    }
}

/// Remote-access state reported by `ping`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteState {
    On,
    Off,
    Paused,
    Stale,
}

/// `ping` response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingResponseMeta {
    pub v: u8,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u16>,
}

/// Longest `origin_version` string.
pub const MAX_ORIGIN_VERSION: usize = 64;

impl ResponseMeta for PingResponseMeta {
    fn validate(&self) -> Result<(), MetaError> {
        check_v(self.v)?;
        let ok = self.remote.is_some()
            && self.enrolled_fingerprint.is_some()
            && self.origin_version.is_some();
        check_ok_or_error(self.status, ok, self.error)?;
        if let Some(f) = &self.enrolled_fingerprint {
            check(crate::enrollment::is_fingerprint(f), "enrolled_fingerprint")?;
        }
        if let Some(v) = &self.origin_version {
            check(
                ids::is_display_text(v, MAX_ORIGIN_VERSION) && v.len() <= MAX_ORIGIN_VERSION,
                "origin_version",
            )?;
        }
        check_refusal(self.status, self.error, self.retry_after)
    }
}

/// Validate and encode a response object, refusing it above `cap`.
pub fn encode_response<T: ResponseMeta>(meta: &T, cap: usize) -> Result<Vec<u8>, MetaError> {
    meta.validate()?;
    let bytes = serde_json::to_vec(meta).map_err(|_| MetaError::Invalid("encode"))?;
    check(bytes.len() <= cap, "size")?;
    Ok(bytes)
}

/// Parse and validate a response object (edge side).
pub fn parse_response<T: ResponseMeta>(bytes: &[u8]) -> Result<T, MetaError> {
    probe_version(bytes)?;
    let meta: T = serde_json::from_slice(bytes).map_err(|_| MetaError::Invalid("schema"))?;
    meta.validate()?;
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Mutation<T> = (&'static str, Box<dyn Fn(&mut T)>);
    use serde_json::json;

    pub(crate) fn mcp_meta() -> McpPostMeta {
        McpPostMeta {
            v: 1,
            path: "/mcp".into(),
            content_type: "application/json".into(),
            accept: Accept::Json,
            mcp_protocol_version: Some(McpProtocolVersion::V2025_06_18),
            assertion: "a.b".into(),
            request_id: "AAAAAAAAAAAAAAAAAAAAAA".into(),
            deadline_ms: 25_000,
        }
    }

    fn consent_meta() -> ConsentRequestMeta {
        ConsentRequestMeta {
            v: 1,
            tx: "tx_1".into(),
            grant_id: "g_abc".into(),
            nonce: ids::random_b64url::<32>().unwrap(),
            pairing_code: "K7QM2X".into(),
            client_id: "client-1".into(),
            client_name: "Claude".into(),
            client_registered_at: 1_700_000_000,
            redirect_host: "claude.ai".into(),
            requested_at: 1_700_000_100,
            scopes: vec!["wiskit:read".into()],
            max_lifetime_secs: 86_400,
            expires_at: 1_700_000_280,
        }
    }

    #[test]
    fn mcp_post_meta_round_trip_and_tag() {
        let meta = RequestMeta::McpPost(mcp_meta());
        let bytes = meta.encode().unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["op"], "mcp_post");
        assert_eq!(v["mcp_protocol_version"], "2025-06-18");
        assert_eq!(parse_request_meta(&bytes).unwrap(), meta);
    }

    #[test]
    fn unknown_field_op_and_version() {
        let mut v = serde_json::to_value(RequestMeta::McpPost(mcp_meta())).unwrap();
        v["url"] = json!("http://127.0.0.1/");
        assert_eq!(
            parse_request_meta(v.to_string().as_bytes()),
            Err(MetaError::Invalid("schema"))
        );
        for (field, value) in [
            ("headers", json!({"x": "y"})),
            ("authorization", json!("Bearer x")),
            ("host", json!("example.com")),
            ("method", json!("GET")),
        ] {
            let mut v = serde_json::to_value(RequestMeta::McpPost(mcp_meta())).unwrap();
            v[field] = value;
            assert!(
                parse_request_meta(v.to_string().as_bytes()).is_err(),
                "{field}"
            );
        }
        let unknown_op = json!({"v": 1, "op": "authorize_get"});
        assert_eq!(
            parse_request_meta(unknown_op.to_string().as_bytes()),
            Err(MetaError::Invalid("schema"))
        );
        let v2 = json!({"v": 2, "op": "ping", "future": true});
        assert_eq!(
            parse_request_meta(v2.to_string().as_bytes()),
            Err(MetaError::VersionUnsupported)
        );
        for bad in [
            json!({"op": "ping"}),
            json!({"v": "1", "op": "ping"}),
            json!([1]),
        ] {
            assert!(matches!(
                parse_request_meta(bad.to_string().as_bytes()),
                Err(MetaError::Invalid(_))
            ));
        }
        assert!(parse_request_meta(br#"{"v":1,"op":"ping"}"#).is_ok());
        // Duplicate fields are refused by the strict parse.
        assert!(parse_request_meta(br#"{"v":1,"op":"ping","v":1}"#).is_err());
    }

    #[test]
    fn mcp_post_field_rules() {
        let cases: Vec<Mutation<McpPostMeta>> = vec![
            ("path", Box::new(|m| m.path = "/mcp/x".into())),
            ("path", Box::new(|m| m.path = "/MCP".into())),
            (
                "content_type",
                Box::new(|m| m.content_type = "text/plain".into()),
            ),
            ("assertion", Box::new(|m| m.assertion = String::new())),
            (
                "assertion",
                Box::new(|m| m.assertion = "a".repeat(limits::ASSERTION + 1)),
            ),
            ("request_id", Box::new(|m| m.request_id = "short".into())),
            ("deadline_ms", Box::new(|m| m.deadline_ms = 999)),
            ("deadline_ms", Box::new(|m| m.deadline_ms = 25_001)),
        ];
        for (field, mutate) in cases {
            let mut m = mcp_meta();
            mutate(&mut m);
            assert_eq!(m.validate(), Err(MetaError::Invalid(field)));
        }
        let mut m = mcp_meta();
        m.assertion = "a".repeat(limits::ASSERTION);
        m.validate().unwrap();
        // Unknown protocol versions are not a free string.
        let mut v = serde_json::to_value(RequestMeta::McpPost(mcp_meta())).unwrap();
        v["mcp_protocol_version"] = json!("2024-11-05");
        assert!(parse_request_meta(v.to_string().as_bytes()).is_err());
    }

    #[test]
    fn request_meta_size_cap() {
        let mut m = mcp_meta();
        m.assertion = "a".repeat(limits::ASSERTION);
        let bytes = RequestMeta::McpPost(m).encode().unwrap();
        assert!(bytes.len() <= limits::REQUEST_META);
        let mut padded = bytes.clone();
        padded.splice(1..1, std::iter::repeat_n(b' ', limits::REQUEST_META));
        assert_eq!(parse_request_meta(&padded), Err(MetaError::Invalid("size")));
    }

    #[test]
    fn consent_request_rules() {
        consent_meta().validate().unwrap();
        let cases: Vec<Mutation<ConsentRequestMeta>> = vec![
            ("tx", Box::new(|m| m.tx = "x".repeat(33))),
            ("grant_id", Box::new(|m| m.grant_id = "abc".into())),
            (
                "grant_id",
                Box::new(|m| m.grant_id = format!("g_{}", "a".repeat(39))),
            ),
            ("nonce", Box::new(|m| m.nonce = "AAAA".into())),
            (
                "pairing_code",
                Box::new(|m| m.pairing_code = "K7QM2".into()),
            ),
            (
                "pairing_code",
                Box::new(|m| m.pairing_code = "K7QM2I".into()),
            ),
            (
                "pairing_code",
                Box::new(|m| m.pairing_code = "k7qm2x".into()),
            ),
            ("client_id", Box::new(|m| m.client_id = "c".repeat(65))),
            (
                "client_name",
                Box::new(|m| m.client_name = "Claude\u{7}".into()),
            ),
            ("client_name", Box::new(|m| m.client_name = "x".repeat(81))),
            (
                "client_name",
                Box::new(|m| m.client_name = "a\u{202e}b\nc".into()),
            ),
            (
                "redirect_host",
                Box::new(|m| m.redirect_host = "claude.ai/x".into()),
            ),
            (
                "redirect_host",
                Box::new(|m| m.redirect_host = "claude.ai:443".into()),
            ),
            ("scopes", Box::new(|m| m.scopes = vec![])),
            ("scopes", Box::new(|m| m.scopes = vec!["a".into(); 5])),
            ("scopes", Box::new(|m| m.scopes = vec!["Read All".into()])),
            ("max_lifetime_secs", Box::new(|m| m.max_lifetime_secs = 299)),
            ("expires_at", Box::new(|m| m.expires_at = m.requested_at)),
            (
                "expires_at",
                Box::new(|m| m.expires_at = m.requested_at + 181),
            ),
        ];
        for (field, mutate) in cases {
            let mut m = consent_meta();
            mutate(&mut m);
            assert_eq!(m.validate(), Err(MetaError::Invalid(field)), "{field}");
        }
        let mut m = consent_meta();
        m.grant_id = format!("g_{}", "a".repeat(38));
        m.validate().unwrap();
        m.client_name = "x".repeat(80);
        m.validate().unwrap();
    }

    #[test]
    fn grant_sync_and_revoke_rules() {
        let ok = GrantSyncMeta {
            v: 1,
            grants: (0..64)
                .map(|i| GrantRef {
                    grant_id: format!("g_{i}"),
                    gen: 1,
                })
                .collect(),
        };
        ok.validate().unwrap();
        let mut too_many = ok.clone();
        too_many.grants.push(GrantRef {
            grant_id: "g_x".into(),
            gen: 1,
        });
        assert!(too_many.validate().is_err());
        let mut dup = ok.clone();
        dup.grants[1].grant_id = "g_0".into();
        assert!(dup.validate().is_err());
        let r = GrantRevokeMeta {
            v: 1,
            grant_id: "g_1".into(),
            gen: 2,
            reason: RevokeReason::Owner,
        };
        let bytes = RequestMeta::GrantRevoke(r.clone()).encode().unwrap();
        assert_eq!(
            parse_request_meta(&bytes).unwrap(),
            RequestMeta::GrantRevoke(r)
        );
        let bad = json!({"v":1,"op":"grant_revoke","grant_id":"g_1","gen":1,"reason":"because"});
        assert!(parse_request_meta(bad.to_string().as_bytes()).is_err());
    }

    #[test]
    fn mcp_response_rules() {
        let ok = McpPostResponseMeta {
            v: 1,
            status: 200,
            content_type: Some(ContentType::Json),
            error: None,
            retry_after: None,
        };
        let bytes = encode_response(&ok, limits::RESPONSE_META).unwrap();
        assert_eq!(parse_response::<McpPostResponseMeta>(&bytes).unwrap(), ok);
        let accepted = McpPostResponseMeta {
            status: 202,
            content_type: None,
            ..ok.clone()
        };
        accepted.validate().unwrap();
        for bad in [
            McpPostResponseMeta {
                status: 302,
                ..ok.clone()
            },
            McpPostResponseMeta {
                status: 201,
                ..ok.clone()
            },
            McpPostResponseMeta {
                content_type: None,
                ..ok.clone()
            },
            // error/status mismatch
            McpPostResponseMeta {
                status: 200,
                error: Some(ErrorCode::Busy),
                ..ok.clone()
            },
            McpPostResponseMeta {
                status: 429,
                error: Some(ErrorCode::Busy),
                retry_after: Some(0),
                ..ok.clone()
            },
            McpPostResponseMeta {
                status: 429,
                error: Some(ErrorCode::Busy),
                retry_after: Some(301),
                ..ok.clone()
            },
            McpPostResponseMeta {
                status: 429,
                error: Some(ErrorCode::Busy),
                content_type: Some(ContentType::EventStream),
                ..ok.clone()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        McpPostResponseMeta {
            status: 429,
            error: Some(ErrorCode::Busy),
            retry_after: Some(2),
            ..ok.clone()
        }
        .validate()
        .unwrap();
        assert!(parse_response::<McpPostResponseMeta>(
            br#"{"v":1,"status":200,"content_type":"application/json","location":"http://x"}"#
        )
        .is_err());
        assert!(parse_response::<McpPostResponseMeta>(
            br#"{"v":1,"status":200,"content_type":"text/html"}"#
        )
        .is_err());
    }

    #[test]
    fn control_response_rules() {
        let ok = ConsentResponseMeta {
            v: 1,
            status: 200,
            approval: Some("p.s".into()),
            error: None,
            retry_after: None,
        };
        ok.validate().unwrap();
        assert!(ConsentResponseMeta {
            approval: None,
            ..ok.clone()
        }
        .validate()
        .is_err());
        assert!(ConsentResponseMeta {
            approval: Some("x".repeat(limits::APPROVAL + 1)),
            ..ok.clone()
        }
        .validate()
        .is_err());
        ConsentResponseMeta {
            status: 429,
            approval: None,
            error: Some(ErrorCode::ConsentBusy),
            ..ok.clone()
        }
        .validate()
        .unwrap();
        assert!(ConsentResponseMeta {
            status: 200,
            approval: None,
            error: Some(ErrorCode::ConsentBusy),
            ..ok.clone()
        }
        .validate()
        .is_err());
        let ping = PingResponseMeta {
            v: 1,
            status: 200,
            remote: Some(RemoteState::On),
            enrolled_fingerprint: Some("0000-0000-0000-0000".into()),
            origin_version: Some("1.7.0".into()),
            error: None,
            retry_after: None,
        };
        ping.validate().unwrap();
        assert!(PingResponseMeta {
            remote: None,
            ..ping.clone()
        }
        .validate()
        .is_err());
        assert!(PingResponseMeta {
            enrolled_fingerprint: Some("nope".into()),
            ..ping.clone()
        }
        .validate()
        .is_err());
        let revoke = GrantRevokeResponseMeta {
            v: 1,
            status: 200,
            error: None,
            retry_after: None,
        };
        revoke.validate().unwrap();
        assert!(GrantRevokeResponseMeta {
            status: 201,
            ..revoke.clone()
        }
        .validate()
        .is_err());
        let sync = GrantSyncResponseMeta {
            v: 1,
            status: 200,
            grants: Some(vec![GrantSyncEntry {
                grant_id: "g_1".into(),
                state: GrantState::Revoked,
            }]),
            error: None,
            retry_after: None,
        };
        let bytes = encode_response(&sync, limits::GRANT_SYNC_RESPONSE).unwrap();
        assert_eq!(
            parse_response::<GrantSyncResponseMeta>(&bytes).unwrap(),
            sync
        );
        assert!(encode_response(&sync, 10).is_err());
    }

    #[test]
    fn caps_per_op() {
        assert_eq!(Op::McpPost.body_cap(), 64 * 1024);
        assert_eq!(Op::McpPost.response_body_cap(), 1024 * 1024);
        assert_eq!(Op::McpPost.response_meta_cap(), 2 * 1024);
        assert_eq!(Op::ConsentRequest.response_meta_cap(), 4 * 1024);
        assert_eq!(Op::GrantSync.response_meta_cap(), 16 * 1024);
        assert_eq!(Op::GrantRevoke.response_meta_cap(), 1024);
        assert_eq!(Op::Ping.response_meta_cap(), 1024);
        for op in [Op::ConsentRequest, Op::GrantSync, Op::GrantRevoke, Op::Ping] {
            assert_eq!(op.body_cap(), 0);
            assert_eq!(op.response_body_cap(), 0);
        }
    }
}
