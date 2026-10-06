//! OAuth 2.1 authorization server for `mcp-edge`.
//!
//! * RFC 8414 issuer metadata and RFC 9728 protected-resource metadata per backend.
//! * RFC 7591 dynamic registration of public clients with an exact redirect allowlist.
//! * Authorization code + S256 PKCE, bound to client, redirect, challenge and resource.
//! * Owner proof by passkey ([`owner::OwnerProof`]) before every consent decision.
//! * Opaque access (15 min) / rotating refresh tokens stored as SHA-256 hashes;
//!   refresh reuse revokes the whole grant; RFC 7009 revocation; owner grant page.
//!
//! The crate exposes an axum [`router`] plus [`AuthState::authenticate_bearer`]
//! for the gateway. It never logs request bodies, tokens, codes or cookies.
#![forbid(unsafe_code)]
// Handlers return early with a ready `Response` as the error value; boxing it
// would only add allocations on the error path.
#![allow(clippy::result_large_err)]

pub mod config;
pub mod origin;
pub mod owner;
mod pages;
mod store;
pub mod support;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, RawQuery, State},
    http::{
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, COOKIE, LOCATION, ORIGIN, PRAGMA,
            SET_COOKIE,
        },
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use config::{
    AuthConfig, ConsentMode, ACCESS_TTL, CEREMONY_TTL, CODE_TTL, FRESH_PROOF, MIN_ENROLL_CODE_LEN,
    PENDING_TTL, SESSION_TTL,
};
use origin::{ConsentAsk, ConsentOutcome, OriginPort, RevokeReason};
use owner::{CeremonyState, OwnerProof};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::Path as FsPath,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc, Mutex, OnceLock, Weak,
    },
};
use store::{CodeTake, PendingRow, RefreshOutcome, Revoked, Store};
use support::{
    ct_eq, hash_secret, hmac_b64, is_b64url, parse_unique_params, pkce_s256_matches, random_bytes,
    random_id, random_secret, valid_verifier, ClientIp, Clock, LogSink, RateLimiter,
};
use url::Url;

const TX_COOKIE: &str = "__Host-edge_tx";
const CEREMONY_COOKIE: &str = "__Host-edge_cer";
const SESSION_COOKIE: &str = "__Host-edge_sid";
const MAX_CEREMONIES_PER_NET: usize = 4;
/// Live pending authorization requests one client network may hold.
const MAX_PENDING_PER_NET: i64 = 4;
/// Per-network enrollment-code failures are counted in windows of this length.
const ENROLL_LOCK_WINDOW: i64 = 15 * 60;
/// Global enrollment-code failures are counted in windows of this length.
const ENROLL_GLOBAL_WINDOW: i64 = 60 * 60;

#[derive(Default)]
struct EnrollFailures {
    /// network -> (window start, failures)
    per_net: HashMap<Option<std::net::IpAddr>, (i64, u32)>,
    /// (window start, failures)
    global: (i64, u32),
}
const MAX_REDIRECT_URIS: usize = 4;
/// An immediately-previous refresh token re-presented by the same client this
/// soon after rotation continues the family instead of revoking it.
const REFRESH_GRACE: i64 = 30;
const MAX_STATE_LEN: usize = 512;
const MAX_TOKEN_LEN: usize = 256;

/// Response extension naming the grant a request acted on (for request logs).
#[derive(Clone, Debug)]
pub struct LoggedGrant(pub String);

/// The verified grant behind a bearer token.
#[derive(Clone, Debug)]
pub struct AccessGrant {
    pub grant_id: String,
    pub client_id: String,
    pub backend: String,
    pub scope: Vec<String>,
    pub resource_scope: Value,
    pub gen: u64,
    pub sub: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerError {
    /// No credentials were presented.
    Missing,
    /// Credentials were presented but are not valid for this backend.
    Invalid,
}

#[derive(Debug)]
pub enum InitError {
    Config(&'static str),
    Store(rusqlite::Error),
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitError::Config(why) => write!(f, "invalid auth configuration: {why}"),
            InitError::Store(e) => write!(f, "auth store unavailable: {e}"),
        }
    }
}
impl std::error::Error for InitError {}

enum CeremonyKind {
    Login { tx: Option<String> },
    Register { bootstrap_code_hash: Option<String> },
}

struct Ceremony {
    kind: CeremonyKind,
    state: CeremonyState,
    expires: i64,
    net: Option<std::net::IpAddr>,
    seq: u64,
}

impl Ceremony {
    /// A login not tied to any pending authorization request.
    fn is_anonymous(&self) -> bool {
        matches!(self.kind, CeremonyKind::Login { tx: None })
    }
}

struct Inner {
    config: AuthConfig,
    enroll_code: Option<String>,
    store: Store,
    proof: Arc<dyn OwnerProof>,
    clock: Arc<dyn Clock>,
    log: Arc<dyn LogSink>,
    limiter: RateLimiter,
    ceremonies: Mutex<HashMap<String, Ceremony>>,
    ceremony_seq: AtomicU64,
    csrf_key: [u8; 32],
    enroll_failures: Mutex<EnrollFailures>,
    owner_id: String,
    issuer_origin: String,
    issuer_host: String,
    csp: String,
    /// The gateway's side of `consent = "origin"` backends (weak: the gateway
    /// owns this state, not the other way round).
    origin_port: OnceLock<Weak<dyn OriginPort>>,
    /// Origin consent attempts by pending-request id. In memory only: the
    /// tunnel stream that carries a consent request does not survive a restart
    /// either, and pairing codes never touch the disk.
    origin_txs: Mutex<HashMap<String, OriginTx>>,
    /// Upper end of the last scan for grants that ended without revocation.
    expiry_scan: AtomicI64,
}

/// Where one origin consent attempt stands (PHASE4.md §3.2).
#[derive(Clone, Debug)]
enum OriginStage {
    Sent,
    Unreachable(&'static str),
    Approved {
        resource_scope: Value,
        lifetime_secs: u64,
        approval: String,
        at: i64,
    },
    Denied,
    Timeout,
}

impl OriginStage {
    fn name(&self) -> &'static str {
        match self {
            OriginStage::Sent => "sent",
            OriginStage::Unreachable(_) => "origin_unreachable",
            OriginStage::Approved { .. } => "approved",
            OriginStage::Denied => "denied",
            OriginStage::Timeout => "origin_timeout",
        }
    }
}

struct OriginTx {
    stage: OriginStage,
    /// Attempts made so far (each with a fresh code, grant id and nonce).
    attempts: u32,
    pairing_code: String,
    grant_id: String,
    started: i64,
    task: Option<tokio::task::AbortHandle>,
}

/// Shared authorization-server state. Cheap to clone.
#[derive(Clone)]
pub struct AuthState(Arc<Inner>);

type HandlerResult = Result<Response, Response>;

fn flat(r: HandlerResult) -> Response {
    r.unwrap_or_else(|e| e)
}

/// Run a handler body (SQLite, WebAuthn verification) on the blocking pool so
/// async workers, and thus `/healthz`, never wait on the database.
async fn blocking<F>(f: F) -> Response
where
    F: FnOnce() -> HandlerResult + Send + 'static,
{
    tokio::task::spawn_blocking(move || flat(f()))
        .await
        .unwrap_or_else(|_| oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))
}

fn no_store(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

fn json_response(status: StatusCode, body: Value) -> Response {
    no_store((status, axum::Json(body)).into_response())
}

fn oauth_error(status: StatusCode, code: &'static str) -> Response {
    json_response(status, json!({ "error": code }))
}

fn too_many() -> Response {
    let mut res = oauth_error(StatusCode::TOO_MANY_REQUESTS, "temporarily_unavailable");
    res.headers_mut()
        .insert("retry-after", HeaderValue::from_static("60"));
    res
}

fn cookie_header(name: &str, value: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; Secure; SameSite=Lax"
    ))
    .expect("cookie values are base64url")
}

fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(COOKIE) {
        let Ok(value) = value.to_str() else { continue };
        for pair in value.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=') {
                if k == name && !v.is_empty() && v.len() <= 128 && is_b64url(v) {
                    return Some(v.to_owned());
                }
            }
        }
    }
    None
}

fn content_type_is(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(expected))
}

fn ip_of(ip: &Option<Extension<ClientIp>>) -> Option<std::net::IpAddr> {
    ip.as_ref().map(|Extension(ClientIp(ip))| *ip)
}

fn redirect_303(location: &str) -> Response {
    let mut res = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        res.headers_mut().insert(LOCATION, v);
    }
    no_store(res)
}

fn redirect_with(uri: &str, pairs: &[(&str, &str)]) -> Response {
    match Url::parse(uri) {
        Ok(mut url) => {
            {
                let mut q = url.query_pairs_mut();
                for (k, v) in pairs {
                    q.append_pair(k, v);
                }
            }
            redirect_303(url.as_str())
        }
        Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    }
}

fn human_duration(secs: i64) -> String {
    if secs % 86_400 == 0 {
        let d = secs / 86_400;
        format!("{d} day{}", if d == 1 { "" } else { "s" })
    } else if secs % 3600 == 0 {
        let h = secs / 3600;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else {
        format!("{} minutes", secs / 60)
    }
}

fn ago(secs: i64) -> String {
    match secs.max(0) {
        s if s < 60 => format!("{s} seconds ago"),
        s if s < 7200 => format!("{} minutes ago", s / 60),
        s if s < 2 * 86_400 => format!("{} hours ago", s / 3600),
        s => format!("{} days ago", s / 86_400),
    }
}

fn format_time(t: i64) -> String {
    // UTC, minute precision, without a date library: days since epoch → civil date.
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (h, m) = (secs / 3600, (secs % 3600) / 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02} UTC")
}

impl AuthState {
    /// Open the store (`db_path = None` → in-memory) and validate configuration.
    pub fn new(
        config: AuthConfig,
        db_path: Option<&FsPath>,
        proof: Arc<dyn OwnerProof>,
        clock: Arc<dyn Clock>,
        log: Arc<dyn LogSink>,
    ) -> Result<Self, InitError> {
        let issuer = Url::parse(&config.issuer).map_err(|_| InitError::Config("issuer"))?;
        if issuer.path() != "/"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || config.issuer.ends_with('/')
            || !matches!(issuer.scheme(), "https" | "http")
            || issuer.host_str().is_none()
        {
            return Err(InitError::Config("issuer must be an origin without path"));
        }
        if config.backends.is_empty() {
            return Err(InitError::Config("no backends"));
        }
        for (i, b) in config.backends.iter().enumerate() {
            if config.backends[..i].iter().any(|o| o.id == b.id) {
                return Err(InitError::Config("duplicate backend id"));
            }
            if b.scopes.is_empty() || b.grant_lifetime_secs <= 0 {
                return Err(InitError::Config("backend scopes/lifetime"));
            }
        }
        let mut form_action = vec!["'self'".to_string()];
        for uri in &config.redirect_allowlist {
            let url = Url::parse(uri).map_err(|_| InitError::Config("redirect allowlist"))?;
            if url.fragment().is_some() || !matches!(url.scheme(), "https" | "http") {
                return Err(InitError::Config("redirect allowlist"));
            }
            let origin = url.origin().ascii_serialization();
            if !form_action.contains(&origin) {
                form_action.push(origin);
            }
        }
        let enroll_code = config.enroll_code.clone().filter(|c| {
            let ok = c.len() >= MIN_ENROLL_CODE_LEN && c.is_ascii();
            if !ok {
                log.line("event=enroll_code_ignored reason=too_short");
            }
            ok
        });
        let lim = &config.limits;
        if !(1..=180).contains(&lim.origin_consent_secs) || lim.origin_consent_attempts == 0 {
            return Err(InitError::Config("origin consent limits"));
        }
        let store = Store::open(db_path).map_err(InitError::Store)?;
        let owner_id = store.owner_id(new_uuid_v4).map_err(InitError::Store)?;
        let started = clock.now();
        let csp = format!(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'self'; form-action {}; frame-ancestors 'none'; base-uri 'none'",
            form_action.join(" ")
        );
        Ok(Self(Arc::new(Inner {
            issuer_origin: issuer.origin().ascii_serialization(),
            issuer_host: issuer.host_str().unwrap_or_default().to_string(),
            config,
            enroll_code,
            store,
            proof,
            clock,
            log,
            limiter: RateLimiter::new(10_000),
            ceremonies: Mutex::new(HashMap::new()),
            csrf_key: random_bytes::<32>(),
            ceremony_seq: AtomicU64::new(0),
            enroll_failures: Mutex::new(EnrollFailures::default()),
            owner_id,
            csp,
            origin_port: OnceLock::new(),
            origin_txs: Mutex::new(HashMap::new()),
            expiry_scan: AtomicI64::new(started),
        })))
    }

    /// Connect the gateway for `consent = "origin"` backends. Only the first
    /// call has an effect; the state keeps a weak reference.
    pub fn set_origin_port(&self, port: Weak<dyn OriginPort>) {
        let _ = self.0.origin_port.set(port);
    }

    fn origin_port(&self) -> Option<Arc<dyn OriginPort>> {
        self.0.origin_port.get().and_then(Weak::upgrade)
    }

    fn is_origin_backend(&self, backend: &str) -> bool {
        self.config()
            .backend(backend)
            .is_some_and(|b| b.consent == ConsentMode::Origin)
    }

    /// Tell the origin (best effort) that the edge ended these grants.
    fn notify_revoked(&self, revoked: &[Revoked], reason: RevokeReason) {
        let Some(port) = self.origin_port() else {
            return;
        };
        for r in revoked {
            if self.is_origin_backend(&r.backend) {
                port.revoked(&r.backend, &r.id, u64::try_from(r.gen).unwrap_or(0), reason);
            }
        }
    }

    /// Record the configured origin EndpointId of an origin backend at start
    /// (PHASE4.md §1.2). A different id than the stored one revokes every
    /// grant of the backend (gen++) and logs `event=origin_reenrolled`; no
    /// grant ever moves silently to a new origin.
    pub fn bind_origin(&self, backend: &str, origin_id: &str) -> Result<(), InitError> {
        let (changed, revoked) = self
            .0
            .store
            .bind_origin(backend, origin_id)
            .map_err(InitError::Store)?;
        if changed {
            self.log(&format!(
                "event=origin_reenrolled backend={backend} revoked={}",
                revoked.len()
            ));
        }
        Ok(())
    }

    /// Active grants of `backend` as `(grant_id, gen)` (for `grant_sync`).
    pub fn live_grants(&self, backend: &str) -> Vec<(String, u64)> {
        match self.0.store.live_grants_for_backend(backend, self.now()) {
            Ok(rows) => rows
                .into_iter()
                .map(|(id, gen)| (id, u64::try_from(gen).unwrap_or(0)))
                .collect(),
            Err(_) => {
                self.log("event=store_error op=live_grants");
                Vec::new()
            }
        }
    }

    /// Revoke a grant because its origin no longer honours it (a refusal such
    /// as `grant_revoked`, or `grant_sync`). The origin is not notified: it
    /// already knows. Logs `event=<event> grant=<id>` when the state changed.
    pub fn revoke_for_origin(&self, grant_id: &str, event: &str) -> bool {
        match self.0.store.revoke_grant(grant_id) {
            Ok(Some(r)) => {
                self.log(&format!(
                    "event={event} backend={} grant={grant_id}",
                    r.backend
                ));
                true
            }
            Ok(None) => false,
            Err(_) => {
                self.log("event=store_error op=revoke");
                false
            }
        }
    }

    pub fn config(&self) -> &AuthConfig {
        &self.0.config
    }

    pub fn now(&self) -> i64 {
        self.0.clock.now()
    }

    /// The owner id used as assertion `sub`.
    pub fn owner_id(&self) -> &str {
        &self.0.owner_id
    }

    pub fn log(&self, line: &str) {
        self.0.log.line(line);
    }

    pub fn limiter(&self) -> &RateLimiter {
        &self.0.limiter
    }

    /// True when the store answers.
    pub fn ready(&self) -> bool {
        self.0.store.ping()
    }

    /// Remove expired state (call periodically).
    pub fn cleanup(&self) {
        let now = self.now();
        let since = self.0.expiry_scan.swap(now, Ordering::SeqCst);
        match self.0.store.ended_without_revocation(since, now) {
            Ok(ended) => self.notify_revoked(&ended, RevokeReason::Expired),
            Err(_) => self.log("event=store_error op=expiry_scan"),
        }
        self.0
            .origin_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, t| t.started + PENDING_TTL > now);
        if self.0.store.cleanup(now).is_err() {
            self.log("event=store_error op=cleanup");
        }
        self.0
            .ceremonies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, c| c.expires > now);
    }

    /// Validate an `Authorization` header for `backend`.
    pub fn authenticate_bearer(
        &self,
        headers: &HeaderMap,
        backend: &str,
    ) -> Result<AccessGrant, BearerError> {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let Some(value) = values.next() else {
            return Err(BearerError::Missing);
        };
        if values.next().is_some() {
            return Err(BearerError::Invalid);
        }
        let value = value.to_str().map_err(|_| BearerError::Invalid)?;
        let (scheme, token) = value.split_once(' ').ok_or(BearerError::Invalid)?;
        if !scheme.eq_ignore_ascii_case("bearer")
            || token.is_empty()
            || token.len() > MAX_TOKEN_LEN
            || !is_b64url(token)
        {
            return Err(BearerError::Invalid);
        }
        let grant = match self
            .0
            .store
            .grant_for_access(&hash_secret(token), self.now())
        {
            Ok(Some(g)) => g,
            Ok(None) => return Err(BearerError::Invalid),
            Err(_) => {
                self.log("event=store_error op=bearer");
                return Err(BearerError::Invalid);
            }
        };
        if grant.backend != backend {
            return Err(BearerError::Invalid);
        }
        Ok(AccessGrant {
            grant_id: grant.id,
            client_id: grant.client_id,
            backend: grant.backend,
            scope: grant.scope.split(' ').map(str::to_owned).collect(),
            resource_scope: serde_json::from_str(&grant.resource_scope).unwrap_or(json!({})),
            gen: u64::try_from(grant.gen).unwrap_or(0),
            sub: self.0.owner_id.clone(),
        })
    }

    fn db<T>(&self, op: &str, r: store::StoreResult<T>) -> Result<T, Response> {
        r.map_err(|_| {
            self.log(&format!("event=store_error op={op}"));
            oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error")
        })
    }

    fn html(&self, status: StatusCode, body: String) -> Response {
        let mut res = (status, axum::response::Html(body)).into_response();
        let h = res.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&self.0.csp) {
            h.insert("content-security-policy", v);
        }
        h.insert("x-frame-options", HeaderValue::from_static("DENY"));
        // `same-origin`, not `no-referrer`: under `no-referrer` browsers send
        // `Origin: null` on our own form POSTs, which `same_origin` refuses.
        h.insert("referrer-policy", HeaderValue::from_static("same-origin"));
        no_store(res)
    }

    fn page_error(&self, status: StatusCode, title: &str, text: &str) -> Response {
        self.html(status, pages::message(title, text))
    }

    /// Browser endpoints refuse cross-origin requests when the browser says so.
    /// `Origin: null` is refused too (sandboxed frames send it), so every page
    /// must use a referrer policy under which same-origin form POSTs keep their
    /// real Origin; see `html`.
    fn same_origin(&self, headers: &HeaderMap) -> Result<(), Response> {
        match headers.get(ORIGIN) {
            None => Ok(()),
            Some(v) if v.as_bytes() == self.0.issuer_origin.as_bytes() => Ok(()),
            Some(_) => Err(oauth_error(StatusCode::FORBIDDEN, "cross_origin_request")),
        }
    }

    fn limit(
        &self,
        bucket: &'static str,
        ip: Option<std::net::IpAddr>,
        limit: u32,
        window: i64,
    ) -> Result<(), Response> {
        if self.0.limiter.allow(bucket, ip, limit, window, self.now()) {
            Ok(())
        } else {
            Err(too_many())
        }
    }

    /// Store a ceremony. Never refuses: a client network keeps at most
    /// `MAX_CEREMONIES_PER_NET`, and the table (`max_ceremonies`, thousands)
    /// evicts instead of refusing. Eviction takes anonymous login ceremonies
    /// (no pending request, no enrollment/session) before ones bound to an
    /// authorization request or a registration, oldest first, so displacing
    /// the owner's in-progress ceremony needs thousands of client networks.
    fn put_ceremony(
        &self,
        kind: CeremonyKind,
        state: CeremonyState,
        ip: Option<std::net::IpAddr>,
    ) -> String {
        let now = self.now();
        let net = ip.map(support::network_key);
        let mut map = self.0.ceremonies.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, c| c.expires > now);
        let evict = |map: &mut HashMap<String, Ceremony>, same_net: bool| {
            let victim = map
                .iter()
                .filter(|(_, c)| !same_net || c.net == net)
                .min_by_key(|(_, c)| (!c.is_anonymous(), c.seq))
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                map.remove(&k);
            }
        };
        if map.values().filter(|c| c.net == net).count() >= MAX_CEREMONIES_PER_NET {
            evict(&mut map, true);
        }
        if map.len() >= self.config().limits.max_ceremonies.max(1) {
            evict(&mut map, false);
        }
        let secret = random_secret("");
        map.insert(
            hash_secret(&secret),
            Ceremony {
                kind,
                state,
                expires: now + CEREMONY_TTL,
                net,
                seq: self.0.ceremony_seq.fetch_add(1, Ordering::SeqCst),
            },
        );
        secret
    }

    fn take_ceremony(&self, headers: &HeaderMap) -> Option<Ceremony> {
        let secret = read_cookie(headers, CEREMONY_COOKIE)?;
        let c = self
            .0
            .ceremonies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&hash_secret(&secret))?;
        (c.expires > self.now()).then_some(c)
    }

    /// A live, unused pending request bound to this browser's transaction cookie.
    fn pending_for_browser(
        &self,
        tx: &str,
        headers: &HeaderMap,
    ) -> Result<(PendingRow, String), Response> {
        let expired = || {
            self.page_error(
                StatusCode::BAD_REQUEST,
                "Request expired",
                "This authorization request has expired, was already used or belongs to another \
                 browser. Start again from the client.",
            )
        };
        if tx.is_empty() || tx.len() > 64 || !is_b64url(tx) {
            return Err(expired());
        }
        let binding = read_cookie(headers, TX_COOKIE).ok_or_else(expired)?;
        let p = self
            .db("pending", self.0.store.pending(tx))?
            .ok_or_else(expired)?;
        if p.used || p.expires <= self.now() || !ct_eq(&hash_secret(&binding), &p.binding_hash) {
            return Err(expired());
        }
        Ok((p, binding))
    }

    fn session(&self, headers: &HeaderMap) -> Result<Option<(String, i64)>, Response> {
        let Some(secret) = read_cookie(headers, SESSION_COOKIE) else {
            return Ok(None);
        };
        let auth_at = self.db(
            "session",
            self.0.store.session(&hash_secret(&secret), self.now()),
        )?;
        Ok(auth_at.map(|t| (secret, t)))
    }

    fn consent_csrf(&self, tx: &str, binding: &str) -> String {
        hmac_b64(&self.0.csrf_key, &["consent", tx, binding])
    }

    fn owner_csrf(&self, session: &str) -> String {
        hmac_b64(&self.0.csrf_key, &["owner", session])
    }
}

fn new_uuid_v4() -> String {
    let mut b = random_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// All authorization-server routes. The caller adds connection limits, the
/// `ClientIp` extension, request logging and global headers.
pub fn router(state: AuthState) -> Router {
    let small = DefaultBodyLimit::max(16 * 1024);
    let medium = DefaultBodyLimit::max(64 * 1024);
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(issuer_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/{backend}/mcp",
            get(resource_metadata),
        )
        .route("/register", post(register).layer(small))
        .route("/authorize", get(authorize))
        .route(
            "/consent",
            get(consent_page).post(consent_submit).layer(small),
        )
        .route("/consent/start", post(consent_start).layer(small))
        .route("/consent/status", get(consent_status))
        .route("/consent/finish", post(consent_finish).layer(small))
        .route("/consent/cancel", post(consent_cancel).layer(small))
        .route("/token", post(token).layer(small))
        .route("/revoke", post(revoke).layer(small))
        .route("/owner", get(owner_home))
        .route("/owner/enroll", get(enroll_page))
        .route("/owner/login/start", post(login_start).layer(small))
        .route("/owner/login/finish", post(login_finish).layer(medium))
        .route("/owner/register/start", post(register_start).layer(small))
        .route(
            "/owner/register/finish",
            post(register_finish).layer(medium),
        )
        .route("/owner/grants/revoke", post(owner_revoke).layer(small))
        .route(
            "/owner/grants/revoke-all",
            post(owner_revoke_all).layer(small),
        )
        .route("/owner/logout", post(owner_logout).layer(small))
        .route("/static/edge.js", get(static_js))
        .route("/static/edge.css", get(static_css))
        .with_state(state)
}

async fn static_js() -> Response {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../static/edge.js"),
    )
        .into_response()
}

async fn static_css() -> Response {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../static/edge.css"),
    )
        .into_response()
}

// ---------------------------------------------------------------- discovery

async fn issuer_metadata(State(s): State<AuthState>) -> Response {
    let iss = &s.config().issuer;
    let mut scopes: Vec<&str> = s
        .config()
        .backends
        .iter()
        .flat_map(|b| b.scopes.iter().map(String::as_str))
        .collect();
    scopes.sort_unstable();
    scopes.dedup();
    json_response(
        StatusCode::OK,
        json!({
            "issuer": iss,
            "authorization_endpoint": format!("{iss}/authorize"),
            "token_endpoint": format!("{iss}/token"),
            "registration_endpoint": format!("{iss}/register"),
            "revocation_endpoint": format!("{iss}/revoke"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": scopes,
            "authorization_response_iss_parameter_supported": true,
        }),
    )
}

async fn resource_metadata(State(s): State<AuthState>, Path(backend): Path<String>) -> Response {
    let Some(b) = s.config().backend(&backend) else {
        return oauth_error(StatusCode::NOT_FOUND, "not_found");
    };
    json_response(
        StatusCode::OK,
        json!({
            "resource": s.config().resource_url(&b.id),
            "authorization_servers": [s.config().issuer],
            "scopes_supported": b.scopes,
            "bearer_methods_supported": ["header"],
            "resource_name": b.display_name,
        }),
    )
}

// ------------------------------------------------------------- registration

#[derive(Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    grant_types: Option<Vec<String>>,
    #[serde(default)]
    response_types: Option<Vec<String>>,
}

async fn register(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || register_inner(&s, ip_of(&ip), &headers, &body)).await
}

fn register_inner(
    s: &AuthState,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> HandlerResult {
    let lim = &s.config().limits;
    s.limit("register", ip, lim.register_per_ip_per_hour, 3600)?;
    s.limit("register-all", None, lim.register_global_per_hour, 3600)?;
    let bad = || oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    if !content_type_is(headers, "application/json") {
        return Err(bad());
    }
    let req: RegistrationRequest = serde_json::from_slice(body).map_err(|_| bad())?;
    if req.redirect_uris.is_empty()
        || req.redirect_uris.len() > MAX_REDIRECT_URIS
        || !req
            .redirect_uris
            .iter()
            .all(|u| s.config().redirect_allowlist.iter().any(|a| a == u))
    {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri"));
    }
    // RFC 7591 §3.2.1: the server may substitute metadata. Whatever method is
    // requested, the client is registered (and told it is) public: "none".
    let _ = req.token_endpoint_auth_method;
    let grant_types = req
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    if grant_types.is_empty()
        || !grant_types
            .iter()
            .all(|g| g == "authorization_code" || g == "refresh_token")
    {
        return Err(bad());
    }
    let response_types = req.response_types.unwrap_or_else(|| vec!["code".into()]);
    if response_types.iter().any(|r| r != "code") {
        return Err(bad());
    }
    let name: Option<String> = req.client_name.map(|n| {
        n.chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect::<String>()
            .trim()
            .to_string()
    });
    let now = s.now();
    let max = i64::try_from(lim.max_clients).unwrap_or(i64::MAX);
    if s.db("clients", s.0.store.client_count())? >= max {
        s.db("clients", s.0.store.prune_unused_clients(now - 3600))?;
        if s.db("clients", s.0.store.client_count())? >= max {
            s.log("event=registration_refused reason=client_limit");
            return Err(too_many());
        }
    }
    let mut uris = req.redirect_uris;
    uris.dedup();
    let client_id = random_id("mcc_");
    s.db(
        "clients",
        s.0.store
            .insert_client(&client_id, name.as_deref(), &uris, now),
    )?;
    s.log("event=client_registered");
    Ok(json_response(
        StatusCode::CREATED,
        json!({
            "client_id": client_id,
            "client_id_issued_at": now,
            "client_name": name,
            "redirect_uris": uris,
            "token_endpoint_auth_method": "none",
            "grant_types": grant_types,
            "response_types": ["code"],
        }),
    ))
}

// ------------------------------------------------------------ authorization

async fn authorize(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    RawQuery(query): RawQuery,
) -> Response {
    blocking(move || authorize_inner(&s, ip_of(&ip), query.as_deref().unwrap_or(""))).await
}

fn authorize_inner(s: &AuthState, ip: Option<std::net::IpAddr>, query: &str) -> HandlerResult {
    s.limit(
        "authorize",
        ip,
        s.config().limits.authorize_per_ip_per_minute,
        60,
    )?;
    let reject = |text: &str| s.page_error(StatusCode::BAD_REQUEST, "Request rejected", text);
    let params = parse_unique_params(query.as_bytes())
        .ok_or_else(|| reject("The authorization request repeats a parameter."))?;
    let get = |k: &str| params.get(k).map(String::as_str).filter(|v| !v.is_empty());

    // Errors before the client and redirect are verified are never redirected.
    let client_id = get("client_id").ok_or_else(|| reject("Unknown client."))?;
    let client = s
        .db("clients", s.0.store.client(client_id))?
        .ok_or_else(|| reject("Unknown client."))?;
    let redirect_uri = get("redirect_uri")
        .filter(|r| client.redirect_uris.iter().any(|u| u == r))
        .filter(|r| s.config().redirect_allowlist.iter().any(|u| u == r))
        .ok_or_else(|| reject("The redirect URI is not registered for this client."))?;

    let state = get("state");
    let iss = s.config().issuer.as_str();
    let fail = |code: &str| {
        let mut pairs = vec![("error", code), ("iss", iss)];
        if let Some(st) = state.filter(|st| st.len() <= MAX_STATE_LEN) {
            pairs.push(("state", st));
        }
        redirect_with(redirect_uri, &pairs)
    };
    if get("response_type") != Some("code") {
        return Err(fail("unsupported_response_type"));
    }
    let Some(state) = state.filter(|st| st.len() <= MAX_STATE_LEN) else {
        return Err(fail("invalid_request"));
    };
    if get("code_challenge_method") != Some("S256") {
        return Err(fail("invalid_request"));
    }
    let challenge = get("code_challenge")
        .filter(|c| c.len() == 43 && is_b64url(c))
        .ok_or_else(|| fail("invalid_request"))?;
    let backend = get("resource")
        .and_then(|r| s.config().backend_for_resource(r))
        .ok_or_else(|| fail("invalid_target"))?;
    let scope = match get("scope") {
        None => backend.scopes.join(" "),
        // Grant the intersection with the backend's scopes; if nothing
        // overlaps, grant the backend's defaults (clients often send scopes
        // from other servers or none we know).
        Some(requested) => {
            let mut wanted: Vec<&str> = requested
                .split(' ')
                .filter(|x| backend.scopes.iter().any(|b| b == x))
                .collect();
            wanted.sort_unstable();
            wanted.dedup();
            if wanted.is_empty() {
                backend.scopes.join(" ")
            } else {
                wanted.join(" ")
            }
        }
    };

    let now = s.now();
    // Bounded without letting anonymous callers lock the owner out: one client
    // network keeps at most a few live requests (its oldest is dropped), and a
    // full table drops the oldest request nobody has proved a passkey for.
    let max_pending = i64::try_from(s.config().limits.max_pending).unwrap_or(i64::MAX);
    let net = ip
        .map(|ip| support::network_key(ip).to_string())
        .unwrap_or_default();
    if !s.db(
        "pending",
        s.0.store
            .make_room_for_pending(&net, MAX_PENDING_PER_NET, max_pending, now),
    )? {
        return Err(too_many());
    }
    let binding = random_secret("");
    let pending = PendingRow {
        id: random_id(""),
        binding_hash: hash_secret(&binding),
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.to_owned(),
        state: state.to_owned(),
        code_challenge: challenge.to_owned(),
        backend: backend.id.clone(),
        scope,
        created: now,
        expires: now + PENDING_TTL,
        verified_at: None,
        used: false,
    };
    s.db("pending", s.0.store.insert_pending(&pending, &net, now))?;
    let mut res = redirect_303(&format!("/consent?tx={}", pending.id));
    res.headers_mut()
        .append(SET_COOKIE, cookie_header(TX_COOKIE, &binding, PENDING_TTL));
    Ok(res)
}

async fn consent_page(
    State(s): State<AuthState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    blocking(move || consent_page_inner(&s, &headers, query.as_deref().unwrap_or(""))).await
}

fn proof_is_fresh(p: &PendingRow, now: i64) -> bool {
    p.verified_at
        .is_some_and(|t| t <= now && now - t <= FRESH_PROOF)
}

/// Plain-language text for an origin consent failure reason.
fn origin_reason_text(reason: &str, app: &str) -> String {
    match reason {
        "origin_offline" | "origin_unavailable" => format!(
            "{app} is not reachable: the computer it runs on is off or asleep, or the app is \
             closed."
        ),
        "origin_remote_off" => format!("Remote access is turned off in {app}."),
        "origin_unenrolled" | "origin_rejected_edge" => format!(
            "{app} does not recognize this edge. Paste the enrollment string from /owner into \
             {app} and try again."
        ),
        "origin_locked" => format!("{app} is locked or not ready yet. Unlock it and try again."),
        "origin_paused" => format!("Remote access in {app} is paused (its audit log failed)."),
        "consent_busy" => format!("{app} is already showing another access request."),
        "origin_busy" => format!("{app} is busy. Try again in a moment."),
        "approval_invalid" => format!(
            "{app}'s answer could not be verified, so it was not accepted. Check the enrollment \
             on both sides."
        ),
        _ => format!("{app} could not be asked."),
    }
}

fn consent_page_inner(s: &AuthState, headers: &HeaderMap, query: &str) -> HandlerResult {
    let params = parse_unique_params(query.as_bytes()).unwrap_or_default();
    let tx = params.get("tx").map(String::as_str).unwrap_or("");
    let (p, binding) = s.pending_for_browser(tx, headers)?;
    let client = s.db("clients", s.0.store.client(&p.client_id))?;
    let backend = s.config().backend(&p.backend).ok_or_else(|| {
        s.page_error(
            StatusCode::BAD_REQUEST,
            "Request rejected",
            "Unknown backend.",
        )
    })?;
    let now = s.now();
    let fresh = proof_is_fresh(&p, now);
    let is_origin = backend.consent == ConsentMode::Origin;
    // Origin backends need CSRF tokens for cancel/finish even after the
    // passkey proof aged; starting (or retrying) still requires a fresh proof.
    let csrf = (fresh || is_origin).then(|| s.consent_csrf(&p.id, &binding));
    let max_attempts = s.config().limits.origin_consent_attempts;
    let origin = is_origin.then(|| {
        let txs = s.0.origin_txs.lock().unwrap_or_else(|e| e.into_inner());
        match txs.get(&p.id) {
            None => pages::OriginPage::Ready {
                attempts_left: max_attempts,
                reason: None,
            },
            Some(t) => {
                let left = max_attempts.saturating_sub(t.attempts);
                match &t.stage {
                    OriginStage::Sent => pages::OriginPage::Sent {
                        pairing_code: t.pairing_code.clone(),
                    },
                    OriginStage::Unreachable(r) => pages::OriginPage::Ready {
                        attempts_left: left,
                        reason: Some(origin_reason_text(r, &backend.display_name)),
                    },
                    OriginStage::Approved { .. } => pages::OriginPage::Approved,
                    OriginStage::Denied => pages::OriginPage::Ended {
                        title: "Denied",
                        text: format!("The request was denied in {}.", backend.display_name),
                    },
                    OriginStage::Timeout => pages::OriginPage::Ended {
                        title: "No decision",
                        text: format!("No decision was made in {} in time.", backend.display_name),
                    },
                }
            }
        }
    });
    let redirect_host = Url::parse(&p.redirect_uri)
        .ok()
        .and_then(|u| u.host_str().map(str::to_owned))
        .unwrap_or_default();
    let resource = s.config().resource_url(&backend.id);
    let view = pages::ConsentView {
        tx: &p.id,
        client_name: client.as_ref().and_then(|c| c.name.as_deref()),
        client_id: &p.client_id,
        redirect_host: &redirect_host,
        backend_name: &backend.display_name,
        resource: &resource,
        scopes: &p.scope,
        grant_lifetime: human_duration(backend.grant_lifetime_secs),
        requested_ago: ago(now - p.created),
        client_registered: client
            .as_ref()
            .map(|c| format!("{} ({})", format_time(c.created), ago(now - c.created)))
            .unwrap_or_else(|| "unknown".into()),
        issuer_host: &s.0.issuer_host,
        csrf: csrf.as_deref(),
        fresh,
        origin,
    };
    Ok(s.html(StatusCode::OK, pages::consent(&view)))
}

/// Deny: one-shot consume, then redirect `access_denied` to the client.
fn deny_redirect(s: &AuthState, p: &PendingRow, now: i64, bad: Response) -> HandlerResult {
    if !s.db("pending", s.0.store.consume_pending(&p.id, now))? {
        return Err(bad);
    }
    s.log("event=consent_denied");
    let iss = s.config().issuer.clone();
    let mut res = redirect_with(
        &p.redirect_uri,
        &[
            ("error", "access_denied"),
            ("state", &p.state),
            ("iss", &iss),
        ],
    );
    res.headers_mut()
        .append(SET_COOKIE, cookie_header(TX_COOKIE, "", 0));
    Ok(res)
}

/// Approve: one-shot consume, then create the grant and its one-use code
/// atomically and redirect with `code`, `state`, `iss`.
#[allow(clippy::too_many_arguments)]
fn issue_code(
    s: &AuthState,
    p: &PendingRow,
    backend: &str,
    grant_id: &str,
    resource_scope: &str,
    approval: Option<&str>,
    grant_expires: i64,
    now: i64,
    bad: Response,
) -> HandlerResult {
    if !s.db("pending", s.0.store.consume_pending(&p.id, now))? {
        return Err(bad);
    }
    let code = random_secret("mec_");
    s.db(
        "grant",
        s.0.store.create_grant_with_code(
            grant_id,
            &p.client_id,
            backend,
            &p.scope,
            resource_scope,
            approval,
            grant_expires,
            &hash_secret(&code),
            &p.redirect_uri,
            &p.code_challenge,
            now + CODE_TTL,
            now,
        ),
    )?;
    s.log(&format!(
        "event=consent_approved grant={grant_id} backend={backend}"
    ));
    let iss = s.config().issuer.clone();
    let mut res = redirect_with(
        &p.redirect_uri,
        &[("code", &code), ("state", &p.state), ("iss", &iss)],
    );
    res.extensions_mut()
        .insert(LoggedGrant(grant_id.to_owned()));
    res.headers_mut()
        .append(SET_COOKIE, cookie_header(TX_COOKIE, "", 0));
    Ok(res)
}

async fn consent_submit(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || consent_submit_inner(&s, &headers, &body)).await
}

fn consent_submit_inner(s: &AuthState, headers: &HeaderMap, body: &[u8]) -> HandlerResult {
    s.same_origin(headers)?;
    let bad = || {
        s.page_error(
            StatusCode::BAD_REQUEST,
            "Request rejected",
            "The consent form was invalid.",
        )
    };
    let form = parse_unique_params(body).ok_or_else(bad)?;
    let tx = form.get("tx").map(String::as_str).unwrap_or("");
    let (p, binding) = s.pending_for_browser(tx, headers)?;
    let csrf = form.get("csrf").map(String::as_str).unwrap_or("");
    if !ct_eq(csrf, &s.consent_csrf(&p.id, &binding)) {
        return Err(bad());
    }
    let now = s.now();
    if !proof_is_fresh(&p, now) {
        return Err(s.page_error(
            StatusCode::FORBIDDEN,
            "Passkey required",
            "Confirm with your passkey before approving this request.",
        ));
    }
    let decision = form.get("decision").map(String::as_str);
    if !matches!(decision, Some("approve") | Some("deny")) {
        return Err(bad());
    }
    let backend = s.config().backend(&p.backend).ok_or_else(bad)?;
    if backend.consent == ConsentMode::Origin {
        // Only the app can approve an origin backend; the edge page can deny.
        if decision == Some("approve") {
            return Err(s.page_error(
                StatusCode::BAD_REQUEST,
                "Approve in the app",
                "This backend is approved in its own app, not on this page.",
            ));
        }
        s.cancel_origin_attempt(&p.id);
        return deny_redirect(s, &p, now, bad());
    }
    if decision == Some("deny") {
        return deny_redirect(s, &p, now, bad());
    }
    let grant_id = random_id("g_");
    issue_code(
        s,
        &p,
        &backend.id,
        &grant_id,
        "{}",
        None,
        now + backend.grant_lifetime_secs,
        now,
        bad(),
    )
}

// ---------------------------------------------------------- origin consent

/// 6 Crockford base32 characters (30 random bits).
fn pairing_code() -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let n = u32::from_be_bytes(random_bytes::<4>());
    (0..6)
        .map(|i| char::from(ALPHABET[((n >> (i * 5)) & 31) as usize]))
        .collect()
}

impl AuthState {
    /// Stop a running origin consent attempt (the dropped stream makes the
    /// origin close its prompt) and forget the attempt.
    fn cancel_origin_attempt(&self, tx: &str) {
        let removed = self
            .0
            .origin_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(tx);
        if let Some(t) = removed {
            if let Some(task) = t.task {
                task.abort();
            }
            if matches!(t.stage, OriginStage::Sent) {
                self.log("event=consent_cancelled");
            }
        }
    }

    /// Record the outcome of attempt number `attempt` of `tx`, unless the
    /// attempt was cancelled or superseded meanwhile.
    fn finish_origin_attempt(&self, tx: &str, attempt: u32, outcome: ConsentOutcome) {
        let now = self.now();
        let mut txs = self.0.origin_txs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(t) = txs.get_mut(tx) else {
            return;
        };
        if t.attempts != attempt || !matches!(t.stage, OriginStage::Sent) {
            return;
        }
        t.task = None;
        let grant = t.grant_id.clone();
        t.stage = match outcome {
            ConsentOutcome::Approved {
                resource_scope,
                lifetime_secs,
                approval,
            } if resource_scope.is_object() && lifetime_secs > 0 => {
                self.log(&format!("event=consent_origin_approved grant={grant}"));
                OriginStage::Approved {
                    resource_scope,
                    lifetime_secs,
                    approval,
                    at: now,
                }
            }
            ConsentOutcome::Approved { .. } => {
                self.log("event=origin_approval_invalid reason=scope");
                OriginStage::Unreachable("approval_invalid")
            }
            ConsentOutcome::Denied => {
                self.log("event=consent_origin_denied");
                OriginStage::Denied
            }
            ConsentOutcome::Timeout => {
                self.log("event=consent_origin_timeout");
                OriginStage::Timeout
            }
            ConsentOutcome::Busy => {
                self.log("event=consent_origin_unreachable reason=consent_busy");
                OriginStage::Unreachable("consent_busy")
            }
            ConsentOutcome::Unreachable(reason) => {
                self.log(&format!("event=consent_origin_unreachable reason={reason}"));
                OriginStage::Unreachable(reason)
            }
        };
    }
}

fn consent_form<'a>(
    s: &AuthState,
    headers: &HeaderMap,
    form: &'a HashMap<String, String>,
) -> Result<(PendingRow, &'a str), Response> {
    let tx = form.get("tx").map(String::as_str).unwrap_or("");
    let (p, binding) = s.pending_for_browser(tx, headers)?;
    let csrf = form.get("csrf").map(String::as_str).unwrap_or("");
    if !ct_eq(csrf, &s.consent_csrf(&p.id, &binding)) {
        return Err(s.page_error(
            StatusCode::BAD_REQUEST,
            "Request rejected",
            "The consent form was invalid.",
        ));
    }
    Ok((p, tx))
}

fn origin_backend<'a>(
    s: &'a AuthState,
    p: &PendingRow,
) -> Result<&'a config::BackendPolicy, Response> {
    s.config()
        .backend(&p.backend)
        .filter(|b| b.consent == ConsentMode::Origin)
        .ok_or_else(|| {
            s.page_error(
                StatusCode::BAD_REQUEST,
                "Request rejected",
                "This request is not waiting for an app.",
            )
        })
}

async fn consent_start(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || consent_start_inner(&s, &headers, &body)).await
}

/// `POST /consent/start`: after a fresh passkey proof, send the request to the
/// origin with a new pairing code (PHASE4.md §3.2 `proved` → `sent`, and the
/// retries from `origin_unreachable`).
fn consent_start_inner(s: &AuthState, headers: &HeaderMap, body: &[u8]) -> HandlerResult {
    s.same_origin(headers)?;
    let bad = || {
        s.page_error(
            StatusCode::BAD_REQUEST,
            "Request rejected",
            "The consent form was invalid.",
        )
    };
    let form = parse_unique_params(body).ok_or_else(bad)?;
    let (p, tx) = consent_form(s, headers, &form)?;
    let backend = origin_backend(s, &p)?;
    let now = s.now();
    if !proof_is_fresh(&p, now) {
        return Err(s.page_error(
            StatusCode::FORBIDDEN,
            "Passkey required",
            "Confirm with your passkey before sending this request.",
        ));
    }
    let back = redirect_303(&format!("/consent?tx={tx}"));
    let client = s.db("clients", s.0.store.client(&p.client_id))?;
    let max_attempts = s.config().limits.origin_consent_attempts;
    let timeout_secs = s.config().limits.origin_consent_secs;
    let mut txs = s.0.origin_txs.lock().unwrap_or_else(|e| e.into_inner());
    let attempts = match txs.get(&p.id) {
        None => 0,
        Some(t) if matches!(t.stage, OriginStage::Unreachable(_)) && t.attempts < max_attempts => {
            t.attempts
        }
        // Already sent, decided, or out of attempts: just show the state.
        Some(_) => return Ok(back),
    } + 1;
    let ask = ConsentAsk {
        backend: backend.id.clone(),
        tx: p.id.clone(),
        grant_id: random_id("g_"),
        nonce: URL_SAFE_NO_PAD.encode(random_bytes::<32>()),
        pairing_code: pairing_code(),
        client_id: p.client_id.clone(),
        client_name: client
            .as_ref()
            .and_then(|c| c.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| "(no name given)".into()),
        client_registered_at: client
            .as_ref()
            .map_or(0, |c| u64::try_from(c.created).unwrap_or(0)),
        redirect_host: Url::parse(&p.redirect_uri)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default(),
        requested_at: u64::try_from(now).unwrap_or(0),
        scopes: p.scope.split(' ').map(str::to_owned).collect(),
        max_lifetime_secs: u64::try_from(backend.grant_lifetime_secs).unwrap_or(0),
        expires_at: u64::try_from(now).unwrap_or(0) + timeout_secs,
    };
    let entry = OriginTx {
        stage: OriginStage::Sent,
        attempts,
        pairing_code: ask.pairing_code.clone(),
        grant_id: ask.grant_id.clone(),
        started: now,
        task: None,
    };
    let Some(port) = s.origin_port() else {
        txs.insert(
            p.id.clone(),
            OriginTx {
                stage: OriginStage::Unreachable("origin_unavailable"),
                ..entry
            },
        );
        s.log("event=consent_origin_unreachable reason=origin_unavailable");
        return Ok(back);
    };
    txs.insert(p.id.clone(), entry);
    drop(txs);
    s.log(&format!(
        "event=consent_sent backend={} attempt={attempts}",
        backend.id
    ));
    let state = s.clone();
    let tx_id = p.id.clone();
    let limit = std::time::Duration::from_secs(timeout_secs);
    let task = tokio::spawn(async move {
        let started = tokio::time::Instant::now();
        // The port's own deadline is `expires_at`; this bound is a backstop.
        let outcome = tokio::time::timeout(
            limit + std::time::Duration::from_secs(10),
            port.consent(ask),
        )
        .await
        .unwrap_or(ConsentOutcome::Timeout);
        // A stream the origin closed at `expires_at` is "no decision".
        let outcome = match outcome {
            ConsentOutcome::Unreachable(_) if started.elapsed() >= limit => ConsentOutcome::Timeout,
            other => other,
        };
        state.finish_origin_attempt(&tx_id, attempts, outcome);
    });
    let mut txs = s.0.origin_txs.lock().unwrap_or_else(|e| e.into_inner());
    match txs.get_mut(&p.id) {
        Some(t) if t.attempts == attempts && matches!(t.stage, OriginStage::Sent) => {
            t.task = Some(task.abort_handle());
        }
        _ => {}
    }
    Ok(back)
}

async fn consent_status(
    State(s): State<AuthState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    blocking(move || {
        let params =
            parse_unique_params(query.as_deref().unwrap_or("").as_bytes()).unwrap_or_default();
        let tx = params.get("tx").map(String::as_str).unwrap_or("");
        let (p, _) = s
            .pending_for_browser(tx, &headers)
            .map_err(|_| oauth_error(StatusCode::NOT_FOUND, "expired"))?;
        let max_attempts = s.config().limits.origin_consent_attempts;
        let txs = s.0.origin_txs.lock().unwrap_or_else(|e| e.into_inner());
        let (state, left) = match txs.get(&p.id) {
            Some(t) => (t.stage.name(), max_attempts.saturating_sub(t.attempts)),
            None if proof_is_fresh(&p, s.now()) => ("proved", max_attempts),
            None => ("created", max_attempts),
        };
        Ok(json_response(
            StatusCode::OK,
            json!({ "state": state, "attempts_left": left }),
        ))
    })
    .await
}

async fn consent_finish(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || consent_finish_inner(&s, &headers, &body)).await
}

/// `POST /consent/finish`: the final redirect (the code never appears in a
/// JSON response). Approved → grant with the approved `resource_scope` and
/// lifetime + one-use code; denied, timed out or unreachable → `access_denied`.
fn consent_finish_inner(s: &AuthState, headers: &HeaderMap, body: &[u8]) -> HandlerResult {
    s.same_origin(headers)?;
    let bad = || {
        s.page_error(
            StatusCode::BAD_REQUEST,
            "Request rejected",
            "The consent form was invalid.",
        )
    };
    let form = parse_unique_params(body).ok_or_else(bad)?;
    let (p, tx) = consent_form(s, headers, &form)?;
    let backend = origin_backend(s, &p)?;
    let now = s.now();
    let stage =
        s.0.origin_txs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&p.id)
            .map(|t| (t.stage.clone(), t.grant_id.clone()));
    match stage {
        Some((
            OriginStage::Approved {
                resource_scope,
                lifetime_secs,
                approval,
                at,
            },
            grant_id,
        )) => {
            let lifetime = i64::try_from(lifetime_secs)
                .unwrap_or(i64::MAX)
                .min(backend.grant_lifetime_secs);
            let scope = serde_json::to_string(&resource_scope).map_err(|_| bad())?;
            let res = issue_code(
                s,
                &p,
                &backend.id,
                &grant_id,
                &scope,
                Some(&approval),
                at + lifetime,
                now,
                bad(),
            )?;
            s.0.origin_txs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&p.id);
            Ok(res)
        }
        Some((OriginStage::Denied | OriginStage::Timeout | OriginStage::Unreachable(_), _)) => {
            s.cancel_origin_attempt(&p.id);
            deny_redirect(s, &p, now, bad())
        }
        Some((OriginStage::Sent, _)) | None => Ok(redirect_303(&format!("/consent?tx={tx}"))),
    }
}

async fn consent_cancel(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || {
        s.same_origin(&headers)?;
        let bad = || {
            s.page_error(
                StatusCode::BAD_REQUEST,
                "Request rejected",
                "The consent form was invalid.",
            )
        };
        let form = parse_unique_params(&body).ok_or_else(bad)?;
        let (p, _) = consent_form(&s, &headers, &form)?;
        origin_backend(&s, &p)?;
        s.cancel_origin_attempt(&p.id);
        deny_redirect(&s, &p, s.now(), bad())
    })
    .await
}

// ------------------------------------------------------------- owner proof

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStart {
    #[serde(default)]
    tx: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterStart {
    #[serde(default)]
    enroll_code: Option<String>,
}

fn json_api_guard(s: &AuthState, headers: &HeaderMap) -> Result<(), Response> {
    s.same_origin(headers)?;
    if !content_type_is(headers, "application/json") {
        return Err(oauth_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "invalid_request",
        ));
    }
    Ok(())
}

fn ceremony_response(options: Value, secret: &str) -> Response {
    let mut res = json_response(StatusCode::OK, options);
    res.headers_mut().append(
        SET_COOKIE,
        cookie_header(CEREMONY_COOKIE, secret, CEREMONY_TTL),
    );
    res
}

async fn login_start(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || login_start_inner(&s, ip_of(&ip), &headers, &body)).await
}

fn login_start_inner(
    s: &AuthState,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> HandlerResult {
    json_api_guard(s, headers)?;
    s.limit("owner", ip, s.config().limits.owner_per_ip_per_minute, 60)?;
    let req: LoginStart = serde_json::from_slice(body)
        .map_err(|_| oauth_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if let Some(tx) = &req.tx {
        s.pending_for_browser(tx, headers)
            .map_err(|_| oauth_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    }
    let creds = s.db("passkeys", s.0.store.passkeys())?;
    if creds.is_empty() {
        return Err(oauth_error(StatusCode::CONFLICT, "not_enrolled"));
    }
    let (options, state) =
        s.0.proof
            .start_login(&creds)
            .map_err(|_| oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    let secret = s.put_ceremony(CeremonyKind::Login { tx: req.tx }, state, ip);
    Ok(ceremony_response(options, &secret))
}

async fn login_finish(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || login_finish_inner(&s, ip_of(&ip), &headers, &body)).await
}

fn login_finish_inner(
    s: &AuthState,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> HandlerResult {
    json_api_guard(s, headers)?;
    s.limit("owner", ip, s.config().limits.owner_per_ip_per_minute, 60)?;
    let failed = || oauth_error(StatusCode::UNAUTHORIZED, "owner_proof_failed");
    let ceremony = s.take_ceremony(headers).ok_or_else(failed)?;
    let CeremonyKind::Login { tx } = ceremony.kind else {
        return Err(failed());
    };
    let response: Value = serde_json::from_slice(body).map_err(|_| failed())?;
    let creds = s.db("passkeys", s.0.store.passkeys())?;
    let proof = match s.0.proof.finish_login(ceremony.state, &response, &creds) {
        Ok(p) => p,
        Err(_) => {
            s.log("event=owner_login_failed");
            return Err(failed());
        }
    };
    let now = s.now();
    s.db(
        "passkeys",
        s.0.store.passkey_used(
            &proof.cred_id,
            proof.updated.as_ref().map(|c| c.data.as_str()),
            now,
        ),
    )?;
    if let Some(tx) = tx {
        // The ceremony was started for this request in this browser; bind the
        // proof to it only if the request is still live and still ours.
        let (p, _) = s
            .pending_for_browser(&tx, headers)
            .map_err(|_| oauth_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
        if !s.db("pending", s.0.store.mark_pending_verified(&p.id, now))? {
            return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
        }
    }
    let session = random_secret("");
    s.db(
        "session",
        s.0.store
            .insert_session(&hash_secret(&session), now, now + SESSION_TTL),
    )?;
    s.log("event=owner_login");
    let mut res = json_response(StatusCode::OK, json!({ "ok": true }));
    let h = res.headers_mut();
    h.append(
        SET_COOKIE,
        cookie_header(SESSION_COOKIE, &session, SESSION_TTL),
    );
    h.append(SET_COOKIE, cookie_header(CEREMONY_COOKIE, "", 0));
    Ok(res)
}

async fn register_start(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || register_start_inner(&s, ip_of(&ip), &headers, &body)).await
}

fn register_start_inner(
    s: &AuthState,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> HandlerResult {
    json_api_guard(s, headers)?;
    s.limit("owner", ip, s.config().limits.owner_per_ip_per_minute, 60)?;
    let req: RegisterStart = serde_json::from_slice(body)
        .map_err(|_| oauth_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let existing = s.db("passkeys", s.0.store.passkeys())?;
    let now = s.now();
    let kind = if existing.is_empty() {
        let Some(configured) = s.0.enroll_code.as_deref() else {
            return Err(oauth_error(StatusCode::FORBIDDEN, "enrollment_disabled"));
        };
        // Wrong codes are limited per client network (`max_enroll_failures`
        // per 15 min) and globally (`max_enroll_failures_global` per hour).
        // Locks lift by themselves. The check, comparison and increment all
        // happen under one lock, so parallel guesses cannot overshoot.
        let limits = &s.config().limits;
        let net = ip.map(support::network_key);
        let mut failures =
            s.0.enroll_failures
                .lock()
                .unwrap_or_else(|e| e.into_inner());
        failures
            .per_net
            .retain(|_, (start, _)| now - *start < ENROLL_LOCK_WINDOW);
        if now - failures.global.0 >= ENROLL_GLOBAL_WINDOW {
            failures.global = (now, 0);
        }
        let net_failures = failures.per_net.get(&net).map_or(0, |(_, n)| *n);
        if net_failures >= limits.max_enroll_failures
            || failures.global.1 >= limits.max_enroll_failures_global
        {
            return Err(oauth_error(
                StatusCode::TOO_MANY_REQUESTS,
                "enrollment_locked",
            ));
        }
        // Compare digests: constant time and independent of the code's length.
        let provided = req.enroll_code.unwrap_or_default();
        if !ct_eq(&hash_secret(&provided), &hash_secret(configured)) {
            failures.per_net.entry(net).or_insert((now, 0)).1 += 1;
            failures.global.1 += 1;
            drop(failures);
            s.log("event=enroll_code_rejected");
            return Err(oauth_error(
                StatusCode::FORBIDDEN,
                "invalid_enrollment_code",
            ));
        }
        let code_hash = hash_secret(configured);
        if s.db("enroll", s.0.store.enroll_code_consumed(&code_hash))? {
            return Err(oauth_error(StatusCode::FORBIDDEN, "enrollment_consumed"));
        }
        CeremonyKind::Register {
            bootstrap_code_hash: Some(code_hash),
        }
    } else {
        match s.session(headers)? {
            Some((_, auth_at)) if now - auth_at <= FRESH_PROOF => CeremonyKind::Register {
                bootstrap_code_hash: None,
            },
            _ => {
                return Err(oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "owner_session_required",
                ))
            }
        }
    };
    let (options, state) =
        s.0.proof
            .start_registration(&s.0.owner_id, &existing)
            .map_err(|_| oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    let secret = s.put_ceremony(kind, state, ip);
    Ok(ceremony_response(options, &secret))
}

async fn register_finish(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || register_finish_inner(&s, ip_of(&ip), &headers, &body)).await
}

fn register_finish_inner(
    s: &AuthState,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> HandlerResult {
    json_api_guard(s, headers)?;
    s.limit("owner", ip, s.config().limits.owner_per_ip_per_minute, 60)?;
    let failed = || oauth_error(StatusCode::UNAUTHORIZED, "owner_proof_failed");
    let ceremony = s.take_ceremony(headers).ok_or_else(failed)?;
    let CeremonyKind::Register {
        bootstrap_code_hash,
    } = ceremony.kind
    else {
        return Err(failed());
    };
    let response: Value = serde_json::from_slice(body).map_err(|_| failed())?;
    let cred =
        s.0.proof
            .finish_registration(ceremony.state, &response)
            .map_err(|_| failed())?;
    let now = s.now();
    let stored = match bootstrap_code_hash {
        Some(code_hash) => s.db(
            "enroll",
            s.0.store.enroll_first_passkey(&code_hash, &cred, now),
        )?,
        None => {
            if s.session(headers)?.is_none() {
                return Err(oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "owner_session_required",
                ));
            }
            s.db("passkeys", s.0.store.add_passkey(&cred, now))?
        }
    };
    if !stored {
        return Err(oauth_error(StatusCode::CONFLICT, "enrollment_closed"));
    }
    s.log("event=passkey_registered");
    let mut res = json_response(StatusCode::OK, json!({ "ok": true }));
    res.headers_mut()
        .append(SET_COOKIE, cookie_header(CEREMONY_COOKIE, "", 0));
    Ok(res)
}

// ------------------------------------------------------------- owner pages

async fn owner_home(State(s): State<AuthState>, headers: HeaderMap) -> Response {
    blocking(move || owner_home_inner(&s, &headers)).await
}

fn owner_home_inner(s: &AuthState, headers: &HeaderMap) -> HandlerResult {
    let Some((session, _)) = s.session(headers)? else {
        let enrolled = s.db("passkeys", s.0.store.passkey_count())? > 0;
        return Ok(s.html(StatusCode::OK, pages::owner_login(enrolled)));
    };
    let now = s.now();
    let grants = s
        .db("grants", s.0.store.active_grants(now))?
        .into_iter()
        .map(|(g, name)| pages::GrantView {
            id: g.id,
            client: name
                .filter(|n| !n.is_empty())
                .map(|n| format!("{n} ({})", g.client_id))
                .unwrap_or(g.client_id),
            backend: g.backend,
            created: format_time(g.created),
            expires: format_time(g.expires),
            last_used: g
                .last_used
                .map(format_time)
                .unwrap_or_else(|| "never".into()),
        })
        .collect::<Vec<_>>();
    let panels = s.origin_port().map(|p| p.panels()).unwrap_or_default();
    Ok(s.html(
        StatusCode::OK,
        pages::owner_home(&grants, &panels, &s.owner_csrf(&session)),
    ))
}

async fn enroll_page(State(s): State<AuthState>) -> Response {
    blocking(move || {
        let enrolled = s.db("passkeys", s.0.store.passkey_count())? > 0;
        Ok(s.html(StatusCode::OK, pages::enroll(enrolled)))
    })
    .await
}

fn owner_form(
    s: &AuthState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(HashMap<String, String>, String), Response> {
    s.same_origin(headers)?;
    let denied = || {
        s.page_error(
            StatusCode::FORBIDDEN,
            "Not allowed",
            "Sign in again at /owner.",
        )
    };
    let form = parse_unique_params(body).ok_or_else(denied)?;
    let (session, _) = s.session(headers)?.ok_or_else(denied)?;
    let csrf = form.get("csrf").map(String::as_str).unwrap_or("");
    if !ct_eq(csrf, &s.owner_csrf(&session)) {
        return Err(denied());
    }
    Ok((form, session))
}

async fn owner_revoke(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || {
        (|| {
            let (form, _) = owner_form(&s, &headers, &body)?;
            let grant_id = form.get("grant_id").map(String::as_str).unwrap_or("");
            if let Some(r) = s.db("grants", s.0.store.revoke_grant(grant_id))? {
                s.log(&format!("event=grant_revoked by=owner grant={grant_id}"));
                s.notify_revoked(&[r], RevokeReason::Owner);
            }
            let mut res = redirect_303("/owner");
            res.extensions_mut()
                .insert(LoggedGrant(grant_id.to_owned()));
            Ok(res)
        })()
    })
    .await
}

async fn owner_revoke_all(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || {
        (|| {
            owner_form(&s, &headers, &body)?;
            let revoked = s.db("grants", s.0.store.revoke_all_grants())?;
            s.log(&format!(
                "event=grants_revoked by=owner count={}",
                revoked.len()
            ));
            s.notify_revoked(&revoked, RevokeReason::Owner);
            Ok(redirect_303("/owner"))
        })()
    })
    .await
}

async fn owner_logout(State(s): State<AuthState>, headers: HeaderMap, body: Bytes) -> Response {
    blocking(move || {
        (|| {
            let (_, session) = owner_form(&s, &headers, &body)?;
            s.db("session", s.0.store.delete_session(&hash_secret(&session)))?;
            let mut res = redirect_303("/owner");
            res.headers_mut()
                .append(SET_COOKIE, cookie_header(SESSION_COOKIE, "", 0));
            Ok(res)
        })()
    })
    .await
}

// ------------------------------------------------------------------ tokens

async fn token(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || token_inner(&s, ip_of(&ip), &headers, &body)).await
}

fn token_form(
    s: &AuthState,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<HashMap<String, String>, Response> {
    if !content_type_is(headers, "application/x-www-form-urlencoded") {
        return Err(oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let form = parse_unique_params(body)
        .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    // Public clients only: any client authentication attempt is refused.
    if headers.contains_key(AUTHORIZATION)
        || form.get("client_secret").is_some_and(|v| !v.is_empty())
    {
        return Err(oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"));
    }
    let client_id = form
        .get("client_id")
        .filter(|c| !c.is_empty())
        .ok_or_else(|| oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"))?;
    if s.db("clients", s.0.store.client(client_id))?.is_none() {
        return Err(oauth_error(StatusCode::UNAUTHORIZED, "invalid_client"));
    }
    Ok(form)
}

fn token_inner(
    s: &AuthState,
    ip: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    body: &[u8],
) -> HandlerResult {
    s.limit("token", ip, s.config().limits.token_per_ip_per_minute, 60)?;
    let form = token_form(s, headers, body)?;
    let get = |k: &str| form.get(k).map(String::as_str).filter(|v| !v.is_empty());
    let client_id = get("client_id").unwrap_or_default();
    let invalid_grant = || oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    let now = s.now();
    let access = random_secret("mea_");
    let refresh = random_secret("mer_");
    let grant = match get("grant_type") {
        Some("authorization_code") => {
            let code = get("code").ok_or_else(invalid_grant)?;
            let verifier = get("code_verifier").ok_or_else(invalid_grant)?;
            // Optional (PKCE and the client binding already tie the code to
            // this client); exact match when present.
            let redirect_uri = get("redirect_uri");
            let row = match s.db("codes", s.0.store.take_code(&hash_secret(code)))? {
                CodeTake::Missing => return Err(invalid_grant()),
                CodeTake::Reused(grant_id) => {
                    // A replayed code may mean it leaked: revoke what it produced.
                    if let Some(r) = s.db("grants", s.0.store.revoke_grant(&grant_id))? {
                        s.notify_revoked(&[r], RevokeReason::Replay);
                    }
                    s.log(&format!("event=code_reuse grant={grant_id} action=revoked"));
                    return Err(invalid_grant());
                }
                CodeTake::Fresh(row) => row,
            };
            let resource_ok = match get("resource") {
                None => true,
                Some(r) => s
                    .config()
                    .backend_for_resource(r)
                    .is_some_and(|b| b.id == row.backend),
            };
            let ok = row.expires > now
                && row.client_id == client_id
                && redirect_uri.is_none_or(|r| r == row.redirect_uri)
                && resource_ok
                && valid_verifier(verifier)
                && pkce_s256_matches(verifier, &row.challenge);
            if !ok {
                // The code is burnt; its pending grant can never activate.
                if let Some(r) = s.db("grants", s.0.store.revoke_grant(&row.grant_id))? {
                    s.notify_revoked(&[r], RevokeReason::Client);
                }
                return Err(invalid_grant());
            }
            s.db(
                "grants",
                s.0.store.activate_grant(
                    &row.grant_id,
                    &hash_secret(&access),
                    now + ACCESS_TTL,
                    &hash_secret(&refresh),
                    now,
                ),
            )?
            .ok_or_else(invalid_grant)?
        }
        Some("refresh_token") => {
            let presented = get("refresh_token").ok_or_else(invalid_grant)?;
            let expected_backend = match get("resource") {
                None => None,
                Some(r) => Some(
                    s.config()
                        .backend_for_resource(r)
                        .map(|b| b.id.clone())
                        .ok_or_else(invalid_grant)?,
                ),
            };
            let outcome = s.db(
                "refresh",
                s.0.store.rotate_refresh(
                    &hash_secret(presented),
                    client_id,
                    expected_backend.as_deref(),
                    &hash_secret(&access),
                    now + ACCESS_TTL,
                    &hash_secret(&refresh),
                    now,
                    REFRESH_GRACE,
                ),
            )?;
            // A `scope` parameter is ignored: refreshed tokens always carry
            // exactly the grant's scope, so refresh can never widen it.
            match outcome {
                RefreshOutcome::Rotated { grant, grace } => {
                    if grace {
                        s.log(&format!("event=refresh_grace grant={}", grant.id));
                    }
                    grant
                }
                RefreshOutcome::FamilyRevoked(grant_id, revoked) => {
                    s.log(&format!(
                        "event=refresh_reuse grant={grant_id} action=family_revoked"
                    ));
                    s.notify_revoked(revoked.as_slice(), RevokeReason::Replay);
                    return Err(invalid_grant());
                }
                RefreshOutcome::Missing | RefreshOutcome::Inactive => return Err(invalid_grant()),
            }
        }
        _ => {
            return Err(oauth_error(
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
            ))
        }
    };
    let mut res = json_response(
        StatusCode::OK,
        json!({
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": refresh,
            "scope": grant.scope,
        }),
    );
    res.extensions_mut().insert(LoggedGrant(grant.id));
    Ok(res)
}

async fn revoke(
    State(s): State<AuthState>,
    ip: Option<Extension<ClientIp>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    blocking(move || {
        (|| {
            s.limit(
                "token",
                ip_of(&ip),
                s.config().limits.token_per_ip_per_minute,
                60,
            )?;
            let form = token_form(&s, &headers, &body)?;
            let token = form
                .get("token")
                .filter(|t| !t.is_empty())
                .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
            let client_id = form.get("client_id").map(String::as_str).unwrap_or("");
            let mut res = no_store(StatusCode::OK.into_response());
            if let Some((grant_id, owner)) =
                s.db("revoke", s.0.store.grant_for_any_token(&hash_secret(token)))?
            {
                // RFC 7009: a token of another client is silently ignored.
                if owner == client_id {
                    if let Some(r) = s.db("revoke", s.0.store.revoke_grant(&grant_id))? {
                        s.log(&format!("event=grant_revoked by=client grant={grant_id}"));
                        s.notify_revoked(&[r], RevokeReason::Client);
                        res.extensions_mut().insert(LoggedGrant(grant_id));
                    }
                }
            }
            Ok(res)
        })()
    })
    .await
}
