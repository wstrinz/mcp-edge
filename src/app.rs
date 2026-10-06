//! Router composition: authorization server, gateway (`/<backend>/mcp`),
//! health, and the cross-cutting limits and request log.

use crate::{
    config::{Route, RouteKind},
    echo::{EchoBackend, SUPPORTED_PROTOCOL_VERSIONS},
};
use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, MatchedPath, Path, Request, State},
    http::{
        header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, Method, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use edge_assert::{GrantContext, RequestBinding, Signer};
use edge_auth::{
    config::{AuthConfig, BackendPolicy, ConsentMode, Limits},
    owner::OwnerProof,
    support::{ClientIp, Clock, LogSink},
    AccessGrant, AuthState, BearerError, InitError, LoggedGrant,
};
use http_body_util::BodyExt;
use serde_json::json;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

/// Assertion lifetime for forwarded requests.
pub const ASSERTION_TTL: i64 = 60;
/// Total request-header bytes accepted.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;

/// Limits enforced by the edge itself (the auth crate has its own).
#[derive(Clone, Debug)]
pub struct EdgeLimits {
    /// All requests, per client IP, per minute (before authentication).
    pub per_ip_per_minute: u32,
    /// Authenticated MCP requests per grant per minute.
    pub per_grant_per_minute: u32,
    /// Deadline for reading the request and producing a response.
    pub request_timeout: Duration,
}

impl Default for EdgeLimits {
    fn default() -> Self {
        Self {
            per_ip_per_minute: 600,
            per_grant_per_minute: 300,
            request_timeout: Duration::from_secs(30),
        }
    }
}

pub struct AppConfig {
    pub issuer: String,
    pub routes: Vec<Route>,
    pub redirect_allowlist: Vec<String>,
    pub enroll_code: Option<String>,
    pub trust_forwarded_for: bool,
    pub auth_limits: Limits,
    pub edge_limits: EdgeLimits,
}

pub struct AppDeps {
    /// SQLite file; `None` keeps everything in memory.
    pub db_path: Option<PathBuf>,
    pub proof: Arc<dyn OwnerProof>,
    pub clock: Arc<dyn Clock>,
    pub log: Arc<dyn LogSink>,
    /// Ed25519 seed for edge assertions.
    pub signing_seed: [u8; 32],
}

pub struct App {
    pub router: Router,
    pub auth: AuthState,
    /// base64url Ed25519 public key that backends verify assertions with.
    pub assertion_public_key: String,
}

/// Response extension naming the backend (for request logs).
#[derive(Clone)]
struct LoggedBackend(String);

enum Handler {
    Echo(EchoBackend),
}

struct Backend {
    route: Route,
    handler: Handler,
}

struct Edge {
    auth: AuthState,
    signer: Signer,
    backends: HashMap<String, Backend>,
    trust_forwarded_for: bool,
    limits: EdgeLimits,
}

pub fn build(cfg: AppConfig, deps: AppDeps) -> Result<App, InitError> {
    let signer = Signer::from_seed(&deps.signing_seed, cfg.issuer.clone());
    let public_key = signer.public_key_base64url();
    let mut backends = HashMap::new();
    let mut policies = Vec::new();
    for route in &cfg.routes {
        policies.push(BackendPolicy {
            id: route.id.clone(),
            display_name: route.display_name.clone(),
            scopes: route.scopes.clone(),
            grant_lifetime_secs: route.grant_lifetime_secs,
            consent: ConsentMode::Edge,
        });
        let handler = match route.kind {
            RouteKind::Echo => Handler::Echo(
                EchoBackend::new(&public_key, &cfg.issuer, &route.id)
                    .map_err(|_| InitError::Config("assertion key"))?,
            ),
        };
        backends.insert(
            route.id.clone(),
            Backend {
                route: route.clone(),
                handler,
            },
        );
    }
    let auth = AuthState::new(
        AuthConfig {
            issuer: cfg.issuer.clone(),
            redirect_allowlist: cfg.redirect_allowlist,
            enroll_code: cfg.enroll_code,
            backends: policies,
            limits: cfg.auth_limits,
        },
        deps.db_path.as_deref(),
        deps.proof,
        deps.clock,
        deps.log,
    )?;
    let edge = Arc::new(Edge {
        auth: auth.clone(),
        signer,
        backends,
        trust_forwarded_for: cfg.trust_forwarded_for,
        limits: cfg.edge_limits,
    });
    let gateway = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/.well-known/edge-assertion-key", get(assertion_key))
        .route(
            "/{backend}/mcp",
            axum::routing::post(mcp_post).fallback(mcp_other_method),
        )
        .with_state(edge.clone());
    let router = edge_auth::router(auth.clone())
        .merge(gateway)
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(edge.clone(), guard))
        .layer(middleware::from_fn_with_state(edge, request_log));
    Ok(App {
        router,
        auth,
        assertion_public_key: public_key,
    })
}

fn json_error(status: StatusCode, code: &'static str) -> Response {
    (status, axum::Json(json!({ "error": code }))).into_response()
}

async fn not_found() -> Response {
    json_error(StatusCode::NOT_FOUND, "not_found")
}

async fn healthz() -> Response {
    axum::Json(json!({ "status": "alive", "mode": "edge" })).into_response()
}

async fn readyz(State(edge): State<Arc<Edge>>) -> Response {
    if edge.auth.ready() {
        axum::Json(json!({ "status": "ready" })).into_response()
    } else {
        json_error(StatusCode::SERVICE_UNAVAILABLE, "not_ready")
    }
}

async fn assertion_key(State(edge): State<Arc<Edge>>) -> Response {
    axum::Json(json!({
        "alg": "EdDSA",
        "crv": "Ed25519",
        "format": "edge-assert.v1",
        "issuer": edge.signer.issuer(),
        "public_key": edge.signer.public_key_base64url(),
    }))
    .into_response()
}

/// Client address for limits: the TCP peer, or — only when explicitly
/// configured behind the proxy — the right-most `X-Forwarded-For` entry, which
/// is the address the proxy itself observed.
fn client_ip(edge: &Edge, req: &Request) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    if !edge.trust_forwarded_for {
        return peer;
    }
    req.headers()
        .get_all("x-forwarded-for")
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.rsplit(',').next())
        .and_then(|v| v.trim().parse::<IpAddr>().ok())
        .or(peer)
}

/// Pre-routing guard: refuse proxy-style requests, apply the per-IP limit and
/// the overall request deadline, and set conservative response headers.
async fn guard(State(edge): State<Arc<Edge>>, mut req: Request, next: Next) -> Response {
    if req.uri().scheme().is_some()
        || req.uri().authority().is_some()
        || req.method() == Method::CONNECT
    {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    // hyper's buffer limit is not a strict header cap; enforce one here.
    if crate::deny_all::header_bytes(req.headers()) > MAX_HEADER_BYTES {
        return json_error(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "headers_too_large",
        );
    }
    let ip = client_ip(&edge, &req);
    if let Some(ip) = ip {
        req.extensions_mut().insert(ClientIp(ip));
    }
    let now = edge.auth.now();
    if !edge
        .auth
        .limiter()
        .allow("global", ip, edge.limits.per_ip_per_minute, 60, now)
    {
        let mut res = json_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        res.headers_mut()
            .insert("retry-after", HeaderValue::from_static("60"));
        return res;
    }
    let mut res = match tokio::time::timeout(edge.limits.request_timeout, next.run(req)).await {
        Ok(res) => res,
        Err(_) => json_error(StatusCode::SERVICE_UNAVAILABLE, "timeout"),
    };
    let h = res.headers_mut();
    h.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    if !h.contains_key(CACHE_CONTROL) {
        h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    if !h.contains_key("referrer-policy") {
        h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    }
    res
}

/// One line per request: method, route template, status, duration, backend
/// and grant id. Never paths with parameters, queries, headers or bodies.
async fn request_log(State(edge): State<Arc<Edge>>, req: Request, next: Next) -> Response {
    let start = Instant::now();
    let method = req.method().clone();
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "-".into());
    let res = next.run(req).await;
    let grant = res
        .extensions()
        .get::<LoggedGrant>()
        .map(|g| g.0.as_str())
        .unwrap_or("-");
    let backend = res
        .extensions()
        .get::<LoggedBackend>()
        .map(|b| b.0.as_str())
        .unwrap_or("-");
    edge.auth.log(&format!(
        "req method={} route={} status={} ms={} backend={} grant={}",
        method,
        route,
        res.status().as_u16(),
        start.elapsed().as_millis(),
        backend,
        grant
    ));
    res
}

fn challenge(edge: &Edge, backend: &str, error: Option<&'static str>) -> Response {
    let metadata = edge.auth.config().resource_metadata_url(backend);
    let value = match error {
        None => format!("Bearer resource_metadata=\"{metadata}\""),
        Some(e) => format!("Bearer error=\"{e}\", resource_metadata=\"{metadata}\""),
    };
    let mut res = json_error(StatusCode::UNAUTHORIZED, error.unwrap_or("unauthorized"));
    if let Ok(v) = HeaderValue::from_str(&value) {
        res.headers_mut().insert(WWW_AUTHENTICATE, v);
    }
    res
}

async fn mcp_other_method(State(edge): State<Arc<Edge>>, Path(backend): Path<String>) -> Response {
    if !edge.backends.contains_key(&backend) {
        return json_error(StatusCode::NOT_FOUND, "not_found");
    }
    let mut res = json_error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    res.headers_mut()
        .insert(ALLOW, HeaderValue::from_static("POST"));
    res
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

async fn mcp_post(
    State(edge): State<Arc<Edge>>,
    Path(backend_id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(backend) = edge.backends.get(&backend_id) else {
        return json_error(StatusCode::NOT_FOUND, "not_found");
    };
    // Authenticate before reading the body.
    let grant: AccessGrant = match edge.auth.authenticate_bearer(&headers, &backend.route.id) {
        Ok(g) => g,
        Err(BearerError::Missing) => return challenge(&edge, &backend.route.id, None),
        Err(BearerError::Invalid) => {
            return challenge(&edge, &backend.route.id, Some("invalid_token"))
        }
    };
    let tag = |mut res: Response| {
        res.extensions_mut()
            .insert(LoggedGrant(grant.grant_id.clone()));
        res.extensions_mut()
            .insert(LoggedBackend(backend.route.id.clone()));
        res
    };
    let now = edge.auth.now();
    if !edge.auth.limiter().allow_id(
        "grant",
        &grant.grant_id,
        edge.limits.per_grant_per_minute,
        60,
        now,
    ) {
        return tag(json_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"));
    }
    if let Some(v) = headers.get("mcp-protocol-version") {
        let ok = v
            .to_str()
            .is_ok_and(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(&v));
        if !ok {
            return tag(json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_protocol_version",
            ));
        }
    }
    if !is_json(&headers) {
        return tag(json_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let limited = http_body_util::Limited::new(body, backend.route.max_request_bytes);
    let bytes: Bytes = match limited.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return tag(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
            ))
        }
    };
    let binding = RequestBinding {
        method: "POST",
        path: "/mcp",
        body: &bytes,
    };
    let assertion = match edge.signer.mint(
        &GrantContext {
            aud: backend.route.id.clone(),
            sub: grant.sub.clone(),
            client_id: grant.client_id.clone(),
            grant_id: grant.grant_id.clone(),
            scope: grant.scope.clone(),
            resource_scope: grant.resource_scope.clone(),
            gen: grant.gen,
        },
        binding,
        now,
        ASSERTION_TTL,
    ) {
        Ok(a) => a,
        Err(_) => {
            return tag(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
            ))
        }
    };
    let reply = match &backend.handler {
        Handler::Echo(echo) => echo.handle(Some(&assertion), "POST", "/mcp", &bytes, now),
    };
    let res = match (reply.status, reply.body) {
        (202, _) => StatusCode::ACCEPTED.into_response(),
        (401, _) => {
            // The backend refused the edge's own assertion: an internal fault,
            // never something the client can fix with its token.
            edge.auth.log(&format!(
                "event=backend_rejected_assertion backend={}",
                backend.route.id
            ));
            json_error(StatusCode::BAD_GATEWAY, "backend_rejected")
        }
        (status, Some(body)) => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY),
            [(CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        (status, None) => StatusCode::from_u16(status)
            .unwrap_or(StatusCode::BAD_GATEWAY)
            .into_response(),
    };
    tag(res)
}
