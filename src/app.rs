//! Router composition: authorization server, gateway (`/<backend>/mcp`),
//! health, and the cross-cutting limits and request log.

use crate::{
    config::{forwarded_client, Cidr, Route, RouteKind},
    echo::{EchoBackend, SUPPORTED_PROTOCOL_VERSIONS},
    forward::{self, HttpBackend, Outgoing},
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
    routing::{any, get},
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
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Assertion lifetime for forwarded requests.
pub const ASSERTION_TTL: i64 = 60;
/// Total request-header bytes accepted.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Largest body any OAuth/owner route accepts (route limits are smaller).
const AUTH_BODY_LIMIT: usize = 64 * 1024;

/// Limits enforced by the edge itself (the auth crate has its own).
#[derive(Clone, Debug)]
pub struct EdgeLimits {
    /// All requests, per client IP, per minute (before authentication).
    pub per_ip_per_minute: u32,
    /// Authenticated MCP requests per grant per minute.
    pub per_grant_per_minute: u32,
    /// Deadline for reading the request and producing a response.
    pub request_timeout: Duration,
    /// Requests one client network may have in flight at once.
    pub per_ip_concurrent: usize,
    /// Deadline for receiving the whole body of a non-MCP (OAuth/owner) request.
    pub auth_body_timeout: Duration,
}

impl Default for EdgeLimits {
    fn default() -> Self {
        Self {
            per_ip_per_minute: 600,
            per_grant_per_minute: 300,
            request_timeout: Duration::from_secs(30),
            per_ip_concurrent: 8,
            auth_body_timeout: Duration::from_secs(5),
        }
    }
}

pub struct AppConfig {
    pub issuer: String,
    pub routes: Vec<Route>,
    pub redirect_allowlist: Vec<String>,
    pub enroll_code: Option<String>,
    /// Peers whose `X-Forwarded-For` is honoured.
    pub trusted_proxies: Vec<Cidr>,
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
    Http(HttpBackend),
}

struct Backend {
    route: Route,
    handler: Handler,
}

struct Edge {
    auth: AuthState,
    signer: Signer,
    backends: HashMap<String, Backend>,
    trusted_proxies: Vec<Cidr>,
    limits: EdgeLimits,
    inflight: Mutex<HashMap<IpAddr, usize>>,
}

/// Holds one in-flight slot for a client network; released on drop (also when
/// the request future is cancelled by a deadline or a closed connection).
struct InflightSlot {
    edge: Arc<Edge>,
    net: IpAddr,
}

impl InflightSlot {
    fn acquire(edge: &Arc<Edge>, net: IpAddr) -> Option<Self> {
        let mut map = edge.inflight.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(net).or_insert(0);
        if *count >= edge.limits.per_ip_concurrent.max(1) {
            return None;
        }
        *count += 1;
        Some(Self {
            edge: edge.clone(),
            net,
        })
    }
}

impl Drop for InflightSlot {
    fn drop(&mut self) {
        let mut map = self.edge.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.net) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.net);
            }
        }
    }
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
            RouteKind::Http => {
                let upstream = route
                    .http
                    .as_ref()
                    .ok_or(InitError::Config("http backend without upstream"))?;
                Handler::Http(
                    HttpBackend::new(&route.id, upstream)
                        .map_err(|_| InitError::Config("http client"))?,
                )
            }
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
        trusted_proxies: cfg.trusted_proxies,
        limits: cfg.edge_limits,
        inflight: Mutex::new(HashMap::new()),
    });
    let gateway = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/.well-known/edge-assertion-key", get(assertion_key))
        .route("/{backend}/mcp", any(mcp))
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
    // The store check runs on the blocking pool with its own deadline.
    let auth = edge.auth.clone();
    let ready = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::task::spawn_blocking(move || auth.ready()),
    )
    .await;
    if matches!(ready, Ok(Ok(true))) {
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

/// Client address for limits: the TCP peer, or, when the peer is a trusted
/// proxy, the right-most untrusted `X-Forwarded-For` hop.
fn client_ip(edge: &Edge, req: &Request) -> Option<IpAddr> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip())?;
    let xff: Vec<&str> = req
        .headers()
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    Some(forwarded_client(peer, &xff, &edge.trusted_proxies))
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
    // Slow-request defence (Traefik streams bodies through): a client network
    // holds at most `per_ip_concurrent` requests in flight, and OAuth/owner
    // bodies must arrive within `auth_body_timeout`.
    let is_health = req.uri().path() == "/healthz";
    let _slot = match ip {
        Some(ip) if !is_health => {
            match InflightSlot::acquire(&edge, edge_auth::support::network_key(ip)) {
                Some(slot) => Some(slot),
                None => return json_error(StatusCode::TOO_MANY_REQUESTS, "too_many_in_flight"),
            }
        }
        _ => None,
    };
    let is_mcp = req
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|m| m.as_str() == "/{backend}/mcp");
    let deadline = tokio::time::Instant::now() + edge.limits.request_timeout;
    if !is_mcp && req.method() != Method::GET && req.method() != Method::HEAD {
        let (parts, body) = req.into_parts();
        let limited = http_body_util::Limited::new(body, AUTH_BODY_LIMIT);
        let bytes = match tokio::time::timeout(edge.limits.auth_body_timeout, limited.collect())
            .await
        {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(_)) => return json_error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
            Err(_) => return json_error(StatusCode::REQUEST_TIMEOUT, "request_timeout"),
        };
        req = Request::from_parts(parts, Body::from(bytes));
    }
    let mut res = match tokio::time::timeout_at(deadline, next.run(req)).await {
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
    res.extensions_mut()
        .insert(LoggedBackend(backend.to_owned()));
    res
}

fn method_not_allowed(allow: &'static str) -> Response {
    let mut res = json_error(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed");
    res.headers_mut()
        .insert(ALLOW, HeaderValue::from_static(allow));
    res
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
}

/// Read at most `limit` body bytes (the overall request deadline bounds time).
async fn read_body(body: Body, limit: usize) -> Result<Bytes, Response> {
    match http_body_util::Limited::new(body, limit).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(_) => Err(json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_too_large",
        )),
    }
}

fn grant_context(backend: &Backend, grant: &AccessGrant) -> GrantContext {
    GrantContext {
        aud: backend.route.id.clone(),
        sub: grant.sub.clone(),
        client_id: grant.client_id.clone(),
        grant_id: grant.grant_id.clone(),
        scope: grant.scope.clone(),
        resource_scope: grant.resource_scope.clone(),
        gen: grant.gen,
    }
}

/// `<prefix>/mcp` for every backend: unknown backend -> 404, a method this
/// backend kind does not serve -> 405 (nothing is authenticated or read),
/// then the bearer token (bound to this backend) before the body is read,
/// the per-grant rate limit, and the backend-kind specific handling.
async fn mcp(
    State(edge): State<Arc<Edge>>,
    Path(backend_id): Path<String>,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(backend) = edge.backends.get(&backend_id) else {
        return json_error(StatusCode::NOT_FOUND, "not_found");
    };
    let allowed = match &backend.handler {
        Handler::Echo(_) => method == Method::POST,
        Handler::Http(_) => forward::ALLOWED_METHODS.contains(&method),
    };
    if !allowed {
        let mut res = method_not_allowed(match &backend.handler {
            Handler::Echo(_) => "POST",
            Handler::Http(_) => forward::ALLOW_HEADER,
        });
        res.extensions_mut()
            .insert(LoggedBackend(backend.route.id.clone()));
        return res;
    }
    // Authenticate before reading the body (store lookup on the blocking pool).
    let auth = edge.auth.clone();
    let route_id = backend.route.id.clone();
    let bearer_headers = headers.clone();
    let authenticated =
        tokio::task::spawn_blocking(move || auth.authenticate_bearer(&bearer_headers, &route_id))
            .await
            .unwrap_or(Err(BearerError::Invalid));
    let grant: AccessGrant = match authenticated {
        Ok(g) => g,
        Err(BearerError::Missing) => return challenge(&edge, &backend.route.id, None),
        Err(BearerError::Invalid) => {
            return challenge(&edge, &backend.route.id, Some("invalid_token"))
        }
    };
    let now = edge.auth.now();
    let within_rate = edge.auth.limiter().allow_id(
        "grant",
        &grant.grant_id,
        edge.limits.per_grant_per_minute,
        60,
        now,
    );
    let result = if !within_rate {
        Err(json_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited"))
    } else {
        match &backend.handler {
            Handler::Echo(echo) => {
                echo_request(&edge, backend, echo, &grant, &headers, body, now).await
            }
            Handler::Http(http) => {
                let req = HttpCall {
                    method,
                    headers: &headers,
                    body,
                    now,
                };
                http_request(&edge, backend, http, &grant, req).await
            }
        }
    };
    let mut res = result.unwrap_or_else(|e| e);
    res.extensions_mut()
        .insert(LoggedGrant(grant.grant_id.clone()));
    res.extensions_mut()
        .insert(LoggedBackend(backend.route.id.clone()));
    res
}

/// The built-in echo backend: stateless JSON POST only.
async fn echo_request(
    edge: &Edge,
    backend: &Backend,
    echo: &EchoBackend,
    grant: &AccessGrant,
    headers: &HeaderMap,
    body: Body,
    now: i64,
) -> Result<Response, Response> {
    if let Some(v) = headers.get("mcp-protocol-version") {
        let ok = v
            .to_str()
            .is_ok_and(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(&v));
        if !ok {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "unsupported_protocol_version",
            ));
        }
    }
    if !is_json(headers) {
        return Err(json_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let bytes = read_body(body, backend.route.max_request_bytes).await?;
    let binding = RequestBinding {
        method: "POST",
        path: "/mcp",
        body: &bytes,
    };
    let assertion = edge
        .signer
        .mint(&grant_context(backend, grant), binding, now, ASSERTION_TTL)
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    let reply = echo.handle(Some(&assertion), "POST", "/mcp", &bytes, now);
    Ok(match (reply.status, reply.body) {
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
    })
}

/// The client request as the http forwarder needs it.
struct HttpCall<'a> {
    method: Method,
    headers: &'a HeaderMap,
    body: Body,
    now: i64,
}

/// A `kind = "http"` backend. The upstream request is built from scratch
/// (see `forward`): configured URL, allowlisted headers, the exact body, and
/// an assertion over (method, upstream path, body) minted here, so a
/// client-supplied `Edge-Assertion` can never reach the upstream.
async fn http_request(
    edge: &Edge,
    backend: &Backend,
    http: &HttpBackend,
    grant: &AccessGrant,
    call: HttpCall<'_>,
) -> Result<Response, Response> {
    let HttpCall {
        method,
        headers,
        body,
        now,
    } = call;
    let forwarded = forward::select_request_headers(headers)
        .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    if method == Method::POST && !is_json(headers) {
        return Err(json_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_media_type",
        ));
    }
    let slot = http
        .try_acquire(&grant.grant_id)
        .ok_or_else(|| json_error(StatusCode::TOO_MANY_REQUESTS, "too_many_in_flight"))?;
    // GET (SSE stream) and DELETE (session end) carry no body upstream; a
    // client body there is refused rather than silently dropped.
    let bytes = if method == Method::POST {
        read_body(body, backend.route.max_request_bytes).await?
    } else {
        read_body(body, 0)
            .await
            .map_err(|_| json_error(StatusCode::BAD_REQUEST, "invalid_request"))?
    };
    let binding = RequestBinding {
        method: method.as_str(),
        path: http.upstream_path(),
        body: &bytes,
    };
    let assertion = edge
        .signer
        .mint(&grant_context(backend, grant), binding, now, ASSERTION_TTL)
        .map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))?;
    Ok(http
        .forward(
            Outgoing {
                method,
                headers: forwarded,
                body: bytes,
                assertion,
                grant_id: grant.grant_id.clone(),
            },
            slot,
            edge.auth.clone(),
        )
        .await)
}
