//! Environment and route-table configuration for `EDGE_MODE=edge`.

pub use edge_auth::config::ConsentMode;
use edge_auth::config::{CLAUDE_CALLBACK, DEFAULT_GRANT_LIFETIME};
use edge_tunnel::iroh::EndpointId;
use serde::Deserialize;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

/// Path segments that can never be backend ids.
const RESERVED: &[&str] = &[
    "authorize",
    "consent",
    "healthz",
    "owner",
    "readyz",
    "register",
    "revoke",
    "static",
    "token",
    "mcp",
    "well-known",
];
const MAX_BACKENDS: usize = 32;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_REQUEST_BYTES_LIMIT: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESPONSE_BYTES_LIMIT: usize = 16 * 1024 * 1024;
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
/// Time to the upstream's response headers. Must stay below the edge's
/// 30 s request deadline (which covers authentication and the request body).
pub const DEFAULT_RESPONSE_TIMEOUT_SECS: u64 = 20;
const MAX_RESPONSE_TIMEOUT_SECS: u64 = 25;
pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 60;
const MAX_IDLE_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_MAX_CONCURRENT_PER_GRANT: usize = 4;
const MAX_CONCURRENT_PER_GRANT_LIMIT: usize = 64;
/// `kind = "iroh"`: the tunnel's `mcp_post` caps (PHASE4.md §2.3) are the
/// upper bounds; a route may only lower them.
pub const IROH_MAX_REQUEST_BYTES: usize = edge_tunnel::limits::MCP_BODY;
pub const IROH_MAX_RESPONSE_BYTES: usize = edge_tunnel::limits::MCP_RESPONSE;
/// Required prefix of `origin_endpoint_env`, so a route can only name a
/// variable meant for it (never, say, `EDGE_ENROLL_CODE`).
pub const ORIGIN_ENV_PREFIX: &str = "EDGE_ORIGIN_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration error: {}", self.0)
    }
}
impl std::error::Error for ConfigError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(msg.into()))
}

/// What serves a route: the built-in echo backend, an HTTP upstream fixed in
/// the route table, or a local app reached over iroh (`mcp-edge/1`) whose
/// EndpointId comes from an environment variable named in the route table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Echo,
    Http,
    Iroh,
}

/// Settings of a `kind = "iroh"` backend (always `consent = "origin"`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohOrigin {
    /// Name of the environment variable holding the origin EndpointId.
    pub env: String,
    /// The configured origin; `None` until [`resolve_origins`] ran.
    pub origin_id: Option<EndpointId>,
    /// Response body cap (≤ the tunnel's 1 MiB).
    pub max_response_bytes: usize,
}

/// Settings of a `kind = "http"` backend. The upstream URL comes only from
/// the route table; nothing in a request can change it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpUpstream {
    /// The exact upstream MCP endpoint (canonical form, no query/fragment/userinfo).
    pub url: url::Url,
    pub max_response_bytes: usize,
    pub connect_timeout: Duration,
    /// Time to first byte (the upstream's response headers).
    pub response_timeout: Duration,
    /// Longest gap between response body chunks (SSE streams included).
    pub idle_timeout: Duration,
    /// Requests (including open streams) one grant may have in flight here.
    pub max_concurrent_per_grant: usize,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub id: String,
    pub kind: RouteKind,
    pub display_name: String,
    pub scopes: Vec<String>,
    pub grant_lifetime_secs: i64,
    pub max_request_bytes: usize,
    /// Who approves resource scope: the edge page, or the origin app.
    pub consent: ConsentMode,
    /// Present exactly when `kind == RouteKind::Http`.
    pub http: Option<HttpUpstream>,
    /// Present exactly when `kind == RouteKind::Iroh`.
    pub iroh: Option<IrohOrigin>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteFile {
    #[serde(rename = "backend", default)]
    backends: Vec<BackendEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendEntry {
    id: String,
    kind: String,
    #[serde(default)]
    consent: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    #[serde(default)]
    grant_lifetime_secs: Option<i64>,
    #[serde(default)]
    max_request_bytes: Option<usize>,
    // kind = "http" only:
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    max_response_bytes: Option<usize>,
    #[serde(default)]
    connect_timeout_secs: Option<u64>,
    #[serde(default)]
    response_timeout_secs: Option<u64>,
    #[serde(default)]
    idle_timeout_secs: Option<u64>,
    #[serde(default)]
    max_concurrent_per_grant: Option<usize>,
    // kind = "iroh" only:
    #[serde(default)]
    origin_endpoint_env: Option<String>,
}

impl BackendEntry {
    fn has_http_keys(&self) -> bool {
        self.url.is_some()
            || self.max_response_bytes.is_some()
            || self.connect_timeout_secs.is_some()
            || self.response_timeout_secs.is_some()
            || self.idle_timeout_secs.is_some()
            || self.max_concurrent_per_grant.is_some()
    }

    /// Keys only an http backend may set (`max_response_bytes` is shared
    /// with iroh).
    fn has_http_only_keys(&self) -> bool {
        self.url.is_some()
            || self.connect_timeout_secs.is_some()
            || self.response_timeout_secs.is_some()
            || self.idle_timeout_secs.is_some()
            || self.max_concurrent_per_grant.is_some()
    }
}

fn valid_env_name(name: &str) -> bool {
    let b = name.as_bytes();
    name.len() > ORIGIN_ENV_PREFIX.len()
        && name.len() <= 64
        && name.starts_with(ORIGIN_ENV_PREFIX)
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

fn iroh_origin(b: &BackendEntry) -> Result<IrohOrigin, ConfigError> {
    let id = &b.id;
    if b.has_http_only_keys() {
        return err(format!(
            "backend {id:?}: url, timeouts and max_concurrent_per_grant are only valid for \
             kind = \"http\""
        ));
    }
    let Some(env) = b.origin_endpoint_env.clone() else {
        return err(format!(
            "backend {id:?}: kind = \"iroh\" needs origin_endpoint_env"
        ));
    };
    if !valid_env_name(&env) {
        return err(format!(
            "backend {id:?}: origin_endpoint_env must be an upper-case variable name starting \
             with {ORIGIN_ENV_PREFIX}"
        ));
    }
    let max_response_bytes = b.max_response_bytes.unwrap_or(IROH_MAX_RESPONSE_BYTES);
    if !(1024..=IROH_MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
        return err(format!(
            "backend {id:?}: max_response_bytes must be 1024..={IROH_MAX_RESPONSE_BYTES} for \
             kind = \"iroh\""
        ));
    }
    Ok(IrohOrigin {
        env,
        origin_id: None,
        max_response_bytes,
    })
}

/// Fill in each iroh route's origin EndpointId from its environment variable
/// (PHASE4.md §1.2, D6): it must be set and hold exactly 64 lowercase hex
/// characters that decode to a valid Ed25519 point, and no two routes may name
/// the same origin. Error messages name the variable, never its value.
pub fn resolve_origins(
    routes: &mut [Route],
    get: impl Fn(&str) -> Option<String>,
) -> Result<(), ConfigError> {
    let mut seen: Vec<EndpointId> = Vec::new();
    for route in routes.iter_mut() {
        let Some(iroh) = route.iroh.as_mut() else {
            continue;
        };
        let Some(value) = get(&iroh.env) else {
            return err(format!(
                "backend {:?}: {} is not set (the origin EndpointId, 64 lowercase hex)",
                route.id, iroh.env
            ));
        };
        let Some(id) = edge_tunnel::ids::parse_endpoint_id_hex(&value) else {
            return err(format!(
                "backend {:?}: {} must be exactly 64 lowercase hex characters encoding a valid \
                 EndpointId",
                route.id, iroh.env
            ));
        };
        if seen.contains(&id) {
            return err(format!(
                "backend {:?}: another route already uses this origin EndpointId",
                route.id
            ));
        }
        seen.push(id);
        iroh.origin_id = Some(id);
    }
    Ok(())
}

fn private_or_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn never_a_backend(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_unspecified() || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 link-local (incl. cloud metadata over IPv6).
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.to_ipv4_mapped().is_some_and(|v4| never_a_backend(IpAddr::V4(v4)))
        }
    }
}

/// A single DNS label, e.g. a Docker service/container name (`hevy-mcp`).
fn single_label(host: &str) -> bool {
    let b = host.as_bytes();
    (1..=63).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
        && !b.iter().all(u8::is_ascii_digit)
}

/// Validate an upstream URL from the route table.
///
/// * `https` to any host, or `http` only to an RFC 1918 / loopback IP or a
///   single-label name (a service on the container network);
/// * no userinfo, query or fragment; never unspecified, link-local,
///   multicast or broadcast IPs; port 0 refused;
/// * the text must already be in canonical form (what the forwarder will
///   send and sign), so the configured string *is* the upstream request.
pub fn validate_upstream_url(text: &str) -> Result<url::Url, String> {
    if text
        .bytes()
        .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err("url must not contain whitespace or control characters".into());
    }
    let url = url::Url::parse(text).map_err(|_| "url is not a valid URL".to_string())?;
    let https = match url.scheme() {
        "https" => true,
        "http" => false,
        _ => return Err("url scheme must be https (or http on a private network)".into()),
    };
    if !url.username().is_empty() || url.password().is_some() {
        return Err("url must not contain userinfo".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("url must not contain a query or fragment".into());
    }
    if url.cannot_be_a_base() || !url.path().starts_with('/') {
        return Err("url must have an absolute path".into());
    }
    if url.port() == Some(0) {
        return Err("url port must not be 0".into());
    }
    let ip = match url.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        Some(url::Host::Domain(_)) => None,
        None => return Err("url must name a host".into()),
    };
    if ip.is_some_and(never_a_backend) {
        return Err(
            "url host is an unspecified, link-local, multicast or broadcast address".into(),
        );
    }
    if !https {
        let ok = match (ip, url.host_str()) {
            (Some(ip), _) => private_or_loopback(ip),
            (None, Some(host)) => single_label(host),
            _ => false,
        };
        if !ok {
            return Err(
                "plain http is only allowed to an RFC 1918/loopback IP or a single-label \
                 service name; use https"
                    .into(),
            );
        }
    }
    if url.as_str() != text {
        return Err(format!(
            "url must be written in canonical form: {}",
            url.as_str()
        ));
    }
    Ok(url)
}

fn secs(
    value: Option<u64>,
    default: u64,
    max: u64,
    what: &str,
    id: &str,
) -> Result<Duration, ConfigError> {
    let v = value.unwrap_or(default);
    if !(1..=max).contains(&v) {
        return err(format!("backend {id:?}: {what} must be 1..={max}"));
    }
    Ok(Duration::from_secs(v))
}

fn http_upstream(b: &BackendEntry) -> Result<HttpUpstream, ConfigError> {
    let id = &b.id;
    let Some(text) = b.url.as_deref() else {
        return err(format!("backend {id:?}: kind = \"http\" needs url"));
    };
    let url =
        validate_upstream_url(text).map_err(|e| ConfigError(format!("backend {id:?}: {e}")))?;
    let max_response_bytes = b.max_response_bytes.unwrap_or(DEFAULT_MAX_RESPONSE_BYTES);
    if !(1024..=MAX_RESPONSE_BYTES_LIMIT).contains(&max_response_bytes) {
        return err(format!(
            "backend {id:?}: max_response_bytes must be 1024..={MAX_RESPONSE_BYTES_LIMIT}"
        ));
    }
    let max_concurrent_per_grant = b
        .max_concurrent_per_grant
        .unwrap_or(DEFAULT_MAX_CONCURRENT_PER_GRANT);
    if !(1..=MAX_CONCURRENT_PER_GRANT_LIMIT).contains(&max_concurrent_per_grant) {
        return err(format!(
            "backend {id:?}: max_concurrent_per_grant must be 1..={MAX_CONCURRENT_PER_GRANT_LIMIT}"
        ));
    }
    Ok(HttpUpstream {
        url,
        max_response_bytes,
        connect_timeout: secs(
            b.connect_timeout_secs,
            DEFAULT_CONNECT_TIMEOUT_SECS,
            30,
            "connect_timeout_secs",
            id,
        )?,
        response_timeout: secs(
            b.response_timeout_secs,
            DEFAULT_RESPONSE_TIMEOUT_SECS,
            MAX_RESPONSE_TIMEOUT_SECS,
            "response_timeout_secs",
            id,
        )?,
        idle_timeout: secs(
            b.idle_timeout_secs,
            DEFAULT_IDLE_TIMEOUT_SECS,
            MAX_IDLE_TIMEOUT_SECS,
            "idle_timeout_secs",
            id,
        )?,
        max_concurrent_per_grant,
    })
}

fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_scope(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b':' | b'.' | b'_' | b'-')
        })
}

/// Parse and validate a route table (TOML).
pub fn parse_routes(text: &str) -> Result<Vec<Route>, ConfigError> {
    let file: RouteFile =
        toml::from_str(text).map_err(|e| ConfigError(format!("route table: {}", e.message())))?;
    if file.backends.is_empty() || file.backends.len() > MAX_BACKENDS {
        return err("route table must list 1..=32 [[backend]] entries");
    }
    let mut routes: Vec<Route> = Vec::new();
    for b in file.backends {
        if !valid_id(&b.id) || RESERVED.contains(&b.id.as_str()) {
            return err(format!("invalid or reserved backend id {:?}", b.id));
        }
        if routes.iter().any(|r| r.id == b.id) {
            return err(format!("duplicate backend id {:?}", b.id));
        }
        let kind = match b.kind.as_str() {
            "echo" => RouteKind::Echo,
            "http" => RouteKind::Http,
            "iroh" => RouteKind::Iroh,
            other => return err(format!("backend {:?}: unknown kind {other:?}", b.id)),
        };
        let consent = match b.consent.as_deref() {
            None | Some("edge") => ConsentMode::Edge,
            Some("origin") => ConsentMode::Origin,
            Some(other) => return err(format!("backend {:?}: unknown consent {other:?}", b.id)),
        };
        // v1: the origin decides exactly for iroh backends (PHASE4.md §5).
        if (kind == RouteKind::Iroh) != (consent == ConsentMode::Origin) {
            return err(format!(
                "backend {:?}: kind = \"iroh\" requires consent = \"origin\" and vice versa",
                b.id
            ));
        }
        if kind != RouteKind::Iroh && b.origin_endpoint_env.is_some() {
            return err(format!(
                "backend {:?}: origin_endpoint_env is only valid for kind = \"iroh\"",
                b.id
            ));
        }
        let scopes = b.scopes.clone().unwrap_or_else(|| vec!["mcp".into()]);
        // iroh: the scopes travel in the enrollment string and consent
        // requests, which carry at most 4.
        let max_scopes = if kind == RouteKind::Iroh { 4 } else { 16 };
        if scopes.is_empty() || scopes.len() > max_scopes || !scopes.iter().all(|s| valid_scope(s))
        {
            return err(format!("backend {:?}: invalid scopes", b.id));
        }
        let lifetime = b.grant_lifetime_secs.unwrap_or(DEFAULT_GRANT_LIFETIME);
        let max_lifetime = if kind == RouteKind::Iroh {
            edge_tunnel::meta::MAX_GRANT_LIFETIME_SECS as i64
        } else {
            90 * 86_400
        };
        if !(300..=max_lifetime).contains(&lifetime) {
            return err(format!(
                "backend {:?}: grant_lifetime_secs must be 300..={max_lifetime}",
                b.id
            ));
        }
        let (default_request, request_limit) = if kind == RouteKind::Iroh {
            (IROH_MAX_REQUEST_BYTES, IROH_MAX_REQUEST_BYTES)
        } else {
            (DEFAULT_MAX_REQUEST_BYTES, MAX_REQUEST_BYTES_LIMIT)
        };
        let max_request_bytes = b.max_request_bytes.unwrap_or(default_request);
        if !(1024..=request_limit).contains(&max_request_bytes) {
            return err(format!(
                "backend {:?}: max_request_bytes must be 1024..={request_limit}",
                b.id
            ));
        }
        let (http, iroh) = match kind {
            RouteKind::Http => (Some(http_upstream(&b)?), None),
            RouteKind::Iroh => (None, Some(iroh_origin(&b)?)),
            RouteKind::Echo => {
                if b.has_http_keys() {
                    return err(format!(
                        "backend {:?}: url and upstream limits are only valid for kind = \"http\"",
                        b.id
                    ));
                }
                (None, None)
            }
        };
        let display_name = b
            .display_name
            .map(|n| n.chars().filter(|c| !c.is_control()).take(80).collect())
            .unwrap_or_else(|| b.id.clone());
        routes.push(Route {
            id: b.id,
            kind,
            display_name,
            scopes,
            grant_lifetime_secs: lifetime,
            max_request_bytes,
            consent,
            http,
            iroh,
        });
    }
    Ok(routes)
}

/// Private and loopback ranges: only Coolify's Traefik (on the Docker
/// network) can reach the container, so these are the proxies by default.
pub const DEFAULT_TRUSTED_PROXIES: &str =
    "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128,fc00::/7";

/// An IP network in CIDR notation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

impl Cidr {
    pub fn parse(text: &str) -> Option<Self> {
        let (addr, prefix) = match text.trim().split_once('/') {
            Some((a, p)) => (a.parse::<IpAddr>().ok()?, p.parse::<u8>().ok()?),
            None => {
                let a = text.trim().parse::<IpAddr>().ok()?;
                (a, if a.is_ipv4() { 32 } else { 128 })
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { net: addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canonical_ip(ip)) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }
}

/// Comma-separated CIDRs; an empty string trusts no proxy.
pub fn parse_cidrs(text: &str) -> Result<Vec<Cidr>, ConfigError> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| Cidr::parse(s).ok_or_else(|| ConfigError(format!("invalid CIDR {s:?}"))))
        .collect()
}

/// The client address for limits. `X-Forwarded-For` is honoured only when the
/// TCP peer is a trusted proxy; then the right-most hop that is not itself a
/// trusted proxy is the client. An unparsable hop stops the walk (the chain
/// beyond it cannot be trusted) and the last trusted address is used.
pub fn forwarded_client(peer: IpAddr, xff: &[&str], trusted: &[Cidr]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|c| c.contains(ip));
    let peer = canonical_ip(peer);
    if !is_trusted(peer) {
        return peer;
    }
    let mut current = peer;
    for hop in xff.iter().rev().flat_map(|v| v.rsplit(',')) {
        let Ok(ip) = hop.trim().parse::<IpAddr>() else {
            return current;
        };
        current = canonical_ip(ip);
        if !is_trusted(current) {
            return current;
        }
    }
    current
}

/// Validated process configuration for edge mode.
#[derive(Clone, Debug)]
pub struct EdgeConfig {
    pub public_url: String,
    pub rp_id: String,
    pub rp_name: String,
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub routes: Vec<Route>,
    pub redirect_allowlist: Vec<String>,
    pub enroll_code: Option<String>,
    /// Peers whose `X-Forwarded-For` is honoured (Coolify's Traefik).
    pub trusted_proxies: Vec<Cidr>,
}

/// Default listener (container port published to Traefik).
pub const DEFAULT_BIND: &str = "0.0.0.0:8080";

/// Validate a public URL: an `https` origin, or `http` only for localhost.
pub fn validate_public_url(value: &str) -> Result<(String, String), ConfigError> {
    let url = url_parse(value)?;
    let host = url.host_str().unwrap_or_default().to_string();
    let local = host == "localhost" || host == "127.0.0.1";
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && local);
    if !scheme_ok
        || host.is_empty()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || value.ends_with('/')
    {
        return err("EDGE_PUBLIC_URL must be an https origin without path or trailing slash");
    }
    Ok((value.to_string(), host))
}

fn url_parse(value: &str) -> Result<url::Url, ConfigError> {
    url::Url::parse(value).map_err(|_| ConfigError("EDGE_PUBLIC_URL is not a URL".into()))
}

impl EdgeConfig {
    /// Read configuration through `get` (normally `std::env::var`). The route
    /// table file is read through `read_file`.
    pub fn from_env(
        get: impl Fn(&str) -> Option<String>,
        read_file: impl Fn(&str) -> std::io::Result<String>,
    ) -> Result<Self, ConfigError> {
        let public_url = get("EDGE_PUBLIC_URL")
            .ok_or_else(|| ConfigError("EDGE_PUBLIC_URL is required".into()))?;
        let (public_url, host) = validate_public_url(&public_url)?;
        let bind = get("EDGE_BIND")
            .unwrap_or_else(|| DEFAULT_BIND.into())
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError("EDGE_BIND must be ip:port".into()))?;
        let data_dir = PathBuf::from(get("EDGE_DATA_DIR").unwrap_or_else(|| "/data".into()));
        let routes_path = get("EDGE_ROUTES").unwrap_or_else(|| "/etc/mcp-edge/routes.toml".into());
        let routes_text = read_file(&routes_path)
            .map_err(|_| ConfigError("EDGE_ROUTES file is not readable".into()))?;
        let mut routes = parse_routes(&routes_text)?;
        resolve_origins(&mut routes, &get)?;
        let redirect_allowlist = match get("EDGE_REDIRECT_ALLOWLIST") {
            None => vec![CLAUDE_CALLBACK.to_string()],
            Some(list) => {
                let items: Vec<String> = list
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                for item in &items {
                    let url = url_parse(item)
                        .map_err(|_| ConfigError("EDGE_REDIRECT_ALLOWLIST entry".into()))?;
                    if url.scheme() != "https" || url.fragment().is_some() {
                        return err("EDGE_REDIRECT_ALLOWLIST entries must be https URLs");
                    }
                }
                if items.is_empty() {
                    return err("EDGE_REDIRECT_ALLOWLIST is empty");
                }
                items
            }
        };
        let enroll_code = get("EDGE_ENROLL_CODE").filter(|c| !c.is_empty());
        if get("EDGE_TRUST_FORWARDED_FOR").is_some() {
            return err("EDGE_TRUST_FORWARDED_FOR was replaced by EDGE_TRUSTED_PROXIES");
        }
        let trusted_proxies = parse_cidrs(
            &get("EDGE_TRUSTED_PROXIES").unwrap_or_else(|| DEFAULT_TRUSTED_PROXIES.into()),
        )?;
        let rp_id = get("EDGE_RP_ID").unwrap_or_else(|| host.clone());
        if !(host == rp_id || host.ends_with(&format!(".{rp_id}"))) {
            return err("EDGE_RP_ID must be the public host or a parent domain of it");
        }
        Ok(Self {
            public_url,
            rp_id,
            rp_name: get("EDGE_RP_NAME").unwrap_or_else(|| "mcp-edge".into()),
            bind,
            data_dir,
            routes,
            redirect_allowlist,
            enroll_code,
            trusted_proxies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const ROUTES: &str = r#"
[[backend]]
id = "echo"
kind = "echo"
consent = "edge"
display_name = "Echo"
"#;

    #[test]
    fn forwarded_for_is_honoured_only_from_trusted_proxies() {
        let trusted = parse_cidrs(DEFAULT_TRUSTED_PROXIES).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        // Untrusted peer: XFF ignored entirely.
        assert_eq!(
            forwarded_client(ip("203.0.113.9"), &["198.51.100.1"], &trusted),
            ip("203.0.113.9")
        );
        // Trusted peer: right-most untrusted hop wins; spoofed left entries ignored.
        assert_eq!(
            forwarded_client(ip("10.0.1.2"), &["1.1.1.1, 198.51.100.7"], &trusted),
            ip("198.51.100.7")
        );
        assert_eq!(
            forwarded_client(
                ip("10.0.1.2"),
                &["1.1.1.1", "198.51.100.7, 172.16.0.3"],
                &trusted
            ),
            ip("198.51.100.7")
        );
        // No XFF, garbage, or all-trusted chains fall back sensibly.
        assert_eq!(
            forwarded_client(ip("10.0.1.2"), &[], &trusted),
            ip("10.0.1.2")
        );
        assert_eq!(
            forwarded_client(ip("10.0.1.2"), &["1.1.1.1, garbage"], &trusted),
            ip("10.0.1.2")
        );
        assert_eq!(
            forwarded_client(ip("::ffff:10.0.1.2"), &["192.168.1.1"], &trusted),
            ip("192.168.1.1")
        );
        // Empty list trusts nobody.
        assert_eq!(
            forwarded_client(ip("127.0.0.1"), &["198.51.100.7"], &[]),
            ip("127.0.0.1")
        );
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("fc00::/7").unwrap().contains(ip("fd12::1")));
        assert!(!Cidr::parse("172.16.0.0/12")
            .unwrap()
            .contains(ip("172.32.0.1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn shipped_route_table_is_valid() {
        let mut routes = parse_routes(include_str!("../config/routes.toml")).unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].id, "echo");
        assert_eq!(routes[0].kind, RouteKind::Echo);
        let hevy = &routes[1];
        assert_eq!((hevy.id.as_str(), hevy.kind), ("hevy", RouteKind::Http));
        assert_eq!(
            hevy.http.as_ref().unwrap().url.as_str(),
            "https://hevy-mcp.app.stri.nz/mcp"
        );
        let wiskit = &routes[2];
        assert_eq!(
            (wiskit.id.as_str(), wiskit.kind),
            ("wiskit", RouteKind::Iroh)
        );
        assert_eq!(wiskit.iroh.as_ref().unwrap().env, "EDGE_ORIGIN_WISKIT");
        assert_eq!(wiskit.scopes, vec!["wiskit:read"]);
        // The origin EndpointId comes only from the environment; without it the edge refuses to start.
        assert!(resolve_origins(&mut routes, |_| None).is_err());
        resolve_origins(&mut routes, |_| Some(ORIGIN_HEX.to_string())).unwrap();
    }

    fn http_route(extra: &str) -> Result<Vec<Route>, ConfigError> {
        parse_routes(&format!(
            "[[backend]]\nid = \"up\"\nkind = \"http\"\nconsent = \"edge\"\n{extra}\n"
        ))
    }

    #[test]
    fn http_backend_defaults_and_limits() {
        let routes = http_route("url = \"http://hevy-mcp:3000/mcp\"").unwrap();
        let r = &routes[0];
        assert_eq!(r.kind, RouteKind::Http);
        let h = r.http.as_ref().unwrap();
        assert_eq!(h.url.as_str(), "http://hevy-mcp:3000/mcp");
        assert_eq!(h.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(
            h.connect_timeout,
            Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)
        );
        assert_eq!(
            h.response_timeout,
            Duration::from_secs(DEFAULT_RESPONSE_TIMEOUT_SECS)
        );
        assert_eq!(
            h.idle_timeout,
            Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)
        );
        assert_eq!(h.max_concurrent_per_grant, DEFAULT_MAX_CONCURRENT_PER_GRANT);
        assert_eq!(r.max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);

        let routes = http_route(
            "url = \"https://mcp.example.com/v1/mcp\"\nmax_request_bytes = 2048\n\
             max_response_bytes = 8192\nconnect_timeout_secs = 2\nresponse_timeout_secs = 3\n\
             idle_timeout_secs = 4\nmax_concurrent_per_grant = 2",
        )
        .unwrap();
        let h = routes[0].http.as_ref().unwrap();
        assert_eq!(
            (
                h.max_response_bytes,
                h.connect_timeout.as_secs(),
                h.response_timeout.as_secs()
            ),
            (8192, 2, 3)
        );
        assert_eq!(
            (h.idle_timeout.as_secs(), h.max_concurrent_per_grant),
            (4, 2)
        );
        assert_eq!(routes[0].max_request_bytes, 2048);

        for bad in [
            "", // url missing
            "url = \"http://hevy-mcp/mcp\"\nmax_response_bytes = 10",
            "url = \"http://hevy-mcp/mcp\"\nmax_response_bytes = 999999999",
            "url = \"http://hevy-mcp/mcp\"\nconnect_timeout_secs = 0",
            "url = \"http://hevy-mcp/mcp\"\nresponse_timeout_secs = 30",
            "url = \"http://hevy-mcp/mcp\"\nidle_timeout_secs = 0",
            "url = \"http://hevy-mcp/mcp\"\nmax_concurrent_per_grant = 0",
            "url = \"http://hevy-mcp/mcp\"\nheaders = { x = \"y\" }", // unknown key
        ] {
            assert!(http_route(bad).is_err(), "{bad}");
        }
        assert!(parse_routes(
            "[[backend]]\nid = \"up\"\nkind = \"http\"\nconsent = \"origin\"\nurl = \"http://hevy-mcp/mcp\"\n"
        )
        .is_err());
    }

    #[test]
    fn upstream_url_policy() {
        for ok in [
            "http://hevy-mcp:3000/mcp",
            "http://localhost:8080/mcp",
            "http://10.0.1.5:3000/mcp",
            "http://172.20.0.3/mcp",
            "http://192.168.1.10:9000/mcp",
            "http://127.0.0.1:41000/x/mcp",
            "http://[::1]:41000/mcp",
            "https://mcp.example.com/mcp",
            "https://203.0.113.10:8443/mcp",
            "https://hevy-mcp/mcp",
        ] {
            assert!(validate_upstream_url(ok).is_ok(), "{ok}");
        }
        // The planned hevy route: the signed path is exactly `/mcp`, and
        // `/mcp/` stays a different (also exact) upstream path.
        let hevy = validate_upstream_url("https://hevy-mcp.app.stri.nz/mcp").unwrap();
        assert_eq!(hevy.path(), "/mcp");
        let slash = validate_upstream_url("https://hevy-mcp.app.stri.nz/mcp/").unwrap();
        assert_eq!(slash.path(), "/mcp/");
        for bad in [
            "http://mcp.example.com/mcp", // public name over plain http
            "http://hevy.internal/mcp",   // multi-label name over plain http
            "http://203.0.113.10/mcp",    // public IP over plain http
            "http://8.8.8.8/mcp",
            "http://[fd00::1]/mcp",          // ULA not allowed for plain http
            "http://169.254.169.254/latest", // link-local / metadata
            "https://169.254.169.254/x",
            "https://0.0.0.0/mcp",
            "http://[fe80::1]/mcp",
            "https://224.0.0.1/mcp",
            "ftp://10.0.0.1/mcp",
            "file:///etc/passwd",
            "https://user:pw@mcp.example.com/mcp",
            "https://mcp.example.com/mcp?key=1",
            "https://mcp.example.com/mcp#x",
            "https://mcp.example.com:0/mcp",
            "https://MCP.example.com/mcp", // not canonical
            "https://mcp.example.com",     // not canonical (no path)
            "http://hevy-mcp:80/mcp",      // not canonical (default port)
            "http://hevy-mcp/a/../mcp",    // not canonical (dot segment)
            "http://hevy-mcp/mcp ",
            "http://hevy\n-mcp/mcp",
            "http://-bad-/mcp",
            "not a url",
            "",
        ] {
            assert!(validate_upstream_url(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn route_table_accepts_echo_and_rejects_unavailable_kinds() {
        let routes = parse_routes(ROUTES).unwrap();
        assert_eq!(routes[0].id, "echo");
        assert_eq!(routes[0].scopes, vec!["mcp"]);
        assert_eq!(routes[0].max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);
        assert!(routes[0].http.is_none());
        for bad in [
            "[[backend]]\nid = \"x\"\nkind = \"http\"\n",
            "[[backend]]\nid = \"x\"\nkind = \"echo\"\nmax_response_bytes = 4096\n",
            "[[backend]]\nid = \"x\"\nkind = \"iroh\"\n",
            "[[backend]]\nid = \"x\"\nkind = \"iroh\"\nconsent = \"edge\"\n",
            "[[backend]]\nid = \"x\"\nkind = \"echo\"\nconsent = \"origin\"\n",
            "[[backend]]\nid = \"x\"\nkind = \"echo\"\nurl = \"http://10.0.0.1\"\n",
            "[[backend]]\nid = \"owner\"\nkind = \"echo\"\n",
            "[[backend]]\nid = \"Echo\"\nkind = \"echo\"\n",
            "[[backend]]\nid = \"../x\"\nkind = \"echo\"\n",
            "[[backend]]\nid = \"e\"\nkind = \"echo\"\n[[backend]]\nid = \"e\"\nkind = \"echo\"\n",
            "",
        ] {
            assert!(parse_routes(bad).is_err(), "{bad}");
        }
    }

    const ORIGIN_HEX: &str = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394";

    fn iroh_route(extra: &str) -> Result<Vec<Route>, ConfigError> {
        parse_routes(&format!(
            "[[backend]]\nid = \"wiskit\"\nkind = \"iroh\"\nconsent = \"origin\"\n\
             scopes = [\"wiskit:read\"]\n{extra}\n"
        ))
    }

    #[test]
    fn iroh_backend_keys_defaults_and_limits() {
        let routes =
            iroh_route("origin_endpoint_env = \"EDGE_ORIGIN_WISKIT\"\ngrant_lifetime_secs = 86400")
                .unwrap();
        let r = &routes[0];
        assert_eq!((r.kind, r.consent), (RouteKind::Iroh, ConsentMode::Origin));
        let iroh = r.iroh.as_ref().unwrap();
        assert_eq!(iroh.env, "EDGE_ORIGIN_WISKIT");
        assert_eq!(iroh.origin_id, None);
        assert_eq!(iroh.max_response_bytes, IROH_MAX_RESPONSE_BYTES);
        assert_eq!(r.max_request_bytes, IROH_MAX_REQUEST_BYTES);
        assert!(r.http.is_none());
        for bad in [
            "",                                             // env missing
            "origin_endpoint_env = \"EDGE_ENROLL_CODE\"",   // wrong prefix
            "origin_endpoint_env = \"EDGE_ORIGIN_\"",       // prefix only
            "origin_endpoint_env = \"EDGE_ORIGIN_wiskit\"", // lower case
            "origin_endpoint_env = \"EDGE_ORIGIN_W\"\nurl = \"https://x.example/mcp\"",
            "origin_endpoint_env = \"EDGE_ORIGIN_W\"\nmax_response_bytes = 2097152",
            "origin_endpoint_env = \"EDGE_ORIGIN_W\"\nmax_request_bytes = 65537",
            "origin_endpoint_env = \"EDGE_ORIGIN_W\"\ngrant_lifetime_secs = 2592001",
            "origin_endpoint_env = \"EDGE_ORIGIN_W\"\nconnect_timeout_secs = 2",
            "origin_endpoint_env = \"EDGE_ORIGIN_W\"\nscopes = [\"a\",\"b\",\"c\",\"d\",\"e\"]",
        ] {
            assert!(iroh_route(bad).is_err(), "{bad}");
        }
        // origin_endpoint_env on a non-iroh backend.
        assert!(parse_routes(
            "[[backend]]\nid = \"e\"\nkind = \"echo\"\norigin_endpoint_env = \"EDGE_ORIGIN_X\"\n"
        )
        .is_err());
    }

    #[test]
    fn iroh_origin_ids_come_from_env_and_are_strict_and_unique() {
        let table = "[[backend]]\nid = \"a\"\nkind = \"iroh\"\nconsent = \"origin\"\n\
                     origin_endpoint_env = \"EDGE_ORIGIN_A\"\n\
                     [[backend]]\nid = \"b\"\nkind = \"iroh\"\nconsent = \"origin\"\n\
                     origin_endpoint_env = \"EDGE_ORIGIN_B\"\n";
        let other = edge_tunnel::ids::endpoint_id_hex(
            &edge_tunnel::iroh::SecretKey::from_bytes(&[7u8; 32]).public(),
        );
        let mut routes = parse_routes(table).unwrap();
        resolve_origins(
            &mut routes,
            env(&[("EDGE_ORIGIN_A", ORIGIN_HEX), ("EDGE_ORIGIN_B", &other)]),
        )
        .unwrap();
        assert_eq!(
            edge_tunnel::ids::endpoint_id_hex(&routes[0].iroh.as_ref().unwrap().origin_id.unwrap()),
            ORIGIN_HEX
        );
        let upper = ORIGIN_HEX.to_uppercase();
        let short = &ORIGIN_HEX[..62];
        let padded = format!("{ORIGIN_HEX} ");
        for (a, b) in [
            (None, Some(other.as_str())),                  // unset
            (Some(""), Some(other.as_str())),              // empty
            (Some(upper.as_str()), Some(other.as_str())),  // not lower case
            (Some(short), Some(other.as_str())),           // too short
            (Some(padded.as_str()), Some(other.as_str())), // whitespace
            (Some(ORIGIN_HEX), Some(ORIGIN_HEX)),          // duplicate origin
        ] {
            let mut routes = parse_routes(table).unwrap();
            let mut pairs = Vec::new();
            if let Some(a) = a {
                pairs.push(("EDGE_ORIGIN_A", a));
            }
            if let Some(b) = b {
                pairs.push(("EDGE_ORIGIN_B", b));
            }
            let e = resolve_origins(&mut routes, env(&pairs)).unwrap_err();
            assert!(!e.0.contains(ORIGIN_HEX), "never echo the value: {e}");
        }
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    #[test]
    fn env_requires_https_origin() {
        let read = |_: &str| Ok(ROUTES.to_string());
        let ok = EdgeConfig::from_env(env(&[("EDGE_PUBLIC_URL", "https://mcp.app.stri.nz")]), read)
            .unwrap();
        assert_eq!(ok.rp_id, "mcp.app.stri.nz");
        assert_eq!(ok.redirect_allowlist, vec![CLAUDE_CALLBACK]);
        assert_eq!(ok.trusted_proxies.len(), 6);
        for bad in [
            "http://mcp.app.stri.nz",
            "https://mcp.app.stri.nz/",
            "https://mcp.app.stri.nz/x",
            "https://user@mcp.app.stri.nz",
            "not a url",
        ] {
            assert!(
                EdgeConfig::from_env(env(&[("EDGE_PUBLIC_URL", bad)]), read).is_err(),
                "{bad}"
            );
        }
        assert!(EdgeConfig::from_env(env(&[]), read).is_err());
        assert!(EdgeConfig::from_env(
            env(&[
                ("EDGE_PUBLIC_URL", "https://mcp.app.stri.nz"),
                ("EDGE_REDIRECT_ALLOWLIST", "http://claude.ai/cb")
            ]),
            read
        )
        .is_err());
    }
}
