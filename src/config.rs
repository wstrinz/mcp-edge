//! Environment and route-table configuration for `EDGE_MODE=edge`.

use edge_auth::config::{CLAUDE_CALLBACK, DEFAULT_GRANT_LIFETIME};
use serde::Deserialize;
use std::{fmt, net::SocketAddr, path::PathBuf};

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

/// What serves a route. Phase 2 only has the built-in echo backend; `http`
/// and `iroh` kinds are rejected until their phases land.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteKind {
    Echo,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub id: String,
    pub kind: RouteKind,
    pub display_name: String,
    pub scopes: Vec<String>,
    pub grant_lifetime_secs: i64,
    pub max_request_bytes: usize,
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
            "http" | "iroh" => {
                return err(format!(
                    "backend {:?}: kind {:?} is not available in this phase",
                    b.id, b.kind
                ))
            }
            other => return err(format!("backend {:?}: unknown kind {other:?}", b.id)),
        };
        match b.consent.as_deref() {
            None | Some("edge") => {}
            Some("origin") => {
                return err(format!(
                    "backend {:?}: consent = \"origin\" is not available in this phase",
                    b.id
                ))
            }
            Some(other) => return err(format!("backend {:?}: unknown consent {other:?}", b.id)),
        }
        let scopes = b.scopes.unwrap_or_else(|| vec!["mcp".into()]);
        if scopes.is_empty() || scopes.len() > 16 || !scopes.iter().all(|s| valid_scope(s)) {
            return err(format!("backend {:?}: invalid scopes", b.id));
        }
        let lifetime = b.grant_lifetime_secs.unwrap_or(DEFAULT_GRANT_LIFETIME);
        if !(300..=90 * 86_400).contains(&lifetime) {
            return err(format!(
                "backend {:?}: grant_lifetime_secs must be 300..=7776000",
                b.id
            ));
        }
        let max_request_bytes = b.max_request_bytes.unwrap_or(DEFAULT_MAX_REQUEST_BYTES);
        if !(1024..=MAX_REQUEST_BYTES_LIMIT).contains(&max_request_bytes) {
            return err(format!(
                "backend {:?}: max_request_bytes must be 1024..=4194304",
                b.id
            ));
        }
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
        });
    }
    Ok(routes)
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
    pub trust_forwarded_for: bool,
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
        let routes = parse_routes(&routes_text)?;
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
        let trust_forwarded_for = match get("EDGE_TRUST_FORWARDED_FOR").as_deref() {
            None | Some("0") | Some("false") => false,
            Some("1") | Some("true") => true,
            _ => return err("EDGE_TRUST_FORWARDED_FOR must be 0 or 1"),
        };
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
            trust_forwarded_for,
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
    fn shipped_route_table_is_valid() {
        let routes = parse_routes(include_str!("../config/routes.toml")).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].id, "echo");
        assert_eq!(routes[0].kind, RouteKind::Echo);
    }

    #[test]
    fn route_table_accepts_echo_and_rejects_unavailable_kinds() {
        let routes = parse_routes(ROUTES).unwrap();
        assert_eq!(routes[0].id, "echo");
        assert_eq!(routes[0].scopes, vec!["mcp"]);
        assert_eq!(routes[0].max_request_bytes, DEFAULT_MAX_REQUEST_BYTES);
        for bad in [
            "[[backend]]\nid = \"x\"\nkind = \"http\"\n",
            "[[backend]]\nid = \"x\"\nkind = \"iroh\"\n",
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
        assert!(!ok.trust_forwarded_for);
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
