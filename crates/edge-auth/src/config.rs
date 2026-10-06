//! Authorization-server configuration.

/// Claude's hosted OAuth callback; the default (and only default) redirect URI.
pub const CLAUDE_CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";

/// Authorization codes live this long (seconds).
pub const CODE_TTL: i64 = 60;
/// Access tokens live this long (seconds).
pub const ACCESS_TTL: i64 = 15 * 60;
/// A pending authorization request (consent page) lives this long.
pub const PENDING_TTL: i64 = 10 * 60;
/// Owner proof for a pending request must be at most this old at approval.
pub const FRESH_PROOF: i64 = 5 * 60;
/// WebAuthn ceremonies must finish within this time.
pub const CEREMONY_TTL: i64 = 5 * 60;
/// Owner page sessions (grant list, adding passkeys) last this long.
pub const SESSION_TTL: i64 = 30 * 60;
/// Default absolute grant lifetime (30 days).
pub const DEFAULT_GRANT_LIFETIME: i64 = 30 * 24 * 3600;
/// Minimum accepted enrollment-code length.
pub const MIN_ENROLL_CODE_LEN: usize = 16;

/// Who approves resource scope for a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentMode {
    /// The edge's own consent page is sufficient.
    Edge,
}

/// The authorization-relevant part of one route-table entry.
#[derive(Clone, Debug)]
pub struct BackendPolicy {
    /// Path segment and assertion audience, e.g. `echo`.
    pub id: String,
    /// Human-readable name for the consent page.
    pub display_name: String,
    /// Scopes a grant for this backend can carry (the default request is all).
    pub scopes: Vec<String>,
    /// Absolute grant lifetime in seconds; refresh never extends it.
    pub grant_lifetime_secs: i64,
    pub consent: ConsentMode,
}

/// Pre-authentication rate limits (per client IP unless stated).
#[derive(Clone, Debug)]
pub struct Limits {
    pub register_per_ip_per_hour: u32,
    pub register_global_per_hour: u32,
    pub authorize_per_ip_per_minute: u32,
    pub token_per_ip_per_minute: u32,
    pub owner_per_ip_per_minute: u32,
    /// Live pending authorization requests across all clients.
    pub max_pending: usize,
    /// Live WebAuthn ceremonies across all clients (about 1 KiB each).
    pub max_ceremonies: usize,
    /// Registered clients; unused old registrations are pruned first.
    pub max_clients: usize,
    /// Wrong enrollment codes per client network per 15 minutes.
    pub max_enroll_failures: u32,
    /// Wrong enrollment codes across all networks per hour.
    pub max_enroll_failures_global: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            register_per_ip_per_hour: 20,
            register_global_per_hour: 10_000,
            authorize_per_ip_per_minute: 30,
            token_per_ip_per_minute: 60,
            owner_per_ip_per_minute: 20,
            max_pending: 4096,
            max_ceremonies: 4096,
            max_clients: 100,
            max_enroll_failures: 10,
            max_enroll_failures_global: 100,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// Issuer and public base URL, e.g. `https://mcp.app.stri.nz` (no trailing slash).
    pub issuer: String,
    /// Exact redirect URIs a client may register.
    pub redirect_allowlist: Vec<String>,
    /// One-time code that authorizes registering the first passkey.
    pub enroll_code: Option<String>,
    pub backends: Vec<BackendPolicy>,
    pub limits: Limits,
}

impl AuthConfig {
    pub fn backend(&self, id: &str) -> Option<&BackendPolicy> {
        self.backends.iter().find(|b| b.id == id)
    }

    /// The protected-resource identifier for a backend.
    pub fn resource_url(&self, backend: &str) -> String {
        format!("{}/{backend}/mcp", self.issuer)
    }

    /// Map a `resource` parameter to a configured backend. Both sides are
    /// normalized ([`normalize_resource`]) before an exact comparison.
    pub fn backend_for_resource(&self, resource: &str) -> Option<&BackendPolicy> {
        let wanted = normalize_resource(resource)?;
        self.backends
            .iter()
            .find(|b| normalize_resource(&self.resource_url(&b.id)).as_deref() == Some(&wanted))
    }

    pub fn resource_metadata_url(&self, backend: &str) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource/{backend}/mcp",
            self.issuer
        )
    }
}

/// Canonical form of a resource indicator: scheme and host lowercased, default
/// port dropped, dot segments resolved (all by the URL parser), and one
/// trailing `/` removed. Query, fragment and userinfo are not allowed.
pub fn normalize_resource(resource: &str) -> Option<String> {
    let url = url::Url::parse(resource).ok()?;
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return None;
    }
    let mut out = url.as_str().to_string();
    if url.path() != "/" && out.ends_with('/') {
        out.pop();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::normalize_resource;

    #[test]
    fn resource_normalization() {
        let canonical = Some("https://edge.test/echo/mcp".to_string());
        for variant in [
            "https://edge.test/echo/mcp",
            "HTTPS://EDGE.TEST/echo/mcp",
            "https://edge.test:443/echo/mcp",
            "https://edge.test/echo/mcp/",
        ] {
            assert_eq!(normalize_resource(variant), canonical, "{variant}");
        }
        for different in [
            "https://edge.test/ECHO/mcp",
            "https://edge.test:8443/echo/mcp",
            "http://edge.test/echo/mcp",
            "https://edge.test/echo/mcp//",
        ] {
            assert_ne!(normalize_resource(different), canonical, "{different}");
        }
        for invalid in [
            "https://edge.test/echo/mcp?x=1",
            "https://u@edge.test/echo/mcp",
            "mcp",
        ] {
            assert_eq!(normalize_resource(invalid), None, "{invalid}");
        }
    }
}
