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
    /// Failed enrollment-code attempts before enrollment locks until restart.
    pub max_enroll_failures: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            register_per_ip_per_hour: 10,
            register_global_per_hour: 60,
            authorize_per_ip_per_minute: 30,
            token_per_ip_per_minute: 60,
            owner_per_ip_per_minute: 20,
            max_pending: 4096,
            max_ceremonies: 4096,
            max_clients: 100,
            max_enroll_failures: 10,
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

    /// Map a `resource` parameter to a configured backend (exact match only).
    pub fn backend_for_resource(&self, resource: &str) -> Option<&BackendPolicy> {
        self.backends
            .iter()
            .find(|b| self.resource_url(&b.id) == resource)
    }

    pub fn resource_metadata_url(&self, backend: &str) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource/{backend}/mcp",
            self.issuer
        )
    }
}
