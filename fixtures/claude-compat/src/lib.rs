//! In-process HTTP/OAuth policy fixture. No listener, browser, identity provider,
//! credential storage, Wiskit store, or real Claude client is connected.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const ISSUER: &str = "https://origin.poc.invalid";
pub const RESOURCE: &str = "https://origin.poc.invalid/mcp";
pub const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
// Deliberately synthetic, not a guessed Claude-published CIMD URL.
pub const FIXTURE_CIMD: &str = "https://client.poc.invalid/client.json";
pub const READ_SCOPE: &str = "wiskit:read";
pub const VERSIONS: [&str; 3] = ["2025-03-26", "2025-06-18", "2025-11-25"];
const MAX_BODY: usize = 16 * 1024;
const MAX_CLIENTS: usize = 32;
const MAX_PENDING: usize = 8;
const MAX_GRANTS: usize = 32;
const MAX_SPENT_REFRESH: usize = 2048;
const ACCESS_TTL: u64 = 900;
const GRANT_TTL: u64 = 86400;

pub fn pkce(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
fn opaque() -> String {
    URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>())
}
fn key(secret: &str) -> String {
    pkce(secret)
}
fn params(raw: &[u8]) -> Result<BTreeMap<String, String>, &'static str> {
    let mut result = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(raw) {
        if result.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err("invalid_request");
        }
    }
    Ok(result)
}

#[derive(Clone)]
pub struct HttpReply {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
impl HttpReply {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            headers: BTreeMap::from([
                ("content-type".into(), "application/json".into()),
                ("cache-control".into(), "no-store".into()),
            ]),
            body: serde_json::to_vec(&value).unwrap(),
        }
    }
    pub fn value(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }
    fn error(status: u16, error: &'static str) -> Self {
        Self::json(status, json!({"error":error}))
    }
    fn challenge() -> Self {
        let mut r = Self::error(401, "invalid_token");
        r.headers.insert("www-authenticate".into(), format!("Bearer resource_metadata=\"{ISSUER}/.well-known/oauth-protected-resource/mcp\", scope=\"{READ_SCOPE}\""));
        r
    }
    fn rpc(id: Value, result: Value) -> Self {
        Self::json(200, json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
    fn rpc_error(id: Value, code: i64, message: &'static str) -> Self {
        Self::json(
            200,
            json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
        )
    }
    fn accepted() -> Self {
        Self {
            status: 202,
            headers: BTreeMap::new(),
            body: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct Client {
    redirect: String,
}
#[derive(Clone)]
struct Pending {
    client: String,
    redirect: String,
    challenge: String,
    state: String,
    browser: String,
    offline: bool,
    expires: u64,
}
#[derive(Clone)]
struct Grant {
    client: String,
    trackers: BTreeSet<String>,
    offline: bool,
    revoked: bool,
    expires: u64,
}
#[derive(Clone)]
struct Code {
    grant: String,
    client: String,
    redirect: String,
    challenge: String,
    expires: u64,
}
#[derive(Clone)]
struct Token {
    grant: String,
    client: String,
    expires: u64,
}
#[derive(Serialize, Clone)]
pub struct Audit {
    pub grant_handle: String,
    pub operation: String,
    pub decision: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    #[serde(default)]
    client_name: String,
}

pub struct Fixture {
    pub remote_enabled: bool,
    pub audit_available: bool,
    pub use_cimd: bool,
    pub dispatches: usize,
    pub now: u64,
    clients: BTreeMap<String, Client>,
    pending: BTreeMap<String, Pending>,
    grants: BTreeMap<String, Grant>,
    codes: BTreeMap<String, Code>,
    access: BTreeMap<String, Token>,
    refresh: BTreeMap<String, Token>,
    spent: BTreeMap<String, Token>,
    audit: Vec<Audit>,
    // Synthetic resource-owner authority; no shared/non-owned tracker is grantable.
    owned: BTreeSet<String>,
}
impl Default for Fixture {
    fn default() -> Self {
        Self::new(false)
    }
}
impl Fixture {
    pub fn new(use_cimd: bool) -> Self {
        Self {
            remote_enabled: true,
            audit_available: true,
            use_cimd,
            dispatches: 0,
            now: 1,
            clients: BTreeMap::new(),
            pending: BTreeMap::new(),
            grants: BTreeMap::new(),
            codes: BTreeMap::new(),
            access: BTreeMap::new(),
            refresh: BTreeMap::new(),
            spent: BTreeMap::new(),
            audit: Vec::new(),
            owned: BTreeSet::from(["synthetic-a".into(), "synthetic-b".into()]),
        }
    }
    pub fn audit_json(&self) -> String {
        serde_json::to_string(&self.audit).unwrap()
    }
    fn denied_auth(&mut self) -> HttpReply {
        self.record("-", "authentication", false);
        HttpReply::challenge()
    }
    fn record(&mut self, grant: &str, operation: &str, allowed: bool) {
        if self.audit.len() == 256 {
            self.audit.remove(0);
        }
        self.audit.push(Audit {
            grant_handle: grant.into(),
            operation: operation.into(),
            decision: if allowed {
                "allowed".into()
            } else {
                "denied".into()
            },
        });
    }
    pub fn revoke(&mut self, handle: &str) {
        if let Some(g) = self.grants.get_mut(handle) {
            g.revoked = true;
        }
    }
    pub fn restart(&mut self) {
        self.clients.clear();
        self.pending.clear();
        self.grants.clear();
        self.codes.clear();
        self.access.clear();
        self.refresh.clear();
        self.spent.clear();
        self.remote_enabled = false;
    }
    pub fn client_document(&self) -> Value {
        json!({"client_id":FIXTURE_CIMD,"client_name":"Synthetic published client","redirect_uris":[CALLBACK],"token_endpoint_auth_method":"none"})
    }
    fn resolve_client(&self, id: &str) -> Option<Client> {
        // Models a pinned/cache-loaded document. NO arbitrary client URL fetching.
        if self.use_cimd && id == FIXTURE_CIMD {
            Some(Client {
                redirect: CALLBACK.into(),
            })
        } else {
            self.clients.get(id).cloned()
        }
    }
    pub fn valid_cimd(id: &str, document: &Value) -> bool {
        id == FIXTURE_CIMD
            && document["client_id"] == id
            && document["redirect_uris"] == json!([CALLBACK])
            && document["token_endpoint_auth_method"] == "none"
    }
    pub fn claude_uses_cimd(metadata: &Value) -> bool {
        metadata["client_id_metadata_document_supported"] == true
            && metadata["token_endpoint_auth_methods_supported"]
                .as_array()
                .is_some_and(|v| v.contains(&json!("none")))
    }

    /// Trusted LOCAL approval hook, never an unauthenticated HTTP /approve route.
    /// `browser` stands in for a bound, authenticated consent-page session.
    /// A production component must supply browser/CSRF and local-owner proof.
    pub fn approve(
        &mut self,
        handle: &str,
        browser: &str,
        owner_unlocked: bool,
        trackers: &[&str],
    ) -> Result<(HttpReply, String), &'static str> {
        let p = self.pending.get(handle).ok_or("invalid_request")?.clone();
        if !owner_unlocked
            || !self.remote_enabled
            || p.browser != browser
            || p.expires <= self.now
            || trackers.is_empty()
            || self.grants.len() >= MAX_GRANTS
        {
            return Err("access_denied");
        }
        let trackers: BTreeSet<String> = trackers.iter().map(|s| s.to_string()).collect();
        if !trackers.is_subset(&self.owned) {
            return Err("access_denied");
        }
        self.pending.remove(handle);
        let grant = opaque();
        self.grants.insert(
            grant.clone(),
            Grant {
                client: p.client.clone(),
                trackers,
                offline: p.offline,
                revoked: false,
                expires: self.now + GRANT_TTL,
            },
        );
        let code = opaque();
        self.codes.insert(
            key(&code),
            Code {
                grant: grant.clone(),
                client: p.client,
                redirect: p.redirect.clone(),
                challenge: p.challenge,
                expires: self.now + 60,
            },
        );
        let mut redirect = url::Url::parse(&p.redirect).unwrap();
        redirect
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &p.state)
            .append_pair("iss", ISSUER);
        let mut r = HttpReply::json(303, Value::Null);
        r.headers.insert("location".into(), redirect.into());
        Ok((r, grant))
    }
    pub fn valid_callback(location: &str, expected_state: &str, expected_issuer: &str) -> bool {
        let Ok(u) = url::Url::parse(location) else {
            return false;
        };
        let Ok(p) = params(u.query().unwrap_or("").as_bytes()) else {
            return false;
        };
        let mut bare = u.clone();
        bare.set_query(None);
        bare.as_str() == CALLBACK
            && p.get("state").is_some_and(|v| v == expected_state)
            && p.get("iss").is_some_and(|v| v == expected_issuer)
    }
    fn grant_live(&self, id: &str, client: &str) -> bool {
        self.remote_enabled
            && self
                .grants
                .get(id)
                .is_some_and(|g| !g.revoked && g.client == client && g.expires > self.now)
    }
    fn issue(&mut self, grant: String, client: String) -> HttpReply {
        let g = self.grants.get(&grant).unwrap();
        let ttl = ACCESS_TTL.min(g.expires - self.now);
        let offline = g.offline;
        let a = opaque();
        self.access.insert(
            key(&a),
            Token {
                grant: grant.clone(),
                client: client.clone(),
                expires: self.now + ttl,
            },
        );
        let mut body =
            json!({"access_token":a,"token_type":"Bearer","expires_in":ttl,"scope":READ_SCOPE});
        if offline {
            let r = opaque();
            self.refresh.insert(
                key(&r),
                Token {
                    grant,
                    client,
                    expires: g.expires,
                },
            );
            body["refresh_token"] = json!(r);
        }
        HttpReply::json(200, body)
    }
    fn token(&mut self, p: BTreeMap<String, String>) -> HttpReply {
        let client = p.get("client_id").map(String::as_str).unwrap_or("");
        if p.contains_key("client_secret") || p.get("scope").is_some_and(|v| v != READ_SCOPE) {
            return HttpReply::error(400, "invalid_scope");
        }
        if self.resolve_client(client).is_none() {
            return HttpReply::error(400, "invalid_client");
        }
        if p.get("grant_type").map(String::as_str) == Some("authorization_code") {
            if p.get("resource").map(String::as_str) != Some(RESOURCE) {
                return HttpReply::error(400, "invalid_target");
            }
            let Some(c) = p.get("code").and_then(|c| self.codes.remove(&key(c))) else {
                return HttpReply::error(400, "invalid_grant");
            };
            let verifier = p.get("code_verifier").map(String::as_str).unwrap_or("");
            if c.client != client
                || p.get("redirect_uri") != Some(&c.redirect)
                || c.expires <= self.now
                || !(43..=128).contains(&verifier.len())
                || pkce(verifier) != c.challenge
                || !self.grant_live(&c.grant, client)
            {
                return HttpReply::error(400, "invalid_grant");
            }
            return self.issue(c.grant, client.into());
        }
        if p.get("grant_type").map(String::as_str) == Some("refresh_token") {
            // Omitted refresh resource retains the original audience; never widens it.
            if p.get("resource").is_some_and(|r| r != RESOURCE) {
                return HttpReply::error(400, "invalid_target");
            }
            let hash = key(p.get("refresh_token").map(String::as_str).unwrap_or(""));
            if let Some(old) = self.spent.get(&hash).cloned() {
                if old.client == client {
                    self.revoke(&old.grant);
                }
                return HttpReply::error(400, "invalid_grant");
            }
            let Some(r) = self.refresh.get(&hash).cloned() else {
                return HttpReply::error(400, "invalid_grant");
            };
            if r.client != client || r.expires <= self.now || !self.grant_live(&r.grant, client) {
                return HttpReply::error(400, "invalid_grant");
            }
            if self.spent.len() >= MAX_SPENT_REFRESH {
                return HttpReply::error(503, "temporarily_unavailable");
            }
            self.refresh.remove(&hash);
            self.spent.insert(hash, r.clone());
            return self.issue(r.grant, client.into());
        }
        HttpReply::error(400, "unsupported_grant_type")
    }

    /// Semantic HTTP handler exercised in process; not a public OAuth server.
    pub fn handle(
        &mut self,
        method: &str,
        target: &str,
        headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> HttpReply {
        if body.len() > MAX_BODY {
            return HttpReply::error(413, "body_limit");
        }
        if headers.get("host").map(String::as_str) != Some("origin.poc.invalid")
            || target.starts_with("http")
        {
            return HttpReply::error(403, "host_not_admitted");
        }
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        if method == "GET"
            && matches!(
                path,
                "/.well-known/oauth-protected-resource"
                    | "/.well-known/oauth-protected-resource/mcp"
            )
        {
            return HttpReply::json(
                200,
                json!({"resource":RESOURCE,"authorization_servers":[ISSUER],"scopes_supported":[READ_SCOPE],"bearer_methods_supported":["header"]}),
            );
        }
        if method == "GET" && path == "/.well-known/oauth-authorization-server" {
            let mut v = json!({"issuer":ISSUER,"authorization_endpoint":format!("{ISSUER}/authorize"),"token_endpoint":format!("{ISSUER}/token"),"revocation_endpoint":format!("{ISSUER}/revoke"),"response_types_supported":["code"],"grant_types_supported":["authorization_code","refresh_token"],"code_challenge_methods_supported":["S256"],"token_endpoint_auth_methods_supported":["none"],"scopes_supported":[READ_SCOPE,"offline_access"],"authorization_response_iss_parameter_supported":true,"client_id_metadata_document_supported":self.use_cimd});
            if !self.use_cimd {
                v["registration_endpoint"] = json!(format!("{ISSUER}/register"));
            }
            return HttpReply::json(200, v);
        }
        if method == "POST" && path == "/register" && !self.use_cimd {
            if headers.get("content-type").map(String::as_str) != Some("application/json") {
                return HttpReply::error(415, "content_type");
            }
            let Ok(r) = serde_json::from_slice::<Registration>(body) else {
                return HttpReply::error(400, "invalid_client_metadata");
            };
            if r.redirect_uris != [CALLBACK]
                || r.token_endpoint_auth_method != "none"
                || r.grant_types != ["authorization_code", "refresh_token"]
                || r.response_types != ["code"]
                || r.client_name.len() > 64
            {
                return HttpReply::error(400, "invalid_client_metadata");
            }
            if self.clients.len() >= MAX_CLIENTS {
                return HttpReply::error(429, "registration_limit");
            }
            let id = opaque();
            self.clients.insert(
                id.clone(),
                Client {
                    redirect: CALLBACK.into(),
                },
            );
            return HttpReply::json(
                201,
                json!({"client_id":id,"redirect_uris":[CALLBACK],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]}),
            );
        }
        if method == "GET" && path == "/authorize" {
            let Ok(p) = params(query.as_bytes()) else {
                return HttpReply::error(400, "invalid_request");
            };
            let Some(client) = p.get("client_id").and_then(|id| self.resolve_client(id)) else {
                return HttpReply::error(400, "invalid_client");
            };
            if p.get("redirect_uri") != Some(&client.redirect)
                || p.get("resource").map(String::as_str) != Some(RESOURCE)
                || p.get("response_type").map(String::as_str) != Some("code")
                || p.get("code_challenge_method").map(String::as_str) != Some("S256")
            {
                return HttpReply::error(400, "invalid_request");
            }
            let challenge = p.get("code_challenge").cloned().unwrap_or_default();
            let state = p.get("state").cloned().unwrap_or_default();
            if challenge.len() != 43
                || URL_SAFE_NO_PAD.decode(&challenge).is_err()
                || !(16..=128).contains(&state.len())
            {
                return HttpReply::error(400, "invalid_request");
            }
            let scope = p.get("scope").cloned().unwrap_or_default();
            if !matches!(scope.as_str(), READ_SCOPE | "wiskit:read offline_access") {
                return HttpReply::error(400, "invalid_scope");
            }
            if !self.remote_enabled {
                return HttpReply::error(503, "remote_disabled");
            }
            self.pending.retain(|_, v| v.expires > self.now);
            if self.pending.len() >= MAX_PENDING {
                return HttpReply::error(429, "consent_limit");
            }
            let handle = opaque();
            let browser = headers
                .get("fixture-browser-session")
                .cloned()
                .unwrap_or_default();
            if browser.is_empty() {
                return HttpReply::error(400, "browser_session_required");
            }
            self.pending.insert(
                handle.clone(),
                Pending {
                    client: p["client_id"].clone(),
                    redirect: client.redirect,
                    challenge,
                    state,
                    browser,
                    offline: scope.contains("offline_access"),
                    expires: self.now + 180,
                },
            );
            return HttpReply::json(
                200,
                json!({"local_approval_required":true,"pending_handle":handle,"redirect_host":"claude.ai","scope":READ_SCOPE}),
            );
        }
        if method == "POST" && matches!(path, "/token" | "/revoke") {
            if headers.get("content-type").map(String::as_str)
                != Some("application/x-www-form-urlencoded")
            {
                return HttpReply::error(415, "content_type");
            }
            let Ok(p) = params(body) else {
                return HttpReply::error(400, "invalid_request");
            };
            if path == "/token" {
                return self.token(p);
            }
            if let Some(raw) = p.get("token") {
                if let Some(t) = self
                    .access
                    .get(&key(raw))
                    .or_else(|| self.refresh.get(&key(raw)))
                    .cloned()
                {
                    if p.get("client_id") == Some(&t.client) {
                        self.revoke(&t.grant);
                    }
                }
            }
            return HttpReply::json(200, Value::Null);
        }
        if path != "/mcp" || !query.is_empty() {
            return HttpReply::error(404, "unknown_route");
        }
        if method != "POST" {
            let mut r = HttpReply::error(405, "method_not_allowed");
            r.headers.insert("allow".into(), "POST".into());
            return r;
        }
        if !self.remote_enabled {
            return HttpReply::error(503, "remote_disabled");
        }
        let Some(raw) = headers
            .get("authorization")
            .and_then(|s| s.strip_prefix("Bearer "))
        else {
            return self.denied_auth();
        };
        let Some(t) = self.access.get(&key(raw)).cloned() else {
            return self.denied_auth();
        };
        if t.expires <= self.now || !self.grant_live(&t.grant, &t.client) {
            return self.denied_auth();
        }
        if !self.audit_available {
            return HttpReply::error(503, "audit_unavailable");
        }
        if headers
            .get("origin")
            .is_some_and(|v| v != ISSUER && v != "https://claude.ai")
        {
            return HttpReply::error(403, "origin_not_admitted");
        }
        if headers.get("content-type").map(String::as_str) != Some("application/json")
            || !headers
                .get("accept")
                .is_some_and(|s| s.contains("application/json") && s.contains("text/event-stream"))
        {
            return HttpReply::error(400, "mcp_headers");
        }
        if headers
            .get("mcp-protocol-version")
            .is_some_and(|v| !VERSIONS.contains(&v.as_str()))
        {
            return HttpReply::error(400, "unsupported_protocol_version");
        }
        let Ok(v) = serde_json::from_slice::<Value>(body) else {
            return HttpReply::rpc_error(Value::Null, -32700, "Parse error");
        };
        if !v.is_object() || v["jsonrpc"] != "2.0" {
            return HttpReply::rpc_error(Value::Null, -32600, "Invalid request");
        }
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        match v["method"].as_str().unwrap_or("") {
            "initialize" => {
                let asked = v["params"]["protocolVersion"].as_str().unwrap_or("");
                let version = if VERSIONS.contains(&asked) {
                    asked
                } else {
                    VERSIONS[2]
                };
                HttpReply::rpc(
                    id,
                    json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"Wiskit synthetic read-only","version":"0.1.0"}}),
                )
            }
            "notifications/initialized" | "notifications/cancelled" if id.is_null() => {
                HttpReply::accepted()
            }
            "ping" => HttpReply::rpc(id, json!({})),
            "tools/list" => HttpReply::rpc(
                id,
                json!({"tools":[
                    {"name":"wiskit_list_trackers","description":"List only explicitly granted synthetic trackers","inputSchema":{"type":"object","properties":{},"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},
                    {"name":"wiskit_read_tracker_bundle","description":"Read one explicitly granted synthetic tracker","inputSchema":{"type":"object","properties":{"trackerId":{"type":"string"}},"required":["trackerId"],"additionalProperties":false},"annotations":{"readOnlyHint":true,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}}
                ]}),
            ),
            "tools/call" => {
                let name = v["params"]["name"].as_str().unwrap_or("");
                let grant = self.grants[&t.grant].clone();
                let result = if name == "wiskit_list_trackers"
                    && v["params"]["arguments"]
                        .as_object()
                        .is_some_and(|a| a.is_empty())
                {
                    Some(
                        json!({"trackers":grant.trackers.iter().map(|id| json!({"id":id,"name":"Synthetic tracker"})).collect::<Vec<_>>()}),
                    )
                } else if name == "wiskit_read_tracker_bundle"
                    && v["params"]["arguments"]
                        .as_object()
                        .is_some_and(|a| a.len() == 1)
                {
                    v["params"]["arguments"]["trackerId"]
                        .as_str()
                        .filter(|id| grant.trackers.contains(*id))
                        .map(|id| json!({"tracker":{"id":id},"events":[{"synthetic":true}]}))
                } else {
                    None
                };
                let operation =
                    if matches!(name, "wiskit_list_trackers" | "wiskit_read_tracker_bundle") {
                        name
                    } else {
                        "unknown_tool"
                    };
                self.record(&t.grant, operation, result.is_some());
                if let Some(result) = result {
                    self.dispatches += 1;
                    HttpReply::rpc(
                        id,
                        json!({"content":[{"type":"text","text":result.to_string()}],"isError":false}),
                    )
                } else {
                    HttpReply::rpc(
                        id,
                        json!({"content":[{"type":"text","text":"Tool or tracker not permitted"}],"isError":true}),
                    )
                }
            }
            _ => HttpReply::rpc_error(id, -32601, "Method not found"),
        }
    }
}
