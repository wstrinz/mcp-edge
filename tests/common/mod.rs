//! Shared harness: the real edge router on an ephemeral loopback port, a
//! software passkey driving real WebAuthn ceremonies, a manual clock and an
//! in-memory log sink. All values are synthetic.
#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use edge_auth::{
    config::Limits,
    owner::WebauthnOwnerProof,
    support::{ManualClock, MemoryLog},
};
use mcp_edge::{
    app::{self, AppConfig, AppDeps, EdgeLimits},
    config::{parse_cidrs, parse_routes, resolve_origins},
    server::serve,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use webauthn_authenticator_rs::{
    prelude::{CreationChallengeResponse, RequestChallengeResponse, Url},
    softpasskey::SoftPasskey,
    WebauthnAuthenticator,
};

pub const ISSUER: &str = "https://edge.test";
pub const ENROLL_CODE: &str = "SYNTHETIC-enroll-code-0123456789";
pub const CALLBACK: &str = "https://claude.ai/api/mcp/auth_callback";
pub const OTHER_CALLBACK: &str = "https://client.test/callback";
pub const SEED: [u8; 32] = [42u8; 32];

pub const ROUTES: &str = r#"
[[backend]]
id = "echo"
kind = "echo"
consent = "edge"
display_name = "Echo A"

[[backend]]
id = "echo2"
kind = "echo"
consent = "edge"
display_name = "Echo B"
grant_lifetime_secs = 86400
max_request_bytes = 4096
"#;

pub struct Options {
    pub auth_limits: Limits,
    pub edge_limits: EdgeLimits,
    pub enroll_code: Option<String>,
    /// Route table (TOML); defaults to [`ROUTES`].
    pub routes: String,
    /// Environment for `origin_endpoint_env` lookups (iroh routes).
    pub env: HashMap<String, String>,
    /// The edge's iroh identity/endpoint (iroh routes).
    pub iroh: Option<mcp_edge::tunnel::IrohDeps>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            // Tests drive many ceremonies from one loopback address; the
            // per-IP limits under test are lowered explicitly where needed.
            auth_limits: Limits {
                authorize_per_ip_per_minute: 1000,
                owner_per_ip_per_minute: 1000,
                token_per_ip_per_minute: 1000,
                ..Limits::default()
            },
            edge_limits: EdgeLimits::default(),
            enroll_code: Some(ENROLL_CODE.into()),
            routes: ROUTES.to_string(),
            env: HashMap::new(),
            iroh: None,
        }
    }
}

/// A browser's cookie jar (handled by hand: the cookies are `Secure` and the
/// test talks plain HTTP to loopback).
#[derive(Default, Clone)]
pub struct Browser {
    pub cookies: HashMap<String, String>,
    /// Simulated client address, sent as `X-Forwarded-For` (loopback is a
    /// trusted proxy in the harness).
    pub from: Option<String>,
}

impl Browser {
    pub fn from_ip(ip: &str) -> Self {
        Self {
            from: Some(ip.to_string()),
            ..Self::default()
        }
    }

    pub fn apply(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(c) = self.header() {
            req = req.header("cookie", c);
        }
        if let Some(ip) = &self.from {
            req = req.header("x-forwarded-for", ip);
        }
        req
    }

    pub fn header(&self) -> Option<String> {
        if self.cookies.is_empty() {
            return None;
        }
        Some(
            self.cookies
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    pub fn absorb(&mut self, res: &reqwest::Response) {
        for value in res.headers().get_all("set-cookie") {
            let value = value.to_str().unwrap();
            assert!(value.contains("HttpOnly"), "cookie must be HttpOnly");
            assert!(value.contains("Secure"), "cookie must be Secure");
            assert!(
                value.contains("SameSite=Lax"),
                "cookie must be SameSite=Lax"
            );
            assert!(
                value.starts_with("__Host-"),
                "cookie must use __Host- prefix"
            );
            let (pair, _) = value.split_once(';').unwrap();
            let (name, val) = pair.split_once('=').unwrap();
            if val.is_empty() || value.contains("Max-Age=0") {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.to_string(), val.to_string());
            }
        }
    }

    pub fn values(&self) -> Vec<String> {
        self.cookies.values().cloned().collect()
    }
}

pub fn pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).unwrap();
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

pub fn resource(backend: &str) -> String {
    format!("{ISSUER}/{backend}/mcp")
}

pub fn query_param(url: &str, key: &str) -> Option<String> {
    let parsed = Url::parse(url).unwrap();
    parsed
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
}

pub fn extract_csrf(html: &str) -> Option<String> {
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

pub struct Harness {
    pub addr: SocketAddr,
    pub http: reqwest::Client,
    pub clock: Arc<ManualClock>,
    pub log: Arc<MemoryLog>,
    pub passkey: WebauthnAuthenticator<SoftPasskey>,
    pub origin: Url,
    pub assertion_key: String,
    pub owner_id: String,
    stop: CancellationToken,
    task: JoinHandle<std::io::Result<()>>,
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(Options::default()).await
    }

    pub async fn start_with(opts: Options) -> Self {
        let origin = Url::parse(ISSUER).unwrap();
        let clock = Arc::new(ManualClock::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        ));
        let log = Arc::new(MemoryLog::default());
        let proof = WebauthnOwnerProof::new("edge.test", &origin, "edge test").unwrap();
        let mut routes = parse_routes(&opts.routes).unwrap();
        resolve_origins(&mut routes, |k| opts.env.get(k).cloned()).unwrap();
        let built = app::build(
            AppConfig {
                issuer: ISSUER.into(),
                routes,
                redirect_allowlist: vec![CALLBACK.into(), OTHER_CALLBACK.into()],
                enroll_code: opts.enroll_code,
                trusted_proxies: parse_cidrs("127.0.0.0/8").unwrap(),
                auth_limits: opts.auth_limits,
                edge_limits: opts.edge_limits,
            },
            AppDeps {
                db_path: None,
                proof: Arc::new(proof),
                clock: clock.clone(),
                log: log.clone(),
                signing_seed: SEED,
                iroh: opts.iroh,
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let owner_id = built.auth.owner_id().to_string();
        let task = tokio::spawn(serve(listener, built.router, stop.clone()));
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            addr,
            http,
            clock,
            log,
            passkey: WebauthnAuthenticator::new(SoftPasskey::new(true)),
            origin,
            assertion_key: built.assertion_public_key,
            owner_id,
            stop,
            task,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub fn logs(&self) -> Vec<String> {
        self.log.lines()
    }

    pub async fn finish(self) {
        self.stop.cancel();
        self.task.await.unwrap().unwrap();
    }

    pub async fn get(&self, browser: &mut Browser, path: &str) -> reqwest::Response {
        let res = browser
            .apply(self.http.get(self.url(path)))
            .send()
            .await
            .unwrap();
        browser.absorb(&res);
        res
    }

    pub async fn post_json(
        &self,
        browser: &mut Browser,
        path: &str,
        body: &Value,
    ) -> reqwest::Response {
        let res = browser
            .apply(
                self.http
                    .post(self.url(path))
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(body).unwrap()),
            )
            .send()
            .await
            .unwrap();
        browser.absorb(&res);
        res
    }

    pub async fn post_form(
        &self,
        browser: &mut Browser,
        path: &str,
        form: &[(&str, &str)],
    ) -> reqwest::Response {
        let res = browser
            .apply(self.http.post(self.url(path)).form(form))
            .send()
            .await
            .unwrap();
        browser.absorb(&res);
        res
    }

    /// `post_form` plus the `Origin` header a browser attaches to a form POST.
    /// Browsers send the literal `null` when the page's referrer policy is
    /// `no-referrer` (Fetch: "append a request Origin header"); see `same_origin`.
    pub async fn post_form_origin(
        &self,
        browser: &mut Browser,
        path: &str,
        form: &[(&str, &str)],
        origin: &str,
    ) -> reqwest::Response {
        let res = browser
            .apply(
                self.http
                    .post(self.url(path))
                    .header("origin", origin)
                    .form(form),
            )
            .send()
            .await
            .unwrap();
        browser.absorb(&res);
        res
    }

    /// Register the first owner passkey with the enrollment code.
    pub async fn enroll(&mut self) {
        let mut browser = Browser::default();
        let res = self
            .post_json(
                &mut browser,
                "/owner/register/start",
                &json!({ "enroll_code": ENROLL_CODE }),
            )
            .await;
        assert_eq!(res.status(), 200, "register/start");
        let options: CreationChallengeResponse = res.json().await.unwrap();
        let cred = self
            .passkey
            .do_registration(self.origin.clone(), options)
            .unwrap();
        let res = self
            .post_json(
                &mut browser,
                "/owner/register/finish",
                &serde_json::to_value(cred).unwrap(),
            )
            .await;
        assert_eq!(res.status(), 200, "register/finish");
    }

    /// Run a passkey login (bound to `tx` if given). Returns the finish status.
    pub async fn owner_login(&mut self, browser: &mut Browser, tx: Option<&str>) -> u16 {
        let body = match tx {
            Some(tx) => json!({ "tx": tx }),
            None => json!({}),
        };
        let res = self.post_json(browser, "/owner/login/start", &body).await;
        if res.status() != 200 {
            return res.status().as_u16();
        }
        let options: RequestChallengeResponse = res.json().await.unwrap();
        let cred = self
            .passkey
            .do_authentication(self.origin.clone(), options)
            .unwrap();
        self.post_json(
            browser,
            "/owner/login/finish",
            &serde_json::to_value(cred).unwrap(),
        )
        .await
        .status()
        .as_u16()
    }

    pub async fn register_client(&self, redirect: &str) -> String {
        let res = self
            .http
            .post(self.url("/register"))
            .json(&json!({
                "client_name": "Synthetic <Client>",
                "redirect_uris": [redirect],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 201);
        let body: Value = res.json().await.unwrap();
        body["client_id"].as_str().unwrap().to_string()
    }

    pub fn authorize_query(
        client_id: &str,
        redirect: &str,
        backend: &str,
        challenge: &str,
        state: &str,
    ) -> String {
        let mut url = Url::parse("http://x/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", state)
            .append_pair("resource", &resource(backend));
        format!("/authorize?{}", url.query().unwrap())
    }

    /// GET /authorize; returns the pending transaction id.
    pub async fn begin(
        &self,
        browser: &mut Browser,
        client_id: &str,
        redirect: &str,
        backend: &str,
        challenge: &str,
        state: &str,
    ) -> String {
        let res = self
            .get(
                browser,
                &Self::authorize_query(client_id, redirect, backend, challenge, state),
            )
            .await;
        assert_eq!(res.status(), 303, "authorize should redirect to consent");
        let location = res.headers()["location"].to_str().unwrap().to_string();
        assert!(location.starts_with("/consent?tx="), "{location}");
        location.trim_start_matches("/consent?tx=").to_string()
    }

    pub async fn consent_csrf(&self, browser: &mut Browser, tx: &str) -> Option<String> {
        let res = self.get(browser, &format!("/consent?tx={tx}")).await;
        assert_eq!(res.status(), 200);
        extract_csrf(&res.text().await.unwrap())
    }

    /// The whole browser leg; returns (code, browser, redirect Location).
    pub async fn authorize_code(
        &mut self,
        client_id: &str,
        redirect: &str,
        backend: &str,
        challenge: &str,
    ) -> (String, Browser) {
        let mut browser = Browser::default();
        let tx = self
            .begin(
                &mut browser,
                client_id,
                redirect,
                backend,
                challenge,
                "st-1",
            )
            .await;
        assert_eq!(self.owner_login(&mut browser, Some(&tx)).await, 200);
        let csrf = self.consent_csrf(&mut browser, &tx).await.expect("csrf");
        let res = self
            .post_form(
                &mut browser,
                "/consent",
                &[("tx", &tx), ("csrf", &csrf), ("decision", "approve")],
            )
            .await;
        assert_eq!(res.status(), 303);
        let location = res.headers()["location"].to_str().unwrap().to_string();
        assert!(location.starts_with(redirect), "{location}");
        assert_eq!(query_param(&location, "state").as_deref(), Some("st-1"));
        assert_eq!(query_param(&location, "iss").as_deref(), Some(ISSUER));
        (query_param(&location, "code").expect("code"), browser)
    }

    pub async fn token(&self, form: &[(&str, &str)]) -> (u16, Value) {
        let res = self
            .http
            .post(self.url("/token"))
            .form(form)
            .send()
            .await
            .unwrap();
        let status = res.status().as_u16();
        assert_eq!(res.headers()["cache-control"], "no-store");
        (status, res.json().await.unwrap_or(Value::Null))
    }

    pub async fn exchange(
        &self,
        client_id: &str,
        code: &str,
        verifier: &str,
        redirect: &str,
        backend: &str,
    ) -> (u16, Value) {
        let resource = resource(backend);
        self.token(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code),
            ("code_verifier", verifier),
            ("redirect_uri", redirect),
            ("resource", &resource),
        ])
        .await
    }

    pub async fn refresh(&self, client_id: &str, refresh: &str) -> (u16, Value) {
        self.token(&[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", refresh),
        ])
        .await
    }

    pub async fn mcp(&self, backend: &str, token: Option<&str>, body: &Value) -> reqwest::Response {
        let mut req = self
            .http
            .post(self.url(&format!("/{backend}/mcp")))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(serde_json::to_vec(body).unwrap());
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        req.send().await.unwrap()
    }

    /// Enroll, register a client and obtain tokens for `backend`.
    pub async fn tokens_for(&mut self, backend: &str) -> (String, Value) {
        let client = self.register_client(CALLBACK).await;
        let (verifier, challenge) = pkce();
        let (code, _) = self
            .authorize_code(&client, CALLBACK, backend, &challenge)
            .await;
        let (status, tokens) = self
            .exchange(&client, &code, &verifier, CALLBACK, backend)
            .await;
        assert_eq!(status, 200, "{tokens}");
        (client, tokens)
    }
}

pub fn rpc(id: i64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}
