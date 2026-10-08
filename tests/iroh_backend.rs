//! Phase 4 end to end: the real edge router with a `kind = "iroh"` route,
//! talking over loopback iroh (relays and address lookup off, ephemeral keys)
//! to an in-test fake origin built on `edge-origin`. The test plays the owner
//! on both sides: passkey on the edge, pairing code and decision in the "app".
//! All identities and data are synthetic.

mod common;

use common::*;
use edge_origin::{
    edge_tunnel::{
        self,
        approval::{
            self, ApprovalBinding, ApprovalClaims, Decision as WireDecision, ResourceScope,
        },
        client::ClientConfig,
        enrollment::Enrollment,
        frame, ids, limits,
        meta::{self, ConsentResponseMeta, RequestMeta},
    },
    ConsentRequestMeta, ConsentResponder, ErrorCode, GrantRef, GrantRevokeMeta, GrantState,
    GrantSyncEntry, McpRequest, McpResponse, OriginApp, OriginConfig, OriginHandler, Refusal,
    RemoteState, VerifiedGrant,
};
use edge_tunnel::iroh::{
    endpoint::{presets, Connection},
    protocol::Router,
    Endpoint, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use mcp_edge::tunnel::IrohDeps;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

const ROUTE: &str = "wiskit";
const ENV: &str = "EDGE_ORIGIN_WISKIT";

fn routes() -> String {
    format!(
        r#"
[[backend]]
id = "echo"
kind = "echo"
consent = "edge"
display_name = "Echo"

[[backend]]
id = "{ROUTE}"
kind = "iroh"
consent = "origin"
display_name = "Wiskit (test)"
scopes = ["wiskit:read"]
grant_lifetime_secs = 86400
max_request_bytes = 65536
max_response_bytes = 1048576
origin_endpoint_env = "{ENV}"
"#
    )
}

async fn loopback_endpoint(key: SecretKey, alpns: Vec<Vec<u8>>) -> Endpoint {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .relay_mode(RelayMode::Disabled)
        .clear_relay_transports()
        .clear_address_lookup()
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .transport_config(edge_tunnel::transport_config())
        .alpns(alpns)
        .bind()
        .await
        .unwrap();
    for a in &endpoint.addr().addrs {
        assert!(matches!(a, TransportAddr::Ip(a) if a.ip().is_loopback()));
    }
    endpoint
}

// ------------------------------------------------------------ fake origin

#[derive(Clone, Debug)]
struct Record {
    client_id: String,
    trackers: Vec<String>,
    gen: Option<u64>,
    revoked: bool,
}

enum OwnerDecision {
    Approve {
        code: String,
        trackers: Vec<String>,
        lifetime: u64,
    },
    Deny,
    Refuse(ErrorCode),
}

struct Prompt {
    request: ConsentRequestMeta,
    decide: oneshot::Sender<OwnerDecision>,
}

/// A stand-in for the Wiskit app: memory grant records written at approval,
/// enforcement from the record (never from the assertion), two read tools.
struct FakeWiskit {
    remote: Mutex<RemoteState>,
    records: Mutex<HashMap<String, Record>>,
    events: Mutex<Vec<String>>,
    grants_seen: Mutex<Vec<VerifiedGrant>>,
    prompts: mpsc::UnboundedSender<Prompt>,
    mcp_calls: AtomicUsize,
    refuse_mcp: Mutex<Option<ErrorCode>>,
}

impl FakeWiskit {
    fn event(&self, e: String) {
        self.events.lock().unwrap().push(e);
    }
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn tool_result(id: &Value, payload: Value, is_error: bool) -> McpResponse {
    McpResponse::json(
        json!({"jsonrpc": "2.0", "id": id, "result": {
            "content": [{"type": "text", "text": payload.to_string()}],
            "structuredContent": payload,
            "isError": is_error,
        }})
        .to_string(),
    )
}

impl OriginApp for FakeWiskit {
    fn remote_state(&self) -> RemoteState {
        *self.remote.lock().unwrap()
    }

    fn origin_version(&self) -> String {
        "fake-wiskit-1.7.0-test".into()
    }

    async fn mcp_post(&self, req: McpRequest) -> Result<McpResponse, Refusal> {
        self.mcp_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(code) = *self.refuse_mcp.lock().unwrap() {
            return Err(Refusal::new(code));
        }
        let g = req.grant.clone();
        self.grants_seen.lock().unwrap().push(g.clone());
        let trackers = {
            let mut records = self.records.lock().unwrap();
            let Some(rec) = records.get_mut(&g.grant_id) else {
                return Err(Refusal::new(ErrorCode::UnknownGrant));
            };
            if rec.revoked {
                return Err(Refusal::new(ErrorCode::GrantRevoked));
            }
            if rec.client_id != g.client_id {
                return Err(Refusal::new(ErrorCode::AssertionInvalid));
            }
            match rec.gen {
                None => rec.gen = Some(g.gen),
                Some(gen) if gen != g.gen => return Err(Refusal::new(ErrorCode::AssertionInvalid)),
                Some(_) => {}
            }
            let asked: Vec<String> = g.resource_scope["trackers"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            if g.resource_scope["access"] != "read"
                || !asked.iter().all(|t| rec.trackers.contains(t))
            {
                rec.revoked = true;
                return Err(Refusal::new(ErrorCode::ScopeMismatch));
            }
            // Authority comes from the record, never from the assertion.
            rec.trackers.clone()
        };
        let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let id = body["id"].clone();
        let method = body["method"].as_str().unwrap_or_default().to_owned();
        Ok(match method.as_str() {
            "initialize" => McpResponse::json(
                json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": body["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "fake-wiskit", "version": "0"},
                }})
                .to_string(),
            ),
            m if m.starts_with("notifications/") => McpResponse::accepted(),
            "tools/list" => McpResponse::json(
                json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [
                    {"name": "wiskit_list_trackers", "inputSchema": {"type": "object"},
                     "annotations": {"readOnlyHint": true}},
                    {"name": "wiskit_read_tracker_bundle", "inputSchema": {"type": "object"},
                     "annotations": {"readOnlyHint": true}},
                ]}})
                .to_string(),
            ),
            "tools/call" => match body["params"]["name"].as_str() {
                Some("wiskit_list_trackers") => tool_result(
                    &id,
                    json!({"trackers": trackers.iter().map(|t| json!({"id": t, "name": format!("Synthetic {t}")})).collect::<Vec<_>>()}),
                    false,
                ),
                Some("wiskit_read_tracker_bundle") => {
                    let wanted = body["params"]["arguments"]["trackerId"]
                        .as_str()
                        .unwrap_or_default();
                    if trackers.iter().any(|t| t == wanted) {
                        tool_result(
                            &id,
                            json!({"tracker": {"id": wanted}, "events": [{"id": "e1", "timestamp": 1, "details": {}}], "nextCursor": null}),
                            false,
                        )
                    } else {
                        tool_result(&id, json!({"error": "tracker_not_granted"}), true)
                    }
                }
                _ => McpResponse::json(
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": "unknown tool"}})
                        .to_string(),
                ),
            },
            "stream" => {
                let events = futures_util::stream::iter(vec![
                    Ok(bytes::Bytes::from_static(b"data: {\"n\":1}\n\n")),
                    Ok(bytes::Bytes::from_static(b"data: {\"n\":2}\n\n")),
                ]);
                McpResponse::event_stream(Box::pin(events))
            }
            _ => McpResponse::json(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})
                    .to_string(),
            ),
        })
    }

    async fn consent_request(&self, responder: ConsentResponder) {
        let (decide, decision) = oneshot::channel();
        let request = responder.request().clone();
        self.event(format!("prompt:{}", request.client_name));
        let _ = self.prompts.send(Prompt {
            request: request.clone(),
            decide,
        });
        let cancel = responder.cancelled();
        tokio::select! {
            d = decision => match d {
                Ok(OwnerDecision::Approve { code, trackers, lifetime }) => {
                    if !responder.pairing_code_matches(&code) {
                        self.event("wrong_code".into());
                        return;
                    }
                    let mut sorted = trackers.clone();
                    sorted.sort();
                    // Record first; drop it if the approval is not delivered.
                    self.records.lock().unwrap().insert(request.grant_id.clone(), Record {
                        client_id: request.client_id.clone(),
                        trackers: sorted,
                        gen: None,
                        revoked: false,
                    });
                    match responder.approve(trackers, lifetime).await {
                        Ok(()) => self.event(format!("approved:{}", request.grant_id)),
                        Err(e) => {
                            self.records.lock().unwrap().remove(&request.grant_id);
                            self.event(format!("approve_failed:{e}"));
                        }
                    }
                }
                Ok(OwnerDecision::Deny) => {
                    let _ = responder.deny().await;
                    self.event("denied".into());
                }
                Ok(OwnerDecision::Refuse(code)) => {
                    let _ = responder.refuse(Refusal::new(code)).await;
                }
                Err(_) => {}
            },
            _ = cancel.cancelled() => self.event("prompt_cancelled".into()),
        }
    }

    async fn grant_sync(&self, grants: Vec<GrantRef>) -> Result<Vec<GrantSyncEntry>, Refusal> {
        let records = self.records.lock().unwrap();
        Ok(grants
            .into_iter()
            .filter_map(|g| {
                records.get(&g.grant_id).map(|r| GrantSyncEntry {
                    grant_id: g.grant_id.clone(),
                    state: if r.revoked {
                        GrantState::Revoked
                    } else {
                        GrantState::Active
                    },
                })
            })
            .collect())
    }

    async fn grant_revoke(&self, revoke: GrantRevokeMeta) -> Result<(), Refusal> {
        if let Some(r) = self.records.lock().unwrap().get_mut(&revoke.grant_id) {
            r.revoked = true;
        }
        let reason = serde_json::to_value(revoke.reason).unwrap();
        self.event(format!(
            "revoke:{}:{}:{}",
            revoke.grant_id,
            revoke.gen,
            reason.as_str().unwrap()
        ));
        Ok(())
    }
}

struct Origin {
    app: Arc<FakeWiskit>,
    handler: OriginHandler<FakeWiskit>,
    router: Router,
    prompts: tokio::sync::Mutex<mpsc::UnboundedReceiver<Prompt>>,
}

impl Origin {
    async fn next_prompt(&self) -> Prompt {
        // 30 s, not 10: the full workspace suite can run this on a loaded machine.
        tokio::time::timeout(Duration::from_secs(30), self.prompts.lock().await.recv())
            .await
            .expect("the app receives a consent prompt")
            .unwrap()
    }

    async fn wait_event(&self, wanted: &str) {
        let start = Instant::now();
        while !self.app.events().iter().any(|e| e.contains(wanted)) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "event {wanted} not seen: {:?}",
                self.app.events()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

struct Setup {
    h: Harness,
    origin: Origin,
    owner: Browser,
    enrollment: Enrollment,
}

struct SetupOptions {
    auth_limits: edge_auth::config::Limits,
    /// Configure this origin id instead of the fake origin's real one (the
    /// address still points at the fake origin).
    configured_id: Option<EndpointId>,
    endpoint_available: bool,
    enroll_origin: bool,
}

impl Default for SetupOptions {
    fn default() -> Self {
        Self {
            auth_limits: Options::default().auth_limits,
            configured_id: None,
            endpoint_available: true,
            enroll_origin: true,
        }
    }
}

async fn start_origin(key: SecretKey) -> (Origin, Endpoint) {
    let (prompts_tx, prompts_rx) = mpsc::unbounded_channel();
    let app = Arc::new(FakeWiskit {
        remote: Mutex::new(RemoteState::On),
        records: Mutex::new(HashMap::new()),
        events: Mutex::new(Vec::new()),
        grants_seen: Mutex::new(Vec::new()),
        prompts: prompts_tx,
        mcp_calls: AtomicUsize::new(0),
        refuse_mcp: Mutex::new(None),
    });
    let endpoint = loopback_endpoint(key.clone(), vec![edge_tunnel::ALPN.to_vec()]).await;
    let handler = OriginHandler::new(app.clone(), key, OriginConfig::default());
    let router = Router::builder(endpoint.clone())
        .accept(edge_tunnel::ALPN, handler.clone())
        .spawn();
    (
        Origin {
            app,
            handler,
            router,
            prompts: tokio::sync::Mutex::new(prompts_rx),
        },
        endpoint,
    )
}

async fn setup_with(o: SetupOptions) -> Setup {
    let origin_key = SecretKey::generate();
    let (origin, origin_endpoint) = start_origin(origin_key.clone()).await;
    let edge_key = SecretKey::generate();
    let edge_endpoint = loopback_endpoint(edge_key.clone(), vec![]).await;
    let configured = o.configured_id.unwrap_or(origin_key.public());
    let mut addresses = HashMap::new();
    let mut addr = origin_endpoint.addr();
    addr.id = configured;
    addresses.insert(configured, addr);
    let mut env = HashMap::new();
    env.insert(ENV.to_string(), ids::endpoint_id_hex(&configured));
    let mut h = Harness::start_with(Options {
        auth_limits: o.auth_limits,
        routes: routes(),
        env,
        iroh: Some(IrohDeps {
            secret_key: edge_key,
            endpoint: o.endpoint_available.then_some(edge_endpoint),
            client: ClientConfig::default(),
            addresses,
        }),
        ..Options::default()
    })
    .await;
    h.enroll().await;
    let mut owner = Browser::default();
    assert_eq!(h.owner_login(&mut owner, None).await, 200);
    // §1.3: the owner copies the enrollment string from /owner into the app.
    let page = h.get(&mut owner, "/owner").await.text().await.unwrap();
    let enrollment_text = between(&page, "spellcheck=\"false\">", "</textarea>").expect("panel");
    let enrollment = Enrollment::parse(&enrollment_text).unwrap();
    assert!(page.contains(&enrollment.fingerprint()));
    let configured_hex = ids::endpoint_id_hex(&configured);
    assert!(page.contains(&configured_hex), "configured origin id shown");
    assert!(page.contains(&configured_hex[..8]));
    assert_eq!(enrollment.aud, ROUTE);
    assert_eq!(enrollment.iss, ISSUER);
    assert_eq!(enrollment.sub, h.owner_id);
    assert_eq!(enrollment.assert_key, h.assertion_key);
    assert_eq!(enrollment.scopes, vec!["wiskit:read".to_string()]);
    if o.enroll_origin {
        origin
            .handler
            .set_enrollment(Some(enrollment.clone()))
            .unwrap();
    }
    Setup {
        h,
        origin,
        owner,
        enrollment,
    }
}

async fn setup() -> Setup {
    setup_with(SetupOptions::default()).await
}

fn between(html: &str, start: &str, end: &str) -> Option<String> {
    let a = html.find(start)? + start.len();
    let b = html[a..].find(end)? + a;
    Some(html[a..b].to_string())
}

fn pairing_code(html: &str) -> String {
    between(html, "class=\"code\"><strong>", "</strong>")
        .expect("pairing code on the page")
        .replace('-', "")
}

/// The browser leg up to the point where the request was sent to the app.
struct Pending {
    browser: Browser,
    tx: String,
    client: String,
    verifier: String,
    csrf: String,
}

impl Setup {
    async fn begin(&mut self) -> Pending {
        let client = self.h.register_client(CALLBACK).await;
        let (verifier, challenge) = pkce();
        let mut browser = Browser::default();
        let tx = self
            .h
            .begin(&mut browser, &client, CALLBACK, ROUTE, &challenge, "st-1")
            .await;
        assert_eq!(self.h.owner_login(&mut browser, Some(&tx)).await, 200);
        let page = self
            .h
            .get(&mut browser, &format!("/consent?tx={tx}"))
            .await
            .text()
            .await
            .unwrap();
        assert!(page.contains("Continue to Wiskit (test)"), "{page}");
        assert!(page.contains("will see it in plaintext"));
        assert!(
            !page.contains("value=\"approve\""),
            "no edge approve button"
        );
        let csrf = extract_csrf(&page).unwrap();
        Pending {
            browser,
            tx,
            client,
            verifier,
            csrf,
        }
    }

    async fn start(&mut self, p: &mut Pending) -> u16 {
        let res = self
            .h
            .post_form(
                &mut p.browser,
                "/consent/start",
                &[("tx", &p.tx), ("csrf", &p.csrf)],
            )
            .await;
        res.status().as_u16()
    }

    async fn page(&mut self, p: &mut Pending) -> String {
        self.h
            .get(&mut p.browser, &format!("/consent?tx={}", p.tx))
            .await
            .text()
            .await
            .unwrap()
    }

    async fn status(&mut self, p: &mut Pending) -> Value {
        self.h
            .get(&mut p.browser, &format!("/consent/status?tx={}", p.tx))
            .await
            .json()
            .await
            .unwrap()
    }

    async fn wait_state(&mut self, p: &mut Pending, wanted: &str) -> Value {
        let start = Instant::now();
        loop {
            let s = self.status(p).await;
            if s["state"] == wanted {
                return s;
            }
            assert!(
                start.elapsed() < Duration::from_secs(15),
                "state {wanted} not reached: {s}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn finish(&mut self, p: &mut Pending) -> String {
        let res = self
            .h
            .post_form(
                &mut p.browser,
                "/consent/finish",
                &[("tx", &p.tx), ("csrf", &p.csrf)],
            )
            .await;
        assert_eq!(res.status(), 303);
        res.headers()["location"].to_str().unwrap().to_string()
    }

    /// Full origin consent with the given trackers; returns (client, tokens, grant id).
    async fn connect(&mut self, trackers: &[&str], lifetime: u64) -> (String, Value, String) {
        let mut p = self.begin().await;
        assert_eq!(self.start(&mut p).await, 303);
        let page = self.page(&mut p).await;
        let code = pairing_code(&page);
        assert!(page.contains("data-poll"));
        let prompt = self.origin.next_prompt().await;
        assert_eq!(prompt.request.client_name, "Synthetic <Client>");
        assert_eq!(prompt.request.client_id, p.client);
        assert_eq!(prompt.request.redirect_host, "claude.ai");
        assert_eq!(prompt.request.scopes, vec!["wiskit:read".to_string()]);
        assert_eq!(prompt.request.max_lifetime_secs, 86_400);
        let grant_id = prompt.request.grant_id.clone();
        prompt
            .decide
            .send(OwnerDecision::Approve {
                code: code.to_lowercase(),
                trackers: trackers.iter().map(|t| t.to_string()).collect(),
                lifetime,
            })
            .ok()
            .unwrap();
        self.wait_state(&mut p, "approved").await;
        let page = self.page(&mut p).await;
        assert!(page.contains("data-autosubmit"));
        let location = self.finish(&mut p).await;
        assert!(location.starts_with(CALLBACK), "{location}");
        assert_eq!(query_param(&location, "state").as_deref(), Some("st-1"));
        assert_eq!(query_param(&location, "iss").as_deref(), Some(ISSUER));
        let code = query_param(&location, "code").expect("code");
        let (status, tokens) = self
            .h
            .exchange(&p.client, &code, &p.verifier, CALLBACK, ROUTE)
            .await;
        assert_eq!(status, 200, "{tokens}");
        (p.client, tokens, grant_id)
    }

    async fn mcp(&self, token: &str, body: &Value) -> reqwest::Response {
        self.h.mcp(ROUTE, Some(token), body).await
    }

    fn assert_logs_clean(&self, secrets: &[&str]) {
        for line in self.h.logs() {
            for s in secrets {
                assert!(!line.contains(s), "secret in log: {line}");
            }
        }
    }
}

fn access(tokens: &Value) -> String {
    tokens["access_token"].as_str().unwrap().to_string()
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn origin_consent_issues_scoped_token_and_mcp_reaches_the_origin() {
    let mut s = setup().await;
    let (client, tokens, grant_id) = s.connect(&["t2", "t1"], 3600).await;
    let token = access(&tokens);

    // initialize, tools/list, tools/call reach the fake origin with a valid
    // assertion (the origin verified it before calling the app).
    let res = s
        .mcp(
            &token,
            &rpc(1, "initialize", json!({"protocolVersion": "2025-06-18"})),
        )
        .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "application/json");
    assert_eq!(res.headers()["cache-control"], "no-store");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "fake-wiskit");
    assert_eq!(body["id"], 1);

    let res =
        s.h.http
            .post(s.h.url(&format!("/{ROUTE}/mcp")))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string())
            .send()
            .await
            .unwrap();
    assert_eq!(res.status(), 202);

    let body: Value = s
        .mcp(&token, &rpc(2, "tools/list", json!({})))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["result"]["tools"].as_array().unwrap().len(), 2);

    let body: Value = s
        .mcp(
            &token,
            &rpc(
                3,
                "tools/call",
                json!({"name": "wiskit_list_trackers", "arguments": {}}),
            ),
        )
        .await
        .json()
        .await
        .unwrap();
    let listed = &body["result"]["structuredContent"]["trackers"];
    assert_eq!(listed.as_array().unwrap().len(), 2);
    let body: Value = s
        .mcp(
            &token,
            &rpc(
                4,
                "tools/call",
                json!({"name": "wiskit_read_tracker_bundle", "arguments": {"trackerId": "t9"}}),
            ),
        )
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(body["result"]["isError"], true, "ungranted tracker refused");

    // SSE answers stream through.
    let res =
        s.h.http
            .post(s.h.url(&format!("/{ROUTE}/mcp")))
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("authorization", format!("Bearer {token}"))
            .body(rpc(5, "stream", json!({})).to_string())
            .send()
            .await
            .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    assert_eq!(res.headers()["x-accel-buffering"], "no");
    let text = res.text().await.unwrap();
    assert!(text.contains("{\"n\":1}") && text.contains("{\"n\":2}"));

    // What the origin saw: the edge-signed identity and the approved scope.
    let seen = s.origin.app.grants_seen.lock().unwrap().clone();
    assert!(!seen.is_empty());
    for g in &seen {
        assert_eq!(g.grant_id, grant_id);
        assert_eq!(g.client_id, client);
        assert_eq!(g.sub, s.h.owner_id);
        assert_eq!(g.scope, vec!["wiskit:read".to_string()]);
        assert_eq!(
            g.resource_scope,
            json!({"v": 1, "access": "read", "trackers": ["t1", "t2"]})
        );
        assert_eq!(g.gen, 1);
    }

    // Refresh never widens or drops the approved scope.
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let (status, refreshed) = s.h.refresh(&client, refresh).await;
    assert_eq!(status, 200, "{refreshed}");
    assert_eq!(refreshed["scope"], "wiskit:read");
    let res = s
        .mcp(&access(&refreshed), &rpc(6, "tools/list", json!({})))
        .await;
    assert_eq!(res.status(), 200);
    let last = s
        .origin
        .app
        .grants_seen
        .lock()
        .unwrap()
        .last()
        .cloned()
        .unwrap();
    assert_eq!(
        last.resource_scope,
        json!({"v": 1, "access": "read", "trackers": ["t1", "t2"]})
    );

    // The token is bound to this backend.
    let res =
        s.h.mcp("echo", Some(&token), &rpc(7, "tools/list", json!({})))
            .await;
    assert_eq!(res.status(), 401);

    // Only POST; the client's own Edge-Assertion is irrelevant (never sent on).
    let res =
        s.h.http
            .get(s.h.url(&format!("/{ROUTE}/mcp")))
            .header("authorization", format!("Bearer {token}"))
            .send()
            .await
            .unwrap();
    assert_eq!(res.status(), 405);
    assert_eq!(res.headers()["allow"], "POST");
    let res =
        s.h.http
            .post(s.h.url(&format!("/{ROUTE}/mcp")))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("edge-assertion", "forged.forged")
            .header("mcp-protocol-version", "1999-01-01")
            .body(rpc(8, "tools/list", json!({})).to_string())
            .send()
            .await
            .unwrap();
    assert_eq!(res.status(), 400, "unknown protocol version");

    let logs = s.h.logs();
    assert!(logs.iter().any(|l| l.contains("event=consent_sent")));
    assert!(logs
        .iter()
        .any(|l| l.contains(&format!("event=consent_origin_approved grant={grant_id}"))));
    s.assert_logs_clean(&[&token, refresh]);
    s.h.finish().await;
}

#[tokio::test]
async fn edge_page_cannot_approve_an_origin_backend() {
    let mut s = setup().await;
    let mut p = s.begin().await;
    let res =
        s.h.post_form(
            &mut p.browser,
            "/consent",
            &[("tx", &p.tx), ("csrf", &p.csrf), ("decision", "approve")],
        )
        .await;
    assert_eq!(res.status(), 400);
    assert!(res.headers().get("location").is_none());
    // finish without an approval only returns to the consent page.
    let res =
        s.h.post_form(
            &mut p.browser,
            "/consent/finish",
            &[("tx", &p.tx), ("csrf", &p.csrf)],
        )
        .await;
    assert_eq!(res.status(), 303);
    assert!(res.headers()["location"]
        .to_str()
        .unwrap()
        .starts_with("/consent?tx="));
    // A forged CSRF token cannot start the request.
    let res =
        s.h.post_form(
            &mut p.browser,
            "/consent/start",
            &[("tx", &p.tx), ("csrf", "forged")],
        )
        .await;
    assert_eq!(res.status(), 400);
    // Cross-origin start is refused.
    let res =
        s.h.post_form_origin(
            &mut p.browser,
            "/consent/start",
            &[("tx", &p.tx), ("csrf", &p.csrf)],
            "https://evil.example",
        )
        .await;
    assert_eq!(res.status(), 403);
    // Deny on the edge page works and never yields a code.
    let res =
        s.h.post_form(
            &mut p.browser,
            "/consent",
            &[("tx", &p.tx), ("csrf", &p.csrf), ("decision", "deny")],
        )
        .await;
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert!(query_param(&location, "code").is_none());
    assert_eq!(s.origin.app.events().len(), 0, "the app was never asked");
    s.h.finish().await;
}

#[tokio::test]
async fn origin_denial_ends_with_access_denied() {
    let mut s = setup().await;
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    let prompt = s.origin.next_prompt().await;
    prompt.decide.send(OwnerDecision::Deny).ok().unwrap();
    s.wait_state(&mut p, "denied").await;
    let location = s.finish(&mut p).await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert!(query_param(&location, "code").is_none());
    assert!(s
        .h
        .logs()
        .iter()
        .any(|l| l.contains("event=consent_origin_denied")));
    // The pending request is consumed.
    let res =
        s.h.get(&mut p.browser, &format!("/consent?tx={}", p.tx))
            .await;
    assert_eq!(res.status(), 400);
    s.h.finish().await;
}

#[tokio::test]
async fn no_decision_in_time_is_origin_timeout() {
    let mut s = setup_with(SetupOptions {
        auth_limits: edge_auth::config::Limits {
            origin_consent_secs: 2,
            ..Options::default().auth_limits
        },
        ..SetupOptions::default()
    })
    .await;
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    let _prompt = s.origin.next_prompt().await; // the owner never answers
    let started = Instant::now();
    s.wait_state(&mut p, "origin_timeout").await;
    assert!(started.elapsed() < Duration::from_secs(12));
    let page = s.page(&mut p).await;
    assert!(page.contains("No decision"), "{page}");
    s.origin.wait_event("prompt_cancelled").await;
    let location = s.finish(&mut p).await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    s.h.finish().await;
}

#[tokio::test]
async fn cancel_stops_the_prompt_and_denies() {
    let mut s = setup().await;
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    let _prompt = s.origin.next_prompt().await;
    let res =
        s.h.post_form(
            &mut p.browser,
            "/consent/cancel",
            &[("tx", &p.tx), ("csrf", &p.csrf)],
        )
        .await;
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    // The dropped stream reaches the app, which closes its prompt.
    s.origin.wait_event("prompt_cancelled").await;
    s.h.finish().await;
}

#[tokio::test]
async fn cancelling_after_the_app_approved_tells_the_app() {
    let mut s = setup().await;
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    let code = pairing_code(&s.page(&mut p).await);
    let prompt = s.origin.next_prompt().await;
    let grant_id = prompt.request.grant_id.clone();
    prompt
        .decide
        .send(OwnerDecision::Approve {
            code,
            trackers: vec!["t1".into()],
            lifetime: 3600,
        })
        .ok()
        .unwrap();
    s.wait_state(&mut p, "approved").await;
    // The owner changes their mind on the edge page before returning.
    let res =
        s.h.post_form(
            &mut p.browser,
            "/consent/cancel",
            &[("tx", &p.tx), ("csrf", &p.csrf)],
        )
        .await;
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_string();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert!(query_param(&location, "code").is_none());
    // The app's record for the never-issued grant is ended.
    s.origin
        .wait_event(&format!("revoke:{grant_id}:1:client"))
        .await;
    s.h.finish().await;
}

#[tokio::test]
async fn unreachable_origin_refunds_then_allows_three_attempts_then_denies() {
    // The app never showed a prompt, so the first tries are given back (here
    // 2, by configuration); after that each try costs an attempt.
    let mut s = setup_with(SetupOptions {
        auth_limits: edge_auth::config::Limits {
            origin_consent_refunds: 2,
            ..Options::default().auth_limits
        },
        ..SetupOptions::default()
    })
    .await;
    let _ = s.origin.router.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut p = s.begin().await;
    for left in [3, 3, 2, 1, 0] {
        assert_eq!(s.start(&mut p).await, 303);
        let st = s.wait_state(&mut p, "origin_unreachable").await;
        assert_eq!(st["attempts_left"], left, "{st}");
    }
    let page = s.page(&mut p).await;
    assert!(page.contains("is not reachable"), "{page}");
    assert!(page.contains("No attempts are left"), "{page}");
    // A fourth start does nothing.
    assert_eq!(s.start(&mut p).await, 303);
    assert_eq!(s.status(&mut p).await["attempts_left"], 0);
    let location = s.finish(&mut p).await;
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    s.h.finish().await;
}

#[tokio::test]
async fn origin_offline_is_a_fast_503_with_retry_after() {
    let mut s = setup().await;
    let (_, tokens, _) = s.connect(&["t1"], 3600).await;
    let token = access(&tokens);
    assert_eq!(
        s.mcp(&token, &rpc(1, "tools/list", json!({})))
            .await
            .status(),
        200
    );
    // The home PC goes away.
    let _ = s.origin.router.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    let res = s.mcp(&token, &rpc(77, "tools/list", json!({}))).await;
    assert!(
        started.elapsed() < Duration::from_millis(3_500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(res.status(), 503);
    assert_eq!(res.headers()["retry-after"], "30");
    assert_eq!(res.headers()["cache-control"], "no-store");
    assert_eq!(res.headers()["content-type"], "application/json");
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["id"], 77);
    assert_eq!(body["error"]["code"], -32010);
    assert_eq!(body["error"]["data"]["reason"], "origin_offline");
    assert!(body["error"]["message"]
        .as_str()
        .unwrap()
        .contains("is not reachable"));
    // Within the offline window the answer is immediate.
    let started = Instant::now();
    let res = s.mcp(&token, &rpc(78, "tools/list", json!({}))).await;
    assert_eq!(res.status(), 503);
    assert!(started.elapsed() < Duration::from_millis(500));
    // Health is unaffected.
    let res = s.h.http.get(s.h.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    assert!(s
        .h
        .logs()
        .iter()
        .any(|l| l.contains("event=origin_offline backend=wiskit")));
    s.h.finish().await;
}

#[tokio::test]
async fn origin_refusals_map_to_the_http_contract() {
    let mut s = setup().await;
    let (_, tokens, grant_id) = s.connect(&["t1"], 3600).await;
    let token = access(&tokens);
    let refuse = |code: Option<ErrorCode>| *s.origin.app.refuse_mcp.lock().unwrap() = code;
    // (code, HTTP status, error / reason)
    let rows: &[(ErrorCode, u16, &str)] = &[
        (ErrorCode::RemoteDisabled, 503, "origin_remote_off"),
        (ErrorCode::EnrollmentStale, 503, "origin_unenrolled"),
        (ErrorCode::OriginLocked, 503, "origin_locked"),
        (ErrorCode::AuditUnavailable, 503, "origin_paused"),
        (ErrorCode::AssertionInvalid, 502, "backend_rejected"),
        (ErrorCode::Busy, 429, "too_many_in_flight"),
        (ErrorCode::Deadline, 504, "upstream_timeout"),
        (ErrorCode::BadRequest, 502, "backend_protocol"),
        (ErrorCode::VersionUnsupported, 502, "backend_protocol"),
    ];
    for (code, status, reason) in rows {
        refuse(Some(*code));
        let res = s.mcp(&token, &rpc(5, "tools/list", json!({}))).await;
        assert_eq!(res.status().as_u16(), *status, "{code}");
        if *status == 503 {
            assert_eq!(res.headers()["retry-after"], "30");
            let body: Value = res.json().await.unwrap();
            assert_eq!(body["error"]["data"]["reason"], *reason, "{code}");
            assert_eq!(body["id"], 5);
        } else {
            if *status == 429 {
                assert!(res.headers().contains_key("retry-after"));
            }
            let body: Value = res.json().await.unwrap();
            assert_eq!(body["error"], *reason, "{code}");
        }
    }
    assert!(s
        .h
        .logs()
        .iter()
        .any(|l| l.contains("event=backend_rejected_assertion backend=wiskit")));
    // unknown/revoked/expired grant: 401 challenge, and the edge revokes too.
    refuse(Some(ErrorCode::GrantRevoked));
    let res = s.mcp(&token, &rpc(6, "tools/list", json!({}))).await;
    assert_eq!(res.status(), 401);
    assert!(res.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .contains("invalid_token"));
    refuse(None);
    let calls = s.origin.app.mcp_calls.load(Ordering::SeqCst);
    let res = s.mcp(&token, &rpc(7, "tools/list", json!({}))).await;
    assert_eq!(res.status(), 401, "the edge revoked the grant");
    assert_eq!(s.origin.app.mcp_calls.load(Ordering::SeqCst), calls);
    assert!(s.h.logs().iter().any(|l| l.contains(&format!(
        "event=origin_grant_revoked backend=wiskit grant={grant_id}"
    ))));
    s.h.finish().await;
}

#[tokio::test]
async fn owner_revocation_propagates_grant_revoke_to_the_origin() {
    let mut s = setup().await;
    let (_, tokens, grant_id) = s.connect(&["t1"], 3600).await;
    let token = access(&tokens);
    assert_eq!(
        s.mcp(&token, &rpc(1, "tools/list", json!({})))
            .await
            .status(),
        200
    );
    let page = s.h.get(&mut s.owner, "/owner").await.text().await.unwrap();
    assert!(page.contains(&grant_id));
    let csrf = extract_csrf(&page).unwrap();
    let mut owner = s.owner.clone();
    let res =
        s.h.post_form(
            &mut owner,
            "/owner/grants/revoke",
            &[("csrf", &csrf), ("grant_id", &grant_id)],
        )
        .await;
    assert_eq!(res.status(), 303);
    // gen is the value the grant's assertions carried.
    s.origin
        .wait_event(&format!("revoke:{grant_id}:1:owner"))
        .await;
    assert!(s.origin.app.records.lock().unwrap()[&grant_id].revoked);
    let res = s.mcp(&token, &rpc(2, "tools/list", json!({}))).await;
    assert_eq!(res.status(), 401);
    s.h.finish().await;
}

#[tokio::test]
async fn grant_sync_on_reconnect_revokes_grants_the_origin_forgot() {
    let mut s = setup().await;
    let (_, tokens_a, grant_a) = s.connect(&["t1"], 3600).await;
    let token_a = access(&tokens_a);
    assert_eq!(
        s.mcp(&token_a, &rpc(1, "tools/list", json!({})))
            .await
            .status(),
        200
    );
    // Wiskit restarts (trial: memory-only grants) and the connection drops.
    s.origin.app.records.lock().unwrap().clear();
    s.origin
        .handler
        .close_all(edge_origin::CloseCode::ShuttingDown);
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The next connection (here: a new consent) runs grant_sync first.
    let (_, tokens_b, grant_b) = s.connect(&["t2"], 3600).await;
    let start = Instant::now();
    while !s.h.logs().iter().any(|l| {
        l.contains(&format!(
            "event=grant_sync_revoked backend=wiskit grant={grant_a}"
        ))
    }) {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            s.h.logs()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let calls = s.origin.app.mcp_calls.load(Ordering::SeqCst);
    let res = s.mcp(&token_a, &rpc(2, "tools/list", json!({}))).await;
    assert_eq!(res.status(), 401, "revoked at the edge without asking");
    assert_eq!(s.origin.app.mcp_calls.load(Ordering::SeqCst), calls);
    let res = s
        .mcp(&access(&tokens_b), &rpc(3, "tools/list", json!({})))
        .await;
    assert_eq!(res.status(), 200);
    assert!(!s.h.logs().iter().any(|l| l.contains(&format!(
        "grant_sync_revoked backend=wiskit grant={grant_b}"
    ))));
    s.h.finish().await;
}

#[tokio::test]
async fn origin_refusing_consent_shows_the_reason_and_allows_retry() {
    let mut s = setup().await;
    assert_eq!(
        s.origin.handler.enrollment().unwrap().fingerprint(),
        s.enrollment.fingerprint()
    );
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    let prompt = s.origin.next_prompt().await;
    prompt
        .decide
        .send(OwnerDecision::Refuse(ErrorCode::OriginLocked))
        .ok()
        .unwrap();
    let st = s.wait_state(&mut p, "origin_unreachable").await;
    // A refusal before any decision (locked) does not use up an attempt.
    assert_eq!(st["attempts_left"], 3);
    let page = s.page(&mut p).await;
    assert!(page.contains("is locked or still starting"), "{page}");
    assert!(page.contains("Try again"));
    // Retry: a new pairing code and grant id; the owner mistypes the code,
    // so the app sends no decision (never an approval).
    let first = prompt.request.clone();
    assert_eq!(s.start(&mut p).await, 303);
    let prompt = s.origin.next_prompt().await;
    assert_ne!(prompt.request.pairing_code, first.pairing_code);
    assert_ne!(prompt.request.grant_id, first.grant_id);
    assert_ne!(prompt.request.nonce, first.nonce);
    prompt
        .decide
        .send(OwnerDecision::Approve {
            code: "ZZZZZZ".into(),
            trackers: vec!["t1".into()],
            lifetime: 300,
        })
        .ok()
        .unwrap();
    let st = s.wait_state(&mut p, "origin_unreachable").await;
    // The owner saw this prompt and typed a code: that attempt counts.
    assert_eq!(st["attempts_left"], 2);
    s.origin.wait_event("wrong_code").await;
    // Next attempt: the right code.
    assert_eq!(s.start(&mut p).await, 303);
    let page = s.page(&mut p).await;
    let code = pairing_code(&page);
    let prompt = s.origin.next_prompt().await;
    prompt
        .decide
        .send(OwnerDecision::Approve {
            code,
            trackers: vec!["t1".into()],
            lifetime: 300,
        })
        .ok()
        .unwrap();
    s.wait_state(&mut p, "approved").await;
    let location = s.finish(&mut p).await;
    assert!(query_param(&location, "code").is_some());
    s.h.finish().await;
}

#[tokio::test]
async fn wrong_origin_peer_is_never_asked() {
    // The route names another EndpointId; the address points at the fake
    // origin, whose TLS identity then does not match: the dial fails.
    let other = SecretKey::generate().public();
    let mut s = setup_with(SetupOptions {
        configured_id: Some(other),
        ..SetupOptions::default()
    })
    .await;
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    s.wait_state(&mut p, "origin_unreachable").await;
    assert!(
        s.origin.app.events().is_empty(),
        "{:?}",
        s.origin.app.events()
    );
    s.h.finish().await;
}

#[tokio::test]
async fn unenrolled_edge_is_rejected_by_the_origin() {
    let mut s = setup_with(SetupOptions {
        enroll_origin: false,
        ..SetupOptions::default()
    })
    .await;
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    s.wait_state(&mut p, "origin_unreachable").await;
    let page = s.page(&mut p).await;
    assert!(page.contains("does not recognize this edge"), "{page}");
    assert!(s.origin.app.events().is_empty());
    assert!(s
        .h
        .logs()
        .iter()
        .any(|l| l.contains("consent_origin_unreachable reason=origin_rejected_edge")));
    s.h.finish().await;
}

#[tokio::test]
async fn unavailable_endpoint_keeps_health_green() {
    let mut s = setup_with(SetupOptions {
        endpoint_available: false,
        ..SetupOptions::default()
    })
    .await;
    let res = s.h.http.get(s.h.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let res = s.h.http.get(s.h.url("/readyz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
    let page = s.h.get(&mut s.owner, "/owner").await.text().await.unwrap();
    assert!(page.contains("iroh endpoint is unavailable"));
    let mut p = s.begin().await;
    assert_eq!(s.start(&mut p).await, 303);
    s.wait_state(&mut p, "origin_unreachable").await;
    s.h.finish().await;
}

// --------------------------------------------- forged approvals (raw origin)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Forgery {
    /// Valid signature, then the payload is widened (more trackers).
    Tampered,
    /// Signed by another key that claims to be the origin.
    WrongKey,
    /// Right key, but under `edge-assert.v1.` instead of the approval prefix.
    WrongDomain,
    /// Right key and prefix, bound to another nonce.
    WrongNonce,
    /// A correct approval (control case).
    Valid,
}

/// Speaks `mcp-edge/1` by hand to answer `consent_request` with crafted
/// approvals.
#[derive(Clone, Debug)]
struct ForgingOrigin {
    key: SecretKey,
    mode: Arc<Mutex<Forgery>>,
}

fn sign_raw(key: &SecretKey, claims: &ApprovalClaims, prefix: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let json = edge_assert::canonical_json(&serde_json::to_value(claims).unwrap()).unwrap();
    let payload = URL_SAFE_NO_PAD.encode(json);
    let mut msg = prefix.to_vec();
    msg.extend_from_slice(payload.as_bytes());
    let sig = key.sign(&msg);
    format!("{payload}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

impl ForgingOrigin {
    fn approval(&self, m: &ConsentRequestMeta, edge: EndpointId) -> String {
        let mut binding = ApprovalBinding {
            origin_id: self.key.public(),
            edge_id: edge,
            issuer: ISSUER.into(),
            backend: ROUTE.into(),
            tx: m.tx.clone(),
            grant_id: m.grant_id.clone(),
            nonce: m.nonce.clone(),
            client_id: m.client_id.clone(),
            max_lifetime_secs: m.max_lifetime_secs,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let scope = ResourceScope::read(["t1".to_string()]).unwrap();
        let claims = ApprovalClaims {
            v: 1,
            decision: WireDecision::Approve,
            iss: ids::endpoint_id_hex(&self.key.public()),
            edge_id: ids::endpoint_id_hex(&edge),
            aud: ISSUER.into(),
            backend: ROUTE.into(),
            tx: m.tx.clone(),
            grant_id: m.grant_id.clone(),
            nonce: m.nonce.clone(),
            client_id: m.client_id.clone(),
            resource_scope: Some(scope.clone()),
            lifetime_secs: Some(3600),
            iat: now,
            exp: now + 60,
        };
        match *self.mode.lock().unwrap() {
            Forgery::Valid => approval::sign(
                &self.key,
                &binding,
                WireDecision::Approve,
                Some(scope),
                Some(3600),
                now,
                60,
            )
            .unwrap(),
            Forgery::WrongNonce => {
                binding.nonce = ids::random_b64url::<32>().unwrap();
                approval::sign(
                    &self.key,
                    &binding,
                    WireDecision::Approve,
                    Some(scope),
                    Some(3600),
                    now,
                    60,
                )
                .unwrap()
            }
            Forgery::WrongKey => {
                sign_raw(&SecretKey::generate(), &claims, approval::SIGNING_PREFIX)
            }
            Forgery::WrongDomain => sign_raw(&self.key, &claims, b"edge-assert.v1."),
            Forgery::Tampered => {
                let good = sign_raw(&self.key, &claims, approval::SIGNING_PREFIX);
                let sig = good.split_once('.').unwrap().1.to_string();
                let mut wider = claims.clone();
                wider.resource_scope =
                    Some(ResourceScope::read(["t1".to_string(), "t2".to_string()]).unwrap());
                let forged = sign_raw(&self.key, &wider, approval::SIGNING_PREFIX);
                format!("{}.{sig}", forged.split_once('.').unwrap().0)
            }
        }
    }
}

impl edge_tunnel::iroh::protocol::ProtocolHandler for ForgingOrigin {
    async fn accept(
        &self,
        conn: Connection,
    ) -> Result<(), edge_tunnel::iroh::protocol::AcceptError> {
        let edge = conn.remote_id();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let Ok(meta_bytes) = frame::read_field(&mut recv, limits::REQUEST_META).await else {
                continue;
            };
            let _ = frame::read_field(&mut recv, 0).await;
            let Ok(RequestMeta::ConsentRequest(m)) = meta::parse_request_meta(&meta_bytes) else {
                continue; // grant_sync / ping are not used by these tests
            };
            let response = ConsentResponseMeta {
                v: 1,
                status: 200,
                approval: Some(self.approval(&m, edge)),
                error: None,
                retry_after: None,
            };
            let bytes = meta::encode_response(&response, limits::CONSENT_RESPONSE).unwrap();
            let _ = frame::write_field(&mut send, &bytes, limits::CONSENT_RESPONSE).await;
            let _ = frame::write_terminator(&mut send).await;
            let _ = send.finish();
            let _ = send.stopped().await;
        }
        Ok(())
    }
}

#[tokio::test]
async fn forged_approvals_are_never_accepted() {
    // The real fake origin is replaced by a forging one under the same id.
    let origin_key = SecretKey::generate();
    let forging = ForgingOrigin {
        key: origin_key.clone(),
        mode: Arc::new(Mutex::new(Forgery::Tampered)),
    };
    let endpoint = loopback_endpoint(origin_key.clone(), vec![edge_tunnel::ALPN.to_vec()]).await;
    let router = Router::builder(endpoint.clone())
        .accept(edge_tunnel::ALPN, forging.clone())
        .spawn();
    let edge_key = SecretKey::generate();
    let edge_endpoint = loopback_endpoint(edge_key.clone(), vec![]).await;
    let mut env = HashMap::new();
    env.insert(ENV.to_string(), ids::endpoint_id_hex(&origin_key.public()));
    let mut h = Harness::start_with(Options {
        auth_limits: edge_auth::config::Limits {
            origin_consent_attempts: 5,
            ..Options::default().auth_limits
        },
        routes: routes(),
        env,
        iroh: Some(IrohDeps {
            secret_key: edge_key,
            endpoint: Some(edge_endpoint),
            client: ClientConfig::default(),
            addresses: [(origin_key.public(), endpoint.addr())]
                .into_iter()
                .collect(),
        }),
        ..Options::default()
    })
    .await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let (verifier, challenge) = pkce();
    let mut browser = Browser::default();
    let tx = h
        .begin(&mut browser, &client, CALLBACK, ROUTE, &challenge, "st-1")
        .await;
    assert_eq!(h.owner_login(&mut browser, Some(&tx)).await, 200);
    let csrf = h.consent_csrf(&mut browser, &tx).await.unwrap();
    let status = |b: Browser| {
        let h = &h;
        let tx = tx.clone();
        async move {
            let mut b = b;
            let v: Value = h
                .get(&mut b, &format!("/consent/status?tx={tx}"))
                .await
                .json()
                .await
                .unwrap();
            v
        }
    };
    for forgery in [
        Forgery::Tampered,
        Forgery::WrongKey,
        Forgery::WrongDomain,
        Forgery::WrongNonce,
    ] {
        *forging.mode.lock().unwrap() = forgery;
        let res = h
            .post_form(
                &mut browser,
                "/consent/start",
                &[("tx", &tx), ("csrf", &csrf)],
            )
            .await;
        assert_eq!(res.status(), 303);
        let start = Instant::now();
        loop {
            let st = status(browser.clone()).await;
            if st["state"] == "origin_unreachable" {
                break;
            }
            assert_ne!(st["state"], "approved", "{forgery:?} accepted");
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "{forgery:?}: {st}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let invalid = h
        .logs()
        .iter()
        .filter(|l| l.contains("event=origin_approval_invalid backend=wiskit"))
        .count();
    assert_eq!(invalid, 4, "{:?}", h.logs());
    // The control case is accepted, so the rejections above were the checks.
    *forging.mode.lock().unwrap() = Forgery::Valid;
    let res = h
        .post_form(
            &mut browser,
            "/consent/start",
            &[("tx", &tx), ("csrf", &csrf)],
        )
        .await;
    assert_eq!(res.status(), 303);
    let start = Instant::now();
    while status(browser.clone()).await["state"] != "approved" {
        assert!(start.elapsed() < Duration::from_secs(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let res = h
        .post_form(
            &mut browser,
            "/consent/finish",
            &[("tx", &tx), ("csrf", &csrf)],
        )
        .await;
    let location = res.headers()["location"].to_str().unwrap().to_string();
    let code = query_param(&location, "code").expect("valid approval issues a code");
    let (status, tokens) = h.exchange(&client, &code, &verifier, CALLBACK, ROUTE).await;
    assert_eq!(status, 200, "{tokens}");
    let _ = router.shutdown().await;
    h.finish().await;
}
