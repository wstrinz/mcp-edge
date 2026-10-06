//! Loopback-only test harness: ephemeral keys, relays and address lookup off,
//! IP transports bound to 127.0.0.1 (as in fixtures/iroh-transport-poc).
#![allow(dead_code)]

use bytes::Bytes;
use edge_origin::{
    edge_tunnel::{
        self,
        client::{ClientConfig, McpPostRequest, OriginClient},
        enrollment::Enrollment,
        meta::{Accept, McpProtocolVersion},
    },
    Body, BodyAborted, ConsentResponder, GrantRef, GrantRevokeMeta, GrantState, GrantSyncEntry,
    McpRequest, McpResponse, OriginApp, OriginConfig, OriginHandler, Refusal, RemoteState,
    VerifiedGrant,
};
use iroh::{
    endpoint::presets, protocol::Router, Endpoint, EndpointAddr, RelayMode, SecretKey,
    TransportAddr,
};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

pub const ISS: &str = "https://edge.test";
pub const AUD: &str = "wiskit";
pub const SUB: &str = "owner";
pub const SCOPE: &str = "wiskit:read";
pub const ASSERT_SEED: [u8; 32] = [1u8; 32];

pub async fn loopback_endpoint(key: SecretKey, alpns: Vec<Vec<u8>>) -> Endpoint {
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
    let addr = endpoint.addr();
    assert!(!addr.addrs.is_empty());
    for a in &addr.addrs {
        assert!(matches!(a, TransportAddr::Ip(a) if a.ip().is_loopback()));
    }
    endpoint
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[derive(Default)]
pub struct Counters {
    pub in_app: AtomicUsize,
    pub dropped_incomplete: AtomicUsize,
    pub cancel_seen: AtomicUsize,
    pub mcp_calls: AtomicUsize,
}

/// Counts app work dropped before completion (the PoC's MockStream idea).
pub struct WorkGuard {
    counters: Arc<Counters>,
    pub complete: bool,
}
impl WorkGuard {
    pub fn new(counters: &Arc<Counters>) -> Self {
        counters.in_app.fetch_add(1, Ordering::SeqCst);
        Self {
            counters: counters.clone(),
            complete: false,
        }
    }
}
impl Drop for WorkGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.counters
                .dropped_incomplete
                .fetch_add(1, Ordering::SeqCst);
        }
        self.counters.in_app.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentMode {
    Approve,
    Deny,
    Hold,
    Refuse,
    WrongCode,
}

pub struct FakeApp {
    pub remote: Mutex<RemoteState>,
    pub counters: Arc<Counters>,
    pub consent_mode: Mutex<ConsentMode>,
    pub events: Mutex<Vec<String>>,
    pub last_grant: Mutex<Option<VerifiedGrant>>,
}

impl Default for FakeApp {
    fn default() -> Self {
        Self {
            remote: Mutex::new(RemoteState::On),
            counters: Arc::new(Counters::default()),
            consent_mode: Mutex::new(ConsentMode::Approve),
            events: Mutex::new(Vec::new()),
            last_grant: Mutex::new(None),
        }
    }
}

impl FakeApp {
    pub fn set_remote(&self, s: RemoteState) {
        *self.remote.lock().unwrap() = s;
    }
    pub fn event(&self, e: impl Into<String>) {
        self.events.lock().unwrap().push(e.into());
    }
    pub fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn sse_stream(
    counters: Arc<Counters>,
    chunks: Option<usize>,
    every: Duration,
    abort_after: Option<usize>,
) -> edge_origin::BodyStream {
    struct State {
        guard: WorkGuard,
        i: usize,
    }
    Box::pin(futures_util::stream::unfold(
        State {
            guard: WorkGuard::new(&counters),
            i: 0,
        },
        move |mut st| async move {
            tokio::time::sleep(every).await;
            if abort_after == Some(st.i) {
                return Some((Err(BodyAborted), st));
            }
            if chunks.is_some_and(|n| st.i >= n) {
                st.guard.complete = true;
                drop(st);
                return None;
            }
            let item = Bytes::from(format!("data: {{\"chunk\":{}}}\n\n", st.i));
            st.i += 1;
            Some((Ok(item), st))
        },
    ))
}

impl OriginApp for FakeApp {
    fn remote_state(&self) -> RemoteState {
        *self.remote.lock().unwrap()
    }

    fn origin_version(&self) -> String {
        "test-1.0".into()
    }

    async fn mcp_post(&self, req: McpRequest) -> Result<McpResponse, Refusal> {
        self.counters.mcp_calls.fetch_add(1, Ordering::SeqCst);
        *self.last_grant.lock().unwrap() = Some(req.grant.clone());
        let json: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let method = json["method"].as_str().unwrap_or("").to_string();
        let counters = self.counters.clone();
        match method.as_str() {
            "echo" => Ok(McpResponse::json(
                serde_json::json!({"jsonrpc":"2.0","id":json["id"],"result":{"grant":req.grant.grant_id,"echo":json}})
                    .to_string(),
            )),
            "notify" => Ok(McpResponse::accepted()),
            "stream" => Ok(McpResponse::event_stream(sse_stream(
                counters,
                Some(5),
                Duration::from_millis(60),
                None,
            ))),
            "endless" => Ok(McpResponse::event_stream(sse_stream(
                counters,
                None,
                Duration::from_millis(50),
                None,
            ))),
            "abort" => Ok(McpResponse::event_stream(sse_stream(
                counters,
                None,
                Duration::from_millis(10),
                Some(1),
            ))),
            "big" => {
                let n = json["params"]["size"].as_u64().unwrap_or(0) as usize;
                Ok(McpResponse::json(vec![b'x'; n]))
            }
            "slow" => {
                let mut guard = WorkGuard::new(&counters);
                tokio::select! {
                    _ = req.cancel.cancelled() => {
                        counters.cancel_seen.fetch_add(1, Ordering::SeqCst);
                        guard.complete = true;
                        Err(Refusal::new(edge_origin::ErrorCode::Deadline))
                    }
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        guard.complete = true;
                        Ok(McpResponse::json("{}"))
                    }
                }
            }
            "revoked" => Err(Refusal::new(edge_origin::ErrorCode::GrantRevoked)),
            "bad_status" => Ok(McpResponse {
                status: 302,
                content_type: Some(edge_origin::ContentType::Json),
                body: Body::Empty,
            }),
            _ => Ok(McpResponse {
                status: 400,
                content_type: Some(edge_origin::ContentType::Json),
                body: Body::Full(Bytes::from_static(b"{\"error\":\"unknown method\"}")),
            }),
        }
    }

    async fn consent_request(&self, responder: ConsentResponder) {
        let mode = *self.consent_mode.lock().unwrap();
        let code = responder.request().pairing_code.clone();
        self.event(format!("consent_prompt:{}", responder.request().tx));
        match mode {
            ConsentMode::Approve => {
                assert!(responder.pairing_code_matches(&code.to_lowercase()));
                self.event("record_written");
                match responder
                    .approve(vec!["t2".into(), "t1".into()], 3600)
                    .await
                {
                    Ok(()) => self.event("approved_delivered"),
                    Err(e) => self.event(format!("approve_failed:{e}")),
                }
            }
            ConsentMode::Deny => {
                let _ = responder.deny().await;
                self.event("denied");
            }
            ConsentMode::Refuse => {
                let _ = responder
                    .refuse(Refusal::new(edge_origin::ErrorCode::OriginLocked))
                    .await;
            }
            ConsentMode::WrongCode => {
                assert!(!responder.pairing_code_matches("ZZZZZZ"));
                drop(responder);
                self.event("no_decision");
            }
            ConsentMode::Hold => {
                let cancel = responder.cancelled();
                cancel.cancelled().await;
                self.event("consent_cancelled");
                let r = responder.approve(vec!["t1".into()], 3600).await;
                self.event(format!("late_approve:{}", r.is_err()));
            }
        }
    }

    async fn grant_sync(&self, grants: Vec<GrantRef>) -> Result<Vec<GrantSyncEntry>, Refusal> {
        Ok(grants
            .into_iter()
            .filter_map(|g| match g.grant_id.as_str() {
                "g_active" => Some(GrantSyncEntry {
                    grant_id: g.grant_id,
                    state: GrantState::Active,
                }),
                "g_revoked" => Some(GrantSyncEntry {
                    grant_id: g.grant_id,
                    state: GrantState::Revoked,
                }),
                // A stray extra entry the handler must drop.
                "g_omitted" => Some(GrantSyncEntry {
                    grant_id: "g_not_asked".into(),
                    state: GrantState::Active,
                }),
                _ => None,
            })
            .collect())
    }

    async fn grant_revoke(&self, revoke: GrantRevokeMeta) -> Result<(), Refusal> {
        self.event(format!("revoke:{}:{}", revoke.grant_id, revoke.gen));
        Ok(())
    }
}

pub struct Harness {
    pub app: Arc<FakeApp>,
    pub handler: OriginHandler<FakeApp>,
    pub router: Router,
    pub origin_key: SecretKey,
    pub origin_addr: EndpointAddr,
    pub edge: Endpoint,
    pub edge_key: SecretKey,
    pub enrollment: Enrollment,
    pub signer: edge_assert::Signer,
    pub client: OriginClient,
}

impl Harness {
    pub async fn start() -> Self {
        Self::start_with(OriginConfig::default(), ClientConfig::default()).await
    }

    pub async fn start_with(origin_config: OriginConfig, client_config: ClientConfig) -> Self {
        let app = Arc::new(FakeApp::default());
        let origin_key = SecretKey::generate();
        let edge_key = SecretKey::generate();
        let origin = loopback_endpoint(origin_key.clone(), vec![edge_tunnel::ALPN.to_vec()]).await;
        let edge = loopback_endpoint(edge_key.clone(), vec![]).await;
        let signer = edge_assert::Signer::from_seed(&ASSERT_SEED, ISS);
        let enrollment = Enrollment::new(
            ISS,
            AUD,
            &edge.id(),
            signer.public_key_base64url(),
            SUB,
            vec![SCOPE.into()],
        )
        .unwrap();
        let handler = OriginHandler::new(app.clone(), origin_key.clone(), origin_config);
        handler.set_enrollment(Some(enrollment.clone())).unwrap();
        let router = Router::builder(origin.clone())
            .accept(edge_tunnel::ALPN, handler.clone())
            .spawn();
        let origin_addr = origin.addr();
        let client = OriginClient::new(edge.clone(), origin_addr.clone(), client_config);
        Self {
            app,
            handler,
            router,
            origin_key,
            origin_addr,
            edge,
            edge_key,
            enrollment,
            signer,
            client,
        }
    }

    pub fn grant(&self, grant_id: &str) -> edge_assert::GrantContext {
        edge_assert::GrantContext {
            aud: AUD.into(),
            sub: SUB.into(),
            client_id: "client-1".into(),
            grant_id: grant_id.into(),
            scope: vec![SCOPE.into()],
            resource_scope: serde_json::json!({"v":1,"access":"read","trackers":["t1"]}),
            gen: 1,
        }
    }

    pub fn mint(&self, grant: &edge_assert::GrantContext, body: &[u8]) -> String {
        self.signer
            .mint(
                grant,
                edge_assert::RequestBinding {
                    method: "POST",
                    path: "/mcp",
                    body,
                },
                unix_now(),
                60,
            )
            .unwrap()
    }

    pub fn request(&self, grant_id: &str, body: serde_json::Value) -> McpPostRequest {
        let body = Bytes::from(body.to_string());
        McpPostRequest {
            grant_id: grant_id.into(),
            accept: Accept::JsonOrSse,
            mcp_protocol_version: Some(McpProtocolVersion::V2025_06_18),
            assertion: self.mint(&self.grant(grant_id), &body),
            request_id: edge_tunnel::client::new_request_id(),
            body,
            budget: Duration::from_secs(25),
        }
    }

    pub async fn shutdown(self) {
        let _ = self.router.shutdown().await;
        self.edge.close().await;
    }
}

pub fn rpc(method: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc":"2.0","id":1,"method":method})
}

pub async fn wait_until(mut cond: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !cond() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded wait for state transition");
}
