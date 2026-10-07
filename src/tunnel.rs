//! `kind = "iroh"` backends (PHASE4.md §2, §3, §5): the edge's single iroh
//! endpoint, one [`OriginClient`] per route, the origin-consent port for
//! `edge-auth`, `grant_sync` on every new connection and best-effort
//! `grant_revoke`.
//!
//! The edge only dials: its endpoint registers no ALPN, so any inbound
//! connection fails the handshake. Each route dials exactly the EndpointId
//! configured for it (from an environment variable, D6); nothing in a request
//! can choose or add a peer. Wire formats and the client live in
//! `edge-tunnel`; this module maps them to the edge's HTTP contract and to the
//! grant store.

use crate::config::{Route, RouteKind};
use edge_auth::{
    origin::{BoxFuture, ConsentAsk, ConsentOutcome, OriginPanel, OriginPort, RevokeReason},
    AuthState, InitError,
};
use edge_tunnel::{
    approval::{self, ApprovalBinding, Decision},
    client::{ClientConfig, OriginClient, PingInfo, Reply, TunnelError},
    enrollment::Enrollment,
    ids,
    iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey},
    meta::{ConsentRequestMeta, GrantRef, GrantState, RemoteState, RevokeReason as WireReason},
    EdgeFailure, PROTOCOL_VERSION,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// Name of the edge's iroh secret key file in `EDGE_DATA_DIR` (§1.1).
pub const IROH_KEY_FILE: &str = "iroh-edge.key";
/// How long a `ping` result is shown on `/owner` before a refresh is started.
const PING_REFRESH: Duration = Duration::from_secs(10);

/// The edge's iroh identity and endpoint, prepared by the caller.
pub struct IrohDeps {
    /// The persistent edge key (its public half is the edge EndpointId).
    pub secret_key: SecretKey,
    /// The bound endpoint, or `None` when binding failed: iroh routes then
    /// answer `origin_offline` and the rest of the edge keeps working.
    pub endpoint: Option<Endpoint>,
    pub client: ClientConfig,
    /// Direct addresses for configured origin ids (tests: loopback). Never
    /// adds a peer: only ids already in the route table are looked up here.
    pub addresses: HashMap<EndpointId, EndpointAddr>,
}

/// Bind the production edge endpoint: n0 relays and n0 DNS/pkarr address
/// lookup (D5), no address publishing, no portmapper, the §2.2 QUIC settings,
/// and no ALPN (the edge accepts no inbound protocol). Binding does not wait
/// for a relay, so unreachable relays never block startup.
pub async fn bind_edge_endpoint(key: SecretKey) -> Result<Endpoint, String> {
    use edge_tunnel::iroh::{
        address_lookup::{DnsAddressLookup, PkarrResolver},
        endpoint::{default_relay_mode, presets},
    };
    let bind = Endpoint::builder(presets::Minimal)
        .secret_key(key)
        .relay_mode(default_relay_mode())
        .address_lookup(PkarrResolver::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns())
        .transport_config(edge_tunnel::transport_config())
        .alpns(Vec::new())
        .bind();
    match tokio::time::timeout(Duration::from_secs(10), bind).await {
        Ok(Ok(endpoint)) => Ok(endpoint),
        Ok(Err(_)) => Err("bind failed".into()),
        Err(_) => Err("bind timed out".into()),
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `first 8 … last 4` of a 64-hex EndpointId (§1.2 visibility).
pub fn short_id(hex: &str) -> String {
    if hex.len() == 64 {
        format!("{}…{}", &hex[..8], &hex[60..])
    } else {
        hex.to_owned()
    }
}

#[derive(Clone, Debug)]
enum PingStatus {
    Never,
    Ok(PingInfo, i64),
    Refused(&'static str, i64),
    Failed(TunnelError, i64),
}

/// One `kind = "iroh"` route.
pub struct IrohBackend {
    pub id: String,
    pub display_name: String,
    pub origin_id: EndpointId,
    /// `None` when the endpoint is unavailable.
    pub client: Option<OriginClient>,
    pub max_response_bytes: usize,
    pub max_request_bytes: usize,
    pub max_lifetime_secs: u64,
    pub scopes: Vec<String>,
    pub enrollment: Enrollment,
    ping: Mutex<PingStatus>,
    ping_running: Mutex<bool>,
}

/// All iroh routes, plus the port `edge-auth` calls for origin consent and
/// revocation notices.
pub struct Gateway {
    edge_id: EndpointId,
    issuer: String,
    assertion_key: String,
    owner_id: String,
    auth: AuthState,
    routes: HashMap<String, Arc<IrohBackend>>,
}

impl Gateway {
    /// Build the iroh routes of `routes`, bind them to `auth` (re-enrollment
    /// check, consent port) and start their `grant_sync` watchers. Returns
    /// `None` when the table has no iroh route.
    pub fn new(
        issuer: &str,
        routes: &[Route],
        deps: Option<IrohDeps>,
        auth: &AuthState,
        assertion_key: &str,
    ) -> Result<Option<Arc<Self>>, InitError> {
        let iroh_routes: Vec<&Route> = routes
            .iter()
            .filter(|r| r.kind == RouteKind::Iroh)
            .collect();
        if iroh_routes.is_empty() {
            return Ok(None);
        }
        let deps = deps.ok_or(InitError::Config("iroh routes need the edge iroh identity"))?;
        let edge_id = deps.secret_key.public();
        let mut backends = HashMap::new();
        for route in iroh_routes {
            let iroh = route
                .iroh
                .as_ref()
                .ok_or(InitError::Config("iroh route without origin"))?;
            let origin_id = iroh
                .origin_id
                .ok_or(InitError::Config("iroh route origin id not resolved"))?;
            if origin_id == edge_id {
                return Err(InitError::Config("iroh origin id equals the edge id"));
            }
            let enrollment = Enrollment::new(
                issuer,
                route.id.clone(),
                &edge_id,
                assertion_key,
                auth.owner_id(),
                route.scopes.clone(),
            )
            .map_err(|_| InitError::Config("iroh enrollment (issuer must be https)"))?;
            let client = deps.endpoint.as_ref().map(|endpoint| {
                let addr = deps
                    .addresses
                    .get(&origin_id)
                    .cloned()
                    .unwrap_or_else(|| EndpointAddr::new(origin_id));
                OriginClient::new(endpoint.clone(), addr, deps.client.clone())
            });
            auth.bind_origin(&route.id, &ids::endpoint_id_hex(&origin_id))?;
            backends.insert(
                route.id.clone(),
                Arc::new(IrohBackend {
                    id: route.id.clone(),
                    display_name: route.display_name.clone(),
                    origin_id,
                    client,
                    max_response_bytes: iroh.max_response_bytes,
                    max_request_bytes: route.max_request_bytes,
                    max_lifetime_secs: u64::try_from(route.grant_lifetime_secs).unwrap_or(0),
                    scopes: route.scopes.clone(),
                    enrollment,
                    ping: Mutex::new(PingStatus::Never),
                    ping_running: Mutex::new(false),
                }),
            );
        }
        let gateway = Arc::new(Self {
            edge_id,
            issuer: issuer.to_owned(),
            assertion_key: assertion_key.to_owned(),
            owner_id: auth.owner_id().to_owned(),
            auth: auth.clone(),
            routes: backends,
        });
        let weak: Weak<dyn OriginPort> = Arc::downgrade(&gateway) as Weak<dyn OriginPort>;
        auth.set_origin_port(weak);
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            for backend in gateway.routes.values() {
                spawn_grant_sync(&rt, &gateway, backend);
            }
        }
        Ok(Some(gateway))
    }

    pub fn edge_id(&self) -> EndpointId {
        self.edge_id
    }

    pub fn backend(&self, id: &str) -> Option<&Arc<IrohBackend>> {
        self.routes.get(id)
    }

    /// Reconcile the edge's active grants of `route` with the origin (§3.6):
    /// those it reports `revoked` or `unknown` are revoked at the edge.
    pub async fn grant_sync(&self, route: &str) {
        let Some(backend) = self.routes.get(route) else {
            return;
        };
        let Some(client) = backend.client.clone() else {
            return;
        };
        let auth = self.auth.clone();
        let id = route.to_owned();
        let grants = tokio::task::spawn_blocking(move || auth.live_grants(&id))
            .await
            .unwrap_or_default();
        for chunk in grants.chunks(edge_tunnel::limits::GRANT_SYNC_ENTRIES) {
            let refs: Vec<GrantRef> = chunk
                .iter()
                .map(|(grant_id, gen)| GrantRef {
                    grant_id: grant_id.clone(),
                    gen: *gen,
                })
                .collect();
            match client.grant_sync(refs).await {
                Ok(Reply::Ok(entries)) => {
                    let ended: Vec<String> = entries
                        .into_iter()
                        .filter(|e| matches!(e.state, GrantState::Revoked | GrantState::Unknown))
                        .map(|e| e.grant_id)
                        .collect();
                    if ended.is_empty() {
                        continue;
                    }
                    let auth = self.auth.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        for grant in ended {
                            auth.revoke_for_origin(&grant, "grant_sync_revoked");
                        }
                    })
                    .await;
                }
                Ok(Reply::Refused(r)) => {
                    self.auth.log(&format!(
                        "event=grant_sync_failed backend={route} reason={}",
                        r.error
                    ));
                    return;
                }
                Err(e) => {
                    self.auth.log(&format!(
                        "event=grant_sync_failed backend={route} reason={}",
                        e.edge_failure().reason()
                    ));
                    return;
                }
            }
        }
    }

    fn refresh_ping(&self, backend: &Arc<IrohBackend>) {
        let Some(client) = backend.client.clone() else {
            return;
        };
        let due = match &*backend.ping.lock().unwrap_or_else(|e| e.into_inner()) {
            PingStatus::Never => true,
            PingStatus::Ok(_, at) | PingStatus::Refused(_, at) | PingStatus::Failed(_, at) => {
                unix_now() - at >= PING_REFRESH.as_secs() as i64
            }
        };
        if !due {
            return;
        }
        {
            let mut running = backend
                .ping_running
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if *running {
                return;
            }
            *running = true;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            *backend
                .ping_running
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = false;
            return;
        };
        let backend = backend.clone();
        rt.spawn(async move {
            let status = match client.ping().await {
                Ok(Reply::Ok(info)) => PingStatus::Ok(info, unix_now()),
                Ok(Reply::Refused(r)) => PingStatus::Refused(r.error.as_str(), unix_now()),
                Err(e) => PingStatus::Failed(e, unix_now()),
            };
            *backend.ping.lock().unwrap_or_else(|e| e.into_inner()) = status;
            *backend
                .ping_running
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = false;
        });
    }
}

fn spawn_grant_sync(
    rt: &tokio::runtime::Handle,
    gateway: &Arc<Gateway>,
    backend: &Arc<IrohBackend>,
) {
    let Some(client) = &backend.client else {
        return;
    };
    let mut connects = client.subscribe_connections();
    let weak = Arc::downgrade(gateway);
    let route = backend.id.clone();
    rt.spawn(async move {
        // Ends when the client (and with it the sender) is dropped.
        while connects.changed().await.is_ok() {
            let Some(gateway) = weak.upgrade() else {
                break;
            };
            gateway.grant_sync(&route).await;
        }
    });
}

fn wire_reason(r: RevokeReason) -> WireReason {
    match r {
        RevokeReason::Owner => WireReason::Owner,
        RevokeReason::Client => WireReason::Client,
        RevokeReason::Replay => WireReason::Replay,
        RevokeReason::Expired => WireReason::Expired,
    }
}

fn ping_text(status: &PingStatus, fingerprint: &str) -> String {
    let ago = |at: &i64| format!("checked {} s ago", (unix_now() - at).max(0));
    match status {
        PingStatus::Never => "not checked yet (reload in a few seconds)".into(),
        PingStatus::Ok(info, at) => {
            let remote = match info.remote {
                RemoteState::On => "remote access on",
                RemoteState::Off => "remote access off",
                RemoteState::Paused => "remote access paused (audit failure)",
                RemoteState::Stale => "enrollment stale in the app",
            };
            let enrolled = if info.enrolled_fingerprint == fingerprint {
                "enrolled with this edge (fingerprint matches)".to_string()
            } else {
                format!(
                    "enrolled with a different edge fingerprint ({}): paste the enrollment \
                     string above",
                    info.enrolled_fingerprint
                )
            };
            format!(
                "reachable, {remote}, {enrolled}; app version {} ({})",
                info.origin_version,
                ago(at)
            )
        }
        PingStatus::Refused(code, at) => format!("reachable, refused: {code} ({})", ago(at)),
        PingStatus::Failed(e, at) => {
            let text = match e.edge_failure() {
                EdgeFailure::OriginOffline => {
                    "not reachable: computer off or asleep, or the app closed"
                }
                EdgeFailure::OriginRejectedEdge => {
                    "reachable, but it does not admit this edge: paste the enrollment string \
                     above into the app"
                }
                EdgeFailure::OriginRemoteOff => "reachable, remote access off",
                EdgeFailure::OriginUnenrolled => "reachable, enrollment stale in the app",
                EdgeFailure::OriginBusy => "reachable, connection limit reached",
                _ => "error talking to the app",
            };
            format!("{text} ({})", ago(at))
        }
    }
}

impl OriginPort for Gateway {
    fn consent(&self, ask: ConsentAsk) -> BoxFuture<ConsentOutcome> {
        let backend = self.routes.get(&ask.backend).cloned();
        let edge_id = self.edge_id;
        let issuer = self.issuer.clone();
        let auth = self.auth.clone();
        Box::pin(async move {
            let Some(backend) = backend else {
                return ConsentOutcome::Unreachable("origin_unavailable");
            };
            let Some(client) = backend.client.clone() else {
                return ConsentOutcome::Unreachable("origin_offline");
            };
            // The origin checks the window against its own clock: stamp it
            // with system time, keeping the edge's chosen length.
            let requested_at = u64::try_from(unix_now()).unwrap_or(0);
            let window = ask
                .expires_at
                .saturating_sub(ask.requested_at)
                .clamp(1, edge_tunnel::timing::CONSENT.as_secs());
            let expires_at = requested_at + window;
            let meta = ConsentRequestMeta {
                v: PROTOCOL_VERSION,
                tx: ask.tx.clone(),
                grant_id: ask.grant_id.clone(),
                nonce: ask.nonce.clone(),
                pairing_code: ask.pairing_code,
                client_id: ask.client_id.clone(),
                client_name: ask.client_name,
                client_registered_at: ask.client_registered_at,
                redirect_host: ask.redirect_host,
                requested_at,
                scopes: ask.scopes,
                max_lifetime_secs: backend.max_lifetime_secs,
                expires_at,
            };
            if meta.validate().is_err() {
                auth.log(&format!(
                    "event=consent_request_invalid backend={}",
                    backend.id
                ));
                return ConsentOutcome::Unreachable("origin_unavailable");
            }
            let approval = match client.consent_request(meta).await {
                Ok(Reply::Ok(approval)) => approval,
                Ok(Reply::Refused(r)) if r.error == edge_tunnel::ErrorCode::ConsentBusy => {
                    return ConsentOutcome::Busy
                }
                Ok(Reply::Refused(r)) => {
                    return ConsentOutcome::Unreachable(r.edge_failure().reason())
                }
                // Only "no answer by expires_at" is a timeout; a write or
                // idle deadline on a half-dead connection is a transport
                // failure the owner may retry.
                Err(TunnelError::Timeout) if unix_now() + 1 >= expires_at as i64 => {
                    return ConsentOutcome::Timeout
                }
                Err(TunnelError::EdgeBusy) => return ConsentOutcome::Busy,
                Err(e) => return ConsentOutcome::Unreachable(e.edge_failure().reason()),
            };
            let binding = ApprovalBinding {
                origin_id: backend.origin_id,
                edge_id,
                issuer,
                backend: backend.id.clone(),
                tx: ask.tx,
                grant_id: ask.grant_id,
                nonce: ask.nonce,
                client_id: ask.client_id,
                max_lifetime_secs: backend.max_lifetime_secs,
            };
            // An invalid answer of either kind is "unreachable", never approval.
            let claims = match approval::verify(&approval, &binding, unix_now()) {
                Ok(c) => c,
                Err(e) => {
                    auth.log(&format!(
                        "event=origin_approval_invalid backend={} reason={}",
                        backend.id,
                        e.code()
                    ));
                    return ConsentOutcome::Unreachable("approval_invalid");
                }
            };
            match (claims.decision, claims.resource_scope, claims.lifetime_secs) {
                (Decision::Approve, Some(scope), Some(lifetime)) => ConsentOutcome::Approved {
                    resource_scope: scope.to_value(),
                    lifetime_secs: lifetime.min(backend.max_lifetime_secs),
                    approval,
                },
                (Decision::Deny, None, None) => ConsentOutcome::Denied,
                _ => {
                    auth.log(&format!(
                        "event=origin_approval_invalid backend={} reason=shape",
                        backend.id
                    ));
                    ConsentOutcome::Unreachable("approval_invalid")
                }
            }
        })
    }

    fn revoked(&self, backend: &str, grant_id: &str, gen: u64, reason: RevokeReason) {
        let Some(route) = self.routes.get(backend) else {
            return;
        };
        let Some(client) = route.client.clone() else {
            return;
        };
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let auth = self.auth.clone();
        let grant = grant_id.to_owned();
        let backend = backend.to_owned();
        rt.spawn(async move {
            let outcome = match client.grant_revoke(&grant, gen, wire_reason(reason)).await {
                Ok(Reply::Ok(())) => "ok".to_string(),
                Ok(Reply::Refused(r)) => r.error.to_string(),
                Err(e) => e.edge_failure().reason().to_string(),
            };
            auth.log(&format!(
                "event=grant_revoke_sent backend={backend} grant={grant} result={outcome}"
            ));
        });
    }

    fn panels(&self) -> Vec<OriginPanel> {
        let mut out: Vec<OriginPanel> = self
            .routes
            .values()
            .map(|b| {
                self.refresh_ping(b);
                let fingerprint = b.enrollment.fingerprint();
                let status = ping_text(
                    &b.ping.lock().unwrap_or_else(|e| e.into_inner()),
                    &fingerprint,
                );
                let status = if b.client.is_none() {
                    "the edge's iroh endpoint is unavailable (see the startup log)".to_string()
                } else {
                    status
                };
                let origin_hex = ids::endpoint_id_hex(&b.origin_id);
                OriginPanel {
                    backend: b.id.clone(),
                    display_name: b.display_name.clone(),
                    enrollment: b.enrollment.to_enrollment_string(),
                    fingerprint,
                    edge_id: ids::endpoint_id_hex(&self.edge_id),
                    assertion_key: self.assertion_key.clone(),
                    issuer: self.issuer.clone(),
                    owner_id: self.owner_id.clone(),
                    scopes: b.scopes.clone(),
                    origin_short: short_id(&origin_hex),
                    origin_id: origin_hex,
                    status,
                }
            })
            .collect();
        out.sort_by(|a, b| a.backend.cmp(&b.backend));
        out
    }
}
