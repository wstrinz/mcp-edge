//! Phase 3: `kind = "http"` backends against a fake upstream on loopback.
//!
//! The fake upstream verifies every `Edge-Assertion` with `edge-assert`'s
//! verifier and the edge public key (as a real backend would), records what it
//! received, and answers according to its path and a `mode` in the body. All
//! values are synthetic.

mod common;

use axum::{
    body::{Body, Bytes},
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Router,
};
use common::*;
use edge_assert::{RequestBinding, Signer, Verifier};
use edge_auth::support::{Clock, ManualClock};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, sync::Semaphore};

const SESSION_UP: &str = "sess-upstream-SYNTHETIC-1";
const SESSION_CLIENT: &str = "sess-client-SYNTHETIC-1";
const MARKER: &str = "SYNTHETIC_BODY_MARKER";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    verified: Result<(), String>,
}

struct UpState {
    /// upstream path -> verifier for the backend id (audience) it serves.
    verifiers: HashMap<&'static str, Verifier>,
    seen: Mutex<Vec<Seen>>,
    release: Arc<Semaphore>,
    clock: OnceLock<Arc<ManualClock>>,
}

struct Upstream {
    addr: SocketAddr,
    state: Arc<UpState>,
}

impl Upstream {
    async fn start() -> Self {
        let key = Signer::from_seed(&SEED, ISSUER).public_key_base64url();
        let mut verifiers = HashMap::new();
        for (path, aud) in [
            ("/v1/mcp", "up"),
            ("/v2/mcp", "up2"),
            ("/redirect", "redir"),
            ("/big", "big"),
            ("/slow", "slow"),
            ("/tamper", "tamper"),
            ("/mcp", "hevy"),
        ] {
            verifiers.insert(
                path,
                Verifier::from_public_key_base64url(&key, ISSUER, aud)
                    .unwrap()
                    .with_replay_cache(1000),
            );
        }
        let state = Arc::new(UpState {
            verifiers,
            seen: Mutex::new(Vec::new()),
            release: Arc::new(Semaphore::new(0)),
            clock: OnceLock::new(),
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().fallback(upstream).with_state(state.clone());
        tokio::spawn(async move { axum::serve(listener, app).await });
        Self { addr, state }
    }

    fn seen(&self) -> Vec<Seen> {
        self.state.seen.lock().unwrap().clone()
    }

    fn seen_at(&self, path: &str) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.path == path).collect()
    }

    fn release(&self, n: usize) {
        self.state.release.add_permits(n);
    }
}

fn sse_response(
    stream: impl futures_util::Stream<Item = Result<Bytes, Infallible>> + Send + 'static,
) -> Response {
    Response::builder()
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("mcp-session-id", SESSION_UP)
        .header("set-cookie", "upstream=1")
        .body(Body::from_stream(stream))
        .unwrap()
}

async fn upstream(State(st): State<Arc<UpState>>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    let path = parts.uri.path().to_string();
    let method = parts.method.as_str().to_string();
    let Some(verifier) = st.verifiers.get(path.as_str()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = st.clock.get().map(|c| c.now()).unwrap_or(0);
    let assertion = parts
        .headers
        .get("edge-assertion")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // `/tamper` checks a body that differs by one byte from what it got.
    let mut bound = body.to_vec();
    if path == "/tamper" {
        bound.push(b' ');
    }
    let verified = verifier
        .verify(
            &assertion,
            RequestBinding {
                method: &method,
                path: &path,
                body: &bound,
            },
            now,
        )
        .map(|_| ())
        .map_err(|e| e.code().to_string());
    let headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    st.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        headers: headers.clone(),
        body: body.to_vec(),
        verified: verified.clone(),
    });
    if verified.is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            [("www-authenticate", "Bearer realm=\"upstream\"")],
            "{\"error\":\"invalid_assertion\"}",
        )
            .into_response();
    }
    let mode = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["mode"].as_str().map(str::to_string))
        .unwrap_or_default();
    let echo = json!({
        "method": method,
        "path": path,
        "headers": headers.iter().cloned().collect::<HashMap<_, _>>(),
        "body": String::from_utf8_lossy(&body),
        "assertion": assertion,
    });
    match (path.as_str(), method.as_str(), mode.as_str()) {
        ("/redirect", _, _) => (
            StatusCode::FOUND,
            [("location", "http://evil.example/steal")],
            "",
        )
            .into_response(),
        ("/big", _, "length") => {
            ([("content-type", "application/json")], vec![b'x'; 8192]).into_response()
        }
        ("/big", _, _) => {
            let chunks = futures_util::stream::unfold(0, |i| async move {
                (i < 4).then(|| (Ok::<_, Infallible>(Bytes::from(vec![b'y'; 2048])), i + 1))
            });
            Response::builder()
                .header("content-type", "application/json")
                .body(Body::from_stream(chunks))
                .unwrap()
        }
        ("/slow", _, "stall") => sse_response(futures_util::stream::unfold(0, |i| async move {
            match i {
                0 => Some((Ok(Bytes::from_static(b"data: first\n\n")), 1)),
                1 => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Some((Ok(Bytes::from_static(b"data: late\n\n")), 2))
                }
                _ => None,
            }
        })),
        ("/slow", _, _) => {
            tokio::time::sleep(Duration::from_secs(3)).await;
            axum::Json(echo).into_response()
        }
        (_, "GET", _) => {
            let event = Bytes::from(format!("id: 42\ndata: {echo}\n\n"));
            sse_response(futures_util::stream::once(async move {
                Ok::<_, Infallible>(event)
            }))
        }
        (_, "POST", "sse") => {
            let release = st.release.clone();
            sse_response(futures_util::stream::unfold(0, move |i| {
                let release = release.clone();
                async move {
                    match i {
                        0 => Some((Ok(Bytes::from_static(b"id: 1\ndata: first\n\n")), 1)),
                        1 => {
                            release.acquire().await.unwrap().forget();
                            Some((Ok(Bytes::from_static(b"id: 2\ndata: second\n\n")), 2))
                        }
                        _ => None,
                    }
                }
            }))
        }
        _ => (
            [
                ("content-type", "application/json"),
                ("mcp-session-id", SESSION_UP),
                ("cache-control", "no-cache"),
                ("set-cookie", "upstream=1"),
                ("x-internal", "upstream-only"),
                ("location", "http://evil.example/"),
                ("www-authenticate", "Basic realm=\"upstream\""),
            ],
            axum::Json(echo),
        )
            .into_response(),
    }
}

fn routes(port: u16, down_port: u16) -> String {
    format!(
        r#"
[[backend]]
id = "echo"
kind = "echo"

[[backend]]
id = "up"
kind = "http"
consent = "edge"
url = "http://127.0.0.1:{port}/v1/mcp"
max_request_bytes = 4096
max_concurrent_per_grant = 2

[[backend]]
id = "up2"
kind = "http"
url = "http://127.0.0.1:{port}/v2/mcp"

[[backend]]
id = "redir"
kind = "http"
url = "http://127.0.0.1:{port}/redirect"

[[backend]]
id = "big"
kind = "http"
url = "http://127.0.0.1:{port}/big"
max_response_bytes = 4096

[[backend]]
id = "slow"
kind = "http"
url = "http://127.0.0.1:{port}/slow"
response_timeout_secs = 1
idle_timeout_secs = 1

[[backend]]
id = "tamper"
kind = "http"
url = "http://127.0.0.1:{port}/tamper"

[[backend]]
id = "hevy"
kind = "http"
url = "http://127.0.0.1:{port}/mcp"

[[backend]]
id = "down"
kind = "http"
url = "http://127.0.0.1:{down_port}/mcp"
connect_timeout_secs = 1
"#
    )
}

async fn setup() -> (Harness, Upstream) {
    let up = Upstream::start().await;
    // A loopback port with nothing listening.
    let down_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut h = Harness::start_with(Options {
        routes: routes(up.addr.port(), down_port),
        ..Options::default()
    })
    .await;
    up.state.clock.set(h.clock.clone()).ok();
    h.enroll().await;
    (h, up)
}

async fn access_token(h: &mut Harness, backend: &str) -> String {
    let (_, tokens) = h.tokens_for(backend).await;
    tokens["access_token"].as_str().unwrap().to_string()
}

fn post(h: &Harness, backend: &str, token: &str, body: &Value) -> reqwest::RequestBuilder {
    h.http
        .post(h.url(&format!("/{backend}/mcp")))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(serde_json::to_vec(body).unwrap())
}

async fn error_code(res: reqwest::Response) -> String {
    let v: Value = res.json().await.unwrap();
    v["error"].as_str().unwrap().to_string()
}

/// Read chunks until `needle` shows up (or fail after 5 s).
async fn read_until(res: &mut reqwest::Response, needle: &str) -> String {
    let mut text = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !text.contains(needle) {
        let left = deadline.saturating_duration_since(Instant::now());
        let chunk = tokio::time::timeout(left, res.chunk())
            .await
            .expect("chunk in time")
            .expect("chunk")
            .expect("stream not ended");
        text.push_str(&String::from_utf8_lossy(&chunk));
    }
    text
}

fn header_names(seen: &Seen) -> Vec<String> {
    let mut names: Vec<String> = seen.headers.iter().map(|(k, _)| k.clone()).collect();
    names.sort();
    names.dedup();
    names
}

fn header<'a>(seen: &'a Seen, name: &str) -> Option<&'a str> {
    seen.headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

#[tokio::test]
async fn json_post_round_trip_binds_upstream_path_and_body() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "up").await;
    let body = rpc(
        1,
        "tools/call",
        json!({ "name": "x", "arguments": { "m": MARKER } }),
    );
    let sent = serde_json::to_vec(&body).unwrap();
    let res = post(&h, "up", &token, &body)
        .header("mcp-session-id", SESSION_CLIENT)
        .header("mcp-protocol-version", "2025-06-18")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let hd = res.headers().clone();
    assert_eq!(hd["content-type"], "application/json");
    assert_eq!(hd["mcp-session-id"], SESSION_UP);
    assert_eq!(hd["cache-control"], "no-cache");
    for dropped in ["set-cookie", "x-internal", "location", "www-authenticate"] {
        assert!(hd.get(dropped).is_none(), "{dropped} must not pass");
    }
    let echo: Value = res.json().await.unwrap();
    assert_eq!(echo["method"], "POST");
    assert_eq!(echo["path"], "/v1/mcp");
    assert_eq!(echo["body"].as_str().unwrap().as_bytes(), sent.as_slice());
    assert_eq!(echo["headers"]["mcp-session-id"], SESSION_CLIENT);
    assert_eq!(echo["headers"]["mcp-protocol-version"], "2025-06-18");
    let seen = up.seen_at("/v1/mcp");
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].verified, Ok(()));
    assert_eq!(seen[0].body, sent);

    // The assertion binds exactly (method, upstream path, body): any change fails.
    let assertion = echo["assertion"].as_str().unwrap();
    let verifier = || Verifier::from_public_key_base64url(&h.assertion_key, ISSUER, "up").unwrap();
    let now = h.clock.now();
    let check = |method: &str, path: &str, body: &[u8]| {
        verifier()
            .verify(assertion, RequestBinding { method, path, body }, now)
            .map(|c| c.aud)
            .map_err(|e| e.code())
    };
    assert_eq!(check("POST", "/v1/mcp", &sent), Ok("up".to_string()));
    assert_eq!(check("POST", "/up/mcp", &sent), Err("request_mismatch"));
    assert_eq!(check("POST", "/mcp", &sent), Err("request_mismatch"));
    assert_eq!(check("GET", "/v1/mcp", &sent), Err("request_mismatch"));
    let mut altered = sent.clone();
    altered.push(b' ');
    assert_eq!(check("POST", "/v1/mcp", &altered), Err("request_mismatch"));
    let other = Verifier::from_public_key_base64url(&h.assertion_key, ISSUER, "up2").unwrap();
    assert_eq!(
        other
            .verify(
                assertion,
                RequestBinding {
                    method: "POST",
                    path: "/v1/mcp",
                    body: &sent
                },
                now
            )
            .map_err(|e| e.code())
            .err(),
        Some("wrong_audience")
    );

    // Logs carry route, status, backend and grant only.
    let logs = h.logs().join("\n");
    assert!(logs.contains("backend=up grant=g_"));
    for secret in [
        token.as_str(),
        MARKER,
        SESSION_CLIENT,
        SESSION_UP,
        assertion,
    ] {
        assert!(!logs.contains(secret), "log leaked a value");
    }
    h.finish().await;
}

#[tokio::test]
async fn client_credentials_and_forwarding_headers_never_reach_upstream() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "up").await;
    let forged = "eyJmb3JnZWQiOnRydWV9.Zm9yZ2Vk";
    let res = post(&h, "up", &token, &rpc(2, "ping", json!({})))
        .header("cookie", "__Host-edge=SYNTHETIC")
        .header("edge-assertion", forged)
        .header("x-forwarded-for", "198.51.100.7")
        .header("x-forwarded-host", "evil.example")
        .header("forwarded", "for=198.51.100.7;host=evil.example")
        .header("x-evil", "1")
        .header("user-agent", "synthetic-client")
        .header("origin", "https://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let seen = up.seen_at("/v1/mcp");
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    let allowed = [
        "accept",
        "content-length",
        "content-type",
        "edge-assertion",
        "host",
        "last-event-id",
        "mcp-protocol-version",
        "mcp-session-id",
    ];
    for name in header_names(s) {
        assert!(allowed.contains(&name.as_str()), "{name} reached upstream");
    }
    assert_eq!(
        s.headers
            .iter()
            .filter(|(k, _)| k == "edge-assertion")
            .count(),
        1
    );
    assert_ne!(header(s, "edge-assertion"), Some(forged));
    assert_eq!(s.verified, Ok(()));
    assert_eq!(header(s, "host").unwrap(), up.addr.to_string());
    assert!(!s.headers.iter().any(|(_, v)| v.contains(&token)));

    // A repeated allowlisted header is refused, never forwarded.
    let res = post(&h, "up", &token, &rpc(3, "ping", json!({})))
        .header("mcp-session-id", "a")
        .header("mcp-session-id", "b")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(error_code(res).await, "invalid_request");
    // Non-JSON POST and oversized bodies stop at the edge too.
    let res = h
        .http
        .post(h.url("/up/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415);
    let big = json!({ "jsonrpc": "2.0", "id": 4, "method": "ping", "params": { "pad": "x".repeat(5000) } });
    let res = post(&h, "up", &token, &big).send().await.unwrap();
    assert_eq!(res.status(), 413);
    assert_eq!(up.seen_at("/v1/mcp").len(), 1);
    h.finish().await;
}

#[tokio::test]
async fn sse_response_is_streamed_before_upstream_finishes() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "up").await;
    let mut res = post(
        &h,
        "up",
        &token,
        &json!({ "jsonrpc": "2.0", "id": 5, "method": "x", "mode": "sse" }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    assert_eq!(res.headers()["mcp-session-id"], SESSION_UP);
    assert!(res.headers().get("set-cookie").is_none());
    // The upstream cannot send its second event until we release it, which we
    // only do after the first event has arrived through the edge.
    let first = read_until(&mut res, "data: first\n\n").await;
    assert!(!first.contains("second"));
    up.release(1);
    let rest = read_until(&mut res, "data: second\n\n").await;
    assert!(rest.contains("id: 2"));
    assert!(res.chunk().await.unwrap().is_none(), "stream ends cleanly");
    h.finish().await;
}

#[tokio::test]
async fn get_stream_and_delete_carry_session_headers() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "up").await;
    let mut res = h
        .http
        .get(h.url("/up/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", SESSION_CLIENT)
        .header("mcp-protocol-version", "2025-06-18")
        .header("last-event-id", "41")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.headers()["content-type"], "text/event-stream");
    assert_eq!(res.headers()["mcp-session-id"], SESSION_UP);
    let text = read_until(&mut res, "\n\n").await;
    let data = text.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
    let echo: Value = serde_json::from_str(data).unwrap();
    assert_eq!(echo["method"], "GET");
    assert_eq!(echo["body"], "");
    assert_eq!(echo["headers"]["mcp-session-id"], SESSION_CLIENT);
    assert_eq!(echo["headers"]["last-event-id"], "41");
    assert_eq!(echo["headers"]["accept"], "text/event-stream");
    assert!(echo["headers"].get("content-length").is_none());

    let res = h
        .http
        .delete(h.url("/up/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-session-id", SESSION_CLIENT)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let echo: Value = res.json().await.unwrap();
    assert_eq!(echo["method"], "DELETE");
    assert_eq!(echo["body"], "");
    assert_eq!(echo["headers"]["mcp-session-id"], SESSION_CLIENT);
    let verified: Vec<_> = up
        .seen_at("/v1/mcp")
        .iter()
        .map(|s| s.verified.clone())
        .collect();
    assert_eq!(verified, vec![Ok(()), Ok(())]);
    let methods: Vec<String> = up
        .seen_at("/v1/mcp")
        .into_iter()
        .map(|s| s.method)
        .collect();
    assert_eq!(methods, ["GET", "DELETE"]);

    // GET/DELETE bodies are refused at the edge, not dropped silently.
    let res = h
        .http
        .delete(h.url("/up/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .body("{\"x\":1}")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);
    assert_eq!(up.seen_at("/v1/mcp").len(), 2);
    h.finish().await;
}

#[tokio::test]
async fn token_for_one_backend_is_rejected_at_another() {
    let (mut h, up) = setup().await;
    let token_a = access_token(&mut h, "up").await;
    let token_b = access_token(&mut h, "up2").await;
    let res = post(&h, "up2", &token_a, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    assert_eq!(
        res.headers()["www-authenticate"],
        format!(
            "Bearer error=\"invalid_token\", resource_metadata=\"{ISSUER}/.well-known/oauth-protected-resource/up2/mcp\""
        )
        .as_str()
    );
    let res = h
        .http
        .get(h.url("/up2/mcp"))
        .header("authorization", format!("Bearer {token_a}"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = post(&h, "up", &token_b, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
    let res = h.http.post(h.url("/up/mcp")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    assert!(up.seen().is_empty(), "nothing reached any upstream");

    let res = post(&h, "up2", &token_b, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let seen = up.seen_at("/v2/mcp");
    assert_eq!((seen.len(), seen[0].verified.clone()), (1, Ok(())));
    h.finish().await;
}

#[tokio::test]
async fn upstream_redirect_is_502_without_location() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "redir").await;
    let res = post(&h, "redir", &token, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert!(res.headers().get("location").is_none());
    assert_eq!(error_code(res).await, "upstream_redirect");
    assert_eq!(up.seen_at("/redirect").len(), 1, "followed no redirect");
    assert!(h
        .logs()
        .iter()
        .any(|l| l.contains("event=upstream_redirect backend=redir")));
    h.finish().await;
}

#[tokio::test]
async fn oversized_upstream_responses_are_refused_or_cut() {
    let (mut h, _up) = setup().await;
    let token = access_token(&mut h, "big").await;
    // Declared too large: refused before any byte is passed on.
    let res = post(
        &h,
        "big",
        &token,
        &json!({ "jsonrpc": "2.0", "id": 1, "method": "x", "mode": "length" }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 502);
    assert_eq!(error_code(res).await, "upstream_response_too_large");
    // Streamed past the cap: the body is aborted, never delivered complete.
    let res = post(
        &h,
        "big",
        &token,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "x", "mode": "stream" }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    match res.bytes().await {
        Err(_) => {}
        Ok(b) => assert!(b.len() <= 4096, "got {} bytes", b.len()),
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h
        .logs()
        .iter()
        .any(|l| l.contains("event=upstream_response_too_large backend=big")));
    h.finish().await;
}

#[tokio::test]
async fn slow_or_stalled_upstream_times_out() {
    let (mut h, _up) = setup().await;
    let token = access_token(&mut h, "slow").await;
    let started = Instant::now();
    let res = post(&h, "slow", &token, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 504);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(error_code(res).await, "upstream_timeout");

    let mut res = post(
        &h,
        "slow",
        &token,
        &json!({ "jsonrpc": "2.0", "id": 2, "method": "x", "mode": "stall" }),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    read_until(&mut res, "data: first\n\n").await;
    let started = Instant::now();
    let next = tokio::time::timeout(Duration::from_secs(5), res.chunk())
        .await
        .expect("edge ends a stalled stream");
    assert!(next.is_err(), "stalled stream is aborted, not completed");
    assert!(started.elapsed() < Duration::from_secs(4));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(h
        .logs()
        .iter()
        .any(|l| l.contains("event=upstream_idle_timeout backend=slow")));
    h.finish().await;
}

#[tokio::test]
async fn unreachable_upstream_is_502() {
    let (mut h, _up) = setup().await;
    let token = access_token(&mut h, "down").await;
    let res = post(&h, "down", &token, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert_eq!(error_code(res).await, "upstream_unavailable");
    h.finish().await;
}

#[tokio::test]
async fn upstream_rejecting_the_assertion_is_502() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "tamper").await;
    let res = post(&h, "tamper", &token, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 502);
    assert!(res.headers().get("www-authenticate").is_none());
    assert_eq!(error_code(res).await, "backend_rejected");
    let seen = up.seen_at("/tamper");
    assert_eq!(seen[0].verified, Err("request_mismatch".to_string()));
    h.finish().await;
}

#[tokio::test]
async fn unknown_methods_are_405() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "up").await;
    for method in ["PUT", "PATCH", "OPTIONS", "HEAD", "TRACE"] {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        for auth in [Some(&token), None] {
            let mut req = h.http.request(m.clone(), h.url("/up/mcp"));
            if let Some(t) = auth {
                req = req.header("authorization", format!("Bearer {t}"));
            }
            let res = req.send().await.unwrap();
            assert_eq!(res.status(), 405, "{method}");
            assert_eq!(res.headers()["allow"], "GET, POST, DELETE");
        }
    }
    // The echo backend stays POST-only.
    let res = h.http.get(h.url("/echo/mcp")).send().await.unwrap();
    assert_eq!(res.status(), 405);
    assert_eq!(res.headers()["allow"], "POST");
    assert!(up.seen().is_empty());
    h.finish().await;
}

#[tokio::test]
async fn in_flight_requests_are_bounded_per_grant() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "up").await;
    let open = || {
        post(
            &h,
            "up",
            &token,
            &json!({ "jsonrpc": "2.0", "id": 9, "method": "x", "mode": "sse" }),
        )
    };
    let mut a = open().send().await.unwrap();
    let mut b = open().send().await.unwrap();
    read_until(&mut a, "first").await;
    read_until(&mut b, "first").await;
    let res = post(&h, "up", &token, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 429);
    assert_eq!(error_code(res).await, "too_many_in_flight");
    up.release(2);
    read_until(&mut a, "second").await;
    read_until(&mut b, "second").await;
    assert!(a.chunk().await.unwrap().is_none());
    assert!(b.chunk().await.unwrap().is_none());
    // Slots are released when the streams end.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let res = post(&h, "up", &token, &rpc(1, "ping", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    h.finish().await;
}

/// Requirements from the hevy-mcp edge mode (MCP SDK StreamableHTTPServerTransport,
/// session-stateful, verifies `req` over the raw bytes at exactly `/mcp`).
#[tokio::test]
async fn hevy_compatibility_exact_bytes_path_accept_and_session() {
    let (mut h, up) = setup().await;
    let token = access_token(&mut h, "hevy").await;
    // Deliberately non-canonical JSON: odd spacing, key order, trailing newline.
    let raw = "{ \"params\":{\"b\":1,\"a\":[1.50, 2]} ,\"jsonrpc\" : \"2.0\",\"id\":1,\n \"method\":\"initialize\" }\n";
    let accept = "application/json, text/event-stream";
    let res = h
        .http
        .post(h.url("/hevy/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json; charset=utf-8")
        .header("accept", accept)
        .header("accept-encoding", "gzip, deflate, br")
        .header("mcp-protocol-version", "2025-06-18")
        .body(raw)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    // 2. The upstream session id comes back to the client.
    assert_eq!(res.headers()["mcp-session-id"], SESSION_UP);
    assert!(res.headers().get("content-encoding").is_none());
    let seen = up.seen_at("/mcp");
    assert_eq!(seen.len(), 1);
    let s = &seen[0];
    // 4. Signed and sent at exactly the configured path.
    assert_eq!(s.path, "/mcp");
    assert_eq!(s.verified, Ok(()));
    // 3. Byte-for-byte body, no compression negotiated upstream.
    assert_eq!(s.body, raw.as_bytes());
    assert_eq!(
        header(s, "content-length"),
        Some(raw.len().to_string().as_str())
    );
    assert!(header(s, "accept-encoding").is_none());
    assert!(header(s, "content-encoding").is_none());
    // 1. Accept, Content-Type and protocol version unchanged.
    assert_eq!(header(s, "accept"), Some(accept));
    assert_eq!(
        header(s, "content-type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(header(s, "mcp-protocol-version"), Some("2025-06-18"));

    // 5. GET (SSE) and DELETE with the session id, signed at /mcp as well.
    let mut res = h
        .http
        .get(h.url("/hevy/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("accept", "text/event-stream")
        .header("mcp-session-id", SESSION_UP)
        .header("last-event-id", "7")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    read_until(&mut res, "\n\n").await;
    let res = h
        .http
        .delete(h.url("/hevy/mcp"))
        .header("authorization", format!("Bearer {token}"))
        .header("mcp-session-id", SESSION_UP)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let seen = up.seen_at("/mcp");
    type Row = (String, Option<String>, Option<String>, Result<(), String>);
    let summary: Vec<Row> = seen
        .iter()
        .map(|s| {
            (
                s.method.clone(),
                header(s, "mcp-session-id").map(str::to_string),
                header(s, "last-event-id").map(str::to_string),
                s.verified.clone(),
            )
        })
        .collect();
    assert_eq!(
        summary[1..],
        [
            (
                "GET".to_string(),
                Some(SESSION_UP.to_string()),
                Some("7".to_string()),
                Ok(())
            ),
            (
                "DELETE".to_string(),
                Some(SESSION_UP.to_string()),
                None,
                Ok(())
            ),
        ]
    );
    h.finish().await;
}
