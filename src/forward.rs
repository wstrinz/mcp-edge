//! HTTP forwarder for `kind = "http"` backends.
//!
//! The upstream request is built from scratch: the configured URL (never
//! anything from the request), the client's method (GET/POST/DELETE only), an
//! allowlist of request headers, the exact body, and a freshly minted
//! `Edge-Assertion` bound to that method, upstream path and body. Redirects are
//! never followed and environment proxies are ignored. The response passes
//! through with its status and an allowlist of headers; its body is streamed
//! (SSE flushes event by event) under a size cap, an idle deadline between
//! chunks and an overall deadline. Nothing here logs bodies, headers or tokens.

use crate::config::HttpUpstream;
use axum::{
    body::{Body, Bytes},
    http::{header::CACHE_CONTROL, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};
use edge_auth::AuthState;
use serde_json::json;
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Request headers copied to the upstream (each at most once). Everything
/// else is dropped, in particular `Authorization`, `Cookie`, `Host`,
/// `Forwarded`, `X-Forwarded-*` and any client-supplied `Edge-Assertion`.
pub const REQUEST_HEADER_ALLOWLIST: [&str; 5] = [
    "content-type",
    "accept",
    "mcp-session-id",
    "mcp-protocol-version",
    "last-event-id",
];
/// Response headers copied back to the client. `Location`, `Set-Cookie`,
/// `WWW-Authenticate` and everything else are dropped.
pub const RESPONSE_HEADER_ALLOWLIST: [&str; 3] =
    ["content-type", "mcp-session-id", "cache-control"];
/// Longest forwarded header value.
const MAX_HEADER_VALUE: usize = 1024;
/// Upper bound on one response body, streams included. The server also caps
/// each connection at this lifetime (`server::CONNECTION_LIFETIME`).
pub const STREAM_LIFETIME: Duration = Duration::from_secs(300);
/// Methods an http backend accepts at `<prefix>/mcp`.
pub const ALLOWED_METHODS: [Method; 3] = [Method::GET, Method::POST, Method::DELETE];
pub const ALLOW_HEADER: &str = "GET, POST, DELETE";

fn json_error(status: StatusCode, code: &'static str) -> Response {
    (status, axum::Json(json!({ "error": code }))).into_response()
}

/// An allowlisted request header the edge refuses to forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadHeader;

/// Copy the allowlisted request headers. A repeated allowlisted header, a
/// value over 1 KiB or one with bytes outside visible ASCII and space is
/// refused rather than repaired.
pub fn select_request_headers(incoming: &HeaderMap) -> Result<HeaderMap, BadHeader> {
    let mut out = HeaderMap::new();
    for name in REQUEST_HEADER_ALLOWLIST {
        let mut values = incoming.get_all(name).iter();
        let Some(value) = values.next() else { continue };
        if values.next().is_some() {
            return Err(BadHeader);
        }
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_HEADER_VALUE
            || !bytes.iter().all(|b| (0x20..=0x7e).contains(b))
        {
            return Err(BadHeader);
        }
        out.insert(HeaderName::from_static(name), value.clone());
    }
    Ok(out)
}

/// In-flight requests per grant on one backend (open streams included).
pub struct GrantSlots {
    max: usize,
    map: Mutex<HashMap<String, usize>>,
}

/// One in-flight slot; released on drop, which for a streamed response is
/// when the body finishes, fails or the client goes away.
pub struct GrantSlot {
    slots: Arc<GrantSlots>,
    grant: String,
}

impl GrantSlots {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            max: max.max(1),
            map: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, grant: &str) -> Option<GrantSlot> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        let count = map.entry(grant.to_owned()).or_insert(0);
        if *count >= self.max {
            return None;
        }
        *count += 1;
        Some(GrantSlot {
            slots: self.clone(),
            grant: grant.to_owned(),
        })
    }
}

impl Drop for GrantSlot {
    fn drop(&mut self) {
        let mut map = self.slots.map.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = map.get_mut(&self.grant) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.grant);
            }
        }
    }
}

/// The request to send upstream, already authenticated and signed.
pub struct Outgoing {
    pub method: Method,
    /// Output of [`select_request_headers`].
    pub headers: HeaderMap,
    /// Exactly the bytes the assertion's `req` covers (empty for GET/DELETE).
    pub body: Bytes,
    pub assertion: String,
    pub grant_id: String,
}

pub struct HttpBackend {
    id: String,
    cfg: HttpUpstream,
    client: reqwest::Client,
    slots: Arc<GrantSlots>,
}

impl HttpBackend {
    pub fn new(id: &str, cfg: &HttpUpstream) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .http1_only()
            .connect_timeout(cfg.connect_timeout)
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .build()?;
        Ok(Self {
            id: id.to_owned(),
            cfg: cfg.clone(),
            client,
            slots: GrantSlots::new(cfg.max_concurrent_per_grant),
        })
    }

    /// The path the upstream receives and the assertion's `req` binds.
    pub fn upstream_path(&self) -> &str {
        self.cfg.url.path()
    }

    pub fn try_acquire(&self, grant_id: &str) -> Option<GrantSlot> {
        self.slots.try_acquire(grant_id)
    }

    fn event(&self, log: &AuthState, name: &str, grant: &str) {
        log.log(&format!("event={name} backend={} grant={grant}", self.id));
    }

    /// Send `out` upstream and turn the answer into the client's response.
    /// `slot` is held until the response body ends.
    pub async fn forward(&self, out: Outgoing, slot: GrantSlot, log: AuthState) -> Response {
        let mut req = self
            .client
            .request(out.method.clone(), self.cfg.url.clone())
            .headers(out.headers);
        req = req.header(edge_assert::HEADER, out.assertion);
        if out.method == Method::POST {
            req = req.body(out.body);
        }
        let sent = tokio::time::timeout(self.cfg.response_timeout, req.send()).await;
        // Connection failures (refused, DNS, TLS, connect timeout) are 502;
        // an upstream that accepted the request but is slow to answer is 504.
        let resp = match sent {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) if e.is_timeout() && !e.is_connect() => {
                self.event(&log, "upstream_timeout", &out.grant_id);
                return json_error(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout");
            }
            Ok(Err(_)) => {
                self.event(&log, "upstream_unavailable", &out.grant_id);
                return json_error(StatusCode::BAD_GATEWAY, "upstream_unavailable");
            }
            Err(_) => {
                self.event(&log, "upstream_timeout", &out.grant_id);
                return json_error(StatusCode::GATEWAY_TIMEOUT, "upstream_timeout");
            }
        };
        let status = resp.status();
        if status.is_redirection() {
            // Never followed, and Location is never passed on.
            self.event(&log, "upstream_redirect", &out.grant_id);
            return json_error(StatusCode::BAD_GATEWAY, "upstream_redirect");
        }
        if status == StatusCode::UNAUTHORIZED {
            // The upstream refused the edge's own assertion (or still runs its
            // own auth): an edge-side fault, never the client's token.
            self.event(&log, "backend_rejected_assertion", &out.grant_id);
            return json_error(StatusCode::BAD_GATEWAY, "backend_rejected");
        }
        if status.is_informational() {
            return json_error(StatusCode::BAD_GATEWAY, "bad_gateway");
        }
        if resp
            .content_length()
            .is_some_and(|n| n > self.cfg.max_response_bytes as u64)
        {
            self.event(&log, "upstream_response_too_large", &out.grant_id);
            return json_error(StatusCode::BAD_GATEWAY, "upstream_response_too_large");
        }
        let mut headers = HeaderMap::new();
        for name in RESPONSE_HEADER_ALLOWLIST {
            if let Some(v) = resp.headers().get(name) {
                headers.insert(HeaderName::from_static(name), v.clone());
            }
        }
        let body = Body::from_stream(self.body_stream(resp, slot, log, out.grant_id));
        let mut res = Response::new(body);
        *res.status_mut() = status;
        *res.headers_mut() = headers;
        if !res.headers().contains_key(CACHE_CONTROL) {
            res.headers_mut()
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        res
    }

    fn body_stream(
        &self,
        resp: reqwest::Response,
        slot: GrantSlot,
        log: AuthState,
        grant: String,
    ) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> + Send + 'static {
        struct State {
            resp: reqwest::Response,
            received: usize,
            max: usize,
            idle: Duration,
            deadline: tokio::time::Instant,
            done: bool,
            backend: String,
            grant: String,
            log: AuthState,
            _slot: GrantSlot,
        }
        impl State {
            fn abort(mut self, event: &str) -> Option<(Result<Bytes, io::Error>, Self)> {
                self.log.log(&format!(
                    "event={event} backend={} grant={}",
                    self.backend, self.grant
                ));
                self.done = true;
                // An error ends the chunked body without its terminator, so
                // the client sees a truncated response, never a complete one.
                Some((Err(io::Error::other("upstream response aborted")), self))
            }
        }
        let state = State {
            resp,
            received: 0,
            max: self.cfg.max_response_bytes,
            idle: self.cfg.idle_timeout,
            deadline: tokio::time::Instant::now() + STREAM_LIFETIME,
            done: false,
            backend: self.id.clone(),
            grant,
            log,
            _slot: slot,
        };
        futures_util::stream::unfold(state, |mut st| async move {
            if st.done {
                return None;
            }
            let left = st
                .deadline
                .saturating_duration_since(tokio::time::Instant::now());
            let (wait, is_deadline) = if left <= st.idle {
                (left, true)
            } else {
                (st.idle, false)
            };
            match tokio::time::timeout(wait, st.resp.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    st.received = st.received.saturating_add(chunk.len());
                    if st.received > st.max {
                        return st.abort("upstream_response_too_large");
                    }
                    Some((Ok(chunk), st))
                }
                Ok(Ok(None)) => None,
                Ok(Err(_)) => st.abort("upstream_stream_error"),
                Err(_) if is_deadline => st.abort("upstream_stream_deadline"),
                Err(_) => st.abort("upstream_idle_timeout"),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{ACCEPT, CONTENT_TYPE};

    #[test]
    fn request_headers_are_allowlisted_and_validated() {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        h.insert("mcp-session-id", HeaderValue::from_static("abc-123"));
        h.insert("authorization", HeaderValue::from_static("Bearer secret"));
        h.insert("cookie", HeaderValue::from_static("a=b"));
        h.insert("edge-assertion", HeaderValue::from_static("forged.sig"));
        h.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        h.insert("forwarded", HeaderValue::from_static("for=1.2.3.4"));
        h.insert("host", HeaderValue::from_static("evil.example"));
        let out = select_request_headers(&h).unwrap();
        let mut names: Vec<&str> = out.keys().map(|k| k.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["accept", "content-type", "mcp-session-id"]);

        let mut dup = HeaderMap::new();
        dup.append("mcp-session-id", HeaderValue::from_static("a"));
        dup.append("mcp-session-id", HeaderValue::from_static("b"));
        assert!(select_request_headers(&dup).is_err());
        let mut bad = HeaderMap::new();
        bad.insert("last-event-id", HeaderValue::from_bytes(b"x\xffy").unwrap());
        assert!(select_request_headers(&bad).is_err());
        let mut long = HeaderMap::new();
        long.insert(
            "mcp-session-id",
            HeaderValue::from_str(&"a".repeat(MAX_HEADER_VALUE + 1)).unwrap(),
        );
        assert!(select_request_headers(&long).is_err());
    }

    #[test]
    fn grant_slots_are_bounded_and_released() {
        let slots = GrantSlots::new(2);
        let a = slots.try_acquire("g1").unwrap();
        let _b = slots.try_acquire("g1").unwrap();
        assert!(slots.try_acquire("g1").is_none());
        assert!(slots.try_acquire("g2").is_some());
        drop(a);
        assert!(slots.try_acquire("g1").is_some());
    }
}
