//! Edge client <-> origin handler over real iroh endpoints on loopback
//! (ephemeral keys, relays disabled, direct addressing).
mod common;

use bytes::Bytes;
use common::*;
use edge_origin::{
    edge_tunnel::{
        self,
        approval::{self, ApprovalBinding, Decision},
        client::{ClientConfig, McpPostRequest, OriginClient, Reply, TunnelError},
        frame, ids, limits,
        meta::{ConsentRequestMeta, ContentType, GrantRef, GrantState, RemoteState, RevokeReason},
        CloseCode, EdgeFailure, ErrorCode,
    },
    OriginConfig,
};
use iroh::{endpoint::Connection, SecretKey};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn expect_refused<T: std::fmt::Debug>(
    r: Result<Reply<T>, TunnelError>,
) -> edge_tunnel::client::Refusal {
    match r {
        Ok(Reply::Refused(refusal)) => refusal,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn expect_ok<T: std::fmt::Debug>(r: Result<Reply<T>, TunnelError>) -> T {
    match r {
        Ok(Reply::Ok(v)) => v,
        other => panic!("expected success, got {other:?}"),
    }
}

// ------------------------------------------------------------------ mcp_post

#[tokio::test]
async fn mcp_post_json_round_trip() {
    let h = Harness::start().await;
    let resp = expect_ok(h.client.mcp_post(h.request("g_1", rpc("echo"))).await);
    assert_eq!(resp.status, 200);
    assert_eq!(resp.content_type, Some(ContentType::Json));
    let body: serde_json::Value =
        serde_json::from_slice(&resp.body.collect().await.unwrap()).unwrap();
    assert_eq!(body["result"]["grant"], "g_1");
    assert_eq!(body["result"]["echo"], rpc("echo"));
    let grant = h.app.last_grant.lock().unwrap().clone().unwrap();
    assert_eq!(grant.client_id, "client-1");
    assert_eq!(grant.sub, SUB);
    assert_eq!(grant.gen, 1);
    assert_eq!(grant.resource_scope["trackers"][0], "t1");
    // 202 without content type or body.
    let resp = expect_ok(h.client.mcp_post(h.request("g_1", rpc("notify"))).await);
    assert_eq!((resp.status, resp.content_type), (202, None));
    assert!(resp.body.collect().await.unwrap().is_empty());
    // MCP-level errors are ordinary bodies.
    let resp = expect_ok(h.client.mcp_post(h.request("g_1", rpc("nope"))).await);
    assert_eq!(resp.status, 400);
    // One cached connection for all of it.
    assert_eq!(*h.client.subscribe_connections().borrow(), 1);
    assert_eq!(h.handler.live_connections(), 1);
    h.shutdown().await;
}

#[tokio::test]
async fn mcp_post_streams_incrementally() {
    let h = Harness::start().await;
    let resp = expect_ok(h.client.mcp_post(h.request("g_1", rpc("stream"))).await);
    assert_eq!(resp.content_type, Some(ContentType::EventStream));
    let mut body = resp.body;
    let start = Instant::now();
    let first = body.next_chunk().await.unwrap().unwrap();
    let first_at = start.elapsed();
    assert!(first.starts_with(b"data: {\"chunk\":0}"));
    let mut n = 1;
    while let Some(chunk) = body.next_chunk().await {
        chunk.unwrap();
        n += 1;
    }
    assert_eq!(n, 5);
    // The first chunk arrived well before the stream completed (~300 ms).
    assert!(
        first_at < start.elapsed() / 2,
        "{first_at:?} vs {:?}",
        start.elapsed()
    );
    wait_until(|| h.app.counters.in_app.load(Ordering::SeqCst) == 0).await;
    assert_eq!(h.app.counters.dropped_incomplete.load(Ordering::SeqCst), 0);
    h.shutdown().await;
}

#[tokio::test]
async fn response_size_limits() {
    let h = Harness::start().await;
    let big =
        |n: usize| serde_json::json!({"jsonrpc":"2.0","id":1,"method":"big","params":{"size":n}});
    // Exactly 1 MiB passes (64 chunks of 16 KiB).
    let resp = expect_ok(
        h.client
            .mcp_post(h.request("g_1", big(limits::MCP_RESPONSE)))
            .await,
    );
    assert_eq!(
        resp.body.collect().await.unwrap().len(),
        limits::MCP_RESPONSE
    );
    // 1 MiB + 1: the origin refuses to send it and resets the stream; the
    // edge reports a truncated response, never a success.
    let r = h
        .client
        .mcp_post(h.request("g_1", big(limits::MCP_RESPONSE + 1)))
        .await;
    assert_eq!(r.unwrap_err(), TunnelError::Truncated);
    assert_eq!(
        TunnelError::Truncated.edge_failure(),
        EdgeFailure::BackendProtocol
    );
    // App aborting its own stream mid-way is a truncation too.
    // (The reset may overtake the metadata, so either stage reports it.)
    let r = match h.client.mcp_post(h.request("g_1", rpc("abort"))).await {
        Ok(Reply::Ok(resp)) => resp.body.collect().await.map(|_| ()),
        Ok(Reply::Refused(r)) => panic!("{r:?}"),
        Err(e) => Err(e),
    };
    assert_eq!(r, Err(TunnelError::Truncated));
    // An app status outside the allowed set never reaches the edge as a status.
    let r = h.client.mcp_post(h.request("g_1", rpc("bad_status"))).await;
    assert_eq!(r.unwrap_err(), TunnelError::Truncated);
    h.shutdown().await;
}

#[tokio::test]
async fn request_size_limits_at_edge() {
    let h = Harness::start().await;
    let mut req = h.request("g_1", rpc("echo"));
    req.body = Bytes::from(vec![b' '; limits::MCP_BODY + 1]);
    assert_eq!(
        h.client.mcp_post(req).await.unwrap_err(),
        TunnelError::RequestTooLarge
    );
    let mut req = h.request("g_1", rpc("echo"));
    req.assertion = "a".repeat(limits::ASSERTION + 1);
    assert_eq!(
        h.client.mcp_post(req).await.unwrap_err(),
        TunnelError::InvalidRequest("assertion")
    );
    // Body at exactly 64 KiB is accepted by the transport (JSON whitespace
    // padding keeps it a valid JSON-RPC message).
    let mut text = rpc("echo").to_string();
    text.push_str(&" ".repeat(limits::MCP_BODY - text.len()));
    let body = Bytes::from(text);
    let req = McpPostRequest {
        assertion: h.mint(&h.grant("g_1"), &body),
        body,
        ..h.request("g_1", rpc("echo"))
    };
    let resp = expect_ok(h.client.mcp_post(req).await);
    assert_eq!(resp.status, 200);
    // No dial happened for the refused ones: only one connection.
    assert_eq!(*h.client.subscribe_connections().borrow(), 1);
    h.shutdown().await;
}

// ------------------------------------------------------------------ assertions

#[tokio::test]
async fn bad_assertions_are_refused() {
    let h = Harness::start().await;
    let body = Bytes::from(rpc("echo").to_string());
    let now = unix_now();
    let mint_with =
        |signer: &edge_assert::Signer, g: &edge_assert::GrantContext, b: &[u8], at: i64| {
            signer
                .mint(
                    g,
                    edge_assert::RequestBinding {
                        method: "POST",
                        path: "/mcp",
                        body: b,
                    },
                    at,
                    60,
                )
                .unwrap()
        };
    let other_key = edge_assert::Signer::from_seed(&[9u8; 32], ISS);
    let other_iss = edge_assert::Signer::from_seed(&ASSERT_SEED, "https://other.test");
    let g = h.grant("g_1");
    let mut wrong_aud = g.clone();
    wrong_aud.aud = "other".into();
    let mut wrong_sub = g.clone();
    wrong_sub.sub = "intruder".into();
    let mut wrong_scope = g.clone();
    wrong_scope.scope = vec!["wiskit:write".into()];
    let mut extra_scope = g.clone();
    extra_scope.scope = vec![SCOPE.into(), "wiskit:write".into()];
    let good = mint_with(&h.signer, &g, &body, now);
    let (payload, sig) = good.split_once('.').unwrap();
    let tampered_sig = {
        let mut s = sig.as_bytes().to_vec();
        s[0] = if s[0] == b'A' { b'B' } else { b'A' };
        format!("{payload}.{}", String::from_utf8(s).unwrap())
    };
    let cases: Vec<(&str, String)> = vec![
        ("wrong key", mint_with(&other_key, &g, &body, now)),
        ("wrong issuer", mint_with(&other_iss, &g, &body, now)),
        ("wrong aud", mint_with(&h.signer, &wrong_aud, &body, now)),
        ("wrong sub", mint_with(&h.signer, &wrong_sub, &body, now)),
        (
            "wrong scope",
            mint_with(&h.signer, &wrong_scope, &body, now),
        ),
        (
            "extra scope",
            mint_with(&h.signer, &extra_scope, &body, now),
        ),
        ("expired", mint_with(&h.signer, &g, &body, now - 120)),
        ("future", mint_with(&h.signer, &g, &body, now + 120)),
        (
            "other body",
            mint_with(&h.signer, &g, b"{\"jsonrpc\":\"2.0\",\"id\":2}", now),
        ),
        ("tampered signature", tampered_sig),
        ("garbage", "not.an-assertion".into()),
    ];
    for (name, assertion) in cases {
        let req = McpPostRequest {
            assertion,
            body: body.clone(),
            ..h.request("g_1", rpc("echo"))
        };
        let refusal = expect_refused(h.client.mcp_post(req).await);
        assert_eq!(refusal.error, ErrorCode::AssertionInvalid, "{name}");
        assert_eq!(refusal.status, 401, "{name}");
        assert_eq!(
            refusal.edge_failure(),
            EdgeFailure::BackendRejected,
            "{name}"
        );
    }
    assert_eq!(h.app.counters.mcp_calls.load(Ordering::SeqCst), 0);
    // Replay: the same assertion twice.
    let req = McpPostRequest {
        assertion: good.clone(),
        body: body.clone(),
        ..h.request("g_1", rpc("echo"))
    };
    expect_ok(h.client.mcp_post(req.clone()).await);
    let refusal = expect_refused(h.client.mcp_post(req).await);
    assert_eq!(refusal.error, ErrorCode::AssertionInvalid);
    assert_eq!(h.app.counters.mcp_calls.load(Ordering::SeqCst), 1);
    h.shutdown().await;
}

#[tokio::test]
async fn assertions_minted_before_origin_start_are_refused() {
    let config = OriginConfig {
        started_at_unix: unix_now() + 30,
        ..OriginConfig::default()
    };
    let h = Harness::start_with(config, ClientConfig::default()).await;
    let refusal = expect_refused(h.client.mcp_post(h.request("g_1", rpc("echo"))).await);
    assert_eq!(refusal.error, ErrorCode::AssertionInvalid);
    h.shutdown().await;
}

#[tokio::test]
async fn app_refusals_map_to_edge_contract() {
    let h = Harness::start().await;
    let refusal = expect_refused(h.client.mcp_post(h.request("g_1", rpc("revoked"))).await);
    assert_eq!(
        (refusal.status, refusal.error),
        (401, ErrorCode::GrantRevoked)
    );
    assert_eq!(refusal.edge_failure(), EdgeFailure::InvalidToken);
    assert!(refusal.error.revokes_edge_grant());
    h.app.set_remote(RemoteState::Paused);
    let refusal = expect_refused(h.client.mcp_post(h.request("g_1", rpc("echo"))).await);
    assert_eq!(
        (refusal.status, refusal.error),
        (503, ErrorCode::AuditUnavailable)
    );
    assert_eq!(refusal.edge_failure(), EdgeFailure::OriginPaused);
    // Remote turned off while connected: per-stream refusal on the existing
    // connection, close code 3 for new ones.
    h.app.set_remote(RemoteState::Off);
    let refusal = expect_refused(h.client.mcp_post(h.request("g_1", rpc("echo"))).await);
    assert_eq!(refusal.error, ErrorCode::RemoteDisabled);
    h.handler.close_all(CloseCode::RemoteDisabled);
    wait_until(|| h.handler.live_connections() == 0).await;
    let err = h
        .client
        .mcp_post(h.request("g_1", rpc("echo")))
        .await
        .unwrap_err();
    assert_eq!(err, TunnelError::Closed(CloseCode::RemoteDisabled));
    assert_eq!(err.edge_failure(), EdgeFailure::OriginRemoteOff);
    h.app.set_remote(RemoteState::Stale);
    let err = h
        .client
        .mcp_post(h.request("g_1", rpc("echo")))
        .await
        .unwrap_err();
    assert_eq!(err, TunnelError::Closed(CloseCode::EnrollmentStale));
    assert_eq!(err.edge_failure(), EdgeFailure::OriginUnenrolled);
    h.app.set_remote(RemoteState::On);
    expect_ok(h.client.mcp_post(h.request("g_1", rpc("echo"))).await);
    h.shutdown().await;
}

// ------------------------------------------------------------------ admission

#[tokio::test]
async fn non_enrolled_peer_is_refused() {
    let h = Harness::start().await;
    let stranger = loopback_endpoint(SecretKey::generate(), vec![]).await;
    let client = OriginClient::new(
        stranger.clone(),
        h.origin_addr.clone(),
        ClientConfig::default(),
    );
    let err = client.ping().await.unwrap_err();
    assert_eq!(err, TunnelError::Closed(CloseCode::PeerNotAdmitted));
    assert_eq!(err.edge_failure(), EdgeFailure::OriginRejectedEdge);
    assert_eq!(h.app.events().len(), 0);
    assert_eq!(h.handler.live_connections(), 0);
    // The enrolled edge works; re-enrolling another edge cuts it off.
    expect_ok(h.client.ping().await);
    let mut other = h.enrollment.clone();
    other.edge_id = ids::endpoint_id_hex(&stranger.id());
    h.handler.set_enrollment(Some(other)).unwrap();
    let err = h.client.ping().await.unwrap_err();
    assert_eq!(err, TunnelError::Closed(CloseCode::PeerNotAdmitted));
    expect_ok(client.ping().await);
    // Unenrolled: nobody is admitted.
    h.handler.set_enrollment(None).unwrap();
    assert_eq!(
        client.ping().await.unwrap_err(),
        TunnelError::Closed(CloseCode::PeerNotAdmitted)
    );
    stranger.close().await;
    h.shutdown().await;
}

#[tokio::test]
async fn connection_limit_retries_once_then_reports_busy() {
    let config = OriginConfig {
        max_connections: 1,
        ..OriginConfig::default()
    };
    let h = Harness::start_with(config, ClientConfig::default()).await;
    // Hold the only slot with a separate connection from the same edge.
    let holder: Connection = h
        .edge
        .connect(h.origin_addr.clone(), edge_tunnel::ALPN)
        .await
        .unwrap();
    wait_until(|| h.handler.live_connections() == 1).await;
    let start = Instant::now();
    let err = h.client.ping().await.unwrap_err();
    assert_eq!(err, TunnelError::Closed(CloseCode::ConnectionLimit));
    assert_eq!(err.edge_failure(), EdgeFailure::OriginBusy);
    assert!(
        start.elapsed() >= Duration::from_millis(950),
        "re-dialled once after 1 s"
    );
    assert_eq!(*h.client.subscribe_connections().borrow(), 2);
    holder.close(0u32.into(), b"done");
    wait_until(|| h.handler.live_connections() == 0).await;
    expect_ok(h.client.ping().await);
    h.shutdown().await;
}

// ------------------------------------------------------------------ offline

#[tokio::test]
async fn offline_origin_fails_fast_then_immediately() {
    let h = Harness::start().await;
    expect_ok(h.client.ping().await);
    let _ = h.router.shutdown().await;
    // The cached connection is gone (closed by the origin) and the origin
    // endpoint no longer answers.
    let start = Instant::now();
    let err = h
        .client
        .mcp_post(h.request("g_1", rpc("echo")))
        .await
        .unwrap_err();
    let first = start.elapsed();
    assert!(
        matches!(
            err,
            TunnelError::Offline | TunnelError::Closed(CloseCode::ShuttingDown)
        ),
        "{err:?}"
    );
    assert_eq!(err.edge_failure(), EdgeFailure::OriginOffline);
    assert!(
        first <= Duration::from_millis(3500),
        "first failure took {first:?}"
    );
    // Make sure the dial path ran: within the offline window it is immediate.
    let start = Instant::now();
    loop {
        let err = h.client.ping().await.unwrap_err();
        assert_eq!(err.edge_failure(), EdgeFailure::OriginOffline);
        if h.client.is_offline().await {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_millis(3500),
            "dial must fail within 3 s"
        );
    }
    let start = Instant::now();
    assert_eq!(h.client.ping().await.unwrap_err(), TunnelError::Offline);
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "{:?}",
        start.elapsed()
    );
    h.edge.close().await;
}

#[tokio::test]
async fn never_started_origin_fails_within_three_seconds() {
    let edge = loopback_endpoint(SecretKey::generate(), vec![]).await;
    // An address nobody listens on, for a valid but absent EndpointId.
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let origin = iroh::EndpointAddr::new(SecretKey::generate().public()).with_ip_addr(addr);
    let client = OriginClient::new(edge.clone(), origin, ClientConfig::default());
    let start = Instant::now();
    assert_eq!(client.ping().await.unwrap_err(), TunnelError::Offline);
    let took = start.elapsed();
    assert!(took <= Duration::from_millis(3500), "{took:?}");
    let start = Instant::now();
    assert_eq!(client.ping().await.unwrap_err(), TunnelError::Offline);
    assert!(start.elapsed() < Duration::from_millis(100));
    assert!(client.is_offline().await);
    edge.close().await;
}

// ------------------------------------------------------------------ cancellation

#[tokio::test]
async fn dropping_the_response_cancels_origin_work() {
    let h = Harness::start().await;
    let resp = expect_ok(h.client.mcp_post(h.request("g_1", rpc("endless"))).await);
    let mut body = resp.body;
    body.next_chunk().await.unwrap().unwrap();
    body.next_chunk().await.unwrap().unwrap();
    assert_eq!(h.app.counters.in_app.load(Ordering::SeqCst), 1);
    assert_eq!(h.handler.in_flight(), 1);
    drop(body);
    wait_until(|| h.app.counters.in_app.load(Ordering::SeqCst) == 0).await;
    assert_eq!(h.app.counters.dropped_incomplete.load(Ordering::SeqCst), 1);
    wait_until(|| h.handler.in_flight() == 0).await;
    // Cancelling while the app is still computing (before the first byte):
    // the token fires / the future is dropped.
    let client = h.client.clone();
    let req = h.request("g_2", rpc("slow"));
    let task = tokio::spawn(async move { client.mcp_post(req).await });
    wait_until(|| h.app.counters.in_app.load(Ordering::SeqCst) == 1).await;
    task.abort();
    wait_until(|| h.app.counters.in_app.load(Ordering::SeqCst) == 0).await;
    wait_until(|| h.handler.in_flight() == 0).await;
    // The connection is still usable.
    expect_ok(h.client.mcp_post(h.request("g_1", rpc("echo"))).await);
    h.shutdown().await;
}

#[tokio::test]
async fn deadline_cancels_and_answers_deadline() {
    let h = Harness::start().await;
    // Raw request with deadline_ms = 1000 so the origin's deadline fires first.
    let body = rpc("slow").to_string();
    let meta = serde_json::json!({
        "v": 1, "op": "mcp_post", "path": "/mcp", "content_type": "application/json",
        "accept": "json", "assertion": h.mint(&h.grant("g_1"), body.as_bytes()),
        "request_id": edge_tunnel::client::new_request_id(), "deadline_ms": 1000
    });
    let start = Instant::now();
    let (resp, _) = raw_call(
        &h,
        meta.to_string().as_bytes(),
        body.as_bytes(),
        b"",
        64 * 1024,
    )
    .await;
    assert_eq!(resp["error"], "deadline");
    assert_eq!(resp["status"], 504);
    let took = start.elapsed();
    assert!(
        took >= Duration::from_millis(900) && took < Duration::from_secs(4),
        "{took:?}"
    );
    wait_until(|| {
        h.app.counters.cancel_seen.load(Ordering::SeqCst)
            + h.app.counters.dropped_incomplete.load(Ordering::SeqCst)
            >= 1
    })
    .await;
    // Client-side total budget: 1 s budget against the 60 s app.
    let mut req = h.request("g_1", rpc("slow"));
    req.budget = Duration::from_millis(1500);
    let start = Instant::now();
    let r = h.client.mcp_post(req).await;
    assert!(
        matches!(r, Err(TunnelError::Timeout))
            || matches!(&r, Ok(Reply::Refused(x)) if x.error == ErrorCode::Deadline),
        "{r:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    let mut req = h.request("g_1", rpc("echo"));
    req.budget = Duration::from_millis(500);
    assert_eq!(
        h.client.mcp_post(req).await.unwrap_err(),
        TunnelError::Timeout
    );
    h.shutdown().await;
}

// ------------------------------------------------------------------ concurrency

#[tokio::test]
async fn edge_and_origin_concurrency_limits() {
    let h = Harness::start().await;
    let spawn_slow = |grant: &str| {
        let client = h.client.clone();
        let req = h.request(grant, rpc("slow"));
        tokio::spawn(async move { client.mcp_post(req).await })
    };
    // Origin: 2 in flight per grant.
    let a1 = spawn_slow("g_a");
    let a2 = spawn_slow("g_a");
    wait_until(|| h.handler.in_flight() == 2).await;
    let refusal = expect_refused(h.client.mcp_post(h.request("g_a", rpc("echo"))).await);
    assert_eq!(
        (refusal.status, refusal.error, refusal.retry_after),
        (429, ErrorCode::Busy, Some(2))
    );
    assert_eq!(refusal.edge_failure(), EdgeFailure::TooManyRequests);
    // Origin: 4 in flight globally.
    let b1 = spawn_slow("g_b");
    let b2 = spawn_slow("g_b");
    wait_until(|| h.handler.in_flight() == 4).await;
    let refusal = expect_refused(h.client.mcp_post(h.request("g_c", rpc("echo"))).await);
    assert_eq!(refusal.error, ErrorCode::Busy);
    for t in [a1, a2, b1, b2] {
        t.abort();
    }
    wait_until(|| h.handler.in_flight() == 0).await;

    // Edge: 4 per grant, 8 per route (origin limits raised for this part).
    let config = OriginConfig {
        max_in_flight: 16,
        max_in_flight_per_grant: 16,
        ..OriginConfig::default()
    };
    let h2 = Harness::start_with(config, ClientConfig::default()).await;
    let spawn_slow2 = |grant: &str| {
        let client = h2.client.clone();
        let req = h2.request(grant, rpc("slow"));
        tokio::spawn(async move { client.mcp_post(req).await })
    };
    let mut tasks: Vec<_> = (0..4).map(|_| spawn_slow2("g_x")).collect();
    wait_until(|| h2.handler.in_flight() == 4).await;
    assert_eq!(
        h2.client
            .mcp_post(h2.request("g_x", rpc("echo")))
            .await
            .unwrap_err(),
        TunnelError::EdgeBusy
    );
    tasks.extend((0..4).map(|_| spawn_slow2("g_y")));
    wait_until(|| h2.handler.in_flight() == 8).await;
    let err = h2
        .client
        .mcp_post(h2.request("g_z", rpc("echo")))
        .await
        .unwrap_err();
    assert_eq!(err, TunnelError::EdgeBusy);
    assert_eq!(err.edge_failure().http_status(), 429);
    for t in tasks {
        t.abort();
    }
    wait_until(|| h2.handler.in_flight() == 0).await;
    expect_ok(h2.client.mcp_post(h2.request("g_z", rpc("echo"))).await);
    h.shutdown().await;
    h2.shutdown().await;
}

#[tokio::test]
async fn per_grant_rate_limit() {
    let config = OriginConfig {
        max_requests_per_grant_per_minute: 3,
        ..OriginConfig::default()
    };
    let h = Harness::start_with(config, ClientConfig::default()).await;
    for _ in 0..3 {
        expect_ok(h.client.mcp_post(h.request("g_r", rpc("echo"))).await);
    }
    let refusal = expect_refused(h.client.mcp_post(h.request("g_r", rpc("echo"))).await);
    assert_eq!(refusal.error, ErrorCode::Busy);
    assert!(refusal.retry_after.is_some_and(|s| (1..=60).contains(&s)));
    // Other grants are unaffected.
    expect_ok(h.client.mcp_post(h.request("g_s", rpc("echo"))).await);
    h.shutdown().await;
}

// ------------------------------------------------------------------ control ops

#[tokio::test]
async fn ping_grant_sync_and_revoke() {
    let h = Harness::start().await;
    let info = expect_ok(h.client.ping().await);
    assert_eq!(info.remote, RemoteState::On);
    assert_eq!(info.enrolled_fingerprint, h.enrollment.fingerprint());
    assert_eq!(info.origin_version, "test-1.0");
    h.app.set_remote(RemoteState::Paused);
    assert_eq!(expect_ok(h.client.ping().await).remote, RemoteState::Paused);
    h.app.set_remote(RemoteState::On);

    let grants = ["g_active", "g_revoked", "g_unknown", "g_omitted"]
        .iter()
        .map(|g| GrantRef {
            grant_id: g.to_string(),
            gen: 1,
        })
        .collect();
    let entries = expect_ok(h.client.grant_sync(grants).await);
    let states: Vec<(String, GrantState)> =
        entries.into_iter().map(|e| (e.grant_id, e.state)).collect();
    assert_eq!(
        states,
        vec![
            ("g_active".to_string(), GrantState::Active),
            ("g_revoked".to_string(), GrantState::Revoked),
            ("g_unknown".to_string(), GrantState::Unknown),
            ("g_omitted".to_string(), GrantState::Unknown),
        ]
    );
    assert!(expect_ok(h.client.grant_sync(vec![]).await).is_empty());
    expect_ok(
        h.client
            .grant_revoke("g_active", 3, RevokeReason::Owner)
            .await,
    );
    assert!(h.app.events().contains(&"revoke:g_active:3".to_string()));
    h.shutdown().await;
}

fn consent_meta(tx: &str) -> ConsentRequestMeta {
    let now = unix_now() as u64;
    ConsentRequestMeta {
        v: 1,
        tx: tx.into(),
        grant_id: format!("g_{tx}"),
        nonce: ids::random_b64url::<32>().unwrap(),
        pairing_code: "K7QM2X".into(),
        client_id: "client-1".into(),
        client_name: "Claude".into(),
        client_registered_at: now - 60,
        redirect_host: "claude.ai".into(),
        requested_at: now,
        scopes: vec![SCOPE.into()],
        max_lifetime_secs: 86_400,
        expires_at: now + 20,
    }
}

fn binding_for(h: &Harness, m: &ConsentRequestMeta) -> ApprovalBinding {
    ApprovalBinding {
        origin_id: h.origin_key.public(),
        edge_id: h.edge.id(),
        issuer: ISS.into(),
        backend: AUD.into(),
        tx: m.tx.clone(),
        grant_id: m.grant_id.clone(),
        nonce: m.nonce.clone(),
        client_id: m.client_id.clone(),
        max_lifetime_secs: m.max_lifetime_secs,
    }
}

#[tokio::test]
async fn consent_approve_and_deny_round_trip() {
    let h = Harness::start().await;
    let m = consent_meta("tx1");
    let approval_str = expect_ok(h.client.consent_request(m.clone()).await);
    let claims = approval::verify(&approval_str, &binding_for(&h, &m), unix_now()).unwrap();
    assert_eq!(claims.decision, Decision::Approve);
    assert_eq!(claims.resource_scope.unwrap().trackers, vec!["t1", "t2"]);
    assert_eq!(claims.lifetime_secs, Some(3600));
    // Bound to this request only.
    let other = consent_meta("tx9");
    assert!(approval::verify(&approval_str, &binding_for(&h, &other), unix_now()).is_err());
    wait_until(|| h.app.events().contains(&"approved_delivered".to_string())).await;

    wait_until(|| h.handler.pending_consents() == 0).await;
    *h.app.consent_mode.lock().unwrap() = ConsentMode::Deny;
    let m = consent_meta("tx2");
    let deny = expect_ok(h.client.consent_request(m.clone()).await);
    let claims = approval::verify(&deny, &binding_for(&h, &m), unix_now()).unwrap();
    assert_eq!(claims.decision, Decision::Deny);

    wait_until(|| h.handler.pending_consents() == 0).await;
    *h.app.consent_mode.lock().unwrap() = ConsentMode::Refuse;
    let refusal = expect_refused(h.client.consent_request(consent_meta("tx3")).await);
    assert_eq!(
        (refusal.status, refusal.error),
        (503, ErrorCode::OriginLocked)
    );

    // App closes the prompt without a decision: stream error, never an answer.
    *h.app.consent_mode.lock().unwrap() = ConsentMode::WrongCode;
    wait_until(|| h.handler.pending_consents() == 0).await;
    let err = h
        .client
        .consent_request(consent_meta("tx4"))
        .await
        .unwrap_err();
    assert_eq!(err, TunnelError::Truncated);

    // Remote off: refused before any prompt.
    wait_until(|| h.handler.pending_consents() == 0).await;
    h.app.set_remote(RemoteState::Paused);
    let refusal = expect_refused(h.client.consent_request(consent_meta("tx5")).await);
    assert_eq!(refusal.error, ErrorCode::AuditUnavailable);
    assert!(!h.app.events().contains(&"consent_prompt:tx5".to_string()));
    h.shutdown().await;
}

#[tokio::test]
async fn consent_busy_cancel_and_expiry() {
    let h = Harness::start().await;
    *h.app.consent_mode.lock().unwrap() = ConsentMode::Hold;
    let client = h.client.clone();
    let m1 = consent_meta("tx1");
    let pending = tokio::spawn(async move { client.consent_request(m1).await });
    wait_until(|| h.handler.pending_consents() == 1).await;
    // One pending prompt at a time.
    let refusal = expect_refused(h.client.consent_request(consent_meta("tx2")).await);
    assert_eq!(
        (refusal.status, refusal.error),
        (429, ErrorCode::ConsentBusy)
    );
    assert_eq!(refusal.edge_failure(), EdgeFailure::ConsentBusy);
    // Edge cancels (drops the request): the app sees the cancellation and a
    // late approve fails.
    pending.abort();
    wait_until(|| h.app.events().contains(&"consent_cancelled".to_string())).await;
    wait_until(|| h.app.events().contains(&"late_approve:true".to_string())).await;
    wait_until(|| h.handler.pending_consents() == 0).await;
    // Expiry: the prompt is cancelled at expires_at and the edge times out.
    let mut m = consent_meta("tx3");
    m.expires_at = unix_now() as u64 + 2;
    let start = Instant::now();
    let r = h.client.consent_request(m).await;
    assert!(r.is_err(), "{r:?}");
    assert!(start.elapsed() < Duration::from_secs(9));
    assert_eq!(
        h.app
            .events()
            .iter()
            .filter(|e| *e == "consent_cancelled")
            .count(),
        2
    );
    // Expired on arrival → bad_request.
    let mut m = consent_meta("tx4");
    m.requested_at -= 100;
    m.expires_at = unix_now() as u64 - 1;
    let r = h.client.consent_request(m).await;
    assert!(r.is_err());
    h.shutdown().await;
}

// ------------------------------------------------------------------ raw wire

/// Send raw frames and read the response metadata + whether a valid
/// terminator and FIN followed.
async fn raw_call(
    h: &Harness,
    meta: &[u8],
    body: &[u8],
    tail: &[u8],
    meta_send_cap: usize,
) -> (serde_json::Value, bool) {
    let conn = h
        .edge
        .connect(h.origin_addr.clone(), edge_tunnel::ALPN)
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let _ = frame::write_field(&mut send, meta, meta_send_cap).await;
    let _ = frame::write_field(&mut send, body, usize::MAX).await;
    if !tail.is_empty() {
        let _ = tokio::io::AsyncWriteExt::write_all(&mut send, tail).await;
    }
    let _ = send.finish();
    let raw = tokio::time::timeout(
        Duration::from_secs(10),
        frame::read_field(&mut recv, 64 * 1024),
    )
    .await
    .unwrap()
    .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let mut terminated = false;
    while let Ok(chunk) = frame::read_field(&mut recv, limits::CHUNK).await {
        if chunk.is_empty() {
            terminated = frame::expect_end(&mut recv).await.is_ok();
            break;
        }
    }
    conn.close(0u32.into(), b"done");
    (v, terminated)
}

#[tokio::test]
async fn origin_rejects_bad_framing() {
    let h = Harness::start().await;
    let body = rpc("echo").to_string();
    let good_meta = |h: &Harness| {
        serde_json::json!({
            "v": 1, "op": "mcp_post", "path": "/mcp", "content_type": "application/json",
            "accept": "json", "assertion": h.mint(&h.grant("g_1"), body.as_bytes()),
            "request_id": edge_tunnel::client::new_request_id(), "deadline_ms": 5000
        })
    };
    // Baseline works over the raw path.
    let (r, terminated) = raw_call(
        &h,
        good_meta(&h).to_string().as_bytes(),
        body.as_bytes(),
        b"",
        usize::MAX,
    )
    .await;
    assert_eq!(r["status"], 200);
    assert!(terminated);
    // Trailing bytes after the body: refused, app never called.
    let calls = h.app.counters.mcp_calls.load(Ordering::SeqCst);
    let (r, terminated) = raw_call(
        &h,
        good_meta(&h).to_string().as_bytes(),
        body.as_bytes(),
        b"\0\0\0\x02{}",
        usize::MAX,
    )
    .await;
    assert_eq!(
        (r["status"].clone(), r["error"].clone()),
        (400.into(), "bad_request".into())
    );
    assert!(terminated);
    // Oversized metadata (12 KiB + 1).
    let mut big = good_meta(&h);
    big["assertion"] = "a".repeat(limits::REQUEST_META).into();
    let (r, _) = raw_call(
        &h,
        big.to_string().as_bytes(),
        body.as_bytes(),
        b"",
        usize::MAX,
    )
    .await;
    assert_eq!(r["error"], "bad_request");
    // Oversized body (64 KiB + 1).
    let (r, _) = raw_call(
        &h,
        good_meta(&h).to_string().as_bytes(),
        &vec![b' '; limits::MCP_BODY + 1],
        b"",
        usize::MAX,
    )
    .await;
    assert_eq!(r["error"], "bad_request");
    // Empty body.
    let (r, _) = raw_call(
        &h,
        good_meta(&h).to_string().as_bytes(),
        b"",
        b"",
        usize::MAX,
    )
    .await;
    assert_eq!(r["error"], "bad_request");
    // Wrong path, unknown field, unknown op, smuggled destination.
    for mutate in [
        Box::new(|m: &mut serde_json::Value| m["path"] = "/admin".into())
            as Box<dyn Fn(&mut serde_json::Value)>,
        Box::new(|m: &mut serde_json::Value| m["url"] = "http://127.0.0.1:1/".into()),
        Box::new(|m: &mut serde_json::Value| m["op"] = "register_post".into()),
        Box::new(|m: &mut serde_json::Value| {
            m["headers"] = serde_json::json!({"authorization": "x"})
        }),
    ] {
        let mut m = good_meta(&h);
        mutate(&mut m);
        let (r, _) = raw_call(
            &h,
            m.to_string().as_bytes(),
            body.as_bytes(),
            b"",
            usize::MAX,
        )
        .await;
        assert_eq!(r["error"], "bad_request", "{m}");
    }
    // Future version.
    let mut m = good_meta(&h);
    m["v"] = 2.into();
    let (r, _) = raw_call(
        &h,
        m.to_string().as_bytes(),
        body.as_bytes(),
        b"",
        usize::MAX,
    )
    .await;
    assert_eq!(r["error"], "version_unsupported");
    // Control op with a body.
    let (r, _) = raw_call(&h, br#"{"v":1,"op":"ping"}"#, b"x", b"", usize::MAX).await;
    assert_eq!(r["error"], "bad_request");
    assert_eq!(h.app.counters.mcp_calls.load(Ordering::SeqCst), calls);
    h.shutdown().await;
}

// A fake origin that answers with arbitrary bytes, to test the edge's checks.
#[derive(Debug, Clone)]
struct RawOrigin {
    response: Vec<u8>,
    finish: bool,
}

impl iroh::protocol::ProtocolHandler for RawOrigin {
    async fn accept(&self, conn: Connection) -> Result<(), iroh::protocol::AcceptError> {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let _ = frame::read_field(&mut recv, 1 << 20).await;
            let _ = frame::read_field(&mut recv, 1 << 20).await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut send, &self.response).await;
            if self.finish {
                let _ = send.finish();
                let _ = send.stopped().await;
            } else {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
        Ok(())
    }
}

fn field(bytes: &[u8]) -> Vec<u8> {
    let mut v = (bytes.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(bytes);
    v
}

async fn against_raw(
    response: Vec<u8>,
    finish: bool,
    config: ClientConfig,
) -> Result<Vec<u8>, TunnelError> {
    let origin = loopback_endpoint(SecretKey::generate(), vec![edge_tunnel::ALPN.to_vec()]).await;
    let edge = loopback_endpoint(SecretKey::generate(), vec![]).await;
    let router = iroh::protocol::Router::builder(origin.clone())
        .accept(edge_tunnel::ALPN, RawOrigin { response, finish })
        .spawn();
    let client = OriginClient::new(edge.clone(), origin.addr(), config);
    let body = Bytes::from(rpc("echo").to_string());
    let req = McpPostRequest {
        grant_id: "g_1".into(),
        accept: edge_tunnel::meta::Accept::Json,
        mcp_protocol_version: None,
        assertion: "x.y".into(),
        request_id: edge_tunnel::client::new_request_id(),
        body,
        budget: Duration::from_secs(10),
    };
    let r = match client.mcp_post(req).await {
        Ok(Reply::Ok(resp)) => resp.body.collect().await,
        Ok(Reply::Refused(r)) => Ok(format!("refused:{}", r.error).into_bytes()),
        Err(e) => Err(e),
    };
    let _ = router.shutdown().await;
    edge.close().await;
    r
}

#[tokio::test]
async fn edge_detects_truncation_and_bad_responses() {
    let ok_meta = field(br#"{"v":1,"status":200,"content_type":"application/json"}"#);
    let cfg = || ClientConfig {
        chunk_idle: Duration::from_millis(500),
        ..ClientConfig::default()
    };
    // Well-formed.
    let mut good = ok_meta.clone();
    good.extend(field(b"{}"));
    good.extend(field(b""));
    assert_eq!(against_raw(good.clone(), true, cfg()).await.unwrap(), b"{}");
    // Missing terminator, then FIN: truncated, not success.
    let mut trunc = ok_meta.clone();
    trunc.extend(field(b"{\"partial\":"));
    assert_eq!(
        against_raw(trunc.clone(), true, cfg()).await,
        Err(TunnelError::Truncated)
    );
    // Missing terminator, stream left open: idle deadline.
    assert_eq!(
        against_raw(trunc, false, cfg()).await,
        Err(TunnelError::Timeout)
    );
    // FIN inside a chunk.
    let mut cut = ok_meta.clone();
    cut.extend(&field(b"{\"abc\":1}")[..6]);
    assert_eq!(
        against_raw(cut, true, cfg()).await,
        Err(TunnelError::Truncated)
    );
    // Bytes after the terminator.
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(matches!(
        against_raw(trailing, true, cfg()).await,
        Err(TunnelError::Protocol(_))
    ));
    // Chunk over 16 KiB.
    let mut huge_chunk = ok_meta.clone();
    huge_chunk.extend(field(&vec![b'x'; limits::CHUNK + 1]));
    huge_chunk.extend(field(b""));
    assert!(matches!(
        against_raw(huge_chunk, true, cfg()).await,
        Err(TunnelError::Protocol(_))
    ));
    // Total over 1 MiB.
    let mut over = ok_meta.clone();
    for _ in 0..(limits::MCP_RESPONSE / limits::CHUNK) {
        over.extend(field(&vec![b'x'; limits::CHUNK]));
    }
    over.extend(field(b"y"));
    over.extend(field(b""));
    assert_eq!(
        against_raw(over, true, cfg()).await,
        Err(TunnelError::ResponseTooLarge)
    );
    // Status not in the allowed set; unknown meta field; meta over 2 KiB.
    for meta in [
        br#"{"v":1,"status":302,"content_type":"application/json"}"#.to_vec(),
        br#"{"v":1,"status":200,"content_type":"application/json","location":"x"}"#.to_vec(),
        format!(
            r#"{{"v":1,"status":200,"content_type":"application/json","p":"{}"}}"#,
            "x".repeat(2048)
        )
        .into_bytes(),
    ] {
        let mut r = field(&meta);
        r.extend(field(b""));
        assert!(matches!(
            against_raw(r, true, cfg()).await,
            Err(TunnelError::Protocol(_))
        ));
    }
    // A refusal followed by a body is a protocol error.
    let mut r = field(br#"{"v":1,"status":429,"content_type":"application/json","error":"busy"}"#);
    r.extend(field(b"{}"));
    r.extend(field(b""));
    assert!(matches!(
        against_raw(r, true, cfg()).await,
        Err(TunnelError::Protocol(_))
    ));
    // Nothing at all.
    assert_eq!(
        against_raw(vec![], true, cfg()).await,
        Err(TunnelError::Truncated)
    );
}
