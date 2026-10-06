//! DESIGN.md security checklist items 1–5 (and limits) against the real HTTP
//! server on an ephemeral loopback port.

mod common;

use common::*;
use edge_auth::config::Limits;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use webauthn_authenticator_rs::{
    prelude::RequestChallengeResponse, softpasskey::SoftPasskey, WebauthnAuthenticator,
};

fn location(res: &reqwest::Response) -> Option<String> {
    res.headers()
        .get("location")
        .map(|v| v.to_str().unwrap().to_string())
}

async fn approve(h: &Harness, b: &mut Browser, tx: &str, csrf: &str) -> reqwest::Response {
    h.post_form(
        b,
        "/consent",
        &[("tx", tx), ("csrf", csrf), ("decision", "approve")],
    )
    .await
}

fn assert_no_code(res: &reqwest::Response) {
    assert_ne!(res.status(), 303, "no redirect (and thus no code) expected");
    if let Some(l) = location(res) {
        assert!(!l.contains("code="), "a code was issued: {l}");
    }
}

// ---------------------------------------------------------------- origin

/// The consent form is a plain same-origin form POST. Real browsers attach
/// `Origin: <issuer>` to it now that pages use `Referrer-Policy: same-origin`
/// (under `no-referrer` they sent `Origin: null`, which broke the first live
/// claude.ai approval). `null` and foreign origins stay refused: accepting
/// `null` would also admit sandboxed frames.
#[tokio::test]
async fn consent_accepts_own_origin_and_refuses_null_or_foreign_origin() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let (_, challenge) = pkce();
    let mut b = Browser::default();
    let tx = h
        .begin(&mut b, &client, CALLBACK, "echo", &challenge, "s")
        .await;
    assert_eq!(h.owner_login(&mut b, Some(&tx)).await, 200);
    let csrf = h.consent_csrf(&mut b, &tx).await.expect("form after proof");
    let form = [
        ("tx", tx.as_str()),
        ("csrf", &csrf),
        ("decision", "approve"),
    ];
    for bad in ["null", "https://evil.example"] {
        let res = h.post_form_origin(&mut b, "/consent", &form, bad).await;
        assert_eq!(res.status(), 403, "Origin {bad}");
        assert_no_code(&res);
    }
    let res = h.post_form_origin(&mut b, "/consent", &form, ISSUER).await;
    assert_eq!(res.status(), 303);
    assert!(location(&res).unwrap().contains("code="));
}

// ---------------------------------------------------------------- item 1

#[tokio::test]
async fn checklist_1_no_code_without_fresh_owner_passkey_proof() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let (_, challenge) = pkce();

    // (a) No proof at all: no consent form is rendered and a forged submit fails.
    let mut b = Browser::default();
    let tx = h
        .begin(&mut b, &client, CALLBACK, "echo", &challenge, "s")
        .await;
    assert!(h.consent_csrf(&mut b, &tx).await.is_none());
    for csrf in ["", "forged", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
        assert_no_code(&approve(&h, &mut b, &tx, csrf).await);
    }

    // (b) An owner *session* (passkey login without this request) is not proof
    // for this request.
    assert_eq!(h.owner_login(&mut b, None).await, 200);
    assert!(h.consent_csrf(&mut b, &tx).await.is_none());
    assert_no_code(&approve(&h, &mut b, &tx, "forged").await);

    // (c) Proof bound to this request works only while fresh (5 minutes).
    assert_eq!(h.owner_login(&mut b, Some(&tx)).await, 200);
    let csrf = h.consent_csrf(&mut b, &tx).await.expect("form after proof");
    h.clock.advance(5 * 60 + 1);
    assert!(h.consent_csrf(&mut b, &tx).await.is_none());
    let res = approve(&h, &mut b, &tx, &csrf).await;
    assert_eq!(res.status(), 403);
    assert_no_code(&res);

    // (d) Proof from a browser that does not hold the request cookie is refused,
    // and that browser cannot see or approve the request.
    let mut other = Browser::default();
    assert_eq!(h.owner_login(&mut other, Some(&tx)).await, 400);
    let res = h.get(&mut other, &format!("/consent?tx={tx}")).await;
    assert_eq!(res.status(), 400);
    assert_no_code(&approve(&h, &mut other, &tx, &csrf).await);

    // (e) Answers that do not verify fail the ceremony: one signed for an
    // older challenge, and one with a tampered signature.
    let mut b2 = Browser::default();
    let tx2 = h
        .begin(&mut b2, &client, CALLBACK, "echo", &challenge, "s2")
        .await;
    let res = h
        .post_json(&mut b2, "/owner/login/start", &json!({ "tx": tx2 }))
        .await;
    assert_eq!(res.status(), 200);
    let old: RequestChallengeResponse = res.json().await.unwrap();
    let res = h
        .post_json(&mut b2, "/owner/login/start", &json!({ "tx": tx2 }))
        .await;
    assert_eq!(res.status(), 200);
    let stale_answer = h.passkey.do_authentication(h.origin.clone(), old).unwrap();
    let res = h
        .post_json(
            &mut b2,
            "/owner/login/finish",
            &serde_json::to_value(&stale_answer).unwrap(),
        )
        .await;
    assert_eq!(res.status(), 401, "answer to an old challenge is rejected");
    let res = h
        .post_json(&mut b2, "/owner/login/start", &json!({ "tx": tx2 }))
        .await;
    let options: RequestChallengeResponse = res.json().await.unwrap();
    let answer = h
        .passkey
        .do_authentication(h.origin.clone(), options)
        .unwrap();
    let mut tampered = serde_json::to_value(&answer).unwrap();
    let sig = tampered["response"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = if sig.ends_with('A') { "B" } else { "A" };
    tampered["response"]["signature"] = json!(format!("{}{flipped}", &sig[..sig.len() - 1]));
    let res = h.post_json(&mut b2, "/owner/login/finish", &tampered).await;
    assert_eq!(res.status(), 401, "tampered signature is rejected");
    assert!(h.consent_csrf(&mut b2, &tx2).await.is_none());

    // (f) A login answer cannot be replayed (the ceremony is one-shot).
    let res = h
        .post_json(&mut b2, "/owner/login/start", &json!({ "tx": tx2 }))
        .await;
    let options: RequestChallengeResponse = res.json().await.unwrap();
    let answer = h
        .passkey
        .do_authentication(h.origin.clone(), options)
        .unwrap();
    let body = serde_json::to_value(&answer).unwrap();
    let saved = b2.clone();
    assert_eq!(
        h.post_json(&mut b2, "/owner/login/finish", &body)
            .await
            .status(),
        200
    );
    let mut replay = saved;
    assert_eq!(
        h.post_json(&mut replay, "/owner/login/finish", &body)
            .await
            .status(),
        401
    );

    // (g) Cross-origin browser posts are refused outright.
    let csrf = h.consent_csrf(&mut b2, &tx2).await.unwrap();
    let res = h
        .http
        .post(h.url("/consent"))
        .header("origin", "https://evil.test")
        .header("cookie", b2.header().unwrap())
        .form(&[
            ("tx", tx2.as_str()),
            ("csrf", &csrf),
            ("decision", "approve"),
        ])
        .send()
        .await
        .unwrap();
    assert_no_code(&res);

    // Sanity: the fresh, bound proof does produce a code, exactly once.
    let res = approve(&h, &mut b2, &tx2, &csrf).await;
    assert_eq!(res.status(), 303);
    assert!(location(&res).unwrap().contains("code="));
    let res = approve(&h, &mut b2, &tx2, &csrf).await;
    assert_no_code(&res);
    h.finish().await;
}

#[tokio::test]
async fn enrollment_code_is_one_time_and_later_passkeys_need_a_session() {
    let mut h = Harness::start().await;
    // Nobody can log in before enrollment.
    let mut b = Browser::default();
    assert_eq!(h.owner_login(&mut b, None).await, 409);
    // Wrong code.
    let res = h
        .post_json(
            &mut b,
            "/owner/register/start",
            &json!({ "enroll_code": "SYNTHETIC-wrong-code-0000000000" }),
        )
        .await;
    assert_eq!(res.status(), 403);
    h.enroll().await;
    // The code is consumed: a second enrollment with it is refused.
    let res = h
        .post_json(
            &mut b,
            "/owner/register/start",
            &json!({ "enroll_code": ENROLL_CODE }),
        )
        .await;
    assert_eq!(res.status(), 401);
    // With a fresh owner session another passkey can be added.
    assert_eq!(h.owner_login(&mut b, None).await, 200);
    let res = h
        .post_json(&mut b, "/owner/register/start", &json!({}))
        .await;
    assert_eq!(res.status(), 200);
    let options = res.json().await.unwrap();
    let mut second = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let cred = second.do_registration(h.origin.clone(), options).unwrap();
    let res = h
        .post_json(
            &mut b,
            "/owner/register/finish",
            &serde_json::to_value(cred).unwrap(),
        )
        .await;
    assert_eq!(res.status(), 200);
    // ...and that passkey can now log in.
    std::mem::swap(&mut h.passkey, &mut second);
    let mut b2 = Browser::default();
    assert_eq!(h.owner_login(&mut b2, None).await, 200);
    h.finish().await;
}

#[tokio::test]
async fn enrollment_is_disabled_without_a_code_and_locks_after_failures() {
    let h = Harness::start_with(Options {
        enroll_code: None,
        ..Options::default()
    })
    .await;
    let mut b = Browser::default();
    let res = h
        .post_json(
            &mut b,
            "/owner/register/start",
            &json!({ "enroll_code": ENROLL_CODE }),
        )
        .await;
    assert_eq!(res.status(), 403);
    h.finish().await;

    let h = Harness::start_with(Options {
        auth_limits: Limits {
            max_enroll_failures: 2,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    let mut b = Browser::default();
    for expected in [403, 403, 429, 429] {
        let res = h
            .post_json(
                &mut b,
                "/owner/register/start",
                &json!({ "enroll_code": "SYNTHETIC-wrong-code-0000000000" }),
            )
            .await;
        assert_eq!(res.status(), expected);
    }
    // Even the right code is refused once locked.
    let res = h
        .post_json(
            &mut b,
            "/owner/register/start",
            &json!({ "enroll_code": ENROLL_CODE }),
        )
        .await;
    assert_eq!(res.status(), 429);
    // The lock lifts by itself after the 15-minute window.
    h.clock.advance(15 * 60);
    let res = h
        .post_json(
            &mut b,
            "/owner/register/start",
            &json!({ "enroll_code": ENROLL_CODE }),
        )
        .await;
    assert_eq!(res.status(), 200);
    h.finish().await;
}

#[tokio::test]
async fn enrollment_lock_is_per_network_with_a_global_ceiling() {
    let h = Harness::start_with(Options {
        auth_limits: Limits {
            max_enroll_failures: 2,
            max_enroll_failures_global: 5,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    let attempt = |ip: &str, code: &str| {
        let mut b = Browser::from_ip(ip);
        let body = json!({ "enroll_code": code });
        let h = &h;
        async move {
            h.post_json(&mut b, "/owner/register/start", &body)
                .await
                .status()
                .as_u16()
        }
    };
    let wrong = "SYNTHETIC-wrong-code-0000000000";
    // Network A locks itself out...
    assert_eq!(attempt("198.51.100.1", wrong).await, 403);
    assert_eq!(attempt("198.51.100.1", wrong).await, 403);
    assert_eq!(attempt("198.51.100.1", ENROLL_CODE).await, 429);
    // ...without locking out the owner on network B.
    assert_eq!(attempt("203.0.113.7", ENROLL_CODE).await, 200);
    // A shorter or longer wrong code is rejected the same way (digest compare).
    assert_eq!(attempt("198.51.100.2", "x").await, 403);
    assert_eq!(
        attempt("198.51.100.3", &format!("{ENROLL_CODE}x")).await,
        403
    );
    assert_eq!(attempt("198.51.100.4", wrong).await, 403);
    // Five failures across networks reach the global ceiling.
    assert_eq!(attempt("203.0.113.7", ENROLL_CODE).await, 429);
    h.clock.advance(60 * 60);
    assert_eq!(attempt("203.0.113.7", ENROLL_CODE).await, 200);
    h.finish().await;
}

#[tokio::test]
async fn anonymous_floods_cannot_fill_ceremony_or_pending_tables() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let (_, challenge) = pkce();
    // Far more anonymous ceremonies and pending requests than the tables hold.
    for i in 0..100 {
        let mut anon = Browser::default();
        let res = h
            .post_json(&mut anon, "/owner/login/start", &json!({}))
            .await;
        assert_eq!(res.status(), 200);
        let res = h
            .get(
                &mut anon,
                &Harness::authorize_query(&client, CALLBACK, "echo", &challenge, &format!("f{i}")),
            )
            .await;
        assert_eq!(res.status(), 303);
    }
    // The owner can still authorize end to end.
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    let (status, _) = h
        .exchange(&client, &code, &verifier, CALLBACK, "echo")
        .await;
    assert_eq!(status, 200);
    h.finish().await;
}

#[tokio::test]
async fn floods_from_many_networks_never_evict_owner_progress() {
    // Tiny global caps so a 40-network flood overflows both tables.
    let mut h = Harness::start_with(Options {
        auth_limits: Limits {
            max_pending: 8,
            max_ceremonies: 8,
            authorize_per_ip_per_minute: 1000,
            owner_per_ip_per_minute: 1000,
            token_per_ip_per_minute: 1000,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let (_, challenge) = pkce();
    let owner_ip = "203.0.113.10";

    // Request 1: passkey-verified, waiting for the consent click.
    let mut o1 = Browser::from_ip(owner_ip);
    let tx1 = h
        .begin(&mut o1, &client, CALLBACK, "echo", &challenge, "o1")
        .await;
    assert_eq!(h.owner_login(&mut o1, Some(&tx1)).await, 200);
    let csrf1 = h.consent_csrf(&mut o1, &tx1).await.unwrap();

    // Request 2: passkey ceremony in progress.
    let mut o2 = Browser::from_ip(owner_ip);
    let tx2 = h
        .begin(&mut o2, &client, CALLBACK, "echo", &challenge, "o2")
        .await;
    let res = h
        .post_json(&mut o2, "/owner/login/start", &json!({ "tx": tx2 }))
        .await;
    let options: RequestChallengeResponse = res.json().await.unwrap();

    // Flood A: anonymous ceremonies from 40 networks.
    for i in 0..40 {
        let mut anon = Browser::from_ip(&format!("198.51.{i}.1"));
        let res = h
            .post_json(&mut anon, "/owner/login/start", &json!({}))
            .await;
        assert_eq!(res.status(), 200);
    }
    // The owner's bound ceremony survived and completes.
    let answer = h
        .passkey
        .do_authentication(h.origin.clone(), options)
        .unwrap();
    let res = h
        .post_json(
            &mut o2,
            "/owner/login/finish",
            &serde_json::to_value(&answer).unwrap(),
        )
        .await;
    assert_eq!(res.status(), 200, "owner ceremony was evicted");
    let csrf2 = h.consent_csrf(&mut o2, &tx2).await.unwrap();

    // Flood B: authorization requests from 40 networks.
    for i in 0..40 {
        let mut anon = Browser::from_ip(&format!("192.0.{i}.1"));
        let q = Harness::authorize_query(&client, CALLBACK, "echo", &challenge, &format!("f{i}"));
        assert_eq!(h.get(&mut anon, &q).await.status(), 303);
    }
    // Both verified requests survived and yield codes.
    for (b, tx, csrf) in [(&mut o1, &tx1, &csrf1), (&mut o2, &tx2, &csrf2)] {
        let res = approve(&h, b, tx, csrf).await;
        assert_eq!(res.status(), 303);
        assert!(location(&res).unwrap().contains("code="));
    }
    h.finish().await;
}

#[tokio::test]
async fn slow_bodies_time_out_and_in_flight_requests_are_capped_per_network() {
    let h = Harness::start_with(Options {
        edge_limits: mcp_edge::app::EdgeLimits {
            per_ip_concurrent: 2,
            auth_body_timeout: Duration::from_secs(1),
            ..Default::default()
        },
        ..Options::default()
    })
    .await;
    // Two slowloris bodies from one network occupy its in-flight slots.
    let slow = "POST /token HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 198.51.100.9\r\n\
                Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\r\n\r\ngrant";
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut s = TcpStream::connect(h.addr).await.unwrap();
        s.write_all(slow.as_bytes()).await.unwrap();
        held.push(s);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let metadata = |xff: &'static str| {
        h.http
            .get(h.url("/.well-known/oauth-authorization-server"))
            .header("x-forwarded-for", xff)
            .send()
    };
    assert_eq!(metadata("198.51.100.9").await.unwrap().status(), 429);
    // Other networks and the health check are unaffected.
    assert_eq!(metadata("198.51.100.10").await.unwrap().status(), 200);
    assert_eq!(
        h.http.get(h.url("/healthz")).send().await.unwrap().status(),
        200
    );
    // The slow bodies hit the body deadline and free their slots.
    for mut s in held {
        let mut out = vec![0u8; 32];
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut out))
            .await
            .unwrap()
            .unwrap();
        let head = String::from_utf8_lossy(&out[..n]).to_string();
        assert!(head.starts_with("HTTP/1.1 408"), "{head}");
    }
    assert_eq!(metadata("198.51.100.9").await.unwrap().status(), 200);
    h.finish().await;
}

// ---------------------------------------------------------------- item 2

#[tokio::test]
async fn checklist_2_bad_authorization_requests_never_yield_codes() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let (_, challenge) = pkce();
    let good = Harness::authorize_query(&client, CALLBACK, "echo", &challenge, "st");
    let mut b = Browser::default();

    // Not redirected: the client or redirect cannot be trusted.
    for query in [
        good.replace(&client, "mcc_unknown"),
        good.replace("client_id=", "x_client_id="),
        good.replace(
            &url_encode(CALLBACK),
            &url_encode("https://evil.test/callback"),
        ),
        // Registered in the allowlist, but not for this client.
        good.replace(&url_encode(CALLBACK), &url_encode(OTHER_CALLBACK)),
        format!("{good}&state=again"),
    ] {
        let res = h.get(&mut b, &query).await;
        assert_eq!(res.status(), 400, "{query}");
        assert!(location(&res).is_none());
    }

    // Redirected with an error and never a code.
    for (query, error) in [
        (
            good.replace("code_challenge_method=S256", "code_challenge_method=plain"),
            "invalid_request",
        ),
        (
            good.replace("&code_challenge_method=S256", ""),
            "invalid_request",
        ),
        (
            good.replace(
                &format!("code_challenge={challenge}"),
                "code_challenge=short",
            ),
            "invalid_request",
        ),
        (
            good.replace(&format!("&code_challenge={challenge}"), ""),
            "invalid_request",
        ),
        (good.replace("&state=st", ""), "invalid_request"),
        (
            good.replace("response_type=code", "response_type=token"),
            "unsupported_response_type",
        ),
        (good.replace("echo%2Fmcp", "nope%2Fmcp"), "invalid_target"),
        (
            good.replace("edge.test%2Fecho%2Fmcp", "evil.test%2Fecho%2Fmcp"),
            "invalid_target",
        ),
        (
            good.replace(&format!("&resource={}", url_encode(&resource("echo"))), ""),
            "invalid_target",
        ),
    ] {
        let res = h.get(&mut b, &query).await;
        assert_eq!(res.status(), 303, "{query}");
        let l = location(&res).unwrap();
        assert!(l.starts_with(CALLBACK), "{l}");
        assert_eq!(query_param(&l, "error").as_deref(), Some(error), "{query}");
        assert!(query_param(&l, "code").is_none());
    }

    // Registration only accepts allowlisted redirects and public clients.
    for body in [
        json!({ "redirect_uris": ["https://evil.test/cb"] }),
        json!({ "redirect_uris": [] }),
        json!({ "redirect_uris": [CALLBACK], "grant_types": ["client_credentials"] }),
        json!({ "redirect_uris": [CALLBACK], "response_types": ["token"] }),
    ] {
        let res = h
            .http
            .post(h.url("/register"))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400, "{body}");
    }
    h.finish().await;
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// ---------------------------------------------------------------- item 3

#[tokio::test]
async fn checklist_3_bad_code_exchanges_are_invalid_grant() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;
    let other_client = h.register_client(CALLBACK).await;
    let two_redirects = {
        let res = h
            .http
            .post(h.url("/register"))
            .json(&json!({ "redirect_uris": [CALLBACK, OTHER_CALLBACK] }))
            .send()
            .await
            .unwrap();
        let v: Value = res.json().await.unwrap();
        v["client_id"].as_str().unwrap().to_string()
    };
    let invalid = |r: (u16, Value)| {
        assert_eq!(r.0, 400, "{}", r.1);
        assert_eq!(r.1["error"], "invalid_grant");
    };

    // Wrong verifier; the code is then burnt even for the right verifier.
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    let (wrong, _) = pkce();
    invalid(h.exchange(&client, &code, &wrong, CALLBACK, "echo").await);
    invalid(
        h.exchange(&client, &code, &verifier, CALLBACK, "echo")
            .await,
    );

    // Wrong client.
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    invalid(
        h.exchange(&other_client, &code, &verifier, CALLBACK, "echo")
            .await,
    );

    // Wrong resource.
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    invalid(
        h.exchange(&client, &code, &verifier, CALLBACK, "echo2")
            .await,
    );

    // Wrong redirect_uri (another URI registered by the same client).
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&two_redirects, CALLBACK, "echo", &challenge)
        .await;
    invalid(
        h.exchange(&two_redirects, &code, &verifier, OTHER_CALLBACK, "echo")
            .await,
    );

    // Expired (codes live 60 s).
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    h.clock.advance(61);
    invalid(
        h.exchange(&client, &code, &verifier, CALLBACK, "echo")
            .await,
    );

    // Unknown code and missing verifier.
    let (verifier, _) = pkce();
    invalid(
        h.exchange(&client, "mec_unknown", &verifier, CALLBACK, "echo")
            .await,
    );
    let (_, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    invalid(
        h.token(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client),
            ("code", &code),
            ("redirect_uri", CALLBACK),
        ])
        .await,
    );

    // Reuse: the second exchange fails and revokes what the first produced.
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    let (status, tokens) = h
        .exchange(&client, &code, &verifier, CALLBACK, "echo")
        .await;
    assert_eq!(status, 200);
    let access = tokens["access_token"].as_str().unwrap();
    assert_eq!(
        h.mcp("echo", Some(access), &rpc(1, "ping", json!({})))
            .await
            .status(),
        200
    );
    invalid(
        h.exchange(&client, &code, &verifier, CALLBACK, "echo")
            .await,
    );
    assert_eq!(
        h.mcp("echo", Some(access), &rpc(1, "ping", json!({})))
            .await
            .status(),
        401
    );
    invalid(
        h.refresh(&client, tokens["refresh_token"].as_str().unwrap())
            .await,
    );

    // Unknown clients and client authentication attempts are invalid_client.
    let (status, body) = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("client_id", "mcc_unknown"),
            ("code", "x"),
        ])
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client"))
    );
    let (status, body) = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client),
            ("client_secret", "s"),
            ("code", "x"),
        ])
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("invalid_client"))
    );
    h.finish().await;
}

// ---------------------------------------------------------------- item 4

#[tokio::test]
async fn checklist_4_refresh_replay_revokes_the_family() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let (client, t1) = h.tokens_for("echo").await;
    let a1 = t1["access_token"].as_str().unwrap().to_string();
    let r1 = t1["refresh_token"].as_str().unwrap().to_string();
    let (status, t2) = h.refresh(&client, &r1).await;
    assert_eq!(status, 200);
    let a2 = t2["access_token"].as_str().unwrap().to_string();
    let r2 = t2["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(
        h.mcp("echo", Some(&a2), &rpc(1, "ping", json!({})))
            .await
            .status(),
        200
    );

    // Grace: the immediately-previous token, retried by the same client
    // within 30 s, continues the family with a fresh pair.
    let (status, t3) = h.refresh(&client, &r1).await;
    assert_eq!(status, 200, "{t3}");
    let r3 = t3["refresh_token"].as_str().unwrap().to_string();
    assert!(h.logs().iter().any(|l| l.contains("event=refresh_grace")));
    // Normal rotation moves on: r1 is now two generations back.
    let (status, t4) = h.refresh(&client, &r3).await;
    assert_eq!(status, 200);
    let a4 = t4["access_token"].as_str().unwrap().to_string();
    let r4 = t4["refresh_token"].as_str().unwrap().to_string();

    // Replay of an older rotated token: rejected and the whole family dies.
    let (status, body) = h.refresh(&client, &r1).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    for r in [&r2, &r4] {
        let (status, body) = h.refresh(&client, r).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (400, Some("invalid_grant"))
        );
    }
    for token in [&a1, &a2, &a4] {
        assert_eq!(
            h.mcp("echo", Some(token), &rpc(2, "ping", json!({})))
                .await
                .status(),
            401
        );
    }
    assert!(h
        .logs()
        .iter()
        .any(|l| l.contains("event=refresh_reuse") && l.contains("family_revoked")));

    // The immediately-previous token after the grace window also revokes.
    let (client_g, tg) = h.tokens_for("echo").await;
    let rg1 = tg["refresh_token"].as_str().unwrap().to_string();
    let (status, tg2) = h.refresh(&client_g, &rg1).await;
    assert_eq!(status, 200);
    h.clock.advance(31);
    let (status, _) = h.refresh(&client_g, &rg1).await;
    assert_eq!(status, 400);
    let (status, _) = h
        .refresh(&client_g, tg2["refresh_token"].as_str().unwrap())
        .await;
    assert_eq!(status, 400, "family revoked");

    // A refresh token presented by another client also revokes its family,
    // even inside the grace window.
    let (client_b, t3) = h.tokens_for("echo").await;
    let r3 = t3["refresh_token"].as_str().unwrap().to_string();
    let (status, _) = h.refresh(&client, &r3).await;
    assert_eq!(status, 400);
    let (status, _) = h.refresh(&client_b, &r3).await;
    assert_eq!(status, 400);

    // Refresh never outlives the grant's absolute lifetime (echo2: 24 h).
    let (client_c, t4) = h.tokens_for("echo2").await;
    let mut refresh = t4["refresh_token"].as_str().unwrap().to_string();
    for _ in 0..3 {
        h.clock.advance(8 * 3600);
        let (status, t) = h.refresh(&client_c, &refresh).await;
        if status != 200 {
            assert_eq!(t["error"], "invalid_grant");
            h.finish().await;
            return;
        }
        refresh = t["refresh_token"].as_str().unwrap().to_string();
    }
    panic!("refresh outlived the 24 h grant");
}

// ---------------------------------------------------------------- item 5

#[tokio::test]
async fn checklist_5_token_for_backend_a_is_rejected_at_backend_b() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let (client, tokens) = h.tokens_for("echo").await;
    let access = tokens["access_token"].as_str().unwrap();
    let ok = h
        .mcp("echo", Some(access), &rpc(1, "ping", json!({})))
        .await;
    assert_eq!(ok.status(), 200);
    let res = h
        .mcp("echo2", Some(access), &rpc(1, "ping", json!({})))
        .await;
    assert_eq!(res.status(), 401);
    let challenge = res.headers()["www-authenticate"].to_str().unwrap();
    assert!(challenge.contains("error=\"invalid_token\""));
    assert!(challenge.contains("/.well-known/oauth-protected-resource/echo2/mcp"));
    // Refresh cannot be redirected to the other backend either.
    let resource_b = resource("echo2");
    let (status, body) = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("resource", &resource_b),
        ])
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    // Malformed and unknown bearer tokens.
    for header in [
        "Bearer",
        "Bearer ",
        "Basic abc",
        "Bearer a b",
        "Bearer mea_unknown",
    ] {
        let res = h
            .http
            .post(h.url("/echo/mcp"))
            .header("content-type", "application/json")
            .header("authorization", header)
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 401, "{header}");
    }
    // Access tokens expire after 15 minutes.
    h.clock.advance(15 * 60);
    let res = h
        .mcp("echo", Some(access), &rpc(1, "ping", json!({})))
        .await;
    assert_eq!(res.status(), 401);
    h.finish().await;
}

// ---------------------------------------------------------------- limits

#[tokio::test]
async fn limits_methods_and_fixed_errors() {
    let mut h = Harness::start_with(Options {
        auth_limits: Limits {
            register_per_ip_per_hour: 3,
            ..Limits::default()
        },
        ..Options::default()
    })
    .await;
    h.enroll().await;
    let (_, tokens) = h.tokens_for("echo2").await; // 1 registration used
    let access = tokens["access_token"].as_str().unwrap();

    // Registration rate limit per IP.
    let mut statuses = Vec::new();
    for _ in 0..3 {
        let res = h
            .http
            .post(h.url("/register"))
            .json(&json!({ "redirect_uris": [CALLBACK] }))
            .send()
            .await
            .unwrap();
        statuses.push(res.status().as_u16());
    }
    assert_eq!(statuses, vec![201, 201, 429]);
    // Behind a trusted proxy (loopback here) another client network has its
    // own budget; spoofed left-hand X-Forwarded-For entries do not help.
    let mut statuses = Vec::new();
    for xff in [
        "198.51.100.1",
        "198.51.100.1",
        "198.51.100.1",
        "6.6.6.6, 198.51.100.1",
        "6.6.6.6, 198.51.100.1, 127.0.0.2",
    ] {
        let res = h
            .http
            .post(h.url("/register"))
            .header("x-forwarded-for", xff)
            .json(&json!({ "redirect_uris": [CALLBACK] }))
            .send()
            .await
            .unwrap();
        statuses.push(res.status().as_u16());
    }
    assert_eq!(statuses, vec![201, 201, 201, 429, 429]);

    // Body cap (echo2: 4096 bytes) is enforced after authentication.
    let big = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "params": { "pad": "x".repeat(5000) } });
    assert_eq!(h.mcp("echo2", Some(access), &big).await.status(), 413);
    // Unauthenticated oversize bodies are refused without being read.
    assert_eq!(h.mcp("echo2", None, &big).await.status(), 401);
    // Content type and protocol version.
    let res = h
        .http
        .post(h.url("/echo2/mcp"))
        .header("authorization", format!("Bearer {access}"))
        .header("content-type", "text/plain")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 415);
    let res = h
        .http
        .post(h.url("/echo2/mcp"))
        .header("authorization", format!("Bearer {access}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "1999-01-01")
        .body(serde_json::to_vec(&rpc(1, "ping", json!({}))).unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 400);

    // Only POST reaches a backend; unknown backends and paths are fixed 404s.
    let res = h.http.get(h.url("/echo/mcp")).send().await.unwrap();
    assert_eq!(res.status(), 405);
    assert_eq!(res.headers()["allow"], "POST");
    let res = h.http.delete(h.url("/echo/mcp")).send().await.unwrap();
    assert_eq!(res.status(), 405);
    for path in [
        "/nope/mcp",
        "/echo/mcp/extra",
        "/echo",
        "/admin",
        "/%2e%2e/mcp",
    ] {
        let res = h
            .http
            .post(h.url(path))
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 404, "{path}");
        assert_eq!(res.text().await.unwrap(), "{\"error\":\"not_found\"}");
    }
    let res = h
        .http
        .get(h.url("/.well-known/oauth-protected-resource/nope/mcp"))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 404);

    // Health is not readiness; neither needs credentials.
    let health: Value = h
        .http
        .get(h.url("/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["status"], "alive");
    assert_eq!(
        h.http.get(h.url("/readyz")).send().await.unwrap().status(),
        200
    );

    // Proxy-style requests are refused at the door.
    for raw in [
        "GET http://127.0.0.1:9/healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n",
    ] {
        let mut socket = TcpStream::connect(h.addr).await.unwrap();
        socket.write_all(raw.as_bytes()).await.unwrap();
        let mut out = vec![0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut out))
            .await
            .unwrap()
            .unwrap();
        let head = String::from_utf8_lossy(&out[..n]).to_string();
        assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    }
    // Oversized header blocks are never served, however they arrive.
    for _ in 0..5 {
        let res = h
            .http
            .get(h.url("/healthz"))
            .header("x-pad", "a".repeat(40 * 1024))
            .send()
            .await;
        if let Ok(res) = res {
            assert!(
                matches!(res.status().as_u16(), 431 | 400),
                "{}",
                res.status()
            );
        }
    }
    h.finish().await;
}

#[tokio::test]
async fn owner_page_revoke_all_requires_session_and_csrf() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let (_, tokens) = h.tokens_for("echo").await;
    let access = tokens["access_token"].as_str().unwrap();
    let mut owner = Browser::default();
    // Without a session the page only offers sign-in.
    let html = h.get(&mut owner, "/owner").await.text().await.unwrap();
    assert!(html.contains("Sign in with passkey"));
    assert!(extract_csrf(&html).is_none());
    assert_eq!(h.owner_login(&mut owner, None).await, 200);
    let html = h.get(&mut owner, "/owner").await.text().await.unwrap();
    let csrf = extract_csrf(&html).unwrap();
    // Wrong CSRF does nothing.
    let res = h
        .post_form(
            &mut owner,
            "/owner/grants/revoke-all",
            &[("csrf", "forged")],
        )
        .await;
    assert_eq!(res.status(), 403);
    assert_eq!(
        h.mcp("echo", Some(access), &rpc(1, "ping", json!({})))
            .await
            .status(),
        200
    );
    let res = h
        .post_form(&mut owner, "/owner/grants/revoke-all", &[("csrf", &csrf)])
        .await;
    assert_eq!(res.status(), 303);
    assert_eq!(
        h.mcp("echo", Some(access), &rpc(1, "ping", json!({})))
            .await
            .status(),
        401
    );
    h.finish().await;
}
