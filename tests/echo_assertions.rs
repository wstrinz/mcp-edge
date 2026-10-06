//! DESIGN.md checklist item 6 at the backend integration: the echo backend
//! rejects unsigned, expired, replayed, wrong-audience and wrong-request
//! assertions (the edge-assert crate has the same cases as unit tests).

use edge_assert::{GrantContext, RequestBinding, Signer};
use mcp_edge::echo::EchoBackend;
use serde_json::{json, Value};

const ISS: &str = "https://edge.test";
const NOW: i64 = 1_800_000_000;
const BODY: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"whoami"}}"#;

fn signer() -> Signer {
    Signer::from_seed(&[5u8; 32], ISS)
}

fn grant(aud: &str) -> GrantContext {
    GrantContext {
        aud: aud.into(),
        sub: "owner".into(),
        client_id: "mcc_synthetic".into(),
        grant_id: "g_synthetic".into(),
        scope: vec!["mcp".into()],
        resource_scope: json!({}),
        gen: 1,
    }
}

fn mint(aud: &str, body: &[u8], at: i64) -> String {
    signer()
        .mint(
            &grant(aud),
            RequestBinding {
                method: "POST",
                path: "/mcp",
                body,
            },
            at,
            60,
        )
        .unwrap()
}

fn echo() -> EchoBackend {
    EchoBackend::new(&signer().public_key_base64url(), ISS, "echo").unwrap()
}

fn reason(reply: &mcp_edge::echo::BackendReply) -> String {
    let v: Value = serde_json::from_slice(reply.body.as_ref().unwrap()).unwrap();
    v["reason"]
        .as_str()
        .unwrap_or(v["error"].as_str().unwrap())
        .to_string()
}

#[test]
fn valid_assertion_returns_verified_claims() {
    let reply = echo().handle(
        Some(&mint("echo", BODY, NOW)),
        "POST",
        "/mcp",
        BODY,
        NOW + 1,
    );
    assert_eq!(reply.status, 200);
    let v: Value = serde_json::from_slice(&reply.body.unwrap()).unwrap();
    assert_eq!(v["id"], 7);
    assert_eq!(v["result"]["structuredContent"]["grant_id"], "g_synthetic");
    assert_eq!(v["result"]["structuredContent"]["aud"], "echo");
}

#[test]
fn missing_and_unsigned_assertions_are_rejected() {
    let e = echo();
    let reply = e.handle(None, "POST", "/mcp", BODY, NOW);
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "missing_assertion".into())
    );
    let good = mint("echo", BODY, NOW);
    let (payload, _) = good.split_once('.').unwrap();
    for bad in [
        payload.to_string(),
        format!("{payload}."),
        format!("{payload}.AAAA"),
        String::new(),
    ] {
        let reply = e.handle(Some(&bad), "POST", "/mcp", BODY, NOW);
        assert_eq!(reply.status, 401);
        assert!(matches!(
            reason(&reply).as_str(),
            "malformed" | "bad_signature"
        ));
    }
    // Signed by a key the backend does not trust.
    let foreign = Signer::from_seed(&[6u8; 32], ISS)
        .mint(
            &grant("echo"),
            RequestBinding {
                method: "POST",
                path: "/mcp",
                body: BODY,
            },
            NOW,
            60,
        )
        .unwrap();
    let reply = e.handle(Some(&foreign), "POST", "/mcp", BODY, NOW);
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "bad_signature".into())
    );
}

#[test]
fn expired_assertion_is_rejected() {
    let reply = echo().handle(
        Some(&mint("echo", BODY, NOW - 120)),
        "POST",
        "/mcp",
        BODY,
        NOW,
    );
    assert_eq!((reply.status, reason(&reply)), (401, "expired".into()));
    let reply = echo().handle(
        Some(&mint("echo", BODY, NOW + 120)),
        "POST",
        "/mcp",
        BODY,
        NOW,
    );
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "not_yet_valid".into())
    );
}

#[test]
fn replayed_assertion_is_rejected() {
    let e = echo();
    let a = mint("echo", BODY, NOW);
    assert_eq!(e.handle(Some(&a), "POST", "/mcp", BODY, NOW).status, 200);
    let reply = e.handle(Some(&a), "POST", "/mcp", BODY, NOW + 1);
    assert_eq!((reply.status, reason(&reply)), (401, "replayed".into()));
}

#[test]
fn wrong_audience_is_rejected() {
    let reply = echo().handle(Some(&mint("echo2", BODY, NOW)), "POST", "/mcp", BODY, NOW);
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "wrong_audience".into())
    );
}

#[test]
fn wrong_request_binding_is_rejected() {
    let e = echo();
    let a = mint("echo", BODY, NOW);
    let other = br#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#;
    let reply = e.handle(Some(&a), "POST", "/mcp", other, NOW);
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "request_mismatch".into())
    );
    let reply = e.handle(Some(&a), "POST", "/other", BODY, NOW);
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "request_mismatch".into())
    );
    let reply = e.handle(Some(&a), "GET", "/mcp", BODY, NOW);
    assert_eq!(
        (reply.status, reason(&reply)),
        (401, "request_mismatch".into())
    );
}

#[test]
fn json_rpc_surface() {
    let e = echo();
    let call = |body: &[u8]| {
        let reply = e.handle(Some(&mint("echo", body, NOW)), "POST", "/mcp", body, NOW);
        let v: Value = reply
            .body
            .as_deref()
            .map(|b| serde_json::from_slice(b).unwrap())
            .unwrap_or(Value::Null);
        (reply.status, v)
    };
    let (s, v) = call(br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#);
    assert_eq!(
        (s, v["result"]["protocolVersion"].as_str()),
        (200, Some("2025-06-18"))
    );
    let (s, v) = call(br#"{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-03-26"}}"#);
    assert_eq!(
        (s, v["result"]["protocolVersion"].as_str()),
        (200, Some("2025-03-26"))
    );
    assert_eq!(
        call(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).0,
        202
    );
    let (_, v) = call(br#"{"jsonrpc":"2.0","id":2,"method":"resources/list"}"#);
    assert_eq!(v["error"]["code"], -32601);
    let (_, v) = call(br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rm"}}"#);
    assert_eq!(v["error"]["code"], -32602);
    let (s, v) = call(br#"[{"jsonrpc":"2.0","id":4,"method":"ping"}]"#);
    assert_eq!((s, v["error"]["code"].as_i64()), (400, Some(-32600)));
    let (s, v) = call(b"not json");
    assert_eq!((s, v["error"]["code"].as_i64()), (400, Some(-32700)));
}
