use serde_json::{json, Value};
use std::collections::BTreeMap;
use wiskit_claude_compat_fixture::*;

const VERIFIER: &str = "synthetic_public_fixture_verifier_0123456789abcdef";
const STATE: &str = "synthetic_browser_transaction_state";
fn headers() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("host".into(), "origin.poc.invalid".into()),
        ("content-type".into(), "application/json".into()),
        (
            "accept".into(),
            "application/json, text/event-stream".into(),
        ),
        ("fixture-browser-session".into(), "synthetic-browser".into()),
    ])
}
fn form(p: &[(&str, &str)]) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(p.iter().copied())
        .finish()
        .into_bytes()
}
fn token(f: &mut Fixture, p: &[(&str, &str)]) -> HttpReply {
    let mut h = headers();
    h.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    f.handle("POST", "/token", &h, &form(p))
}
fn register(f: &mut Fixture) -> String {
    if f.use_cimd {
        return FIXTURE_CIMD.into();
    }
    let r = f.handle("POST", "/register", &headers(), &serde_json::to_vec(&json!({"redirect_uris":[CALLBACK],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"],"client_name":"Synthetic Claude web"})).unwrap());
    assert_eq!(r.status, 201);
    assert!(r.value().get("client_secret").is_none());
    r.value()["client_id"].as_str().unwrap().into()
}
fn pending(f: &mut Fixture, client: &str) -> String {
    let p = form(&[
        ("client_id", client),
        ("redirect_uri", CALLBACK),
        ("resource", RESOURCE),
        ("response_type", "code"),
        ("code_challenge_method", "S256"),
        ("code_challenge", &pkce(VERIFIER)),
        ("state", STATE),
        ("scope", "wiskit:read offline_access"),
    ]);
    let r = f.handle(
        "GET",
        &format!("/authorize?{}", String::from_utf8(p).unwrap()),
        &headers(),
        b"",
    );
    assert_eq!(r.status, 200);
    r.value()["pending_handle"].as_str().unwrap().into()
}
fn consent(f: &mut Fixture, client: &str, trackers: &[&str]) -> (String, String) {
    let pending = pending(f, client);
    let (r, grant) = f
        .approve(&pending, "synthetic-browser", true, trackers)
        .unwrap();
    assert_eq!(r.status, 303);
    let location = &r.headers["location"];
    assert!(Fixture::valid_callback(location, STATE, ISSUER));
    assert!(!Fixture::valid_callback(location, "another-state", ISSUER));
    assert!(!Fixture::valid_callback(
        location,
        STATE,
        "https://other.poc.invalid"
    ));
    let url = url::Url::parse(location).unwrap();
    let code = url
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    (code, grant)
}
fn exchange(f: &mut Fixture, client: &str, code: &str) -> HttpReply {
    token(
        f,
        &[
            ("client_id", client),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", VERIFIER),
            ("redirect_uri", CALLBACK),
            ("resource", RESOURCE),
        ],
    )
}
fn setup(cimd: bool, trackers: &[&str]) -> (Fixture, String, Value, String) {
    let mut f = Fixture::new(cimd);
    let client = register(&mut f);
    let (code, grant) = consent(&mut f, &client, trackers);
    let r = exchange(&mut f, &client, &code);
    assert_eq!(r.status, 200);
    (f, client, r.value(), grant)
}
fn mcp(f: &mut Fixture, access: &str, message: Value) -> HttpReply {
    let mut h = headers();
    h.insert("authorization".into(), format!("Bearer {access}"));
    h.insert("mcp-protocol-version".into(), "2025-11-25".into());
    f.handle("POST", "/mcp", &h, &serde_json::to_vec(&message).unwrap())
}
fn call(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}})
}

#[test]
fn discovery_challenge_and_claude_cimd_selection() {
    let mut f = Fixture::new(true);
    let r = f.handle("POST", "/mcp", &headers(), b"{}");
    assert_eq!(r.status, 401);
    assert!(r.headers["www-authenticate"].contains("resource_metadata="));
    let r = f.handle(
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        &headers(),
        b"",
    );
    assert_eq!(r.value()["resource"], RESOURCE);
    assert_eq!(r.value()["authorization_servers"], json!([ISSUER]));
    let mut meta = f
        .handle(
            "GET",
            "/.well-known/oauth-authorization-server",
            &headers(),
            b"",
        )
        .value();
    assert!(Fixture::claude_uses_cimd(&meta));
    meta["token_endpoint_auth_methods_supported"] = json!(["client_secret_post"]);
    assert!(!Fixture::claude_uses_cimd(&meta));
    meta["token_endpoint_auth_methods_supported"] = json!(["none"]);
    meta["client_id_metadata_document_supported"] = json!(false);
    assert!(!Fixture::claude_uses_cimd(&meta));
    assert_eq!(f.dispatches, 0);
}

#[test]
fn dcr_and_cimd_code_pkce_round_trips_are_single_use() {
    for cimd in [false, true] {
        let mut f = Fixture::new(cimd);
        let client = register(&mut f);
        let (code, _) = consent(&mut f, &client, &["synthetic-a"]);
        assert_eq!(exchange(&mut f, &client, &code).status, 200);
        assert_eq!(
            exchange(&mut f, &client, &code).value()["error"],
            "invalid_grant"
        );
    }
}

#[test]
fn registration_redirects_cimd_urls_and_duplicate_forms_fail_closed() {
    let mut f = Fixture::new(false);
    let r = f.handle("POST", "/register", &headers(), &serde_json::to_vec(&json!({"redirect_uris":["https://evil.poc.invalid/callback"],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]})).unwrap());
    assert_eq!(r.status, 400);
    assert!(Fixture::valid_cimd(FIXTURE_CIMD, &f.client_document()));
    assert!(!Fixture::valid_cimd(
        "http://127.0.0.1/private",
        &f.client_document()
    ));
    let mut doc = f.client_document();
    doc["client_id"] = json!("https://other.poc.invalid/doc");
    assert!(!Fixture::valid_cimd(FIXTURE_CIMD, &doc));
    let mut h = headers();
    h.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    assert_eq!(
        f.handle("POST", "/token", &h, b"client_id=a&client_id=b")
            .status,
        400
    );
    assert_eq!(f.handle("POST", "/token", &headers(), b"{}").status, 415);
    let client = register(&mut f);
    assert_eq!(
        token(
            &mut f,
            &[("client_id", &client), ("grant_type", "client_credentials")]
        )
        .value()["error"],
        "unsupported_grant_type"
    );
}

#[test]
fn pkce_client_redirect_resource_and_code_expiry_are_bound() {
    for fault in ["verifier", "client", "redirect", "expiry"] {
        let mut f = Fixture::default();
        let client = register(&mut f);
        let other = register(&mut f);
        let (code, _) = consent(&mut f, &client, &["synthetic-a"]);
        if fault == "expiry" {
            f.now += 61;
        }
        let r = token(
            &mut f,
            &[
                (
                    "client_id",
                    if fault == "client" { &other } else { &client },
                ),
                ("grant_type", "authorization_code"),
                ("code", &code),
                (
                    "code_verifier",
                    if fault == "verifier" {
                        "wrong_verifier_0123456789abcdefghijklmnopqrstuvwxyz"
                    } else {
                        VERIFIER
                    },
                ),
                (
                    "redirect_uri",
                    if fault == "redirect" {
                        "https://evil.poc.invalid/callback"
                    } else {
                        CALLBACK
                    },
                ),
                ("resource", RESOURCE),
            ],
        );
        assert_eq!(r.value()["error"], "invalid_grant");
    }
    let mut f = Fixture::default();
    let client = register(&mut f);
    let (code, _) = consent(&mut f, &client, &["synthetic-a"]);
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("redirect_uri", CALLBACK)
            ]
        )
        .value()["error"],
        "invalid_target"
    );
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("code_verifier", VERIFIER),
                ("redirect_uri", CALLBACK),
                ("resource", "https://other.poc.invalid/mcp")
            ]
        )
        .value()["error"],
        "invalid_target"
    );
    assert_eq!(exchange(&mut f, &client, &code).status, 200);
}

#[test]
fn consent_requires_local_owner_browser_binding_and_specific_trackers() {
    let mut f = Fixture::default();
    let client = register(&mut f);
    let p = pending(&mut f, &client);
    assert!(f
        .approve(&p, "synthetic-browser", false, &["synthetic-a"])
        .is_err());
    assert!(f
        .approve(&p, "wrong-browser", true, &["synthetic-a"])
        .is_err());
    assert!(f.approve(&p, "synthetic-browser", true, &[]).is_err());
    assert!(f
        .approve(&p, "synthetic-browser", true, &["not-owned"])
        .is_err());
    assert!(f
        .approve(&p, "synthetic-browser", true, &["synthetic-a"])
        .is_ok());
    assert!(f
        .approve(&p, "synthetic-browser", true, &["synthetic-a"])
        .is_err());
}

#[test]
fn consent_grants_do_not_merge_even_for_same_public_cimd_client() {
    let (mut f, client, a, _) = setup(true, &["synthetic-a"]);
    let (code, _) = consent(&mut f, &client, &["synthetic-b"]);
    let b = exchange(&mut f, &client, &code).value();
    for (tokens, allowed, denied) in [
        (&a, "synthetic-a", "synthetic-b"),
        (&b, "synthetic-b", "synthetic-a"),
    ] {
        let access = tokens["access_token"].as_str().unwrap();
        let r = mcp(&mut f, access, call("wiskit_list_trackers", json!({})));
        let text = r.value()["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(text.contains(allowed));
        assert!(!text.contains(denied));
        assert_eq!(
            mcp(
                &mut f,
                access,
                call("wiskit_read_tracker_bundle", json!({"trackerId":denied}))
            )
            .value()["result"]["isError"],
            true
        );
        assert_eq!(
            mcp(
                &mut f,
                access,
                call("wiskit_read_tracker_bundle", json!({"trackerId":allowed}))
            )
            .value()["result"]["isError"],
            false
        );
        assert_eq!(
            mcp(
                &mut f,
                access,
                call("wiskit_append_event", json!({"trackerId":allowed}))
            )
            .value()["result"]["isError"],
            true
        );
    }
    assert_eq!(f.dispatches, 4);
}

#[test]
fn legacy_initialize_stateless_headers_tools_and_notifications() {
    let (mut f, _, t, _) = setup(false, &["synthetic-a"]);
    let access = t["access_token"].as_str().unwrap();
    for v in VERSIONS {
        let r = mcp(
            &mut f,
            access,
            json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":v,"capabilities":{},"clientInfo":{"name":"Synthetic","version":"1"}}}),
        );
        assert_eq!(r.value()["result"]["protocolVersion"], v);
        assert!(!r.headers.contains_key("mcp-session-id"));
    }
    let r = mcp(
        &mut f,
        access,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    );
    assert_eq!(r.status, 202);
    assert!(r.body.is_empty());
    let tools = mcp(
        &mut f,
        access,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .value();
    assert_eq!(tools["result"]["tools"].as_array().unwrap().len(), 2);
    assert!(tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .all(|t| t["annotations"]["readOnlyHint"] == true));
    let mut h = headers();
    h.insert("authorization".into(), format!("Bearer {access}"));
    h.insert("mcp-protocol-version".into(), "2026-07-28".into());
    assert_eq!(f.handle("POST", "/mcp", &h, b"{}").status, 400);
    h.remove("authorization");
    h.insert("mcp-session-id".into(), access.into());
    assert_eq!(f.handle("POST", "/mcp", &h, b"{}").status, 401);
    assert_eq!(f.handle("GET", "/mcp", &headers(), b"").status, 405);
    assert_eq!(f.handle("DELETE", "/mcp", &headers(), b"").status, 405);
}

#[test]
fn refresh_rotates_stays_bound_and_replay_revokes_the_family() {
    let (mut f, client, t, _) = setup(false, &["synthetic-a"]);
    let old = t["refresh_token"].as_str().unwrap();
    let other = register(&mut f);
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &other),
                ("grant_type", "refresh_token"),
                ("refresh_token", old)
            ]
        )
        .value()["error"],
        "invalid_grant"
    );
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "refresh_token"),
                ("refresh_token", old),
                ("resource", "https://other.poc.invalid/mcp")
            ]
        )
        .value()["error"],
        "invalid_target"
    );
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "refresh_token"),
                ("refresh_token", old),
                ("scope", "wiskit:write")
            ]
        )
        .value()["error"],
        "invalid_scope"
    );
    let r = token(
        &mut f,
        &[
            ("client_id", &client),
            ("grant_type", "refresh_token"),
            ("refresh_token", old),
        ],
    );
    assert_eq!(r.status, 200);
    let next = r.value();
    assert!(next["refresh_token"] != t["refresh_token"]);
    let access = next["access_token"].as_str().unwrap();
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        200
    );
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "refresh_token"),
                ("refresh_token", old)
            ]
        )
        .value()["error"],
        "invalid_grant"
    );
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        401
    );
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "refresh_token"),
                ("refresh_token", next["refresh_token"].as_str().unwrap())
            ]
        )
        .value()["error"],
        "invalid_grant"
    );
}

#[test]
fn expiry_revocation_and_restart_fail_closed() {
    let (mut f, client, t, grant) = setup(false, &["synthetic-a"]);
    let access = t["access_token"].as_str().unwrap();
    f.now += 900;
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        401
    );
    let r = token(
        &mut f,
        &[
            ("client_id", &client),
            ("grant_type", "refresh_token"),
            ("refresh_token", t["refresh_token"].as_str().unwrap()),
        ],
    );
    assert_eq!(r.status, 200);
    let new = r.value();
    let access = new["access_token"].as_str().unwrap();
    f.revoke(&grant);
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        401
    );
    assert_eq!(
        token(
            &mut f,
            &[
                ("client_id", &client),
                ("grant_type", "refresh_token"),
                ("refresh_token", new["refresh_token"].as_str().unwrap())
            ]
        )
        .value()["error"],
        "invalid_grant"
    );
    let (mut f, _, t, _) = setup(false, &["synthetic-a"]);
    f.restart();
    let access = t["access_token"].as_str().unwrap();
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        503
    );
    f.remote_enabled = true;
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        401
    );
}

#[test]
fn redacted_audit_and_audit_failure_never_dispatch_data() {
    let (mut f, _, t, _) = setup(false, &["synthetic-a"]);
    let access = t["access_token"].as_str().unwrap();
    let mut req = call(
        "synthetic_private_event_query",
        json!({"details":"synthetic_private_event_query"}),
    );
    req["id"] = json!("synthetic_private_event_query");
    assert_eq!(mcp(&mut f, access, req).value()["result"]["isError"], true);
    let audit = f.audit_json();
    for sensitive in [
        access,
        t["refresh_token"].as_str().unwrap(),
        VERIFIER,
        STATE,
        "synthetic_private_event_query",
        "synthetic-a",
    ] {
        assert!(!audit.contains(sensitive));
    }
    assert!(audit.contains("unknown_tool") && audit.contains("denied"));
    f.audit_available = false;
    assert_eq!(
        mcp(&mut f, access, call("wiskit_list_trackers", json!({}))).status,
        503
    );
    assert_eq!(f.dispatches, 0);
}

#[test]
fn registration_and_pending_consent_are_bounded() {
    let mut f = Fixture::default();
    let client = register(&mut f);
    for _ in 1..32 {
        register(&mut f);
    }
    let registration = json!({"redirect_uris":[CALLBACK],"token_endpoint_auth_method":"none","grant_types":["authorization_code","refresh_token"],"response_types":["code"]});
    assert_eq!(
        f.handle(
            "POST",
            "/register",
            &headers(),
            &serde_json::to_vec(&registration).unwrap()
        )
        .status,
        429
    );
    for _ in 0..8 {
        pending(&mut f, &client);
    }
    let p = form(&[
        ("client_id", &client),
        ("redirect_uri", CALLBACK),
        ("resource", RESOURCE),
        ("response_type", "code"),
        ("code_challenge_method", "S256"),
        ("code_challenge", &pkce(VERIFIER)),
        ("state", STATE),
        ("scope", READ_SCOPE),
    ]);
    let target = format!("/authorize?{}", String::from_utf8(p).unwrap());
    assert_eq!(f.handle("GET", &target, &headers(), b"").status, 429);
    f.now += 181;
    assert_eq!(f.handle("GET", &target, &headers(), b"").status, 200);
    assert_eq!(
        f.handle("POST", "/mcp", &headers(), &vec![b'x'; 16 * 1024 + 1])
            .status,
        413
    );
}
