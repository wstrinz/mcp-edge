use serde_json::json;
use std::collections::BTreeMap;
use wiskit_claude_compat_fixture::*;

fn h() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("host".into(), "origin.poc.invalid".into()),
        ("content-type".into(), "application/json".into()),
        (
            "accept".into(),
            "application/json, text/event-stream".into(),
        ),
        ("fixture-browser-session".into(), "browser".into()),
    ])
}
fn form(p: &[(&str, &str)]) -> Vec<u8> {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(p.iter().copied())
        .finish()
        .into_bytes()
}
fn issue(f: &mut Fixture) -> (String, String) {
    let verifier = "synthetic_public_boundary_verifier_0123456789abcdef";
    let q = form(&[
        ("client_id", FIXTURE_CIMD),
        ("resource", RESOURCE),
        ("redirect_uri", CALLBACK),
        ("response_type", "code"),
        ("code_challenge_method", "S256"),
        ("code_challenge", &pkce(verifier)),
        ("state", "synthetic_browser_state"),
        ("scope", "wiskit:read offline_access"),
    ]);
    let r = f.handle(
        "GET",
        &format!("/authorize?{}", String::from_utf8(q).unwrap()),
        &h(),
        b"",
    );
    let p = r.value()["pending_handle"].as_str().unwrap().to_owned();
    let (r, _) = f.approve(&p, "browser", true, &["synthetic-a"]).unwrap();
    let u = url::Url::parse(&r.headers["location"]).unwrap();
    let code = u
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let mut headers = h();
    headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    let r = f.handle(
        "POST",
        "/token",
        &headers,
        &form(&[
            ("client_id", FIXTURE_CIMD),
            ("resource", RESOURCE),
            ("redirect_uri", CALLBACK),
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("code_verifier", verifier),
        ]),
    );
    assert_eq!(r.status, 200);
    (
        r.value()["access_token"].as_str().unwrap().into(),
        r.value()["refresh_token"].as_str().unwrap().into(),
    )
}

#[test]
fn revocation_endpoint_is_idempotent_and_client_bound() {
    let mut f = Fixture::new(true);
    let (access, refresh) = issue(&mut f);
    let mut headers = h();
    headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    let r = f.handle(
        "POST",
        "/revoke",
        &headers,
        &form(&[("client_id", "another-client"), ("token", &refresh)]),
    );
    assert_eq!(r.status, 200);
    let mut mcp = h();
    mcp.insert("authorization".into(), format!("Bearer {access}"));
    assert_eq!(
        f.handle(
            "POST",
            "/mcp",
            &mcp,
            br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#
        )
        .status,
        200
    );
    assert_eq!(
        f.handle(
            "POST",
            "/revoke",
            &headers,
            &form(&[("client_id", FIXTURE_CIMD), ("token", &refresh)])
        )
        .status,
        200
    );
    assert_eq!(f.handle("POST", "/mcp", &mcp, b"{}").status, 401);
    assert_eq!(
        f.handle(
            "POST",
            "/revoke",
            &headers,
            &form(&[("client_id", FIXTURE_CIMD), ("token", &refresh)])
        )
        .status,
        200
    );
}

#[test]
fn query_tokens_untrusted_origins_and_http_approval_cannot_dispatch() {
    let mut f = Fixture::new(true);
    let (access, _) = issue(&mut f);
    assert_eq!(
        f.handle("POST", &format!("/mcp?token={access}"), &h(), b"{}")
            .status,
        404
    );
    assert_eq!(f.handle("POST", "/approve", &h(), b"{}").status, 404);
    let mut headers = h();
    headers.insert("authorization".into(), format!("Bearer {access}"));
    headers.insert("origin".into(), "https://evil.poc.invalid".into());
    assert_eq!(f.handle("POST", "/mcp", &headers, b"{}").status, 403);
    headers.remove("origin");
    headers.insert("host".into(), "other.poc.invalid".into());
    assert_eq!(f.handle("POST", "/mcp", &headers, b"{}").status, 403);
    assert_eq!(f.dispatches, 0);
    let mut another = Fixture::new(true);
    let mut headers = h();
    headers.insert("authorization".into(), format!("Bearer {access}"));
    assert_eq!(another.handle("POST", "/mcp", &headers, b"{}").status, 401);
    assert!(!another.audit_json().contains(&access));
}

#[test]
fn authorize_refuses_plain_pkce_redirect_changes_and_write_scope() {
    let mut f = Fixture::new(true);
    for fault in ["pkce", "redirect", "resource", "scope"] {
        let p = form(&[
            ("client_id", FIXTURE_CIMD),
            (
                "resource",
                if fault == "resource" {
                    "https://other.poc.invalid/mcp"
                } else {
                    RESOURCE
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
            ("response_type", "code"),
            (
                "code_challenge_method",
                if fault == "pkce" { "plain" } else { "S256" },
            ),
            (
                "code_challenge",
                &pkce("synthetic_public_fixture_verifier_0123456789abcdef"),
            ),
            ("state", "synthetic_browser_state"),
            (
                "scope",
                if fault == "scope" {
                    "wiskit:write"
                } else {
                    READ_SCOPE
                },
            ),
        ]);
        assert_eq!(
            f.handle(
                "GET",
                &format!("/authorize?{}", String::from_utf8(p).unwrap()),
                &h(),
                b""
            )
            .status,
            400
        );
    }
    assert_eq!(f.dispatches, 0);
    assert_eq!(
        Fixture::new(true).client_document()["redirect_uris"],
        json!([CALLBACK])
    );
}
