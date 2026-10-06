//! Client-compatibility behaviour (lenient where security allows): DCR
//! metadata substitution, scope intersection, resource normalization,
//! optional redirect_uri at /token, refresh-rotation grace.

mod common;

use common::*;
use serde_json::{json, Value};

/// Browser leg for an arbitrary authorization query; returns the code.
async fn code_for_query(h: &mut Harness, query: &str) -> String {
    let mut b = Browser::default();
    let res = h.get(&mut b, query).await;
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_string();
    let tx = location
        .strip_prefix("/consent?tx=")
        .unwrap_or_else(|| panic!("not a consent redirect: {location}"))
        .to_string();
    assert_eq!(h.owner_login(&mut b, Some(&tx)).await, 200);
    let csrf = h.consent_csrf(&mut b, &tx).await.unwrap();
    let res = h
        .post_form(
            &mut b,
            "/consent",
            &[("tx", &tx), ("csrf", &csrf), ("decision", "approve")],
        )
        .await;
    assert_eq!(res.status(), 303);
    query_param(res.headers()["location"].to_str().unwrap(), "code").unwrap()
}

#[tokio::test]
async fn dcr_substitutes_public_client_auth() {
    let h = Harness::start().await;
    let res = h
        .http
        .post(h.url("/register"))
        .json(&json!({
            "redirect_uris": [CALLBACK],
            "token_endpoint_auth_method": "client_secret_basic"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201);
    let body: Value = res.json().await.unwrap();
    assert_eq!(body["token_endpoint_auth_method"], "none");
    h.finish().await;
}

#[tokio::test]
async fn scopes_resource_and_redirect_are_matched_leniently() {
    let mut h = Harness::start().await;
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;

    // Unknown scopes are dropped; the known one is granted. The resource uses
    // an uppercase host, the default port and a trailing slash.
    let (verifier, challenge) = pkce();
    let query = Harness::authorize_query(&client, CALLBACK, "echo", &challenge, "s1").replace(
        &url_encode(&resource("echo")),
        &url_encode("HTTPS://EDGE.TEST:443/echo/mcp/"),
    ) + "&scope=offline_access+mcp+admin";
    let code = code_for_query(&mut h, &query).await;
    // No redirect_uri at /token; resource with a trailing slash.
    let (status, tokens) = h
        .token(&[
            ("grant_type", "authorization_code"),
            ("client_id", &client),
            ("code", &code),
            ("code_verifier", &verifier),
            ("resource", "https://edge.test/echo/mcp/"),
        ])
        .await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["scope"], "mcp");

    // Only unknown scopes → the backend's defaults.
    let (verifier, challenge) = pkce();
    let query =
        Harness::authorize_query(&client, CALLBACK, "echo", &challenge, "s2") + "&scope=admin";
    let code = code_for_query(&mut h, &query).await;
    let (status, tokens) = h
        .exchange(&client, &code, &verifier, CALLBACK, "echo")
        .await;
    assert_eq!((status, tokens["scope"].as_str()), (200, Some("mcp")));

    // A present but different redirect_uri is still refused.
    let (verifier, challenge) = pkce();
    let (code, _) = h
        .authorize_code(&client, CALLBACK, "echo", &challenge)
        .await;
    let (status, body) = h
        .exchange(&client, &code, &verifier, "https://claude.ai/other", "echo")
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    h.finish().await;
}

fn url_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
