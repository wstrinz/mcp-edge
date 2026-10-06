//! Full happy path over real HTTP: discovery → registration → passkey login →
//! consent → code → token → MCP initialize / tools → refresh → revoke → 401.
//! Also checklist item 8: captured logs contain none of the secrets involved.

mod common;

use common::*;
use serde_json::{json, Value};

struct Secrets(Vec<String>);

async fn run_full_flow(h: &mut Harness) -> Secrets {
    let mut secrets = vec![ENROLL_CODE.to_string()];

    // Unauthenticated MCP request points at the protected-resource metadata.
    let res = h.mcp("echo", None, &rpc(1, "initialize", json!({}))).await;
    assert_eq!(res.status(), 401);
    let challenge = res.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        challenge,
        format!(
            "Bearer resource_metadata=\"{ISSUER}/.well-known/oauth-protected-resource/echo/mcp\""
        )
    );

    // Discovery.
    let prm: Value = h
        .http
        .get(h.url("/.well-known/oauth-protected-resource/echo/mcp"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(prm["resource"], resource("echo"));
    assert_eq!(prm["authorization_servers"], json!([ISSUER]));
    let asm: Value = h
        .http
        .get(h.url("/.well-known/oauth-authorization-server"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(asm["issuer"], ISSUER);
    assert_eq!(asm["code_challenge_methods_supported"], json!(["S256"]));
    assert_eq!(
        asm["token_endpoint_auth_methods_supported"],
        json!(["none"])
    );
    assert_eq!(asm["registration_endpoint"], format!("{ISSUER}/register"));

    // Owner enrollment and client registration.
    h.enroll().await;
    let client = h.register_client(CALLBACK).await;

    // Browser leg with passkey proof and consent.
    let (verifier, challenge) = pkce();
    secrets.push(verifier.clone());
    let mut browser = Browser::default();
    let tx = h
        .begin(
            &mut browser,
            &client,
            CALLBACK,
            "echo",
            &challenge,
            "st-happy",
        )
        .await;
    let page = h.get(&mut browser, &format!("/consent?tx={tx}")).await;
    assert!(page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    // A form POST from a `no-referrer` page carries `Origin: null` in real
    // browsers, which the same-origin check refuses (found in the first live
    // claude.ai run). Pages must keep same-origin form posts' Origin intact.
    assert_eq!(page.headers()["referrer-policy"], "same-origin");
    let html = page.text().await.unwrap();
    assert!(html.contains("<meta name=\"referrer\" content=\"same-origin\">"));
    assert!(html.contains("Echo A"));
    assert!(
        html.contains("Synthetic &lt;Client&gt;"),
        "client name is escaped"
    );
    assert!(html.contains("30 days"));
    // Anti-phishing copy: the instruction, request age, client registration
    // time, and the client name labelled as self-reported.
    assert!(html.contains("Approve only if you just clicked Connect in Claude yourself."));
    assert!(html.contains("<dt>Requested</dt><dd>0 seconds ago</dd>"));
    assert!(html.contains("<dt>Client registered</dt>"));
    assert!(html.contains("UTC (0 seconds ago)"));
    assert!(html.contains("name self-reported by the client"));
    assert!(
        extract_csrf(&html).is_none(),
        "no consent form before passkey proof"
    );
    assert_eq!(h.owner_login(&mut browser, Some(&tx)).await, 200);
    let csrf = h
        .consent_csrf(&mut browser, &tx)
        .await
        .expect("consent form");
    secrets.push(csrf.clone());
    secrets.extend(browser.values());
    // Submit as a browser does under `Referrer-Policy: same-origin`.
    let res = h
        .post_form_origin(
            &mut browser,
            "/consent",
            &[("tx", &tx), ("csrf", &csrf), ("decision", "approve")],
            ISSUER,
        )
        .await;
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_string();
    assert!(location.starts_with(CALLBACK));
    assert_eq!(query_param(&location, "state").as_deref(), Some("st-happy"));
    assert_eq!(query_param(&location, "iss").as_deref(), Some(ISSUER));
    let code = query_param(&location, "code").unwrap();
    secrets.push(code.clone());

    // Code → tokens.
    let (status, tokens) = h
        .exchange(&client, &code, &verifier, CALLBACK, "echo")
        .await;
    assert_eq!(status, 200, "{tokens}");
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 900);
    assert_eq!(tokens["scope"], "mcp");
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    secrets.push(access.clone());
    secrets.push(refresh.clone());

    // MCP over the edge.
    let res = h
        .mcp(
            "echo",
            Some(&access),
            &rpc(
                1,
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "synthetic", "version": "0" }
                }),
            ),
        )
        .await;
    assert_eq!(res.status(), 200);
    assert!(res.headers().get("mcp-session-id").is_none());
    let init: Value = res.json().await.unwrap();
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(init["result"]["serverInfo"]["name"], "mcp-edge-echo");

    let res = h
        .mcp(
            "echo",
            Some(&access),
            &json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        )
        .await;
    assert_eq!(res.status(), 202);

    let list: Value = h
        .mcp("echo", Some(&access), &rpc(2, "tools/list", json!({})))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(list["result"]["tools"][0]["name"], "whoami");

    let call_body = rpc(
        3,
        "tools/call",
        json!({ "name": "whoami", "arguments": {} }),
    );
    let call: Value = h
        .mcp("echo", Some(&access), &call_body)
        .await
        .json()
        .await
        .unwrap();
    let claims = &call["result"]["structuredContent"];
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["aud"], "echo");
    assert_eq!(claims["sub"], h.owner_id.as_str());
    assert_eq!(claims["client_id"], client.as_str());
    assert_eq!(claims["scope"], json!(["mcp"]));
    assert_eq!(claims["resource_scope"], json!({}));
    assert_eq!(claims["gen"], 1);
    let exp = claims["exp"].as_i64().unwrap();
    let iat = claims["iat"].as_i64().unwrap();
    assert_eq!(exp - iat, 60);
    assert_eq!(
        claims["req"],
        edge_assert::request_digest("POST", "/mcp", &serde_json::to_vec(&call_body).unwrap())
    );
    let grant_id = claims["grant_id"].as_str().unwrap().to_string();
    assert!(grant_id.starts_with("g_"));
    assert_eq!(call["result"]["isError"], false);

    // The owner page lists the grant.
    let mut owner = Browser::default();
    assert_eq!(h.owner_login(&mut owner, None).await, 200);
    secrets.extend(owner.values());
    let html = h.get(&mut owner, "/owner").await.text().await.unwrap();
    assert!(html.contains(&grant_id));
    if let Some(c) = extract_csrf(&html) {
        secrets.push(c);
    }

    // Refresh rotates both tokens.
    let (status, refreshed) = h.refresh(&client, &refresh).await;
    assert_eq!(status, 200, "{refreshed}");
    let access2 = refreshed["access_token"].as_str().unwrap().to_string();
    let refresh2 = refreshed["refresh_token"].as_str().unwrap().to_string();
    assert_ne!(access2, access);
    assert_ne!(refresh2, refresh);
    secrets.push(access2.clone());
    secrets.push(refresh2.clone());
    let res = h
        .mcp("echo", Some(&access2), &rpc(4, "ping", json!({})))
        .await;
    assert_eq!(res.status(), 200);

    // Client revocation (RFC 7009) ends the grant: both access tokens die.
    let res = h
        .http
        .post(h.url("/revoke"))
        .form(&[
            ("token", refresh2.as_str()),
            ("token_type_hint", "refresh_token"),
            ("client_id", client.as_str()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    for token in [&access, &access2] {
        let res = h.mcp("echo", Some(token), &rpc(5, "ping", json!({}))).await;
        assert_eq!(res.status(), 401);
        assert!(res.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Bearer error=\"invalid_token\", resource_metadata="));
    }
    let (status, body) = h.refresh(&client, &refresh2).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (400, Some("invalid_grant"))
    );
    let html = h.get(&mut owner, "/owner").await.text().await.unwrap();
    assert!(!html.contains(&grant_id), "revoked grant no longer listed");
    Secrets(secrets)
}

#[tokio::test]
async fn happy_path_register_login_consent_token_mcp_refresh_revoke() {
    let mut h = Harness::start().await;
    run_full_flow(&mut h).await;
    h.finish().await;
}

#[tokio::test]
async fn logs_never_contain_tokens_codes_cookies_or_enrollment_code() {
    let mut h = Harness::start().await;
    let Secrets(secrets) = run_full_flow(&mut h).await;
    // Also exercise failure paths that see secrets.
    let _ = h
        .token(&[
            ("grant_type", "refresh_token"),
            ("client_id", "mcc_unknown"),
            ("refresh_token", "mer_SYNTHETIC_DO_NOT_LOG"),
        ])
        .await;
    let _ = h
        .mcp(
            "echo",
            Some("mea_SYNTHETIC_DO_NOT_LOG"),
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "SYNTHETIC_DO_NOT_LOG" }),
        )
        .await;
    let mut wrong = Browser::default();
    let _ = h
        .post_json(
            &mut wrong,
            "/owner/register/start",
            &json!({ "enroll_code": "SYNTHETIC_DO_NOT_LOG_ENROLL" }),
        )
        .await;
    let logs = h.logs();
    assert!(logs.len() > 20, "request lines are logged");
    assert!(logs.iter().any(|l| l.contains("route=/token status=200")));
    assert!(logs
        .iter()
        .any(|l| l.contains("route=/{backend}/mcp") && l.contains("grant=g_")));
    let joined = logs.join("\n");
    assert!(secrets.len() >= 10);
    for secret in secrets.iter().map(String::as_str).chain([
        "SYNTHETIC_DO_NOT_LOG",
        "st-happy",
        "Bearer",
        "cookie",
    ]) {
        assert!(secret.len() >= 6);
        assert!(
            !joined.contains(secret),
            "log leaked a secret-bearing value"
        );
    }
    h.finish().await;
}
