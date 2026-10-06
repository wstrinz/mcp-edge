//! Built-in diagnostic backend. It behaves like any other backend would: it
//! only trusts the `Edge-Assertion` it is handed, verifies it, and answers a
//! stateless MCP (JSON-RPC over Streamable HTTP, JSON responses) subset whose
//! one tool returns the verified claims.

use edge_assert::{Claims, RequestBinding, Verifier, VerifyError};
use serde_json::{json, Value};

/// MCP protocol revisions this backend will negotiate (newest first).
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// What a backend returns to the edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendReply {
    pub status: u16,
    /// JSON body; `None` for 202 Accepted.
    pub body: Option<Vec<u8>>,
}

impl BackendReply {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            body: Some(serde_json::to_vec(&value).unwrap_or_default()),
        }
    }
}

pub struct EchoBackend {
    verifier: Verifier,
}

impl EchoBackend {
    /// `public_key` is the edge's base64url Ed25519 key; `audience` this backend's id.
    pub fn new(public_key: &str, issuer: &str, audience: &str) -> Result<Self, VerifyError> {
        Ok(Self {
            verifier: Verifier::from_public_key_base64url(public_key, issuer, audience)?
                .with_replay_cache(10_000),
        })
    }

    pub fn handle(
        &self,
        assertion: Option<&str>,
        method: &str,
        path: &str,
        body: &[u8],
        now: i64,
    ) -> BackendReply {
        let Some(assertion) = assertion else {
            return BackendReply::json(401, json!({ "error": "missing_assertion" }));
        };
        let claims =
            match self
                .verifier
                .verify(assertion, RequestBinding { method, path, body }, now)
            {
                Ok(c) => c,
                Err(e) => {
                    return BackendReply::json(
                        401,
                        json!({ "error": "invalid_assertion", "reason": e.code() }),
                    )
                }
            };
        if method != "POST" || path != "/mcp" {
            return BackendReply::json(405, json!({ "error": "method_not_allowed" }));
        }
        rpc(&claims, body)
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn rpc(claims: &Claims, body: &[u8]) -> BackendReply {
    let Ok(msg) = serde_json::from_slice::<Value>(body) else {
        return BackendReply::json(400, rpc_error(Value::Null, -32700, "Parse error"));
    };
    let Some(obj) = msg.as_object() else {
        // Batches are not part of the supported transport revisions.
        return BackendReply::json(400, rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return BackendReply::json(400, rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let Some(id) = obj.get("id").cloned() else {
        // Notifications (including notifications/initialized) and responses.
        return BackendReply {
            status: 202,
            body: None,
        };
    };
    if !(id.is_string() || id.is_i64() || id.is_u64()) {
        return BackendReply::json(400, rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return BackendReply::json(400, rpc_error(id, -32600, "Invalid Request"));
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str);
            let version = requested
                .filter(|v| SUPPORTED_PROTOCOL_VERSIONS.contains(v))
                .unwrap_or(DEFAULT_PROTOCOL_VERSION);
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "mcp-edge-echo", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Diagnostic backend: the whoami tool returns the verified edge assertion claims."
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({
            "tools": [{
                "name": "whoami",
                "title": "Who am I",
                "description": "Return the edge assertion claims this request was authorized with.",
                "inputSchema": { "type": "object", "properties": {}, "additionalProperties": false },
                "annotations": { "readOnlyHint": true, "openWorldHint": false }
            }]
        }),
        "tools/call" => {
            if params.get("name").and_then(Value::as_str) != Some("whoami") {
                return BackendReply::json(200, rpc_error(id, -32602, "Unknown tool"));
            }
            let structured = serde_json::to_value(claims).unwrap_or(Value::Null);
            json!({
                "content": [{ "type": "text", "text": structured.to_string() }],
                "structuredContent": structured,
                "isError": false
            })
        }
        _ => return BackendReply::json(200, rpc_error(id, -32601, "Method not found")),
    };
    BackendReply::json(200, json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}
