//! Signed, request-bound assertions that `mcp-edge` attaches to every request it
//! forwards to a backend (`Edge-Assertion` header).
//!
//! The format is deliberately small so that backends in any language can verify
//! it with one Ed25519 check. See the crate README for the wire format and a test
//! vector.
//!
//! * The edge mints with [`Signer::mint`].
//! * A backend verifies with [`Verifier::verify`], which checks the signature,
//!   issuer, audience, lifetime (with skew), the request digest and, when a
//!   [`ReplayCache`] is enabled, that the `jti` has not been seen before.
#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt, sync::Mutex};

/// HTTP header carrying the assertion.
pub const HEADER: &str = "Edge-Assertion";
/// Domain-separation prefix: the signature covers `SIGNING_PREFIX || <claims segment ASCII>`.
pub const SIGNING_PREFIX: &[u8] = b"edge-assert.v1.";
/// Upper bound on `exp - iat`.
pub const MAX_LIFETIME_SECS: i64 = 60;
/// Default tolerated clock skew for `iat`/`exp` checks.
pub const DEFAULT_SKEW_SECS: i64 = 5;
/// Assertions longer than this are rejected before any decoding.
pub const MAX_ASSERTION_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 256;
const MAX_JTI_BYTES: usize = 64;
const MAX_SCOPES: usize = 32;

/// The signed claims. Field order here is irrelevant: the encoded form is
/// canonical JSON (sorted keys, no whitespace).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    /// Edge issuer (the OAuth issuer URL).
    pub iss: String,
    /// Backend id this assertion is for.
    pub aud: String,
    /// Owner id.
    pub sub: String,
    /// OAuth client that holds the grant.
    pub client_id: String,
    /// Independent, non-secret grant id.
    pub grant_id: String,
    /// Granted scopes.
    pub scope: Vec<String>,
    /// Opaque JSON the backend approved (empty object for edge-consent backends).
    pub resource_scope: Value,
    /// Revocation generation of the grant.
    pub gen: u64,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Expiry, Unix seconds; `exp - iat <= 60`.
    pub exp: i64,
    /// Unique assertion id (replay detection).
    pub jti: String,
    /// `base64url(SHA-256(method "\n" path "\n" body))`, see [`request_digest`].
    pub req: String,
}

/// Grant-derived claims supplied by the edge when minting.
#[derive(Clone, Debug)]
pub struct GrantContext {
    pub aud: String,
    pub sub: String,
    pub client_id: String,
    pub grant_id: String,
    pub scope: Vec<String>,
    pub resource_scope: Value,
    pub gen: u64,
}

/// The request an assertion is bound to, exactly as the backend receives it.
/// `path` is the path only (no query string), e.g. `/mcp`.
#[derive(Clone, Copy, Debug)]
pub struct RequestBinding<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub body: &'a [u8],
}

impl RequestBinding<'_> {
    pub fn digest(&self) -> String {
        request_digest(self.method, self.path, self.body)
    }
}

/// `base64url_nopad(SHA-256(method || "\n" || path || "\n" || body))`.
pub fn request_digest(method: &str, path: &str, body: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(method.as_bytes());
    h.update(b"\n");
    h.update(path.as_bytes());
    h.update(b"\n");
    h.update(body);
    URL_SAFE_NO_PAD.encode(h.finalize())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// A claim is empty, too long or otherwise not encodable.
    InvalidClaims(&'static str),
    /// The OS random source failed.
    Random,
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MintError::InvalidClaims(why) => write!(f, "invalid assertion claims: {why}"),
            MintError::Random => f.write_str("random source unavailable"),
        }
    }
}
impl std::error::Error for MintError {}

/// Why an assertion was rejected. Messages never contain assertion content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    InvalidLifetime,
    NotYetValid,
    Expired,
    RequestMismatch,
    Replayed,
    ReplayCacheFull,
}

impl VerifyError {
    pub fn code(&self) -> &'static str {
        match self {
            VerifyError::Malformed => "malformed",
            VerifyError::BadSignature => "bad_signature",
            VerifyError::WrongIssuer => "wrong_issuer",
            VerifyError::WrongAudience => "wrong_audience",
            VerifyError::InvalidLifetime => "invalid_lifetime",
            VerifyError::NotYetValid => "not_yet_valid",
            VerifyError::Expired => "expired",
            VerifyError::RequestMismatch => "request_mismatch",
            VerifyError::Replayed => "replayed",
            VerifyError::ReplayCacheFull => "replay_cache_full",
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "edge assertion rejected: {}", self.code())
    }
}
impl std::error::Error for VerifyError {}

/// Canonical JSON: object keys sorted by UTF-8 bytes, no insignificant
/// whitespace, integers only (no floats), strings escaped as by serde_json.
pub fn canonical_json(value: &Value) -> Result<String, MintError> {
    let mut out = String::new();
    write_canonical(value, &mut out, 0)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String, depth: usize) -> Result<(), MintError> {
    if depth > 16 {
        return Err(MintError::InvalidClaims("nesting too deep"));
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() {
                out.push_str(&n.to_string());
            } else {
                return Err(MintError::InvalidClaims("non-integer number"));
            }
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).map_err(|_| MintError::InvalidClaims("string"))?)
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(
                    &serde_json::to_string(key).map_err(|_| MintError::InvalidClaims("key"))?,
                );
                out.push(':');
                write_canonical(&map[key], out, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn encode_claims(claims: &Claims) -> Result<String, MintError> {
    let value = serde_json::to_value(claims).map_err(|_| MintError::InvalidClaims("encode"))?;
    canonical_json(&value)
}

fn check_id(value: &str, what: &'static str, max: usize) -> Result<(), MintError> {
    if value.is_empty() || value.len() > max {
        Err(MintError::InvalidClaims(what))
    } else {
        Ok(())
    }
}

fn check_claims(claims: &Claims) -> Result<(), MintError> {
    check_id(&claims.iss, "iss", MAX_ID_BYTES * 2)?;
    check_id(&claims.aud, "aud", MAX_ID_BYTES)?;
    check_id(&claims.sub, "sub", MAX_ID_BYTES)?;
    check_id(&claims.client_id, "client_id", MAX_ID_BYTES)?;
    check_id(&claims.grant_id, "grant_id", MAX_ID_BYTES)?;
    check_id(&claims.jti, "jti", MAX_JTI_BYTES)?;
    if claims.scope.len() > MAX_SCOPES || claims.scope.iter().any(|s| s.is_empty()) {
        return Err(MintError::InvalidClaims("scope"));
    }
    let lifetime = claims.exp - claims.iat;
    if !(1..=MAX_LIFETIME_SECS).contains(&lifetime) {
        return Err(MintError::InvalidClaims("lifetime"));
    }
    Ok(())
}

fn random_jti() -> Result<String, MintError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| MintError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn sign_encoded(key: &SigningKey, payload_b64: &str) -> String {
    let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + payload_b64.len());
    message.extend_from_slice(SIGNING_PREFIX);
    message.extend_from_slice(payload_b64.as_bytes());
    let sig = key.sign(&message);
    format!("{payload_b64}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Edge-side minting key.
pub struct Signer {
    key: SigningKey,
    issuer: String,
}

impl Signer {
    /// Build from a 32-byte Ed25519 seed (the private key).
    pub fn from_seed(seed: &[u8; 32], issuer: impl Into<String>) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
            issuer: issuer.into(),
        }
    }

    /// Generate a fresh random 32-byte seed from the OS.
    pub fn generate_seed() -> Result<[u8; 32], MintError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| MintError::Random)?;
        Ok(seed)
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The raw 32-byte public key, base64url without padding.
    pub fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_bytes())
    }

    /// Mint an assertion valid for `ttl_secs` (1..=60) from `now`.
    pub fn mint(
        &self,
        grant: &GrantContext,
        req: RequestBinding<'_>,
        now: i64,
        ttl_secs: i64,
    ) -> Result<String, MintError> {
        let claims = Claims {
            iss: self.issuer.clone(),
            aud: grant.aud.clone(),
            sub: grant.sub.clone(),
            client_id: grant.client_id.clone(),
            grant_id: grant.grant_id.clone(),
            scope: grant.scope.clone(),
            resource_scope: grant.resource_scope.clone(),
            gen: grant.gen,
            iat: now,
            exp: now.saturating_add(ttl_secs),
            jti: random_jti()?,
            req: req.digest(),
        };
        self.sign_claims(&claims)
    }

    /// Sign fully specified claims (used for test vectors). The issuer must be
    /// this signer's issuer and the claims must be structurally valid.
    pub fn sign_claims(&self, claims: &Claims) -> Result<String, MintError> {
        if claims.iss != self.issuer {
            return Err(MintError::InvalidClaims("iss"));
        }
        check_claims(claims)?;
        let encoded = encode_claims(claims)?;
        Ok(sign_encoded(&self.key, &URL_SAFE_NO_PAD.encode(encoded)))
    }
}

/// Bounded memory of seen `jti` values, kept until the assertion can no longer
/// verify. When full of live entries it fails closed.
pub struct ReplayCache {
    seen: Mutex<HashMap<String, i64>>,
    capacity: usize,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            capacity: capacity.max(1),
        }
    }

    /// Record `jti` until `retain_until`; error if it was already recorded.
    pub fn check_and_insert(
        &self,
        jti: &str,
        retain_until: i64,
        now: i64,
    ) -> Result<(), VerifyError> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.contains_key(jti) {
            return Err(VerifyError::Replayed);
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, until| *until >= now);
            if seen.len() >= self.capacity {
                return Err(VerifyError::ReplayCacheFull);
            }
        }
        seen.insert(jti.to_owned(), retain_until);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Backend-side verifier for one audience.
pub struct Verifier {
    key: VerifyingKey,
    issuer: String,
    audience: String,
    skew: i64,
    replay: Option<ReplayCache>,
}

impl Verifier {
    pub fn new(key: VerifyingKey, issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            key,
            issuer: issuer.into(),
            audience: audience.into(),
            skew: DEFAULT_SKEW_SECS,
            replay: None,
        }
    }

    /// Build from the edge's base64url (no padding) 32-byte public key.
    pub fn from_public_key_base64url(
        public_key: &str,
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, VerifyError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(public_key)
            .map_err(|_| VerifyError::Malformed)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| VerifyError::Malformed)?;
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| VerifyError::Malformed)?;
        Ok(Self::new(key, issuer, audience))
    }

    /// Tolerated clock skew in seconds (default 5, clamped to 0..=30).
    pub fn with_skew(mut self, secs: i64) -> Self {
        self.skew = secs.clamp(0, 30);
        self
    }

    /// Enable `jti` replay detection with a bounded cache.
    pub fn with_replay_cache(mut self, capacity: usize) -> Self {
        self.replay = Some(ReplayCache::new(capacity));
        self
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Verify `assertion` for the request the backend actually received.
    pub fn verify(
        &self,
        assertion: &str,
        req: RequestBinding<'_>,
        now: i64,
    ) -> Result<Claims, VerifyError> {
        if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES || !assertion.is_ascii() {
            return Err(VerifyError::Malformed);
        }
        let (payload_b64, sig_b64) = assertion.split_once('.').ok_or(VerifyError::Malformed)?;
        if payload_b64.is_empty() || sig_b64.is_empty() || sig_b64.contains('.') {
            return Err(VerifyError::Malformed);
        }
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|_| VerifyError::Malformed)?;
        let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| VerifyError::Malformed)?;
        let signature = Signature::from_bytes(&sig_bytes);
        let mut message = Vec::with_capacity(SIGNING_PREFIX.len() + payload_b64.len());
        message.extend_from_slice(SIGNING_PREFIX);
        message.extend_from_slice(payload_b64.as_bytes());
        self.key
            .verify_strict(&message, &signature)
            .map_err(|_| VerifyError::BadSignature)?;

        let payload = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|_| VerifyError::Malformed)?;
        let claims: Claims =
            serde_json::from_slice(&payload).map_err(|_| VerifyError::Malformed)?;
        // Only the canonical encoding is accepted (no duplicate keys, no padding tricks).
        let canonical = encode_claims(&claims).map_err(|_| VerifyError::Malformed)?;
        if canonical.as_bytes() != payload.as_slice() {
            return Err(VerifyError::Malformed);
        }
        if claims.iss != self.issuer {
            return Err(VerifyError::WrongIssuer);
        }
        if claims.aud != self.audience {
            return Err(VerifyError::WrongAudience);
        }
        let lifetime = claims.exp - claims.iat;
        if !(1..=MAX_LIFETIME_SECS).contains(&lifetime) {
            return Err(VerifyError::InvalidLifetime);
        }
        if claims.iat > now + self.skew {
            return Err(VerifyError::NotYetValid);
        }
        if now >= claims.exp + self.skew {
            return Err(VerifyError::Expired);
        }
        if claims.req != req.digest() {
            return Err(VerifyError::RequestMismatch);
        }
        if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_BYTES {
            return Err(VerifyError::Malformed);
        }
        if let Some(cache) = &self.replay {
            cache.check_and_insert(&claims.jti, claims.exp + self.skew, now)?;
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ISS: &str = "https://edge.test";
    const NOW: i64 = 1_800_000_000;

    fn signer() -> Signer {
        Signer::from_seed(&[7u8; 32], ISS)
    }

    fn grant(aud: &str) -> GrantContext {
        GrantContext {
            aud: aud.into(),
            sub: "owner-1".into(),
            client_id: "client-1".into(),
            grant_id: "g_1".into(),
            scope: vec!["mcp".into()],
            resource_scope: json!({"trackers": ["t1", "t2"], "mode": "read"}),
            gen: 3,
        }
    }

    fn req(body: &[u8]) -> RequestBinding<'_> {
        RequestBinding {
            method: "POST",
            path: "/mcp",
            body,
        }
    }

    fn verifier(aud: &str) -> Verifier {
        Verifier::new(signer().verifying_key(), ISS, aud).with_replay_cache(64)
    }

    #[test]
    fn round_trip_returns_claims() {
        let s = signer();
        let a = s.mint(&grant("echo"), req(b"{}"), NOW, 60).unwrap();
        let claims = verifier("echo").verify(&a, req(b"{}"), NOW + 10).unwrap();
        assert_eq!(claims.aud, "echo");
        assert_eq!(claims.grant_id, "g_1");
        assert_eq!(claims.gen, 3);
        assert_eq!(claims.exp - claims.iat, 60);
        assert_eq!(claims.req, request_digest("POST", "/mcp", b"{}"));
        // From the published public key too.
        let v =
            Verifier::from_public_key_base64url(&s.public_key_base64url(), ISS, "echo").unwrap();
        v.verify(&a, req(b"{}"), NOW).unwrap();
    }

    #[test]
    fn unsigned_and_malformed_assertions_are_rejected() {
        let s = signer();
        let a = s.mint(&grant("echo"), req(b"x"), NOW, 30).unwrap();
        let (payload, _) = a.split_once('.').unwrap();
        let v = verifier("echo");
        for bad in [
            String::new(),
            payload.to_string(),
            format!("{payload}."),
            format!("{payload}.{}", URL_SAFE_NO_PAD.encode([0u8; 64])),
            format!("{a}.extra"),
            format!("{a}="),
            "not-base64!.sig".to_string(),
            "a".repeat(MAX_ASSERTION_BYTES + 1),
        ] {
            let err = v.verify(&bad, req(b"x"), NOW).unwrap_err();
            assert!(
                matches!(err, VerifyError::Malformed | VerifyError::BadSignature),
                "{err:?}"
            );
        }
    }

    #[test]
    fn wrong_key_and_tampered_payload_fail_signature() {
        let other = Signer::from_seed(&[9u8; 32], ISS);
        let a = other.mint(&grant("echo"), req(b""), NOW, 30).unwrap();
        assert_eq!(
            verifier("echo").verify(&a, req(b""), NOW),
            Err(VerifyError::BadSignature)
        );
        let a = signer().mint(&grant("echo"), req(b""), NOW, 30).unwrap();
        let (payload, sig) = a.split_once('.').unwrap();
        let mut claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        claims["aud"] = json!("other");
        let forged = format!(
            "{}.{sig}",
            URL_SAFE_NO_PAD.encode(canonical_json(&claims).unwrap())
        );
        assert_eq!(
            verifier("other").verify(&forged, req(b""), NOW),
            Err(VerifyError::BadSignature)
        );
    }

    #[test]
    fn expiry_and_future_iat_are_enforced_with_skew() {
        let s = signer();
        let a = s.mint(&grant("echo"), req(b""), NOW, 60).unwrap();
        let v = Verifier::new(s.verifying_key(), ISS, "echo");
        assert!(v.verify(&a, req(b""), NOW + 64).is_ok());
        assert_eq!(v.verify(&a, req(b""), NOW + 65), Err(VerifyError::Expired));
        assert!(v.verify(&a, req(b""), NOW - 5).is_ok());
        assert_eq!(
            v.verify(&a, req(b""), NOW - 6),
            Err(VerifyError::NotYetValid)
        );
    }

    #[test]
    fn lifetime_over_sixty_seconds_is_refused() {
        let s = signer();
        assert!(s.mint(&grant("echo"), req(b""), NOW, 61).is_err());
        assert!(s.mint(&grant("echo"), req(b""), NOW, 0).is_err());
        // A correctly signed but over-long assertion (not producible via mint).
        let claims = Claims {
            iss: ISS.into(),
            aud: "echo".into(),
            sub: "o".into(),
            client_id: "c".into(),
            grant_id: "g".into(),
            scope: vec![],
            resource_scope: json!({}),
            gen: 1,
            iat: NOW,
            exp: NOW + 3600,
            jti: "j".into(),
            req: request_digest("POST", "/mcp", b""),
        };
        let encoded = URL_SAFE_NO_PAD.encode(encode_claims(&claims).unwrap());
        let a = sign_encoded(&SigningKey::from_bytes(&[7u8; 32]), &encoded);
        assert_eq!(
            verifier("echo").verify(&a, req(b""), NOW),
            Err(VerifyError::InvalidLifetime)
        );
    }

    #[test]
    fn replay_is_detected() {
        let a = signer().mint(&grant("echo"), req(b"b"), NOW, 60).unwrap();
        let v = verifier("echo");
        v.verify(&a, req(b"b"), NOW).unwrap();
        assert_eq!(v.verify(&a, req(b"b"), NOW + 1), Err(VerifyError::Replayed));
    }

    #[test]
    fn replay_cache_fails_closed_when_full_of_live_entries() {
        let cache = ReplayCache::new(2);
        cache.check_and_insert("a", NOW + 60, NOW).unwrap();
        cache.check_and_insert("b", NOW + 60, NOW).unwrap();
        assert_eq!(
            cache.check_and_insert("c", NOW + 60, NOW),
            Err(VerifyError::ReplayCacheFull)
        );
        // Once entries expire they are purged and capacity returns.
        cache.check_and_insert("c", NOW + 200, NOW + 100).unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn wrong_audience_and_issuer_are_rejected() {
        let a = signer().mint(&grant("echo"), req(b""), NOW, 60).unwrap();
        assert_eq!(
            verifier("echo2").verify(&a, req(b""), NOW),
            Err(VerifyError::WrongAudience)
        );
        let v = Verifier::new(signer().verifying_key(), "https://other.test", "echo");
        assert_eq!(v.verify(&a, req(b""), NOW), Err(VerifyError::WrongIssuer));
    }

    #[test]
    fn request_binding_covers_method_path_and_body() {
        let a = signer()
            .mint(&grant("echo"), req(b"body"), NOW, 60)
            .unwrap();
        let v = Verifier::new(signer().verifying_key(), ISS, "echo");
        for other in [
            RequestBinding {
                method: "GET",
                path: "/mcp",
                body: b"body",
            },
            RequestBinding {
                method: "POST",
                path: "/mcp/x",
                body: b"body",
            },
            RequestBinding {
                method: "POST",
                path: "/mcp",
                body: b"body2",
            },
        ] {
            assert_eq!(v.verify(&a, other, NOW), Err(VerifyError::RequestMismatch));
        }
        assert!(v.verify(&a, req(b"body"), NOW).is_ok());
    }

    #[test]
    fn non_canonical_payload_is_rejected_even_if_signed() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let good = signer().mint(&grant("echo"), req(b""), NOW, 60).unwrap();
        let (payload, _) = good.split_once('.').unwrap();
        let json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        let spaced = json.replacen(':', ": ", 1);
        let a = sign_encoded(&key, &URL_SAFE_NO_PAD.encode(spaced));
        let v = verifier("echo");
        assert_eq!(v.verify(&a, req(b""), NOW), Err(VerifyError::Malformed));
        // Unknown claims are rejected too.
        let extra = json.replacen('{', "{\"zzz\":1,", 1);
        let a = sign_encoded(&key, &URL_SAFE_NO_PAD.encode(extra));
        assert_eq!(v.verify(&a, req(b""), NOW), Err(VerifyError::Malformed));
    }

    #[test]
    fn canonical_json_sorts_keys_and_refuses_floats() {
        let v = json!({"b": 1, "a": {"d": [true, null, "x\n"], "c": -2}});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":{"c":-2,"d":[true,null,"x\n"]},"b":1}"#
        );
        assert!(canonical_json(&json!({"f": 1.5})).is_err());
    }

    /// The README test vector. If this changes, the documented format changed.
    #[test]
    fn readme_test_vector() {
        let s = Signer::from_seed(&[1u8; 32], "https://edge.example");
        let claims = Claims {
            iss: "https://edge.example".into(),
            aud: "echo".into(),
            sub: "owner".into(),
            client_id: "client".into(),
            grant_id: "g_example".into(),
            scope: vec!["mcp".into()],
            resource_scope: json!({}),
            gen: 1,
            iat: 1_700_000_000,
            exp: 1_700_000_060,
            jti: "jti-example".into(),
            req: request_digest(
                "POST",
                "/mcp",
                br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            ),
        };
        let a = s.sign_claims(&claims).unwrap();
        assert_eq!(s.public_key_base64url(), README_PUBLIC_KEY);
        assert_eq!(claims.req, README_REQ);
        assert_eq!(a, README_ASSERTION);
        let v =
            Verifier::from_public_key_base64url(README_PUBLIC_KEY, "https://edge.example", "echo")
                .unwrap();
        v.verify(
            &a,
            RequestBinding {
                method: "POST",
                path: "/mcp",
                body: br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            },
            1_700_000_030,
        )
        .unwrap();
    }

    const README_PUBLIC_KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w";
    const README_REQ: &str = "mw6zvTQn96sHE6fLxKG0HprEzhyYC6js4quoFBDJhi8";
    const README_ASSERTION: &str = concat!(
        "eyJhdWQiOiJlY2hvIiwiY2xpZW50X2lkIjoiY2xpZW50IiwiZXhwIjoxNzAwMDAwMDYwLCJnZW4iOjEsImdy",
        "YW50X2lkIjoiZ19leGFtcGxlIiwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2VkZ2UuZXhhbXBs",
        "ZSIsImp0aSI6Imp0aS1leGFtcGxlIiwicmVxIjoibXc2enZUUW45NnNIRTZmTHhLRzBIcHJFemh5WUM2anM0",
        "cXVvRkJESmhpOCIsInJlc291cmNlX3Njb3BlIjp7fSwic2NvcGUiOlsibWNwIl0sInN1YiI6Im93bmVyIn0",
        ".",
        "_gS3X4w_uQgz_fjlBuamXMc1nNg5mdVwpP-zYgl-pQIJD73F6F3E9Ht69LEq-XuqavQbHCObRuklC1b9q3JwCg",
    );
}
