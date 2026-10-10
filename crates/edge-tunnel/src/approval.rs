//! Signed consent approvals (PHASE4.md §3.5, decision D2).
//!
//! ```text
//! approval  = <b64url-nopad(canonical JSON claims)>.<b64url-nopad(Ed25519 signature)>
//! signature = Ed25519(origin iroh transport key, "mcp-edge-approval.v1." || payload segment)
//! ```
//!
//! The origin signs with the secret key behind its iroh EndpointId (the key the
//! edge already pins), under a domain-separation prefix so the signature can
//! never be confused with any other use of that key (iroh's TLS handshake
//! signatures, `edge-assert`'s `edge-assert.v1.` prefix). The edge verifies
//! with the configured origin EndpointId; canonical JSON and unknown-claim
//! rejection mirror `edge-assert`.

use crate::{
    ids,
    meta::{valid_grant_id, MAX_GRANT_LIFETIME_SECS, MIN_GRANT_LIFETIME_SECS},
    timing,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Domain-separation prefix.
pub const SIGNING_PREFIX: &[u8] = b"mcp-edge-approval.v1.";
/// Upper bound on `exp - iat`.
pub const MAX_TTL_SECS: i64 = 120;
/// Upper bound on the compact string.
pub const MAX_APPROVAL_BYTES: usize = crate::limits::APPROVAL;
/// Maximum trackers in one approval.
pub const MAX_TRACKERS: usize = 32;
/// Maximum decks (groups of trackers) in one approval.
pub const MAX_DECKS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Deny,
}

/// What the owner allowed. `read` is the original (v1) access; `read_write`
/// lets the app's agent tools change data too, inside the same scope. The edge
/// treats both alike (it only carries the scope); the origin app enforces them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    ReadWrite,
}

/// What the owner approved: `{"v":1,"access":"read","trackers":[...]}`, plus
/// optionally `"decks":[...]` (groups of trackers, resolved by the app at each
/// call). `trackers` and `decks` are the app's resource ids (Wiskit ids); each
/// list sorted, unique, `^[A-Za-z0-9_-]{1,64}$`, at most 32; together at least one
/// id. A scope without decks serializes exactly as it always has.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScope {
    pub v: u8,
    pub access: Access,
    #[serde(default)]
    pub trackers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decks: Vec<String>,
}

impl ResourceScope {
    /// Build a read scope over trackers; sorts and deduplicates.
    pub fn read(trackers: impl IntoIterator<Item = String>) -> Result<Self, ApprovalError> {
        Self::new(Access::Read, trackers, Vec::new())
    }

    /// Build a scope over trackers and/or decks; sorts and deduplicates both.
    pub fn new(
        access: Access,
        trackers: impl IntoIterator<Item = String>,
        decks: impl IntoIterator<Item = String>,
    ) -> Result<Self, ApprovalError> {
        let mut trackers: Vec<String> = trackers.into_iter().collect();
        trackers.sort();
        trackers.dedup();
        let mut decks: Vec<String> = decks.into_iter().collect();
        decks.sort();
        decks.dedup();
        let s = Self {
            v: 1,
            access,
            trackers,
            decks,
        };
        s.validate()?;
        Ok(s)
    }

    pub fn validate(&self) -> Result<(), ApprovalError> {
        fn ok_ids(list: &[String], max: usize) -> bool {
            list.len() <= max
                && list.windows(2).all(|w| w[0] < w[1])
                && list.iter().all(|t| ids::is_token(t, 1, 64))
        }
        if self.v != 1
            || (self.trackers.is_empty() && self.decks.is_empty())
            || !ok_ids(&self.trackers, MAX_TRACKERS)
            || !ok_ids(&self.decks, MAX_DECKS)
        {
            return Err(ApprovalError::InvalidScope);
        }
        let json = serde_json::to_string(self).map_err(|_| ApprovalError::InvalidScope)?;
        if json.len() > 3 * 1024 {
            return Err(ApprovalError::InvalidScope);
        }
        Ok(())
    }

    /// The JSON value carried in `Edge-Assertion.resource_scope`.
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("scope serializes")
    }
}

/// Approval claims. `resource_scope` and `lifetime_secs` are present iff
/// `decision == approve`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalClaims {
    pub v: u8,
    pub decision: Decision,
    /// Origin EndpointId (64 hex); equals the signing key.
    pub iss: String,
    /// Edge EndpointId (64 hex).
    pub edge_id: String,
    /// Edge issuer URL.
    pub aud: String,
    /// Route / backend id.
    pub backend: String,
    pub tx: String,
    pub grant_id: String,
    pub nonce: String,
    pub client_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_scope: Option<ResourceScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifetime_secs: Option<u64>,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalError {
    /// Encoding, length, base64, JSON, canonical form, unknown claims.
    Malformed,
    BadSignature,
    /// A bound value differs from what the edge sent / expects (names the claim).
    Mismatch(&'static str),
    /// `resource_scope` invalid, or present/absent for the wrong decision.
    InvalidScope,
    /// `lifetime_secs` outside `300..=route max`, or present on a deny.
    InvalidLifetime,
    /// `exp - iat` outside `1..=120`.
    InvalidTtl,
    NotYetValid,
    Expired,
}

impl ApprovalError {
    pub fn code(self) -> &'static str {
        match self {
            ApprovalError::Malformed => "malformed",
            ApprovalError::BadSignature => "bad_signature",
            ApprovalError::Mismatch(_) => "mismatch",
            ApprovalError::InvalidScope => "invalid_scope",
            ApprovalError::InvalidLifetime => "invalid_lifetime",
            ApprovalError::InvalidTtl => "invalid_ttl",
            ApprovalError::NotYetValid => "not_yet_valid",
            ApprovalError::Expired => "expired",
        }
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalError::Mismatch(claim) => write!(f, "approval rejected: {claim} mismatch"),
            other => write!(f, "approval rejected: {}", other.code()),
        }
    }
}
impl std::error::Error for ApprovalError {}

/// Everything the approval is bound to: the values the edge sent in
/// `consent_request` and its own identity. Used by both sides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalBinding {
    pub origin_id: EndpointId,
    pub edge_id: EndpointId,
    /// Edge issuer URL (approval `aud`).
    pub issuer: String,
    /// Route id (approval `backend`).
    pub backend: String,
    pub tx: String,
    pub grant_id: String,
    pub nonce: String,
    pub client_id: String,
    /// Route `grant_lifetime_secs` (the `max_lifetime_secs` sent).
    pub max_lifetime_secs: u64,
}

fn structural_check(c: &ApprovalClaims, max_lifetime: u64) -> Result<(), ApprovalError> {
    if c.v != 1 {
        return Err(ApprovalError::Malformed);
    }
    match c.decision {
        Decision::Approve => {
            let scope = c
                .resource_scope
                .as_ref()
                .ok_or(ApprovalError::InvalidScope)?;
            scope.validate()?;
            let l = c.lifetime_secs.ok_or(ApprovalError::InvalidLifetime)?;
            if !(MIN_GRANT_LIFETIME_SECS..=max_lifetime.min(MAX_GRANT_LIFETIME_SECS)).contains(&l) {
                return Err(ApprovalError::InvalidLifetime);
            }
        }
        Decision::Deny => {
            if c.resource_scope.is_some() {
                return Err(ApprovalError::InvalidScope);
            }
            if c.lifetime_secs.is_some() {
                return Err(ApprovalError::InvalidLifetime);
            }
        }
    }
    let ttl = c.exp - c.iat;
    if !(1..=MAX_TTL_SECS).contains(&ttl) {
        return Err(ApprovalError::InvalidTtl);
    }
    if !valid_grant_id(&c.grant_id) {
        return Err(ApprovalError::Mismatch("grant_id"));
    }
    Ok(())
}

fn bound_check(c: &ApprovalClaims, b: &ApprovalBinding) -> Result<(), ApprovalError> {
    let checks: [(&str, bool); 9] = [
        ("iss", c.iss == ids::endpoint_id_hex(&b.origin_id)),
        ("edge_id", c.edge_id == ids::endpoint_id_hex(&b.edge_id)),
        ("aud", c.aud == b.issuer),
        ("backend", c.backend == b.backend),
        ("tx", c.tx == b.tx),
        ("grant_id", c.grant_id == b.grant_id),
        ("nonce", c.nonce == b.nonce),
        ("client_id", c.client_id == b.client_id),
        ("v", c.v == 1),
    ];
    for (claim, ok) in checks {
        if !ok {
            return Err(ApprovalError::Mismatch(claim));
        }
    }
    Ok(())
}

fn encode_claims(c: &ApprovalClaims) -> Result<String, ApprovalError> {
    let value = serde_json::to_value(c).map_err(|_| ApprovalError::Malformed)?;
    edge_assert::canonical_json(&value).map_err(|_| ApprovalError::Malformed)
}

fn signing_message(payload_b64: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIGNING_PREFIX.len() + payload_b64.len());
    m.extend_from_slice(SIGNING_PREFIX);
    m.extend_from_slice(payload_b64.as_bytes());
    m
}

/// Sign fully specified claims with the origin's transport key. Refuses claims
/// whose `iss` is not this key, or that would not verify structurally.
pub fn sign_claims(key: &SecretKey, claims: &ApprovalClaims) -> Result<String, ApprovalError> {
    if claims.iss != ids::endpoint_id_hex(&key.public()) {
        return Err(ApprovalError::Mismatch("iss"));
    }
    structural_check(claims, MAX_GRANT_LIFETIME_SECS)?;
    let payload = URL_SAFE_NO_PAD.encode(encode_claims(claims)?);
    let sig = key.sign(&signing_message(&payload));
    let out = format!("{payload}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
    if out.len() > MAX_APPROVAL_BYTES {
        return Err(ApprovalError::Malformed);
    }
    Ok(out)
}

/// Origin helper: build and sign an approve/deny for a consent request.
/// `scope`/`lifetime_secs` must be `Some` for approve and `None` for deny.
/// The approval is valid for `ttl_secs` (1..=120) from `now`.
pub fn sign(
    key: &SecretKey,
    binding: &ApprovalBinding,
    decision: Decision,
    scope: Option<ResourceScope>,
    lifetime_secs: Option<u64>,
    now: i64,
    ttl_secs: i64,
) -> Result<String, ApprovalError> {
    if key.public() != binding.origin_id {
        return Err(ApprovalError::Mismatch("iss"));
    }
    let claims = ApprovalClaims {
        v: 1,
        decision,
        iss: ids::endpoint_id_hex(&binding.origin_id),
        edge_id: ids::endpoint_id_hex(&binding.edge_id),
        aud: binding.issuer.clone(),
        backend: binding.backend.clone(),
        tx: binding.tx.clone(),
        grant_id: binding.grant_id.clone(),
        nonce: binding.nonce.clone(),
        client_id: binding.client_id.clone(),
        resource_scope: scope,
        lifetime_secs,
        iat: now,
        exp: now.saturating_add(ttl_secs),
    };
    structural_check(&claims, binding.max_lifetime_secs)?;
    sign_claims(key, &claims)
}

/// Edge helper: verify an approval received for `binding` at `now`. Checks,
/// in order: size/encoding, signature (strict Ed25519, by the configured
/// origin EndpointId), canonical form and unknown claims, every bound value,
/// scope and lifetime rules, `exp - iat <= 120` and the 5 s-skewed time window.
pub fn verify(
    approval: &str,
    binding: &ApprovalBinding,
    now: i64,
) -> Result<ApprovalClaims, ApprovalError> {
    if approval.is_empty() || approval.len() > MAX_APPROVAL_BYTES || !approval.is_ascii() {
        return Err(ApprovalError::Malformed);
    }
    let (payload_b64, sig_b64) = approval.split_once('.').ok_or(ApprovalError::Malformed)?;
    if payload_b64.is_empty() || sig_b64.contains('.') {
        return Err(ApprovalError::Malformed);
    }
    let sig = ids::b64url_fixed::<64>(sig_b64).ok_or(ApprovalError::Malformed)?;
    binding
        .origin_id
        .verify(&signing_message(payload_b64), &Signature::from_bytes(&sig))
        .map_err(|_| ApprovalError::BadSignature)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| ApprovalError::Malformed)?;
    let claims: ApprovalClaims =
        serde_json::from_slice(&payload).map_err(|_| ApprovalError::Malformed)?;
    if encode_claims(&claims)?.as_bytes() != payload.as_slice() {
        return Err(ApprovalError::Malformed);
    }
    bound_check(&claims, binding)?;
    structural_check(&claims, binding.max_lifetime_secs)?;
    if claims.iat > now + timing::SKEW_SECS {
        return Err(ApprovalError::NotYetValid);
    }
    if now >= claims.exp + timing::SKEW_SECS {
        return Err(ApprovalError::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Mutation<T> = (&'static str, Box<dyn Fn(&mut T)>);

    const NOW: i64 = 1_800_000_000;

    fn origin_key() -> SecretKey {
        SecretKey::from_bytes(&[2u8; 32])
    }

    fn binding() -> ApprovalBinding {
        ApprovalBinding {
            origin_id: origin_key().public(),
            edge_id: SecretKey::from_bytes(&[4u8; 32]).public(),
            issuer: "https://edge.example".into(),
            backend: "wiskit".into(),
            tx: "tx_1".into(),
            grant_id: "g_example".into(),
            nonce: URL_SAFE_NO_PAD.encode([9u8; 32]),
            client_id: "client".into(),
            max_lifetime_secs: 86_400,
        }
    }

    fn scope() -> ResourceScope {
        ResourceScope::read(["t2".to_string(), "t1".to_string()]).unwrap()
    }

    fn approve(now: i64) -> String {
        sign(
            &origin_key(),
            &binding(),
            Decision::Approve,
            Some(scope()),
            Some(3600),
            now,
            60,
        )
        .unwrap()
    }

    #[test]
    fn round_trip_approve_and_deny() {
        let a = approve(NOW);
        let c = verify(&a, &binding(), NOW + 1).unwrap();
        assert_eq!(c.decision, Decision::Approve);
        assert_eq!(c.resource_scope.unwrap().trackers, vec!["t1", "t2"]);
        assert_eq!(c.lifetime_secs, Some(3600));
        let d = sign(
            &origin_key(),
            &binding(),
            Decision::Deny,
            None,
            None,
            NOW,
            60,
        )
        .unwrap();
        assert_eq!(
            verify(&d, &binding(), NOW).unwrap().decision,
            Decision::Deny
        );
    }

    #[test]
    fn wrong_key_and_tamper_fail_signature() {
        let other = SecretKey::from_bytes(&[5u8; 32]);
        // Signed by a different key that claims to be the origin.
        let mut b = binding();
        b.origin_id = other.public();
        let forged = sign(
            &other,
            &b,
            Decision::Approve,
            Some(scope()),
            Some(3600),
            NOW,
            60,
        )
        .unwrap();
        assert_eq!(
            verify(&forged, &binding(), NOW),
            Err(ApprovalError::BadSignature)
        );
        // Tampered payload: widen the scope, keep the signature.
        let a = approve(NOW);
        let (payload, sig) = a.split_once('.').unwrap();
        let mut v: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        v["resource_scope"]["trackers"] = serde_json::json!(["t1", "t2", "t3"]);
        let tampered = format!(
            "{}.{sig}",
            URL_SAFE_NO_PAD.encode(edge_assert::canonical_json(&v).unwrap())
        );
        assert_eq!(
            verify(&tampered, &binding(), NOW),
            Err(ApprovalError::BadSignature)
        );
        // Flip a decision deny→approve with the signature of the deny.
        let d = sign(
            &origin_key(),
            &binding(),
            Decision::Deny,
            None,
            None,
            NOW,
            60,
        )
        .unwrap();
        let (_, dsig) = d.split_once('.').unwrap();
        let swapped = format!("{payload}.{dsig}");
        assert_eq!(
            verify(&swapped, &binding(), NOW),
            Err(ApprovalError::BadSignature)
        );
    }

    #[test]
    fn domain_separation() {
        let key = origin_key();
        let a = approve(NOW);
        let (payload, _) = a.split_once('.').unwrap();
        // The same payload signed under another prefix (or none) never verifies.
        for prefix in [&b"edge-assert.v1."[..], b"", b"mcp-edge-approval.v2."] {
            let mut m = prefix.to_vec();
            m.extend_from_slice(payload.as_bytes());
            let sig = key.sign(&m);
            let s = format!("{payload}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
            assert_eq!(
                verify(&s, &binding(), NOW),
                Err(ApprovalError::BadSignature)
            );
        }
        // And an approval signature is not an edge-assert signature: a verifier
        // for the same key with edge-assert's prefix rejects it.
        let (p, s) = a.split_once('.').unwrap();
        let sig = Signature::from_bytes(&ids::b64url_fixed::<64>(s).unwrap());
        let mut m = b"edge-assert.v1.".to_vec();
        m.extend_from_slice(p.as_bytes());
        assert!(key.public().verify(&m, &sig).is_err());
    }

    #[test]
    fn each_bound_claim_must_match() {
        let a = approve(NOW);
        let cases: Vec<Mutation<ApprovalBinding>> = vec![
            (
                "edge_id",
                Box::new(|b| b.edge_id = SecretKey::from_bytes(&[6u8; 32]).public()),
            ),
            (
                "aud",
                Box::new(|b| b.issuer = "https://other.example".into()),
            ),
            ("backend", Box::new(|b| b.backend = "other".into())),
            ("tx", Box::new(|b| b.tx = "tx_2".into())),
            ("grant_id", Box::new(|b| b.grant_id = "g_other".into())),
            (
                "nonce",
                Box::new(|b| b.nonce = URL_SAFE_NO_PAD.encode([8u8; 32])),
            ),
            ("client_id", Box::new(|b| b.client_id = "client2".into())),
        ];
        for (claim, mutate) in cases {
            let mut b = binding();
            mutate(&mut b);
            assert_eq!(
                verify(&a, &b, NOW),
                Err(ApprovalError::Mismatch(claim)),
                "{claim}"
            );
        }
    }

    #[test]
    fn a_read_scope_without_decks_serializes_as_before() {
        let s =
            ResourceScope::read(["t2".to_string(), "t1".to_string(), "t1".to_string()]).unwrap();
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"v":1,"access":"read","trackers":["t1","t2"]}"#
        );
        let parsed: ResourceScope =
            serde_json::from_str(r#"{"v":1,"access":"read","trackers":["t1"]}"#).unwrap();
        assert_eq!(parsed.decks, Vec::<String>::new());
    }

    #[test]
    fn a_read_write_deck_scope_round_trips_through_an_approval() {
        let scope = ResourceScope::new(
            Access::ReadWrite,
            Vec::<String>::new(),
            ["deck_b".to_string(), "deck_a".to_string()],
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&scope).unwrap(),
            r#"{"v":1,"access":"read_write","trackers":[],"decks":["deck_a","deck_b"]}"#
        );
        let a = sign(
            &origin_key(),
            &binding(),
            Decision::Approve,
            Some(scope.clone()),
            Some(3600),
            NOW,
            60,
        )
        .unwrap();
        let claims = verify(&a, &binding(), NOW).unwrap();
        assert_eq!(claims.resource_scope, Some(scope));
    }

    #[test]
    fn scope_shapes_that_are_refused() {
        let id = |n: usize| (0..n).map(|i| format!("d{i:02}")).collect::<Vec<_>>();
        assert_eq!(
            ResourceScope::new(
                Access::ReadWrite,
                Vec::<String>::new(),
                Vec::<String>::new()
            ),
            Err(ApprovalError::InvalidScope)
        );
        assert_eq!(
            ResourceScope::new(Access::Read, Vec::<String>::new(), id(MAX_DECKS + 1)),
            Err(ApprovalError::InvalidScope)
        );
        assert_eq!(
            ResourceScope::new(Access::Read, Vec::<String>::new(), ["bad id".to_string()]),
            Err(ApprovalError::InvalidScope)
        );
        let unsorted = ResourceScope {
            v: 1,
            access: Access::Read,
            trackers: vec![],
            decks: vec!["b".into(), "a".into()],
        };
        assert_eq!(unsorted.validate(), Err(ApprovalError::InvalidScope));
        assert!(serde_json::from_str::<ResourceScope>(
            r#"{"v":1,"access":"write","trackers":["t"]}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ResourceScope>(
            r#"{"v":1,"access":"read","trackers":["t"],"extra":1}"#
        )
        .is_err());
    }

    #[test]
    fn lifetime_scope_and_time_rules() {
        // Lifetime above the route max is refused at signing and at verify.
        let mut b = binding();
        b.max_lifetime_secs = 3599;
        assert_eq!(
            verify(&approve(NOW), &b, NOW),
            Err(ApprovalError::InvalidLifetime)
        );
        assert_eq!(
            sign(
                &origin_key(),
                &b,
                Decision::Approve,
                Some(scope()),
                Some(3600),
                NOW,
                60
            ),
            Err(ApprovalError::InvalidLifetime)
        );
        assert_eq!(
            sign(
                &origin_key(),
                &binding(),
                Decision::Approve,
                Some(scope()),
                Some(299),
                NOW,
                60
            ),
            Err(ApprovalError::InvalidLifetime)
        );
        assert_eq!(
            sign(
                &origin_key(),
                &binding(),
                Decision::Approve,
                None,
                Some(3600),
                NOW,
                60
            ),
            Err(ApprovalError::InvalidScope)
        );
        assert_eq!(
            sign(
                &origin_key(),
                &binding(),
                Decision::Deny,
                Some(scope()),
                None,
                NOW,
                60
            ),
            Err(ApprovalError::InvalidScope)
        );
        assert_eq!(
            sign(
                &origin_key(),
                &binding(),
                Decision::Approve,
                Some(scope()),
                Some(3600),
                NOW,
                121
            ),
            Err(ApprovalError::InvalidTtl)
        );
        assert!(ResourceScope::read(Vec::<String>::new()).is_err());
        assert!(ResourceScope::read((0..33).map(|i| format!("t{i}"))).is_err());
        assert!(ResourceScope::read((0..32).map(|i| format!("t{i}"))).is_ok());
        assert!(ResourceScope::read(["bad id".to_string()]).is_err());
        assert!(ResourceScope::read(["x".repeat(65)]).is_err());
        // Time window with 5 s skew.
        let a = approve(NOW);
        assert!(verify(&a, &binding(), NOW + 64).is_ok());
        assert_eq!(
            verify(&a, &binding(), NOW + 65),
            Err(ApprovalError::Expired)
        );
        assert!(verify(&a, &binding(), NOW - 5).is_ok());
        assert_eq!(
            verify(&a, &binding(), NOW - 6),
            Err(ApprovalError::NotYetValid)
        );
        // Signing with a key that is not the binding's origin is refused.
        assert_eq!(
            sign(
                &SecretKey::from_bytes(&[7u8; 32]),
                &binding(),
                Decision::Deny,
                None,
                None,
                NOW,
                60
            ),
            Err(ApprovalError::Mismatch("iss"))
        );
    }

    #[test]
    fn malformed_and_non_canonical() {
        let key = origin_key();
        let a = approve(NOW);
        for bad in [
            String::new(),
            a.split_once('.').unwrap().0.to_string(),
            format!("{a}.x"),
            format!("{a}="),
            "x".repeat(MAX_APPROVAL_BYTES + 1),
        ] {
            assert!(matches!(
                verify(&bad, &binding(), NOW),
                Err(ApprovalError::Malformed | ApprovalError::BadSignature)
            ));
        }
        let (payload, _) = a.split_once('.').unwrap();
        let json = String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        for variant in [
            json.replacen(':', ": ", 1),
            json.replacen('{', "{\"zzz\":1,", 1),
        ] {
            let p = URL_SAFE_NO_PAD.encode(&variant);
            let sig = key.sign(&signing_message(&p));
            let s = format!("{p}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
            assert_eq!(verify(&s, &binding(), NOW), Err(ApprovalError::Malformed));
        }
    }

    /// Pinned test vector: seed 0x02*32 signs, edge 0x04*32. If this changes,
    /// the documented format changed (README).
    #[test]
    fn pinned_vector() {
        let a = sign(
            &origin_key(),
            &binding(),
            Decision::Approve,
            Some(scope()),
            Some(3600),
            1_700_000_000,
            60,
        )
        .unwrap();
        assert_eq!(a, PINNED_APPROVAL);
        verify(PINNED_APPROVAL, &binding(), 1_700_000_030).unwrap();
    }

    const PINNED_APPROVAL: &str = concat!(
        "eyJhdWQiOiJodHRwczovL2VkZ2UuZXhhbXBsZSIsImJhY2tlbmQiOiJ3aXNraXQiLCJjbGllbnRfaWQiOiJj",
        "bGllbnQiLCJkZWNpc2lvbiI6ImFwcHJvdmUiLCJlZGdlX2lkIjoiY2E5M2FjMTcwNTE4NzA3MWQ2N2I4M2M3",
        "ZmYwZWZlODEwOGU4ZWM0NTMwNTc1ZDc3MjY4NzkzMzNkYmRhYmU3YyIsImV4cCI6MTcwMDAwMDA2MCwiZ3Jh",
        "bnRfaWQiOiJnX2V4YW1wbGUiLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6IjgxMzk3NzBlYTg3ZDE3NWY1NmEz",
        "NTQ2NmMzNGM3ZWNjY2I4ZDhhOTFiNGVlMzdhMjVkZjYwZjViOGZjOWIzOTQiLCJsaWZldGltZV9zZWNzIjoz",
        "NjAwLCJub25jZSI6IkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWtKQ1FrSkNRa0pDUWsiLCJyZXNv",
        "dXJjZV9zY29wZSI6eyJhY2Nlc3MiOiJyZWFkIiwidHJhY2tlcnMiOlsidDEiLCJ0MiJdLCJ2IjoxfSwidHgi",
        "OiJ0eF8xIiwidiI6MX0.UZrzyVaAYwMYY9NWTfw2rZmtgivFd-_je6miygMXqbNqwA9D30lKRG0cNtIx_BRl",
        "9t4gKSiywwXEwA7U0GS-Aw",
    );
}
