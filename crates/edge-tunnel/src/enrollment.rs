//! Enrollment string and fingerprint (PHASE4.md §1.3).
//!
//! ```text
//! mcp-edge-enroll:1:<base64url-nopad(canonical JSON)>
//! fingerprint = Crockford base32 of SHA-256(canonical JSON)[..10], as XXXX-XXXX-XXXX-XXXX
//! ```
//!
//! The edge formats it on `/owner`; the owner pastes it into the origin app,
//! which parses it here. It contains no secrets. Parsing is strict: the JSON
//! must be canonical (sorted keys, no whitespace), so one enrollment has exactly
//! one string and one fingerprint.

use crate::{ids, meta::valid_scope};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const PREFIX: &str = "mcp-edge-enroll:1:";
/// Longest accepted enrollment string (well above any valid one).
pub const MAX_ENROLLMENT_STRING: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentError {
    /// Not `mcp-edge-enroll:1:<b64url>`, bad base64, bad or non-canonical JSON.
    Malformed,
    /// A field is outside its bounds; names the field.
    Invalid(&'static str),
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnrollmentError::Malformed => f.write_str("enrollment string is malformed"),
            EnrollmentError::Invalid(what) => write!(f, "enrollment field invalid: {what}"),
        }
    }
}
impl std::error::Error for EnrollmentError {}

/// The decoded enrollment. Field names are the wire names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    /// Format version, 1.
    pub v: u8,
    /// Edge issuer (https URL, ≤ 128 bytes). Assertions must carry it as `iss`.
    pub iss: String,
    /// Backend id (assertion audience), `[a-z][a-z0-9-]{0,31}`.
    pub aud: String,
    /// Edge iroh EndpointId, 64 lowercase hex. The only admitted peer.
    pub edge_id: String,
    /// Edge assertion public key, 43 chars base64url (32 bytes).
    pub assert_key: String,
    /// Edge owner id; every assertion's `sub` must equal it (≤ 64 bytes).
    pub sub: String,
    /// Scopes the edge puts in assertions (≤ 4).
    pub scopes: Vec<String>,
}

fn valid_backend_id(id: &str) -> bool {
    let b = id.as_bytes();
    (1..=32).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn valid_issuer(iss: &str) -> bool {
    let Some(rest) = iss.strip_prefix("https://") else {
        return false;
    };
    iss.len() <= 128
        && !rest.is_empty()
        && !rest.starts_with('/')
        && iss
            .bytes()
            .all(|c| c.is_ascii_graphic() && !matches!(c, b'?' | b'#' | b'@' | b'\\'))
}

impl Enrollment {
    /// Build and validate (edge side).
    pub fn new(
        iss: impl Into<String>,
        aud: impl Into<String>,
        edge_id: &EndpointId,
        assert_key_b64url: impl Into<String>,
        sub: impl Into<String>,
        scopes: Vec<String>,
    ) -> Result<Self, EnrollmentError> {
        let e = Self {
            v: 1,
            iss: iss.into(),
            aud: aud.into(),
            edge_id: ids::endpoint_id_hex(edge_id),
            assert_key: assert_key_b64url.into(),
            sub: sub.into(),
            scopes,
        };
        e.validate()?;
        Ok(e)
    }

    pub fn validate(&self) -> Result<(), EnrollmentError> {
        use EnrollmentError::Invalid;
        if self.v != 1 {
            return Err(Invalid("v"));
        }
        if !valid_issuer(&self.iss) {
            return Err(Invalid("iss"));
        }
        if !valid_backend_id(&self.aud) {
            return Err(Invalid("aud"));
        }
        if ids::parse_endpoint_id_hex(&self.edge_id).is_none() {
            return Err(Invalid("edge_id"));
        }
        if self.assert_key.len() != 43 || self.assertion_key().is_none() {
            return Err(Invalid("assert_key"));
        }
        if !ids::is_display_text(&self.sub, 64) || self.sub.len() > 64 {
            return Err(Invalid("sub"));
        }
        let mut sorted = self.scopes.clone();
        sorted.sort();
        sorted.dedup();
        if self.scopes.is_empty()
            || self.scopes.len() > 4
            || sorted.len() != self.scopes.len()
            || !self.scopes.iter().all(|s| valid_scope(s))
        {
            return Err(Invalid("scopes"));
        }
        Ok(())
    }

    /// The canonical JSON the string encodes and the fingerprint hashes.
    pub fn canonical_json(&self) -> String {
        let value = serde_json::to_value(self).expect("enrollment serializes");
        edge_assert::canonical_json(&value).expect("enrollment has no floats")
    }

    /// `mcp-edge-enroll:1:<b64url(canonical JSON)>`.
    pub fn to_enrollment_string(&self) -> String {
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(self.canonical_json()))
    }

    /// Parse a pasted enrollment string (surrounding whitespace is ignored).
    pub fn parse(s: &str) -> Result<Self, EnrollmentError> {
        let s = s.trim();
        if s.len() > MAX_ENROLLMENT_STRING {
            return Err(EnrollmentError::Malformed);
        }
        let b64 = s.strip_prefix(PREFIX).ok_or(EnrollmentError::Malformed)?;
        let json = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| EnrollmentError::Malformed)?;
        let e: Enrollment =
            serde_json::from_slice(&json).map_err(|_| EnrollmentError::Malformed)?;
        e.validate()?;
        if e.canonical_json().as_bytes() != json.as_slice() {
            return Err(EnrollmentError::Malformed);
        }
        Ok(e)
    }

    /// First 10 bytes of SHA-256 over the canonical JSON, as 4 groups of 4
    /// Crockford base32 characters joined by `-`.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.canonical_json().as_bytes());
        let chars = ids::crockford_encode(&digest[..10]);
        let groups: Vec<&str> = (0..4).map(|i| &chars[i * 4..i * 4 + 4]).collect();
        groups.join("-")
    }

    /// The admitted edge EndpointId.
    pub fn edge_endpoint_id(&self) -> EndpointId {
        ids::parse_endpoint_id_hex(&self.edge_id).expect("validated")
    }

    /// The edge assertion public key bytes, if valid.
    pub fn assertion_key(&self) -> Option<[u8; 32]> {
        let bytes = ids::b64url_fixed::<32>(&self.assert_key)?;
        // Reject keys that are not valid Ed25519 points.
        edge_assert::Verifier::from_public_key_base64url(&self.assert_key, "x", "x").ok()?;
        Some(bytes)
    }

    /// An `edge-assert` verifier for this enrollment (issuer, audience, key),
    /// with a replay cache of `replay_capacity` entries.
    pub fn assertion_verifier(&self, replay_capacity: usize) -> edge_assert::Verifier {
        edge_assert::Verifier::from_public_key_base64url(&self.assert_key, &self.iss, &self.aud)
            .expect("validated")
            .with_replay_cache(replay_capacity)
    }
}

/// `XXXX-XXXX-XXXX-XXXX` over the Crockford alphabet.
pub fn is_fingerprint(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 19
        && b.iter().enumerate().all(|(i, c)| {
            if i % 5 == 4 {
                *c == b'-'
            } else {
                ids::CROCKFORD.contains(c)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Enrollment {
        let edge = iroh::SecretKey::from_bytes(&[4u8; 32]).public();
        let assert_key = edge_assert::Signer::from_seed(&[1u8; 32], "https://edge.example")
            .public_key_base64url();
        Enrollment::new(
            "https://edge.example",
            "wiskit",
            &edge,
            assert_key,
            "owner",
            vec!["wiskit:read".into()],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_and_fingerprint() {
        let e = sample();
        let s = e.to_enrollment_string();
        assert!(s.starts_with("mcp-edge-enroll:1:"));
        assert_eq!(Enrollment::parse(&s).unwrap(), e);
        assert_eq!(Enrollment::parse(&format!("  {s}\n")).unwrap(), e);
        let fp = e.fingerprint();
        assert!(is_fingerprint(&fp), "{fp}");
        assert_eq!(Enrollment::parse(&s).unwrap().fingerprint(), fp);
        // Any field change changes the fingerprint.
        let mut other = e.clone();
        other.sub = "owner2".into();
        assert_ne!(other.fingerprint(), fp);
    }

    /// Pinned vector: if this changes, the documented format changed.
    #[test]
    fn pinned_vector() {
        let e = sample();
        assert_eq!(e.canonical_json(), PINNED_JSON);
        assert_eq!(e.to_enrollment_string(), PINNED_STRING);
        assert_eq!(e.fingerprint(), PINNED_FINGERPRINT);
    }

    const PINNED_JSON: &str = r#"{"assert_key":"iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w","aud":"wiskit","edge_id":"ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c","iss":"https://edge.example","scopes":["wiskit:read"],"sub":"owner","v":1}"#;
    const PINNED_STRING: &str = concat!(
        "mcp-edge-enroll:1:eyJhc3NlcnRfa2V5IjoiaW9qajNYUUo4Wlg5VXRzdFBMcGRjc3BuQ2I4ZGxCSWI4M1",
        "NJQWJRUGIxdyIsImF1ZCI6Indpc2tpdCIsImVkZ2VfaWQiOiJjYTkzYWMxNzA1MTg3MDcxZDY3YjgzYzdmZj",
        "BlZmU4MTA4ZThlYzQ1MzA1NzVkNzcyNjg3OTMzM2RiZGFiZTdjIiwiaXNzIjoiaHR0cHM6Ly9lZGdlLmV4YW",
        "1wbGUiLCJzY29wZXMiOlsid2lza2l0OnJlYWQiXSwic3ViIjoib3duZXIiLCJ2IjoxfQ",
    );
    const PINNED_FINGERPRINT: &str = "KR4R-3MMF-58NB-P74R";

    #[test]
    fn rejects_malformed_and_out_of_bounds() {
        let e = sample();
        let good = e.to_enrollment_string();
        for bad in [
            String::new(),
            good.replacen("enroll:1:", "enroll:2:", 1),
            format!("{good}="),
            format!("{good}!"),
            "x".repeat(MAX_ENROLLMENT_STRING + 1),
        ] {
            assert!(Enrollment::parse(&bad).is_err(), "{bad}");
        }
        // Non-canonical JSON (whitespace) is refused even though it parses.
        let spaced = e.canonical_json().replacen(':', ": ", 1);
        let s = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(spaced));
        assert_eq!(Enrollment::parse(&s), Err(EnrollmentError::Malformed));
        // Unknown field.
        let extra = e.canonical_json().replacen('{', "{\"aaa\":1,", 1);
        let s = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(extra));
        assert_eq!(Enrollment::parse(&s), Err(EnrollmentError::Malformed));

        let cases: Vec<(&str, Box<dyn Fn(&mut Enrollment)>)> = vec![
            ("iss", Box::new(|e| e.iss = "http://edge.example".into())),
            (
                "iss",
                Box::new(|e| e.iss = format!("https://{}", "a".repeat(121))),
            ),
            ("iss", Box::new(|e| e.iss = "https://a b".into())),
            ("aud", Box::new(|e| e.aud = "Wiskit".into())),
            ("aud", Box::new(|e| e.aud = "a".repeat(33))),
            (
                "edge_id",
                Box::new(|e| e.edge_id = e.edge_id.to_uppercase()),
            ),
            ("edge_id", Box::new(|e| e.edge_id = "00".repeat(31))),
            ("assert_key", Box::new(|e| e.assert_key = "AAAA".into())),
            ("sub", Box::new(|e| e.sub = "s".repeat(65))),
            ("sub", Box::new(|e| e.sub = String::new())),
            ("scopes", Box::new(|e| e.scopes = vec![])),
            (
                "scopes",
                Box::new(|e| {
                    e.scopes = vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()]
                }),
            ),
            (
                "scopes",
                Box::new(|e| e.scopes = vec!["a".into(), "a".into()]),
            ),
            ("v", Box::new(|e| e.v = 2)),
        ];
        for (field, mutate) in cases {
            let mut e = sample();
            mutate(&mut e);
            assert_eq!(
                e.validate(),
                Err(EnrollmentError::Invalid(field)),
                "{field}"
            );
            let s = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(e.canonical_json()));
            assert!(Enrollment::parse(&s).is_err(), "{field}");
        }
    }

    #[test]
    fn verifier_uses_enrolled_issuer_audience_and_key() {
        let e = sample();
        let signer = edge_assert::Signer::from_seed(&[1u8; 32], "https://edge.example");
        let grant = edge_assert::GrantContext {
            aud: "wiskit".into(),
            sub: "owner".into(),
            client_id: "c".into(),
            grant_id: "g_1".into(),
            scope: vec!["wiskit:read".into()],
            resource_scope: serde_json::json!({}),
            gen: 1,
        };
        let req = edge_assert::RequestBinding {
            method: "POST",
            path: "/mcp",
            body: b"{}",
        };
        let a = signer.mint(&grant, req, 1_800_000_000, 60).unwrap();
        e.assertion_verifier(4)
            .verify(&a, req, 1_800_000_001)
            .unwrap();
        assert_eq!(e.edge_endpoint_id().to_string(), e.edge_id);
    }
}
