//! Clock, log sink, rate limiting and small helpers shared by the server.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        atomic::{AtomicI64, Ordering},
        Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

/// Source of "now" in Unix seconds. Tests use [`ManualClock`].
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

/// Wall clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// A clock that only moves when told to (for tests of expiry rules).
pub struct ManualClock(AtomicI64);

impl ManualClock {
    pub fn new(start: i64) -> Self {
        Self(AtomicI64::new(start))
    }
    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Destination for operational log lines. Implementations must not add
/// request content; callers only pass route, status, timing and grant ids.
pub trait LogSink: Send + Sync {
    fn line(&self, line: &str);
}

/// Writes lines to stderr.
pub struct StderrLog;

impl LogSink for StderrLog {
    fn line(&self, line: &str) {
        eprintln!("{line}");
    }
}

/// Keeps lines in memory (tests grep them for secrets).
#[derive(Default)]
pub struct MemoryLog(Mutex<Vec<String>>);

impl MemoryLog {
    pub fn lines(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl LogSink for MemoryLog {
    fn line(&self, line: &str) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(line.to_owned());
    }
}

/// The client address used for pre-authentication limits. The binary inserts
/// it as a request extension (peer address, or the proxy-appended
/// `X-Forwarded-For` entry when explicitly configured).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

/// Fixed-window counters keyed by (bucket, client network). IPv6 clients are
/// grouped by /64. The table is bounded; when it is full of live windows new
/// keys are refused (fail closed).
pub struct RateLimiter {
    windows: Mutex<HashMap<BucketKey, (i64, u32)>>,
    max_keys: usize,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum LimitKey {
    Global,
    Net(IpAddr),
    Id(String),
}

type BucketKey = (&'static str, LimitKey);

impl RateLimiter {
    pub fn new(max_keys: usize) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_keys: max_keys.max(16),
        }
    }

    /// Count one event for a client network (`None`: one shared bucket);
    /// returns false when `limit` events already happened in the current
    /// `window_secs` window.
    pub fn allow(
        &self,
        bucket: &'static str,
        ip: Option<IpAddr>,
        limit: u32,
        window_secs: i64,
        now: i64,
    ) -> bool {
        let key = ip.map_or(LimitKey::Global, |ip| LimitKey::Net(network_key(ip)));
        self.count((bucket, key), limit, window_secs, now)
    }

    /// Like [`RateLimiter::allow`], keyed by an identifier (e.g. a grant id).
    pub fn allow_id(
        &self,
        bucket: &'static str,
        id: &str,
        limit: u32,
        window_secs: i64,
        now: i64,
    ) -> bool {
        self.count(
            (bucket, LimitKey::Id(id.to_owned())),
            limit,
            window_secs,
            now,
        )
    }

    fn count(&self, key: BucketKey, limit: u32, window_secs: i64, now: i64) -> bool {
        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        if !windows.contains_key(&key) && windows.len() >= self.max_keys {
            windows.retain(|_, (end, _)| *end > now);
            if windows.len() >= self.max_keys {
                return false;
            }
        }
        let entry = windows.entry(key).or_insert((now + window_secs, 0));
        if now >= entry.0 {
            *entry = (now + window_secs, 0);
        }
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

fn network_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut seg = v6.segments();
                seg[4..].fill(0);
                IpAddr::V6(seg.into())
            }
        },
    }
}

pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("OS random source unavailable");
    bytes
}

/// `prefix` + base64url(32 random bytes). Used for tokens, codes and cookies.
pub(crate) fn random_secret(prefix: &str) -> String {
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(random_bytes::<32>()))
}

/// Non-secret random identifier.
pub(crate) fn random_id(prefix: &str) -> String {
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(random_bytes::<16>()))
}

/// SHA-256, base64url. The only form in which secrets are stored.
pub(crate) fn hash_secret(secret: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(secret.as_bytes()))
}

pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub(crate) fn hmac_b64(key: &[u8], parts: &[&str]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part.as_bytes());
    }
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// PKCE S256: base64url(SHA-256(verifier)) == challenge.
pub(crate) fn pkce_s256_matches(verifier: &str, challenge: &str) -> bool {
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    ct_eq(&computed, challenge)
}

pub(crate) fn is_b64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// RFC 7636 code_verifier: 43..=128 unreserved characters.
pub(crate) fn valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

pub(crate) fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Parse `application/x-www-form-urlencoded` (or a query string), rejecting
/// repeated parameters as OAuth requires.
pub(crate) fn parse_unique_params(raw: &[u8]) -> Option<HashMap<String, String>> {
    let mut out = HashMap::new();
    let mut seen = HashSet::new();
    for (k, v) in url::form_urlencoded::parse(raw) {
        if !seen.insert(k.to_string()) {
            return None;
        }
        out.insert(k.into_owned(), v.into_owned());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_windows_and_bounds() {
        let l = RateLimiter::new(16);
        let ip = Some("10.0.0.1".parse().unwrap());
        assert!(l.allow("b", ip, 2, 60, 100));
        assert!(l.allow("b", ip, 2, 60, 101));
        assert!(!l.allow("b", ip, 2, 60, 102));
        assert!(l.allow("b", ip, 2, 60, 161));
        // IPv6 /64 neighbours share a window.
        let a = Some("2001:db8::1".parse().unwrap());
        let b = Some("2001:db8::2".parse().unwrap());
        assert!(l.allow("v6", a, 1, 60, 100));
        assert!(!l.allow("v6", b, 1, 60, 100));
    }

    #[test]
    fn duplicate_params_are_rejected() {
        assert!(parse_unique_params(b"a=1&b=2").is_some());
        assert!(parse_unique_params(b"a=1&a=2").is_none());
    }

    #[test]
    fn pkce_and_escape() {
        // RFC 7636 appendix B.
        assert!(pkce_s256_matches(
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
        assert_eq!(
            escape_html("<a href=\"x\">&'"),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
    }
}
