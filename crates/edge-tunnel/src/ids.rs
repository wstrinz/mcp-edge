//! Small identifier encodings shared by the metadata, approval and enrollment
//! formats.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use iroh::EndpointId;

/// Crockford base32 alphabet (no I, L, O, U).
pub const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Lowercase hex of an EndpointId (64 chars). Same as iroh's `Display`.
pub fn endpoint_id_hex(id: &EndpointId) -> String {
    let mut out = String::with_capacity(64);
    for b in id.as_bytes() {
        out.push(char::from(b"0123456789abcdef"[(b >> 4) as usize]));
        out.push(char::from(b"0123456789abcdef"[(b & 15) as usize]));
    }
    out
}

/// Strictly parse exactly 64 **lowercase** hex chars that decode to a valid
/// Ed25519 point. (iroh's `FromStr` also accepts other encodings; the tunnel
/// formats do not.)
pub fn parse_endpoint_id_hex(s: &str) -> Option<EndpointId> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in b.chunks_exact(2).enumerate() {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    EndpointId::from_bytes(&out).ok()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decode unpadded base64url to exactly `N` bytes.
pub fn b64url_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() > N.div_ceil(3) * 4 {
        return None;
    }
    let v = URL_SAFE_NO_PAD.decode(s).ok()?;
    v.try_into().ok()
}

/// `N` random bytes as unpadded base64url.
pub fn random_b64url<const N: usize>() -> Result<String, getrandom::Error> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Crockford base32 (big-endian bit order, no padding).
pub fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(CROCKFORD[((acc >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(CROCKFORD[((acc << (5 - bits)) & 31) as usize]));
    }
    out
}

/// `[A-Za-z0-9_-]{min..=max}`.
pub(crate) fn is_token(s: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// No control characters (C0, DEL, C1), non-empty, at most `max_chars` chars
/// and `4 * max_chars` bytes.
pub(crate) fn is_display_text(s: &str, max_chars: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_chars * 4
        && s.chars().count() <= max_chars
        && !s.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_strict() {
        let id = iroh::SecretKey::from_bytes(&[3u8; 32]).public();
        let hex = endpoint_id_hex(&id);
        assert_eq!(hex, id.to_string());
        assert_eq!(parse_endpoint_id_hex(&hex), Some(id));
        assert_eq!(parse_endpoint_id_hex(&hex.to_uppercase()), None);
        assert_eq!(parse_endpoint_id_hex(&hex[..62]), None);
        assert_eq!(parse_endpoint_id_hex(&format!("{hex}0")), None);
        assert_eq!(parse_endpoint_id_hex(&id.to_z32()), None);
    }

    #[test]
    fn crockford_known_values() {
        assert_eq!(crockford_encode(&[]), "");
        assert_eq!(crockford_encode(&[0xff; 5]), "ZZZZZZZZ");
        assert_eq!(crockford_encode(&[0; 10]), "0000000000000000");
        // 0x01 0x23 0x45 0x67 0x89 -> 00000 00100 10001 10100 01010 11001 11100 01001
        assert_eq!(
            crockford_encode(&[0x01, 0x23, 0x45, 0x67, 0x89]),
            "04HMASW9"
        );
    }

    #[test]
    fn b64url_fixed_rejects_wrong_lengths_and_padding() {
        let s = URL_SAFE_NO_PAD.encode([1u8; 16]);
        assert_eq!(b64url_fixed::<16>(&s), Some([1u8; 16]));
        assert_eq!(b64url_fixed::<32>(&s), None);
        assert_eq!(b64url_fixed::<16>(&format!("{s}==")), None);
        assert_eq!(b64url_fixed::<16>("!!"), None);
    }
}
