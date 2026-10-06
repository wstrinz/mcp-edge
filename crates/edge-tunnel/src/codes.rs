//! Origin error codes, QUIC application close codes and what the edge answers
//! for each (PHASE4.md §2.2, §2.7).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Transport/authorization-level refusal sent by the origin in the `error`
/// field of a response. MCP-level errors are ordinary JSON-RPC bodies, never
/// one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    RemoteDisabled,
    EnrollmentStale,
    OriginLocked,
    AuditUnavailable,
    AssertionInvalid,
    UnknownGrant,
    GrantRevoked,
    GrantExpired,
    ScopeMismatch,
    Busy,
    Deadline,
    BadRequest,
    VersionUnsupported,
    ConsentBusy,
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 14] = [
        ErrorCode::RemoteDisabled,
        ErrorCode::EnrollmentStale,
        ErrorCode::OriginLocked,
        ErrorCode::AuditUnavailable,
        ErrorCode::AssertionInvalid,
        ErrorCode::UnknownGrant,
        ErrorCode::GrantRevoked,
        ErrorCode::GrantExpired,
        ErrorCode::ScopeMismatch,
        ErrorCode::Busy,
        ErrorCode::Deadline,
        ErrorCode::BadRequest,
        ErrorCode::VersionUnsupported,
        ErrorCode::ConsentBusy,
    ];

    /// The status the origin sends with this code (§2.7 "Origin status"). A
    /// response whose status differs is a protocol error at the edge.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::RemoteDisabled
            | ErrorCode::EnrollmentStale
            | ErrorCode::OriginLocked
            | ErrorCode::AuditUnavailable => 503,
            ErrorCode::AssertionInvalid
            | ErrorCode::UnknownGrant
            | ErrorCode::GrantRevoked
            | ErrorCode::GrantExpired => 401,
            ErrorCode::ScopeMismatch => 403,
            ErrorCode::Busy | ErrorCode::ConsentBusy => 429,
            ErrorCode::Deadline => 504,
            ErrorCode::BadRequest | ErrorCode::VersionUnsupported => 400,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::RemoteDisabled => "remote_disabled",
            ErrorCode::EnrollmentStale => "enrollment_stale",
            ErrorCode::OriginLocked => "origin_locked",
            ErrorCode::AuditUnavailable => "audit_unavailable",
            ErrorCode::AssertionInvalid => "assertion_invalid",
            ErrorCode::UnknownGrant => "unknown_grant",
            ErrorCode::GrantRevoked => "grant_revoked",
            ErrorCode::GrantExpired => "grant_expired",
            ErrorCode::ScopeMismatch => "scope_mismatch",
            ErrorCode::Busy => "busy",
            ErrorCode::Deadline => "deadline",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::VersionUnsupported => "version_unsupported",
            ErrorCode::ConsentBusy => "consent_busy",
        }
    }

    /// What the edge answers the MCP client (§2.7 "Edge → Claude").
    pub fn edge_failure(self) -> EdgeFailure {
        match self {
            ErrorCode::RemoteDisabled => EdgeFailure::OriginRemoteOff,
            ErrorCode::EnrollmentStale => EdgeFailure::OriginUnenrolled,
            ErrorCode::OriginLocked => EdgeFailure::OriginLocked,
            ErrorCode::AuditUnavailable => EdgeFailure::OriginPaused,
            ErrorCode::AssertionInvalid | ErrorCode::ScopeMismatch => EdgeFailure::BackendRejected,
            ErrorCode::UnknownGrant | ErrorCode::GrantRevoked | ErrorCode::GrantExpired => {
                EdgeFailure::InvalidToken
            }
            ErrorCode::Busy => EdgeFailure::TooManyRequests,
            ErrorCode::Deadline => EdgeFailure::GatewayTimeout,
            ErrorCode::BadRequest | ErrorCode::VersionUnsupported => EdgeFailure::BackendProtocol,
            ErrorCode::ConsentBusy => EdgeFailure::ConsentBusy,
        }
    }

    /// Whether the edge must revoke its grant (gen++) on this code (§2.7 "Edge
    /// side effect").
    pub fn revokes_edge_grant(self) -> bool {
        matches!(
            self,
            ErrorCode::UnknownGrant
                | ErrorCode::GrantRevoked
                | ErrorCode::GrantExpired
                | ErrorCode::ScopeMismatch
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// QUIC application close codes (connection level, §2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseCode {
    PeerNotAdmitted = 1,
    ConnectionLimit = 2,
    RemoteDisabled = 3,
    ShuttingDown = 4,
    EnrollmentStale = 5,
}

impl CloseCode {
    pub fn from_u64(code: u64) -> Option<Self> {
        Some(match code {
            1 => CloseCode::PeerNotAdmitted,
            2 => CloseCode::ConnectionLimit,
            3 => CloseCode::RemoteDisabled,
            4 => CloseCode::ShuttingDown,
            5 => CloseCode::EnrollmentStale,
            _ => return None,
        })
    }

    pub fn code(self) -> u32 {
        self as u32
    }

    pub fn varint(self) -> iroh::endpoint::VarInt {
        iroh::endpoint::VarInt::from_u32(self.code())
    }

    /// Fixed, non-sensitive close reason text.
    pub fn reason(self) -> &'static [u8] {
        match self {
            CloseCode::PeerNotAdmitted => b"peer_not_admitted",
            CloseCode::ConnectionLimit => b"connection_limit",
            CloseCode::RemoteDisabled => b"remote_disabled",
            CloseCode::ShuttingDown => b"shutting_down",
            CloseCode::EnrollmentStale => b"enrollment_stale",
        }
    }

    pub fn edge_failure(self) -> EdgeFailure {
        match self {
            CloseCode::PeerNotAdmitted => EdgeFailure::OriginRejectedEdge,
            CloseCode::ConnectionLimit => EdgeFailure::OriginBusy,
            CloseCode::RemoteDisabled => EdgeFailure::OriginRemoteOff,
            CloseCode::ShuttingDown => EdgeFailure::OriginOffline,
            CloseCode::EnrollmentStale => EdgeFailure::OriginUnenrolled,
        }
    }
}

/// What the edge answers its HTTP client. The gateway renders the body (§2.8
/// for the `origin_*` 503s); this type only fixes status and reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EdgeFailure {
    /// 503: PC off/asleep, app closed, dial failed, connection dropped.
    OriginOffline,
    /// 503: the origin closed with `peer_not_admitted`.
    OriginRejectedEdge,
    /// 503: the origin closed with `connection_limit` (after one re-dial).
    OriginBusy,
    /// 503: remote access is off in the app.
    OriginRemoteOff,
    /// 503: enrollment stale in the app.
    OriginUnenrolled,
    /// 503: app identity locked / not ready.
    OriginLocked,
    /// 503: app audit unavailable (remote mode paused).
    OriginPaused,
    /// 502: the origin refused the assertion or the scope.
    BackendRejected,
    /// 502: framing/metadata/version error on either side.
    BackendProtocol,
    /// 401 + `WWW-Authenticate`: grant unknown/revoked/expired at the origin.
    InvalidToken,
    /// 429 (+ `Retry-After` when the origin gave one).
    TooManyRequests,
    /// 504: deadline passed.
    GatewayTimeout,
    /// 413: the request exceeds a tunnel cap (caught at the edge).
    PayloadTooLarge,
    /// Consent page message (`consent_busy`).
    ConsentBusy,
    /// 500: the edge built an invalid request (a bug at the edge).
    Internal,
}

impl EdgeFailure {
    pub fn http_status(self) -> u16 {
        match self {
            EdgeFailure::OriginOffline
            | EdgeFailure::OriginRejectedEdge
            | EdgeFailure::OriginBusy
            | EdgeFailure::OriginRemoteOff
            | EdgeFailure::OriginUnenrolled
            | EdgeFailure::OriginLocked
            | EdgeFailure::OriginPaused => 503,
            EdgeFailure::BackendRejected | EdgeFailure::BackendProtocol => 502,
            EdgeFailure::InvalidToken => 401,
            EdgeFailure::TooManyRequests | EdgeFailure::ConsentBusy => 429,
            EdgeFailure::GatewayTimeout => 504,
            EdgeFailure::PayloadTooLarge => 413,
            EdgeFailure::Internal => 500,
        }
    }

    /// Machine reason (`data.reason` / log field).
    pub fn reason(self) -> &'static str {
        match self {
            EdgeFailure::OriginOffline => "origin_offline",
            EdgeFailure::OriginRejectedEdge => "origin_rejected_edge",
            EdgeFailure::OriginBusy => "origin_busy",
            EdgeFailure::OriginRemoteOff => "origin_remote_off",
            EdgeFailure::OriginUnenrolled => "origin_unenrolled",
            EdgeFailure::OriginLocked => "origin_locked",
            EdgeFailure::OriginPaused => "origin_paused",
            EdgeFailure::BackendRejected => "backend_rejected",
            EdgeFailure::BackendProtocol => "backend_protocol",
            EdgeFailure::InvalidToken => "invalid_token",
            EdgeFailure::TooManyRequests => "busy",
            EdgeFailure::GatewayTimeout => "deadline",
            EdgeFailure::PayloadTooLarge => "payload_too_large",
            EdgeFailure::ConsentBusy => "consent_busy",
            EdgeFailure::Internal => "internal",
        }
    }

    /// The §2.8 503 contract: every `origin_*` reason is a 503 with
    /// `Retry-After: 30`.
    pub fn is_origin_unavailable(self) -> bool {
        self.http_status() == 503
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_serialize_snake_case_and_map_per_spec_table() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(&code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(serde_json::from_str::<ErrorCode>(&json).unwrap(), code);
        }
        // §2.7 row by row: (code, origin status, edge status, edge reason, revoke)
        let table: &[(ErrorCode, u16, u16, &str, bool)] = &[
            (
                ErrorCode::RemoteDisabled,
                503,
                503,
                "origin_remote_off",
                false,
            ),
            (
                ErrorCode::EnrollmentStale,
                503,
                503,
                "origin_unenrolled",
                false,
            ),
            (ErrorCode::OriginLocked, 503, 503, "origin_locked", false),
            (
                ErrorCode::AuditUnavailable,
                503,
                503,
                "origin_paused",
                false,
            ),
            (
                ErrorCode::AssertionInvalid,
                401,
                502,
                "backend_rejected",
                false,
            ),
            (ErrorCode::UnknownGrant, 401, 401, "invalid_token", true),
            (ErrorCode::GrantRevoked, 401, 401, "invalid_token", true),
            (ErrorCode::GrantExpired, 401, 401, "invalid_token", true),
            (ErrorCode::ScopeMismatch, 403, 502, "backend_rejected", true),
            (ErrorCode::Busy, 429, 429, "busy", false),
            (ErrorCode::Deadline, 504, 504, "deadline", false),
            (ErrorCode::BadRequest, 400, 502, "backend_protocol", false),
            (
                ErrorCode::VersionUnsupported,
                400,
                502,
                "backend_protocol",
                false,
            ),
            (ErrorCode::ConsentBusy, 429, 429, "consent_busy", false),
        ];
        assert_eq!(table.len(), ErrorCode::ALL.len());
        for (code, origin, edge, reason, revoke) in table {
            assert_eq!(code.status(), *origin, "{code}");
            assert_eq!(code.edge_failure().http_status(), *edge, "{code}");
            assert_eq!(code.edge_failure().reason(), *reason, "{code}");
            assert_eq!(code.revokes_edge_grant(), *revoke, "{code}");
        }
    }

    #[test]
    fn close_codes_map_per_spec_table() {
        let table = [
            (1, "origin_rejected_edge"),
            (2, "origin_busy"),
            (3, "origin_remote_off"),
            (4, "origin_offline"),
            (5, "origin_unenrolled"),
        ];
        for (n, reason) in table {
            let code = CloseCode::from_u64(n).unwrap();
            assert_eq!(code.code() as u64, n);
            assert_eq!(code.edge_failure().reason(), reason);
            assert_eq!(code.edge_failure().http_status(), 503);
        }
        assert_eq!(CloseCode::from_u64(0), None);
        assert_eq!(CloseCode::from_u64(6), None);
    }
}
