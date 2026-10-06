//! The app's handle on one pending `consent_request` (PHASE4.md §3.4, §3.5).

use crate::{unix_now, Refusal, CONSENT_DELIVERY};
use edge_tunnel::{
    approval::{self, ApprovalBinding, ApprovalError, Decision, ResourceScope},
    frame, limits,
    meta::{self, ConsentRequestMeta, ConsentResponseMeta},
    PROTOCOL_VERSION,
};
use iroh::{
    endpoint::{SendStream, VarInt},
    SecretKey,
};
use std::fmt;
use tokio::time::{timeout, Instant};
use tokio_util::sync::CancellationToken;

/// How long a signed approval is valid (`exp - iat`, ≤ 120).
pub const APPROVAL_TTL_SECS: i64 = 60;
/// Reset code when the app or handler abandons a consent stream.
pub(crate) const RESET_NO_DECISION: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentError {
    /// The decision cannot be signed (bad trackers, lifetime outside
    /// `300..=max_lifetime_secs`, ...). Nothing was sent; the request is still
    /// pending and can be answered again.
    InvalidDecision(ApprovalError),
    /// The edge cancelled, the connection ended, or `expires_at` passed.
    Cancelled,
    /// Written, but the edge did not acknowledge it (drop the grant record).
    NotDelivered,
}

impl fmt::Display for ConsentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsentError::InvalidDecision(e) => write!(f, "invalid consent decision: {e}"),
            ConsentError::Cancelled => f.write_str("consent request cancelled or expired"),
            ConsentError::NotDelivered => f.write_str("consent answer not delivered"),
        }
    }
}
impl std::error::Error for ConsentError {}

/// One pending consent request. Answer it once with [`approve`](Self::approve),
/// [`deny`](Self::deny) or [`refuse`](Self::refuse). Dropping it unanswered
/// resets the stream (no decision).
pub struct ConsentResponder {
    request: ConsentRequestMeta,
    binding: ApprovalBinding,
    key: SecretKey,
    send: Option<SendStream>,
    cancel: CancellationToken,
    expires: Instant,
}

impl fmt::Debug for ConsentResponder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsentResponder")
            .field("tx", &self.request.tx)
            .field("grant_id", &self.request.grant_id)
            .finish_non_exhaustive()
    }
}

impl ConsentResponder {
    pub(crate) fn new(
        request: ConsentRequestMeta,
        binding: ApprovalBinding,
        key: SecretKey,
        send: SendStream,
        cancel: CancellationToken,
        expires: Instant,
    ) -> Self {
        Self {
            request,
            binding,
            key,
            send: Some(send),
            cancel,
            expires,
        }
    }

    /// The request as sent by the edge (validated). Show `client_name`
    /// (labelled self-reported), `client_id`, `redirect_host`, `scopes`,
    /// `requested_at`; never show `pairing_code`.
    pub fn request(&self) -> &ConsentRequestMeta {
        &self.request
    }

    /// Fires when the edge cancels (stops the stream), the connection ends, or
    /// `expires_at` passes. Close the prompt then.
    pub fn cancelled(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// When the prompt expires (from `expires_at`, at most 180 s).
    pub fn expires(&self) -> Instant {
        self.expires
    }

    /// Constant-time comparison of the code the owner typed with the pairing
    /// code. Case-insensitive; Crockford aliases (`O`→`0`, `I`/`L`→`1`) and
    /// surrounding whitespace / `-` are accepted. Counting attempts (3 wrong
    /// entries deny, §3.4) is the app's job.
    pub fn pairing_code_matches(&self, typed: &str) -> bool {
        let normalized: Vec<u8> = typed
            .trim()
            .bytes()
            .filter(|c| *c != b'-' && *c != b' ')
            .map(|c| match c.to_ascii_uppercase() {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            })
            .collect();
        let expected = self.request.pairing_code.as_bytes();
        if normalized.len() != expected.len() {
            return false;
        }
        normalized
            .iter()
            .zip(expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    /// Sign an approval for `trackers` (sorted/deduplicated here) and
    /// `lifetime_secs` (`300..=max_lifetime_secs`), send it and wait for the
    /// edge to acknowledge it. Write the grant record first; drop it on `Err`.
    pub async fn approve(
        mut self,
        trackers: Vec<String>,
        lifetime_secs: u64,
    ) -> Result<(), ConsentError> {
        let scope = ResourceScope::read(trackers).map_err(ConsentError::InvalidDecision)?;
        let approval = approval::sign(
            &self.key,
            &self.binding,
            Decision::Approve,
            Some(scope),
            Some(lifetime_secs),
            unix_now(),
            APPROVAL_TTL_SECS,
        )
        .map_err(ConsentError::InvalidDecision)?;
        self.send_meta(ConsentResponseMeta {
            v: PROTOCOL_VERSION,
            status: 200,
            approval: Some(approval),
            error: None,
            retry_after: None,
        })
        .await
    }

    /// Send a signed deny.
    pub async fn deny(mut self) -> Result<(), ConsentError> {
        let approval = approval::sign(
            &self.key,
            &self.binding,
            Decision::Deny,
            None,
            None,
            unix_now(),
            APPROVAL_TTL_SECS,
        )
        .map_err(ConsentError::InvalidDecision)?;
        self.send_meta(ConsentResponseMeta {
            v: PROTOCOL_VERSION,
            status: 200,
            approval: Some(approval),
            error: None,
            retry_after: None,
        })
        .await
    }

    /// Refuse without a decision (`origin_locked`, `remote_disabled`, ...).
    pub async fn refuse(mut self, refusal: Refusal) -> Result<(), ConsentError> {
        self.send_meta(ConsentResponseMeta {
            v: PROTOCOL_VERSION,
            status: refusal.code.status(),
            approval: None,
            error: Some(refusal.code),
            retry_after: refusal.retry_after,
        })
        .await
    }

    async fn send_meta(&mut self, meta: ConsentResponseMeta) -> Result<(), ConsentError> {
        if self.cancel.is_cancelled() || Instant::now() >= self.expires {
            return Err(ConsentError::Cancelled);
        }
        let bytes = meta::encode_response(&meta, limits::CONSENT_RESPONSE)
            .map_err(|_| ConsentError::InvalidDecision(ApprovalError::Malformed))?;
        let mut send = self.send.take().ok_or(ConsentError::Cancelled)?;
        let stopped = send.stopped();
        let write = async {
            frame::write_field(&mut send, &bytes, limits::CONSENT_RESPONSE).await?;
            frame::write_terminator(&mut send).await?;
            send.finish().map_err(|_| frame::FrameError::Io)
        };
        let written = tokio::select! {
            _ = self.cancel.cancelled() => None,
            r = timeout(CONSENT_DELIVERY, write) => Some(r),
        };
        match written {
            Some(Ok(Ok(()))) => {}
            None => {
                let _ = send.reset(VarInt::from_u32(RESET_NO_DECISION));
                return Err(ConsentError::Cancelled);
            }
            Some(_) => {
                let _ = send.reset(VarInt::from_u32(RESET_NO_DECISION));
                return Err(ConsentError::NotDelivered);
            }
        }
        // Delivered = the edge acknowledged every byte after FIN.
        match timeout(CONSENT_DELIVERY, stopped).await {
            Ok(Ok(None)) => Ok(()),
            _ => Err(ConsentError::NotDelivered),
        }
    }
}

impl Drop for ConsentResponder {
    fn drop(&mut self) {
        if let Some(mut send) = self.send.take() {
            // Unanswered: no decision. Reset rather than finish, so the edge
            // sees a stream error, never an empty answer.
            let _ = send.reset(VarInt::from_u32(RESET_NO_DECISION));
        }
    }
}
