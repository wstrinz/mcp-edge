//! Owner proof: the passkey (WebAuthn) ceremonies behind a trait.
//!
//! The server only ever stores [`OwnerCredential::data`], the serialized public
//! credential. Ceremony state stays in memory and is consumed on first use.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use std::{any::Any, fmt};
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Uuid, Webauthn, WebauthnBuilder,
};

/// A registered owner credential as stored (public data only).
#[derive(Clone, Debug)]
pub struct OwnerCredential {
    /// base64url credential id.
    pub cred_id: String,
    /// Implementation-defined serialized public credential.
    pub data: String,
}

/// Opaque, in-memory ceremony state.
pub type CeremonyState = Box<dyn Any + Send>;

/// A successful login.
#[derive(Debug)]
pub struct LoginProof {
    pub cred_id: String,
    /// Updated credential data (e.g. signature counter) to persist.
    pub updated: Option<OwnerCredential>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The client response did not verify.
    Rejected,
    /// State/credential data could not be used.
    Internal,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::Rejected => f.write_str("owner proof rejected"),
            ProofError::Internal => f.write_str("owner proof unavailable"),
        }
    }
}
impl std::error::Error for ProofError {}

/// Passkey registration and login. `options` values are sent to the browser
/// as JSON (`navigator.credentials.create/get` options with base64url buffers);
/// `response` values are the browser's JSON-encoded credential.
pub trait OwnerProof: Send + Sync {
    fn start_registration(
        &self,
        owner_id: &str,
        existing: &[OwnerCredential],
    ) -> Result<(Value, CeremonyState), ProofError>;

    fn finish_registration(
        &self,
        state: CeremonyState,
        response: &Value,
    ) -> Result<OwnerCredential, ProofError>;

    fn start_login(&self, creds: &[OwnerCredential]) -> Result<(Value, CeremonyState), ProofError>;

    fn finish_login(
        &self,
        state: CeremonyState,
        response: &Value,
        creds: &[OwnerCredential],
    ) -> Result<LoginProof, ProofError>;
}

/// Real WebAuthn relying party (webauthn-rs, passkeys with user verification).
pub struct WebauthnOwnerProof {
    webauthn: Webauthn,
}

impl WebauthnOwnerProof {
    /// `rp_id` is the registrable domain (e.g. `mcp.app.stri.nz`); `origin` is
    /// the exact public origin (e.g. `https://mcp.app.stri.nz`).
    pub fn new(rp_id: &str, origin: &Url, rp_name: &str) -> Result<Self, ProofError> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)
            .map_err(|_| ProofError::Internal)?
            .rp_name(rp_name)
            .build()
            .map_err(|_| ProofError::Internal)?;
        Ok(Self { webauthn })
    }

    fn decode(creds: &[OwnerCredential]) -> Result<Vec<Passkey>, ProofError> {
        creds
            .iter()
            .map(|c| serde_json::from_str::<Passkey>(&c.data).map_err(|_| ProofError::Internal))
            .collect()
    }

    fn encode(pk: &Passkey) -> Result<OwnerCredential, ProofError> {
        Ok(OwnerCredential {
            cred_id: URL_SAFE_NO_PAD.encode(pk.cred_id().as_ref()),
            data: serde_json::to_string(pk).map_err(|_| ProofError::Internal)?,
        })
    }
}

impl OwnerProof for WebauthnOwnerProof {
    fn start_registration(
        &self,
        owner_id: &str,
        existing: &[OwnerCredential],
    ) -> Result<(Value, CeremonyState), ProofError> {
        let uuid = Uuid::parse_str(owner_id).map_err(|_| ProofError::Internal)?;
        let exclude: Vec<_> = Self::decode(existing)?
            .iter()
            .map(|pk| pk.cred_id().clone())
            .collect();
        let (options, state) = self
            .webauthn
            .start_passkey_registration(uuid, "owner", "Owner", Some(exclude))
            .map_err(|_| ProofError::Internal)?;
        let options = serde_json::to_value(options).map_err(|_| ProofError::Internal)?;
        Ok((options, Box::new(state)))
    }

    fn finish_registration(
        &self,
        state: CeremonyState,
        response: &Value,
    ) -> Result<OwnerCredential, ProofError> {
        let state = state
            .downcast::<PasskeyRegistration>()
            .map_err(|_| ProofError::Internal)?;
        let response: RegisterPublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|_| ProofError::Rejected)?;
        let pk = self
            .webauthn
            .finish_passkey_registration(&response, &state)
            .map_err(|_| ProofError::Rejected)?;
        Self::encode(&pk)
    }

    fn start_login(&self, creds: &[OwnerCredential]) -> Result<(Value, CeremonyState), ProofError> {
        let passkeys = Self::decode(creds)?;
        if passkeys.is_empty() {
            return Err(ProofError::Internal);
        }
        let (options, state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|_| ProofError::Internal)?;
        let options = serde_json::to_value(options).map_err(|_| ProofError::Internal)?;
        Ok((options, Box::new(state)))
    }

    fn finish_login(
        &self,
        state: CeremonyState,
        response: &Value,
        creds: &[OwnerCredential],
    ) -> Result<LoginProof, ProofError> {
        let state = state
            .downcast::<PasskeyAuthentication>()
            .map_err(|_| ProofError::Internal)?;
        let response: PublicKeyCredential =
            serde_json::from_value(response.clone()).map_err(|_| ProofError::Rejected)?;
        let result = self
            .webauthn
            .finish_passkey_authentication(&response, &state)
            .map_err(|_| ProofError::Rejected)?;
        let mut passkeys = Self::decode(creds)?;
        let pk = passkeys
            .iter_mut()
            .find(|pk| pk.cred_id() == result.cred_id())
            .ok_or(ProofError::Rejected)?;
        let changed = pk.update_credential(&result).unwrap_or(false);
        let cred_id = URL_SAFE_NO_PAD.encode(pk.cred_id().as_ref());
        let updated = if changed {
            Some(Self::encode(pk)?)
        } else {
            None
        };
        Ok(LoginProof { cred_id, updated })
    }
}
