//! Device identity primitives for Sentinel Labs.
//!
//! A [`DeviceIdentity`] pairs an Ed25519 keypair with a deterministic
//! decentralized identifier (`did:sentinel:<hex>`). Identities can sign and
//! verify arbitrary byte payloads.

use std::fmt;

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid public key length: expected 32 bytes, got {0}")]
    InvalidPublicKey(usize),
    #[error("invalid secret key length: expected 32 bytes, got {0}")]
    InvalidSecretKey(usize),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("invalid did format: {0}")]
    InvalidDid(String),
    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Decentralized identifier in the form `did:sentinel:<64-hex-chars>`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

impl Did {
    pub const PREFIX: &'static str = "did:sentinel:";

    pub fn from_public_key(pk: &VerifyingKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pk.as_bytes());
        let digest = hasher.finalize();
        Did(format!("{}{}", Self::PREFIX, hex::encode(digest)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parse(s: &str) -> Result<Self, IdentityError> {
        if !s.starts_with(Self::PREFIX) {
            return Err(IdentityError::InvalidDid(format!(
                "missing `{}` prefix",
                Self::PREFIX
            )));
        }
        let body = &s[Self::PREFIX.len()..];
        if body.len() != 64 {
            return Err(IdentityError::InvalidDid(format!(
                "expected 64-hex body, got {} chars",
                body.len()
            )));
        }
        // Ensure body is valid hex.
        hex::decode(body)?;
        Ok(Did(s.to_string()))
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Full device identity (signing + verifying key pair).
pub struct DeviceIdentity {
    signing: SigningKey,
    did: Did,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let did = Did::from_public_key(&signing.verifying_key());
        Self { signing, did }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidSecretKey(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        let signing = SigningKey::from_bytes(&arr);
        let did = Did::from_public_key(&signing.verifying_key());
        Ok(Self { signing, did })
    }

    pub fn did(&self) -> &Did {
        &self.did
    }

    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().as_bytes())
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.signing.sign(payload)
    }

    pub fn sign_hex(&self, payload: &[u8]) -> String {
        hex::encode(self.sign(payload).to_bytes())
    }
}

/// Public-facing record stored in the registry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceRecord {
    pub did: Did,
    pub public_key_hex: String,
    pub registered_at: DateTime<Utc>,
    pub metadata: serde_json::Value,
}

impl DeviceRecord {
    pub fn new(identity: &DeviceIdentity, metadata: serde_json::Value) -> Self {
        Self {
            did: identity.did().clone(),
            public_key_hex: identity.public_key_hex(),
            registered_at: Utc::now(),
            metadata,
        }
    }

    pub fn verifying_key(&self) -> Result<VerifyingKey, IdentityError> {
        let bytes = hex::decode(&self.public_key_hex)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidPublicKey(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr).map_err(|e| IdentityError::InvalidSignature(e.to_string()))
    }
}

/// Verify an Ed25519 signature against a hex-encoded public key and signature.
pub fn verify_hex(
    public_key_hex: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<bool, IdentityError> {
    let pk_bytes = hex::decode(public_key_hex)?;
    if pk_bytes.len() != 32 {
        return Err(IdentityError::InvalidPublicKey(pk_bytes.len()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| IdentityError::InvalidSignature(e.to_string()))?;

    let sig_bytes = hex::decode(signature_hex)?;
    if sig_bytes.len() != 64 {
        return Err(IdentityError::InvalidSignature(format!(
            "expected 64-byte signature, got {}",
            sig_bytes.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    Ok(vk.verify(payload, &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_unique_identities() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        assert_ne!(a.did(), b.did());
        assert_ne!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn did_is_deterministic_from_public_key() {
        let id = DeviceIdentity::generate();
        let recomputed = Did::from_public_key(&id.public_key());
        assert_eq!(id.did(), &recomputed);
        assert!(id.did().as_str().starts_with(Did::PREFIX));
        assert_eq!(id.did().as_str().len(), Did::PREFIX.len() + 64);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = DeviceIdentity::generate();
        let payload = b"telemetry-event-42";
        let sig = id.sign_hex(payload);
        let ok = verify_hex(&id.public_key_hex(), payload, &sig).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_fails_on_tampered_payload() {
        let id = DeviceIdentity::generate();
        let sig = id.sign_hex(b"original");
        let ok = verify_hex(&id.public_key_hex(), b"tampered", &sig).unwrap();
        assert!(!ok);
    }

    #[test]
    fn restores_from_secret_bytes() {
        let id = DeviceIdentity::generate();
        let bytes = id.secret_bytes();
        let restored = DeviceIdentity::from_secret_bytes(&bytes).unwrap();
        assert_eq!(id.did(), restored.did());
        assert_eq!(id.public_key_hex(), restored.public_key_hex());
    }

    #[test]
    fn did_parse_round_trip() {
        let id = DeviceIdentity::generate();
        let s = id.did().to_string();
        let parsed = Did::parse(&s).unwrap();
        assert_eq!(parsed, *id.did());
    }

    #[test]
    fn did_parse_rejects_bad_input() {
        assert!(Did::parse("not-a-did").is_err());
        assert!(Did::parse("did:sentinel:short").is_err());
        assert!(Did::parse(&format!("did:sentinel:{}", "z".repeat(64))).is_err());
    }

    #[test]
    fn device_record_round_trip() {
        let id = DeviceIdentity::generate();
        let rec = DeviceRecord::new(&id, serde_json::json!({"model": "r2d2"}));
        let json = serde_json::to_string(&rec).unwrap();
        let back: DeviceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, back);
        let vk = back.verifying_key().unwrap();
        assert_eq!(vk.as_bytes(), id.public_key().as_bytes());
    }
}
