//! Attestation claims for Sentinel Labs.
//!
//! A [`Claim`] is a structured statement about a device (firmware hash,
//! measured boot PCR digest, software bill of materials, etc.) signed with the
//! device's Ed25519 identity key. Verification recomputes the canonical hash
//! and checks the signature against the registered public key.

use chrono::{DateTime, Utc};
use sentinel_identity::{verify_hex, DeviceIdentity, Did, IdentityError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    FirmwareHash,
    MeasuredBoot,
    SoftwareBom,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimBody {
    pub kind: ClaimKind,
    pub subject: Did,
    pub issued_at: DateTime<Utc>,
    pub nonce: String,
    pub payload: serde_json::Value,
}

impl ClaimBody {
    /// Canonical JSON (sorted keys) used as the signing pre-image.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AttestationError> {
        let v = serde_json::to_value(self)?;
        let canonical = canonicalize(&v);
        Ok(canonical.into_bytes())
    }

    pub fn digest_hex(&self) -> Result<String, AttestationError> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex::encode(hasher.finalize()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claim {
    pub body: ClaimBody,
    pub signature_hex: String,
    pub public_key_hex: String,
}

impl Claim {
    pub fn sign(identity: &DeviceIdentity, body: ClaimBody) -> Result<Self, AttestationError> {
        let bytes = body.canonical_bytes()?;
        let signature_hex = identity.sign_hex(&bytes);
        Ok(Self {
            body,
            signature_hex,
            public_key_hex: identity.public_key_hex(),
        })
    }

    pub fn verify(&self) -> Result<(), AttestationError> {
        let bytes = self.body.canonical_bytes()?;
        let ok = verify_hex(&self.public_key_hex, &bytes, &self.signature_hex)?;
        if ok {
            Ok(())
        } else {
            Err(AttestationError::InvalidSignature)
        }
    }
}

/// Stable canonical JSON: object keys sorted lexicographically, no whitespace.
fn canonicalize(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let inner: Vec<String> = entries
                .into_iter()
                .map(|(k, val)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap(),
                        canonicalize(val)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonicalize).collect();
            format!("[{}]", inner.join(","))
        }
        _ => serde_json::to_string(v).unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body(id: &DeviceIdentity) -> ClaimBody {
        ClaimBody {
            kind: ClaimKind::FirmwareHash,
            subject: id.did().clone(),
            issued_at: Utc::now(),
            nonce: "n-1".into(),
            payload: serde_json::json!({"sha256": "deadbeef", "version": "1.2.3"}),
        }
    }

    #[test]
    fn sign_and_verify() {
        let id = DeviceIdentity::generate();
        let claim = Claim::sign(&id, sample_body(&id)).unwrap();
        claim.verify().unwrap();
    }

    #[test]
    fn verify_fails_on_tampered_payload() {
        let id = DeviceIdentity::generate();
        let mut claim = Claim::sign(&id, sample_body(&id)).unwrap();
        claim.body.payload = serde_json::json!({"sha256": "feedface"});
        assert!(matches!(
            claim.verify(),
            Err(AttestationError::InvalidSignature)
        ));
    }

    #[test]
    fn canonical_form_is_order_independent() {
        let id = DeviceIdentity::generate();
        let body = ClaimBody {
            kind: ClaimKind::Custom,
            subject: id.did().clone(),
            issued_at: Utc::now(),
            nonce: "x".into(),
            payload: serde_json::json!({"b": 1, "a": 2}),
        };
        let body2 = ClaimBody {
            payload: serde_json::json!({"a": 2, "b": 1}),
            ..body.clone()
        };
        assert_eq!(body.digest_hex().unwrap(), body2.digest_hex().unwrap());
    }
}
