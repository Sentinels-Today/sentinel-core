//! Tamper-evident hash chain for fleet audit events.
//!
//! Each [`AuditEntry`] commits to the previous entry's hash plus its own
//! payload, so any later mutation invalidates the chain. Entries can
//! optionally carry an Ed25519 signature from the device that produced them.

use chrono::{DateTime, Utc};
use sentinel_identity::{verify_hex, DeviceIdentity, IdentityError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("chain is empty")]
    Empty,
    #[error("hash mismatch at index {index} (entry {id})")]
    HashMismatch { index: usize, id: String },
    #[error("previous-hash link broken at index {0}")]
    BrokenLink(usize),
    #[error("invalid signature on entry {0}")]
    InvalidSignature(String),
    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: String,
    pub robot_id: String,
    pub action: String,
    pub details: serde_json::Value,
    pub timestamp: DateTime<Utc>,
    pub previous_hash: Option<String>,
    pub hash: String,
    pub signature_hex: Option<String>,
    pub public_key_hex: Option<String>,
}

#[derive(Default, Debug)]
pub struct AuditChain {
    entries: Vec<AuditEntry>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn tail_hash(&self) -> Option<&str> {
        self.entries.last().map(|e| e.hash.as_str())
    }

    /// Append a new entry. If `signer` is `Some`, the entry is signed.
    pub fn append(
        &mut self,
        robot_id: impl Into<String>,
        action: impl Into<String>,
        details: serde_json::Value,
        signer: Option<&DeviceIdentity>,
    ) -> Result<&AuditEntry, AuditError> {
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let previous_hash = self.entries.last().map(|e| e.hash.clone());
        let robot_id = robot_id.into();
        let action = action.into();

        let hash = sha256_hex(&preimage(
            &id,
            &robot_id,
            &action,
            &details,
            &timestamp,
            previous_hash.as_deref(),
        ));

        let (signature_hex, public_key_hex) = if let Some(s) = signer {
            (Some(s.sign_hex(hash.as_bytes())), Some(s.public_key_hex()))
        } else {
            (None, None)
        };

        let entry = AuditEntry {
            id,
            robot_id,
            action,
            details,
            timestamp,
            previous_hash,
            hash,
            signature_hex,
            public_key_hex,
        };
        self.entries.push(entry);
        Ok(self.entries.last().unwrap())
    }

    /// Verify the chain is well-formed: every hash matches its preimage and
    /// every signed entry has a valid signature.
    pub fn verify(&self) -> Result<(), AuditError> {
        let mut previous: Option<&str> = None;
        for (i, e) in self.entries.iter().enumerate() {
            let expected = sha256_hex(&preimage(
                &e.id,
                &e.robot_id,
                &e.action,
                &e.details,
                &e.timestamp,
                previous,
            ));
            if expected != e.hash {
                return Err(AuditError::HashMismatch {
                    index: i,
                    id: e.id.clone(),
                });
            }
            if e.previous_hash.as_deref() != previous {
                return Err(AuditError::BrokenLink(i));
            }
            if let (Some(sig), Some(pk)) = (e.signature_hex.as_deref(), e.public_key_hex.as_deref())
            {
                let ok = verify_hex(pk, e.hash.as_bytes(), sig)?;
                if !ok {
                    return Err(AuditError::InvalidSignature(e.id.clone()));
                }
            }
            previous = Some(e.hash.as_str());
        }
        Ok(())
    }
}

fn preimage(
    id: &str,
    robot_id: &str,
    action: &str,
    details: &serde_json::Value,
    timestamp: &DateTime<Utc>,
    previous_hash: Option<&str>,
) -> String {
    format!(
        "{id}|{robot}|{action}|{details}|{ts}|{prev}",
        id = id,
        robot = robot_id,
        action = action,
        details = serde_json::to_string(details).unwrap_or_default(),
        ts = timestamp.to_rfc3339(),
        prev = previous_hash.unwrap_or("")
    )
}

fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appended_chain_verifies() {
        let mut chain = AuditChain::new();
        chain
            .append("robot-1", "boot", serde_json::json!({"ok": true}), None)
            .unwrap();
        chain
            .append(
                "robot-1",
                "telemetry",
                serde_json::json!({"temp": 42}),
                None,
            )
            .unwrap();
        chain.verify().unwrap();
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn tampering_breaks_chain() {
        let mut chain = AuditChain::new();
        chain
            .append("r", "a", serde_json::json!({"x": 1}), None)
            .unwrap();
        chain
            .append("r", "b", serde_json::json!({"x": 2}), None)
            .unwrap();
        // Mutate the first entry's details.
        chain.entries[0].details = serde_json::json!({"x": 99});
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditError::HashMismatch { .. }));
    }

    #[test]
    fn signed_entries_verify() {
        let id = DeviceIdentity::generate();
        let mut chain = AuditChain::new();
        chain
            .append("r", "boot", serde_json::json!({}), Some(&id))
            .unwrap();
        chain
            .append("r", "telemetry", serde_json::json!({"v": 1}), Some(&id))
            .unwrap();
        chain.verify().unwrap();
    }

    #[test]
    fn forged_signature_is_rejected() {
        let id = DeviceIdentity::generate();
        let mut chain = AuditChain::new();
        chain
            .append("r", "boot", serde_json::json!({}), Some(&id))
            .unwrap();
        // Replace signature with garbage of correct length.
        chain.entries[0].signature_hex = Some("00".repeat(64));
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditError::InvalidSignature(_)));
    }
}
