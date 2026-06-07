//! `sentinel-core` is the umbrella crate for the Sentinel Labs trust engine.
//!
//! It re-exports the four building blocks:
//!
//! - [`identity`]: Ed25519 device identity and DIDs
//! - [`attestation`]: signed attestation claims
//! - [`trust`]: deterministic trust scoring
//! - [`audit`]: hash-chained audit log
//!
//! # Example
//! ```
//! use sentinel_core::{
//!     attestation::{Claim, ClaimBody, ClaimKind},
//!     audit::AuditChain,
//!     identity::DeviceIdentity,
//!     trust::{compute, TrustInputs},
//! };
//!
//! let device = DeviceIdentity::generate();
//! let claim = Claim::sign(
//!     &device,
//!     ClaimBody {
//!         kind: ClaimKind::FirmwareHash,
//!         subject: device.did().clone(),
//!         issued_at: chrono::Utc::now(),
//!         nonce: "1".into(),
//!         payload: serde_json::json!({"sha256": "abc"}),
//!     },
//! ).unwrap();
//! claim.verify().unwrap();
//!
//! let score = compute(&TrustInputs {
//!     firmware_verified: true,
//!     verified_telemetry_events: 5,
//!     heartbeat_count: 200,
//!     ..Default::default()
//! });
//! assert!(score.score >= 80);
//!
//! let mut chain = AuditChain::new();
//! chain
//!     .append("robot-1", "attest", serde_json::json!({"claim": claim.body.digest_hex().unwrap()}), Some(&device))
//!     .unwrap();
//! chain.verify().unwrap();
//! ```

pub use sentinel_attestation as attestation;
pub use sentinel_audit as audit;
pub use sentinel_identity as identity;
pub use sentinel_trust as trust;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn end_to_end_flow() {
        let device = identity::DeviceIdentity::generate();

        let body = attestation::ClaimBody {
            kind: attestation::ClaimKind::FirmwareHash,
            subject: device.did().clone(),
            issued_at: chrono::Utc::now(),
            nonce: "boot-1".into(),
            payload: serde_json::json!({"sha256": "00".repeat(32)}),
        };
        let claim = attestation::Claim::sign(&device, body).unwrap();
        claim.verify().unwrap();

        let mut chain = audit::AuditChain::new();
        chain
            .append(
                "robot-1",
                "firmware_attest",
                serde_json::json!({"digest": claim.body.digest_hex().unwrap()}),
                Some(&device),
            )
            .unwrap();
        chain.verify().unwrap();

        let score = trust::compute(&trust::TrustInputs {
            firmware_verified: true,
            verified_telemetry_events: 4,
            anomaly_detected: false,
            key_rotated_within_7_days: true,
            heartbeat_count: 200,
        });
        assert_eq!(score.level, trust::TrustLevel::Verified);
    }
}
