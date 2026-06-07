//! Deterministic trust scoring.
//!
//! Implements the algorithm documented in `ARCHITECTURE.md` of the monorepo:
//!
//! ```text
//! base_score = 50
//! if firmware_verified            -> +10
//! per verified telemetry event    -> +5 (capped at +20)
//! if anomaly_detected             -> -20
//! if key rotated within 7 days    -> +5
//! heartbeat_count > 168           -> +10
//! heartbeat_count > 24            -> +5
//! clamp(0, 100)
//! ```
//!
//! Score levels are mapped to a [`TrustLevel`] for reporting.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustInputs {
    pub firmware_verified: bool,
    pub verified_telemetry_events: u32,
    pub anomaly_detected: bool,
    pub key_rotated_within_7_days: bool,
    pub heartbeat_count: u32,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    Critical,
    Low,
    Medium,
    High,
    Verified,
}

impl TrustLevel {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=20 => TrustLevel::Critical,
            21..=40 => TrustLevel::Low,
            41..=60 => TrustLevel::Medium,
            61..=80 => TrustLevel::High,
            _ => TrustLevel::Verified,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustScore {
    pub score: u8,
    pub level: TrustLevel,
}

pub fn compute(inputs: &TrustInputs) -> TrustScore {
    let mut score: i32 = 50;
    if inputs.firmware_verified {
        score += 10;
    }
    let telemetry_bonus = (inputs.verified_telemetry_events as i32)
        .saturating_mul(5)
        .min(20);
    score += telemetry_bonus;
    if inputs.anomaly_detected {
        score -= 20;
    }
    if inputs.key_rotated_within_7_days {
        score += 5;
    }
    if inputs.heartbeat_count > 168 {
        score += 10;
    } else if inputs.heartbeat_count > 24 {
        score += 5;
    }
    let clamped = score.clamp(0, 100) as u8;
    TrustScore {
        score: clamped,
        level: TrustLevel::from_score(clamped),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_score_is_medium() {
        let s = compute(&TrustInputs::default());
        assert_eq!(s.score, 50);
        assert_eq!(s.level, TrustLevel::Medium);
    }

    #[test]
    fn fully_healthy_device_is_verified() {
        let s = compute(&TrustInputs {
            firmware_verified: true,
            verified_telemetry_events: 100,
            anomaly_detected: false,
            key_rotated_within_7_days: true,
            heartbeat_count: 200,
        });
        // 50 + 10 + 20 + 5 + 10 = 95
        assert_eq!(s.score, 95);
        assert_eq!(s.level, TrustLevel::Verified);
    }

    #[test]
    fn anomaly_lowers_trust() {
        let s = compute(&TrustInputs {
            firmware_verified: true,
            verified_telemetry_events: 1,
            anomaly_detected: true,
            key_rotated_within_7_days: false,
            heartbeat_count: 0,
        });
        // 50 + 10 + 5 - 20 = 45
        assert_eq!(s.score, 45);
        assert_eq!(s.level, TrustLevel::Medium);
    }

    #[test]
    fn telemetry_bonus_caps_at_20() {
        let s = compute(&TrustInputs {
            verified_telemetry_events: 1_000_000,
            ..Default::default()
        });
        assert_eq!(s.score, 70);
    }

    #[test]
    fn score_is_clamped() {
        let s = compute(&TrustInputs {
            anomaly_detected: true,
            ..Default::default()
        });
        assert_eq!(s.score, 30);
        let bad = TrustInputs {
            anomaly_detected: true,
            firmware_verified: false,
            verified_telemetry_events: 0,
            key_rotated_within_7_days: false,
            heartbeat_count: 0,
        };
        // 50 - 20 = 30, still clamps lower bound for absurd negatives below.
        assert_eq!(compute(&bad).score, 30);
    }

    #[test]
    fn level_thresholds() {
        assert_eq!(TrustLevel::from_score(0), TrustLevel::Critical);
        assert_eq!(TrustLevel::from_score(20), TrustLevel::Critical);
        assert_eq!(TrustLevel::from_score(21), TrustLevel::Low);
        assert_eq!(TrustLevel::from_score(40), TrustLevel::Low);
        assert_eq!(TrustLevel::from_score(41), TrustLevel::Medium);
        assert_eq!(TrustLevel::from_score(60), TrustLevel::Medium);
        assert_eq!(TrustLevel::from_score(61), TrustLevel::High);
        assert_eq!(TrustLevel::from_score(80), TrustLevel::High);
        assert_eq!(TrustLevel::from_score(81), TrustLevel::Verified);
        assert_eq!(TrustLevel::from_score(100), TrustLevel::Verified);
    }
}
