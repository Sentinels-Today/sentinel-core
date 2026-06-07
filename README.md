# sentinel-core

**Trust engine for autonomous systems** — identity, attestation, trust scoring, and tamper-evident audit. Written in Rust.

[![ci](https://github.com/Sentinels-Today/sentinel-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Sentinels-Today/sentinel-core/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![rust](https://img.shields.io/badge/rust-1.75%2B-orange)

## Crates

| Crate | What it does |
|---|---|
| [`sentinel-identity`](./crates/sentinel-identity) | Ed25519 device keypair + `did:sentinel:<hex>` identifiers |
| [`sentinel-attestation`](./crates/sentinel-attestation) | Signed attestation claims (firmware hash, measured boot, SBOM) |
| [`sentinel-trust`](./crates/sentinel-trust) | Deterministic trust scoring (`0..=100` + level) |
| [`sentinel-audit`](./crates/sentinel-audit) | SHA-256 hash-chained audit log with optional per-entry Ed25519 signatures |
| [`sentinel-core`](./crates/sentinel-core) | Umbrella crate that re-exports the four building blocks |

## Quick start

```rust
use sentinel_core::{
    attestation::{Claim, ClaimBody, ClaimKind},
    audit::AuditChain,
    identity::DeviceIdentity,
    trust::{compute, TrustInputs},
};

let device = DeviceIdentity::generate();
let claim = Claim::sign(&device, ClaimBody {
    kind: ClaimKind::FirmwareHash,
    subject: device.did().clone(),
    issued_at: chrono::Utc::now(),
    nonce: "1".into(),
    payload: serde_json::json!({"sha256": "abc"}),
})?;
claim.verify()?;

let mut chain = AuditChain::new();
chain.append("robot-1", "attest", serde_json::json!({}), Some(&device))?;
chain.verify()?;
```

## Develop

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).

## About

Part of [Sentinel Labs](https://sentinels.today). Other components:
[`sentinel-agent`](https://github.com/Sentinels-Today/sentinel-agent) ·
[`sentinel-cloud`](https://github.com/Sentinels-Today/sentinel-cloud) ·
[`sentinel-dashboard`](https://github.com/Sentinels-Today/sentinel-dashboard) ·
[`sentinel-sdk`](https://github.com/Sentinels-Today/sentinel-sdk) ·
[`sentinel-chain`](https://github.com/Sentinels-Today/sentinel-chain) ·
[`sentinel-cli`](https://github.com/Sentinels-Today/sentinel-cli)
