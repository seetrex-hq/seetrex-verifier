# Seetrex Verifier

Open-source format definition and reference verifier for **Seetrex
Compliance** verdict packages.

A verdict package is a self-contained evidence bundle: the facts, evidence,
ruleset and audit-chain material behind a single compliance verdict, with
every quantity hashed and chained so its integrity can be verified offline.
This repository contains everything needed to perform that verification
independently:

| Component | What it is |
|---|---|
| [`crates/format`](crates/format) | `seetrex-format` — the serializable types and the JCS (RFC 8785) canonicalization primitive that define the verdict-package format |
| [`crates/verifier`](crates/verifier) | `seetrex-verifier` — the pure offline verification core: per-file hashes, evidence references, ruleset content hash, verdict preimage, audit chain links |
| [`docs/SPEC_VERDICT_PACKAGE_V1.md`](docs/SPEC_VERDICT_PACKAGE_V1.md) | The byte-level package specification |

## What this proves — and what it does not

Verification splits into two legs:

1. **Record integrity — fully independent.** Using only public material
   (this repository, the published crates, the spec and a signed release),
   a third party can verify every cryptographic quantity of a verdict
   package — per-file hashes, evidence against its references, the ruleset
   content hash, the `verdict_hash` preimage, the audit chain links and the
   external anchor — with no vendor involvement at all.
2. **Outcome re-derivation — engine execution required.** Recomputing the
   verdict *outcome* from the derived facts re-runs the inference engine,
   which is not open source. It is available as a signed, reproducibly
   built binary (black box), or as a source rebuild under NDA for
   regulators.

Leg 1 needs nothing from the vendor. Leg 2 is stated here explicitly so the
guarantee is never oversold: this repository proves integrity of the
record, not re-execution of the engine.

## Building

The build is pinned:

- Rust toolchain: `rust-toolchain.toml` (channel 1.91.1);
- dependencies: `Cargo.lock`, committed in this repository.

```bash
cargo build --locked
cargo test --locked
```

## Getting the verification tool

`seetrex-verifier` (0.3.0 and later) ships an installable command-line
binary of the same name:

```bash
cargo install seetrex-verifier

seetrex-verifier verify-package <dir> [--expected-verdict-hash <hex>]
seetrex-verifier verify-chain <chain-export.json>
```

See [`crates/verifier`](crates/verifier) for the outcome vocabulary and
exit codes (they follow the spec, section 9.6).

## License

`seetrex-format` and `seetrex-verifier` are licensed under the Apache
License, Version 2.0 — see the repository `LICENSE` and each crate's
`LICENSE` and `NOTICE` files. The license does not grant trademark rights;
see the trademark note in each `NOTICE`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This public repository is
regenerated from a curated export of a private source of truth at every
signed release tag; accepted pull requests are ported into the private
repository and attribution is preserved in `NOTICE` and the release
`CHANGELOG`. A DCO sign-off (`git commit -s`) is required on every commit.
