# seetrex-verifier

The pure verification core for Seetrex Compliance verdict packages. It holds
the code that recomputes and verifies the cryptographic quantities of a
compliance verdict from its canonical inputs — hash integrity, not engine
re-execution (full re-derivation is `compliance-cli replay --full`, which
consumes this crate and adds the inference engine on top):

- **verdict preimage v1/v2** — `VerdictCanonicalInput` + JCS RFC 8785 + SHA-256
  (`compute_verdict_hash`, `compute_verdict_hash_v1`, `format_derived_at`);
- **audit chain link** — `compute_chain_hash`;
- **public chain export** — the export envelope/row types and their offline
  verification (`parse_and_verify_package`, `verify_public_chain`);
- **ruleset anchor** — `RulesetFile` parsing, strict unknown-key validation and
  `ruleset_content_hash_hex`;
- **evidence content hash** — `canonicalize`, routed through the shared
  format-layer JCS primitive;
- **package integrity** — `verify_package`, the offline package-integrity
  check the CLI is a thin shell over.

## Command-line tool

Since 0.3.0 the crate ships an installable binary of the same name
(0.2.0 was library-only):

```console
cargo install seetrex-verifier

seetrex-verifier verify-package <dir> [--expected-verdict-hash <hex>]
seetrex-verifier verify-chain <chain-export.json>
```

`verify-package` is the package-integrity check of spec section 9.6 — it
re-computes hashes only. Its outcome vocabulary and exit codes are the
binding ones of the spec: an anchored pass prints `INTEGRITY-OK (weak)`
and exits 0; a pass without an external anchor prints
`SELF-CONSISTENT (unanchored)` and exits 4 (NOT a verification — a
coherent forgery is self-consistent by construction); any failure exits 1.
Always pass `--expected-verdict-hash` with a value obtained OUTSIDE the
package (e.g. from the published chain export).

`verify-chain` verifies a downloaded public chain export fully offline
(spec section 8.1): it recomputes every SHA-256 link and reports the
chain head (`verdict_count`, `last_chain_hash`) to compare against the
published tenant page. Exit 0 on success, 1 on any failure.

This is the SAME code the `compliance-cli` runs — not a replica. An auditor
compiles exactly what production ran. The crate depends only on
`seetrex-format` (the pure format layer: serializable types + JCS
canonicalization); it has zero database, zero network and zero HTTP
dependencies by design (enforced by
`test_intent_verifier_crate_dependency_purity`).

## Open-source boundary

What is open (Apache-2.0, published at each signed release tag):

- `seetrex-format` — the serializable types and the JCS canonicalization
  primitive that define the verdict-package format;
- `seetrex-verifier` — this crate, the offline verification core;
- the byte-level package specification (`SPEC_VERDICT_PACKAGE_V1.md`) and the
  auditor-facing documentation.

What is closed (proprietary): the inference engine (`seetrex-core`), the
derivation dispatcher, the derivation connectors, ingest, the SaaS backend
and the UI.

This boundary is deliberate, and it splits verification into two legs:

1. **Record integrity — fully independent.** Using only public material
   (this repository, the published crates, the spec and a signed release),
   a third party can verify every cryptographic quantity of a verdict
   package with no vendor involvement at all: per-file hashes, evidence
   against its references, the ruleset content hash, the `verdict_hash`
   preimage, the audit chain links and the external anchor.
2. **Outcome re-derivation — engine execution required.** Recomputing the
   verdict *outcome* from the derived facts re-runs the inference engine,
   which is not open source. It is available as a signed, reproducibly
   built binary (black box), or as a source rebuild under NDA for
   regulators.

Leg 1 needs nothing from us. Leg 2 is stated here explicitly so that the
guarantee is never oversold: this crate proves integrity of the record, not
re-execution of the engine.

## Reproducible builds

Reproducibility is pinned at the repository level, not per-crate:

- repo-root `rust-toolchain.toml` (channel `1.91.1`);
- workspace `Cargo.lock`.

There is deliberately NO per-crate `rust-toolchain.toml`.

## Spec

The byte-level package format is specified in `docs/SPEC_VERDICT_PACKAGE_V1.md`.
