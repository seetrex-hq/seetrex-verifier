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

The crate has shipped an installable binary of the same name since 0.3.0
(0.2.0 was library-only). Install the current version, `0.3.8`: the `0.3.0`
and `0.3.1` binaries printed a `verify-chain` trailer that overstated the
scope of that check, and must not be used as the executable.

```console
cargo install seetrex-verifier --locked --version 0.3.8

seetrex-verifier verify-package <dir> [--expected-verdict-hash <hex>]
seetrex-verifier verify-chain <chain-export.json>
seetrex-verifier verify-anchor <anchor.json> --kit <kit.json>
                               [--monitor <bundle.json>] [--chain <chain.json>]
seetrex-verifier emit-sbom --kind <cargo|composer|npm> --lockfile <path>
                           [--manifest <composer.json>] --subject <purl>
                           --out <path>
seetrex-verifier verify-sbom --kind <cargo|composer|npm> --lockfile <path>
                             [--manifest <composer.json>] --subject <purl>
                             --sbom <path> [--third-party] [--dep-v0 <elf>]
```

`verify-record` is new in 0.3.8, see Records below.
`verify-anchor` is new in 0.3.3 and its `--chain` input in 0.3.4; the two SBOM
subcommands are new in 0.3.4.

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

`verify-anchor` checks a producer-published anchor package OFFLINE against a
transparency log's cosigned checkpoint, under the policy pinned in the auditor
`kit.json`. From 0.3.8, a `seetrex/anchor-kit/v2` kit also pins the public keys of the identity: the submitter signatures of the anchored leaves and followed rotations are checked (an invalid one is exit 1; a key derived from the rotations of the package or of a monitor bundle that the kit lacks is exit 2, which prevails over a COMPLETITUD FAILED), and a monitor leaf in the log under a key of the kit without its signature is discarded and counted; one that does not include or serialize is FAILED, as under a v1 kit. A v1 kit prints NOT CHECKED, and 0.3.7 refuses a v2 kit, checks no signature and does not say so. With `--monitor` it also confronts the package with an independent
enumeration of the log. `--chain` supplies the producer's published chain
export as the reference the truncation rule judges against: without it, a head
beyond the package's rows is reported INCONCLUSIVE and the exit code stays 0,
so read the COMPLETITUD line and not the exit status alone.

`emit-sbom` writes the canonical `lockfile-v1` projection of a dependency
lockfile and prints its SHA-256 and nothing else; it verifies nothing and never
exits 1. `verify-sbom` re-derives that projection from the auditor's own
lockfile and confronts an untrusted document with it, exiting 0 only on byte
identity.

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
   which is not open source. It is available on request as a signed,
   reproducibly built binary (black box), or as a source rebuild under
   NDA for regulators.

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

## Records

```console
seetrex-verifier verify-record <record.json> [--kit <kit.json>]
```

`verify-record` is new in 0.3.8, and 0.3.7 does not have it. It checks a `seetrex.record.v1` file offline: the whole chain
it carries, then the walk from its last proved row through the batch chain
`oss-batches` to a leaf of the cosigned log, under the policy of a `kit.json`
whose tenant is `oss-batches`. Exit 0 means the anchor is confirmed; read how
many rows are not anchored yet, and note that it proves existence, not
completeness, and does not detect a chain cut back from the end. Exit 4 means
the chain holds and the record has no anchor: neither a failure nor a pass, and
not a promise that one will follow. Setting `anchor` to null gives exit 4 to any
record whose chain holds, also to one that with its proof would exit 1; with the
chain broken the exit is 1 all the same.

Limits of the anchor it confirms: `rotations` is material chosen by whoever
presents the record and there is no monitor, so a fork left out of it is not
detected; a rotated key is not revoked; `anomalous rotations` does not change the
exit code. A proof needs a `seetrex/anchor-kit/v2` kit, whose `identity_pubkeys`
check the submitter signature of the leaf and of every followed rotation; a v1 kit
with a proof, or a derived key the kit lacks, is exit 2. The witnesses cosign the
consistency of the log, not the validity of its leaves, and the operator of the log
can withhold or delay leaves, so it stays part of what you trust. A
`repository_as_told` that is not a plain `owner/repo`
of at most 256 bytes prints as `<hex:...>`.

`verify-chain` does not read a record: the whole file is exit 1. It takes the
`chain` member extracted into a file of its own (`jq .chain record.json`). Its
comparison with the Trust Center does not apply to the chain of a private
repository, which is published nowhere.

In `oss-batches-chain.json`, `verdict_outcome` and `ruleset_id` are batch
metadata the row format requires, not verdicts: no engine evaluated anything,
and `verdict_hash` is a Merkle root with no package behind it. `verify-chain`
passes over that file as over any other, `verify-package` does not apply, and
the format's `schema_version` is unchanged.
