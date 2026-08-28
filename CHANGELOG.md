# Changelog

All notable changes to the public Seetrex verification crates
(`seetrex-format` and `seetrex-verifier`) are recorded here.

This repository is regenerated from a curated export at every signed release
tag, so this file is the durable record of what changed in each published
version; entries are ported from the private development history. Contributors
of accepted changes are credited here and in `NOTICE`.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the crates aim to follow [Semantic Versioning](https://semver.org/). Each
entry's release date is the date of its signed tag.

## [Unreleased]

Nothing is released here yet. What follows is what this tree holds and no
signed tag carries.

## [seetrex-verifier 0.3.5] — 2026-08-28

Test-harness scaffolding, plus two corrections to the documents that travel
inside the `.crate`. This is also the first release whose signed tag is built
to carry prebuilt, signed release binaries: a signing workflow attaches, to the
GitHub release of the tag, one executable for each of the linux musl targets it
was dispatched for (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`),
a `SHA256SUMS` list covering the artifacts it built, and a detached signature
over that list made with the same release-signing key the tags carry. A run can
be asked for a single target, so a release may carry just one executable, and
the signed list is what says which; a release carrying no `SHA256SUMS`
publishes no binary at all. An executable for a target the runner cannot
execute - the runner is x86_64, so the aarch64 one - is built and signed there
and never run there: such an asset is published as built and signed, and claims
nothing about having been run.

`compliance` and `seetrex-witness` pin the crate with `=0.3.5`, and the auditor
kit pins the same string. Existing commands, formats and exit codes are
unchanged: the `src/` tree of this release is byte-identical to the one
at the `0.3.4` tag (measured with a recursive diff against a fresh clone of
that tag), so no code, no signature and no output moved. Measured the same
way, the files of this crate that differ from that tag are five: the
`version` line of `Cargo.toml`, `tests/bin_e2e.rs`, the label line of
`tests/fixtures/help_exit_codes.tsv`, `README.md` and this file.

### Changed
- The CLI end-to-end test suite (`tests/bin_e2e.rs`) now honours
  the environment variable `SEETREX_VERIFIER_BIN`: when it is set, the suite
  spawns the executable it names instead of the one the build just produced, so
  the same tests that define the tool's behaviour can be pointed at a prebuilt
  binary and answer whether it yields the same verdicts. **The default is
  unchanged**: with the variable unset - which is how every ordinary
  `cargo test` runs it, and how every CI leg runs it except the one that exists
  to point the suite at a prebuilt executable, which sets it deliberately - the
  suite spawns the binary Cargo built, exactly as before, and a test pins that
  default. This is test-harness scaffolding only:
  **no command, no option, no output format, no verdict word and no exit code
  moves**, the shipped library and binary surfaces are untouched, and the
  variable has no effect whatsoever on the `seetrex-verifier` executable itself
  - only on which executable the test suite runs.

### Fixed
- CHANGELOG: the `0.3.4` entry below claimed that existing commands, formats and
  exit codes were all unchanged. The exit codes were NOT, and that entry's own
  `--chain` bullet says so: run WITHOUT `--chain`, `verify-anchor` answers a head
  beyond the anchor package's rows with `INCONCLUSIVE` and exit 0 where `0.3.3`
  answered `FAILED` and exit 1 - same invocation, same arguments, same artifacts.
  The entry is corrected in this tree, under a `### Changed` heading it did not
  have. The `.crate` published to crates.io as `0.3.4` is IMMUTABLE and still
  carries the wrong sentence, so an auditor reading the CHANGELOG inside that
  tarball is reading a false one; this note is the correction, and it reaches
  crates.io with the next release and no sooner.
- `README.md`: the command-line section listed `verify-package` and
  `verify-chain` only, so three subcommands the `0.3.4` binary offers -
  `verify-anchor`, `emit-sbom` and `verify-sbom` - were missing from the file
  that travels INSIDE the `.crate`. Corrected in this tree; the published `0.3.4`
  tarball keeps the short list.

## [seetrex-verifier 0.3.4] — 2026-08-27

Canonical SBOM projection, and the input that makes the anchor package's
truncation rule decidable. Both are PUBLISHED by this release: the signed tag
`seetrex-verifier-v0.3.4` carries `emit-sbom`, `verify-sbom` and
`verify-anchor --chain`, and an auditor who installs `seetrex-verifier
--version 0.3.4` from crates.io obtains all three. The preceding `0.3.3`
carries none of them.

`compliance` and `seetrex-witness` pin the crate with `=0.3.4`, and the auditor
kit pins the same string. Existing commands and formats are unchanged, and the
additions to the library surface are additive except for one new field on
`AnchoredPackageReport`, called out below. Exit codes are NOT all unchanged: one
existing invocation of `verify-anchor` changes its verdict word and its exit
status, under `### Changed`.

### Added
- `emit-sbom --kind <cargo|composer|npm> --lockfile <f> [--manifest <f>]
  --subject <purl> --out <f>`: writes the canonical `lockfile-v1` projection of
  a dependency lockfile (spec `SPEC_SBOM_CANONICAL_V1.md`) and prints its
  SHA-256 on stdout and nothing else, so `sha256sum <out>` reproduces the
  printed digest with stock coreutils. It verifies nothing and therefore never
  exits 1: its only failure class is the auditor's own, exit 2.
- `verify-sbom --kind <...> --lockfile <f> [--manifest <f>] --subject <purl>
  --sbom <f> [--third-party] [--dep-v0 <elf>]`: re-derives the projection from
  the AUDITOR's lockfile and confronts the untrusted document with it. The
  subject is an input and is never read from the document. Exit 0 only on byte
  identity; `--third-party` is the lenient path for a document another tool
  produced and never exits 0; `--dep-v0` additionally confronts the projection
  with the `.dep-v0` section a `cargo auditable` binary carries about itself.
- Library modules backing the pair, all public under `sbom`: the three lockfile
  readers, the canonical document builder, the comparison reader and reporter,
  and the ELF `.dep-v0` extractor.
- `verify-anchor ... [--chain <chain.json>]`: the producer's CURRENT published
  chain export, the input that makes COMPLETITUD's truncation rule (`G-v6-2`)
  DECIDABLE. An anchor package is a SNAPSHOT of the chain emitted on the
  producer's packaging cadence while heads reach the log on a faster one, so the
  package legitimately LAGS the log. Judged against the package alone, an
  enumerated head beyond its rows is indistinguishable from a producer that
  DELETED those rows, and until this change the tool reported that ambiguity as
  `COMPLETITUD: FAILED ... rows were truncated`, exit 1 - a false accusation
  against an honest producer, reproducible against the published artifacts.
  Without `--chain`, such a head is now a NAMED `INCONCLUSIVE` that says which
  input decides it and the exit code stays `0`; a scripted gate must therefore
  read the COMPLETITUD line, not the exit status alone. With `--chain`, a head
  that NO published artifact reaches is a real truncation and still `FAILED`
  with exit 1 under the same discriminant `G-v6-2`. The reference is
  `max(package rows, export rows)` and can only ever RISE: `G-v6-2` asserts that
  a row vanished from the producer's publication, and both artifacts are
  producer publications, so an export shorter than the package (a stale
  download) accuses nothing. The export is UNTRUSTED: it is admitted only if it
  verifies offline as a chain and agrees with the package over the rows both
  reach, and every enumerated head is compared against its row as well as
  against the package's. An unreadable or non-verifying export is vendor
  material, exit 1. Absent the flag, every existing invocation behaves exactly
  as before. Runs now also print a `truncation reference:` line naming both row
  counts, so an absent deciding input never reads like a present one.
- Library: `verify_anchored_package_with_chain` and
  `verify_completitud_with_chain`, the chain-aware entry points behind the flag.
  ADDITIVE - `verify_anchored_package` and `verify_completitud` keep their
  `0.3.3` signatures and behaviour and delegate with `None`.
- Library: `anchor_completitud::TruncationReference`, and the field
  `AnchoredPackageReport::truncation_reference` carrying it. It records what the
  truncation rule ACTUALLY judged against: the package's row count, the supplied
  export's row count, why a supplied export was DECLINED if it was, and the
  resulting `N`. It is reported rather than left to the caller because it is NOT
  derivable from the inputs a caller holds - a declined export raises nothing, so
  a caller recomputing `max(package, supplied_export)` prints a number the rule
  never used. `AnchoredPackageReport` gains a field: code that READS the report is
  unaffected, code that CONSTRUCTS one must add the field, and no consumer has
  reason to construct a report the library returns.
- Library: `anchor_completitud::verify_completitud_reported`, the entry point that
  returns the `TruncationReference` alongside the verdict. Callers that intend to
  REPORT what the truncation rule judged against must use it; the number cannot be
  recomputed at a call site, because a DECLINED export contributes nothing to it.
- `chain_export::PublicChainRow` now derives `PartialEq` and `Eq`. This is a
  surface change to already-published API and is load-bearing, not a convenience:
  the COMPLETITUD export gate compares a package row against an export row for
  FULL equality. `chain_hash` is `SHA256(chain_prev_hash || verdict_hash)`, so with
  both artifacts link-verified it binds `ordinal`, `chain_prev_hash` and
  `verdict_hash` and nothing else - `verdict_id`, `appended_at`, `ruleset_id` and
  `verdict_outcome` sit outside it, and an export contradicting the package in one
  of those was admitted in silence while the gate compared two fields.

### Changed
- `verify-anchor` run WITHOUT `--chain` no longer reports a head beyond the
  anchor package's rows as a truncation. The same invocation, over the same
  artifacts, moves from `COMPLETITUD: FAILED ... rows were truncated ...
  (G-v6-2)` with exit 1 in `0.3.3` to `COMPLETITUD: INCONCLUSIVE ... (G-v6-2
  UNDECIDED)` with exit 0 here. This IS a change of exit code for an existing
  command with existing arguments, and it is deliberate: the `0.3.3` verdict is a
  false accusation against a producer whose published package legitimately lags
  its log, reproducible against the published artifacts and printed in section
  7.4(e.1) of the auditor kit. A scripted gate that read the exit status of
  `verify-anchor` alone therefore stops going red on that input and must read the
  COMPLETITUD line instead. Nothing else moves: every other subcommand keeps the
  exit codes of `0.3.3`, and so does `verify-anchor` on every other input - with
  `--chain`, a head that no published artifact reaches is still `FAILED` with
  exit 1 under the same discriminant.
- `verify-anchor` prints one more line, `truncation reference:`, on every terminal
  verdict (not on the early exits with code 2, where no verdict is reached).
  Output shape of an existing command; no on-disk format changed.

## [seetrex-verifier 0.3.3] — 2026-07-27

Additive release: external-anchor verification. A new `verify-anchor`
subcommand checks a producer-published `anchor.json` package OFFLINE against
a transparency log's cosigned checkpoint. Existing commands, formats and
exit codes are unchanged; 0.3.2 remains valid for `verify-chain` /
`verify-package`.

### Added
- `verify-anchor <anchor.json> --kit <kit.json> [--monitor <bundle>]`: the
  two-verdict anchor gate. `CONSISTENCIA` (offline) re-serializes every
  anchored leaf to the canonical `seetrex/anchor/v1` preimage, verifies each
  leaf's RFC 9162 Merkle inclusion under a checkpoint cosigned by a PINNED
  witness quorum, derives the producer identity set from the PINNED genesis
  key via authorized `rotate` leaves, and checks the package JOIN.
  `COMPLETITUD` stays INCONCLUSIVE unless an independent monitor enumeration
  is supplied with `--monitor`, in which case the completeness rules run for
  real (omission, fork, freshness by consistency proof, per-slug lane rules).
  The witness policy, genesis key and tenant slug come from the auditor kit
  file, never from the untrusted package.
- Library modules backing the subcommand, all public: `anchor` (preimage
  convention + JOIN), `merkle` (RFC 9162 inclusion and consistency proofs,
  verified against live-log vectors), `checkpoint`
  (cosigned-checkpoint + witness-quorum verification, Ed25519 verify-only),
  `anchor_completitud` (the enumeration-dependent rules engine) and
  `anchor_package` (`anchor.json` transport + orchestration).
- `chain_export::parse_and_verify_package_rows`: hands back the VERIFIED
  rows together with the head, so a consumer that needs row contents can
  never obtain rows that skipped the verification gate.

### Dependencies
- New: `ed25519-dalek` 2 (`default-features = false`), verification only —
  the crate never signs.

## [seetrex-verifier 0.3.2] — 2026-07-22

Scope-wording correction. The offline `verify-chain` and `verify-package`
output and the library doc comments no longer claim more than the check
proves. No behaviour change: hashes, canonical form and exit codes are
unchanged; only the explanatory text was corrected.

### Changed
- The four human-readable export columns are no longer all described as
  committed inside the row's verdict hash. Only `verdict_outcome` and
  `ruleset_id` are; `appended_at` and `verdict_id` are committed nowhere —
  inputs to neither the chain link nor the verdict hash — and cannot be
  verified from any published artifact.
- A chain-link match is described as agreement with what the vendor publishes
  now, not as proof that no rows were removed. A republished truncated chain
  also republishes its shorter head, so detecting removal relies on material
  the auditor keeps and compares.
- `verdict_count` is documented as the number of rows present, not a pinned
  total; truncation from the end still verifies.
- The verdict hash is documented as proof of coherence between the hash and
  its inputs, not proof of authorship: the hash is a pure function of its
  inputs (JCS + SHA-256, no secret), so anyone holding them computes the same
  value.

### Superseded
- Releases 0.3.0 and 0.3.1 are superseded. Their earlier chain-check wording
  overstated what the check covers; prefer 0.3.2.
