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

## [seetrex-verifier 0.3.2]

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
