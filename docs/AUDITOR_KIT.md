# Seetrex Compliance — Auditor Kit

This document is for an external technical auditor with no prior knowledge of
Seetrex. It explains what a Seetrex Compliance verdict is, which of its
properties you can verify **independently, offline, with open tooling**, how
to obtain and authenticate that tooling, and exactly where the limit of
independent verification lies.

Background in one paragraph: Seetrex Compliance is a deterministic compliance
engine. Each evaluation emits a *verdict* (one of `SATISFIED`, `AT_RISK`,
`VIOLATED`) over a set of evidence, under a versioned ruleset. Every verdict
is committed to an append-only, per-tenant hash chain whose export is
published on the vendor's Trust Center. A verdict can be exported as a
*verdict package* — a directory of JSON files carrying the verdict, its
evidence, the evaluated ruleset, and a manifest — whose byte-level format is
specified in `docs/SPEC_VERDICT_PACKAGE_V1.md` ("the spec"). Everything in
this kit is driven by that spec; where this document and the spec disagree,
the spec wins.

A note on vocabulary, kept throughout this document: the token `VERIFIED` is
**reserved** output vocabulary of the strong verification surfaces (spec,
section 9.6). This document never uses that word as its own claim — it appears
only when quoting literal tool output or the spec's token tables.

---

## 1. What you can verify (and what you cannot)

The open-source boundary is deliberate, and it is stated identically in the
verifier crate's README, in the spec (section 1), and here. Quoted verbatim
from the `seetrex-verifier` README:

> This boundary is deliberate, and it splits verification into two legs:
>
> 1. **Record integrity — fully independent.** Using only public material
>    (this repository, the published crates, the spec and a signed release),
>    a third party can verify every cryptographic quantity of a verdict
>    package with no vendor involvement at all: per-file hashes, evidence
>    against its references, the ruleset content hash, the `verdict_hash`
>    preimage, the audit chain links and the external anchor.
> 2. **Outcome re-derivation — engine execution required.** Recomputing the
>    verdict *outcome* from the derived facts re-runs the inference engine,
>    which is not open source. It is available as a signed, reproducibly
>    built binary (black box), or as a source rebuild under NDA for
>    regulators.
>
> Leg 1 needs nothing from us. Leg 2 is stated here explicitly so that the
> guarantee is never oversold: this crate proves integrity of the record, not
> re-execution of the engine.

Concretely, with the material in this kit you can prove: that a package's
bytes are what was emitted (nothing added, removed, or altered after
emission); that its evidence files hash to the references the verdict
declares; that the packaged ruleset hashes to the anchor committed inside
the verdict hash (preimage v2); that the `verdict_hash` reproduces from its
declared canonical input; that the public chain's links all recompute; and
that a given package's hash appears in that chain (the external anchor).

What no open tool can prove — and this kit will never claim otherwise — is
that the *outcome* follows from the evidence: that requires re-executing the
inference engine (section 5). Also out of scope of any package-level check:
chain *position and freshness* (a genuine but superseded verdict still
passes; see spec section 9.4) and the truthfulness of the ingested evidence
itself (spec section 9.5).

---

## 2. Get the tools

Two Rust crates are published, both Apache-2.0:

| Crate | Version | Role |
|---|---|---|
| `seetrex-format` | `1.0.0` | the pure format layer: the package's serde types + the RFC 8785 (JCS) canonicalization primitive |
| `seetrex-verifier` | `0.3.3` | the offline verification core (verdict-hash preimages v1/v2, chain link, ruleset anchor, evidence content hash) **plus the `seetrex-verifier` executable** with the `verify-package`, `verify-chain` and `verify-anchor` subcommands |

Version `0.3.3` is the current release. It is ADDITIVE over `0.3.2`: it adds
the `verify-anchor` subcommand and the anchor-verification library modules
(see the `CHANGELOG`); every check this kit walks through uses only
`verify-chain` and `verify-package`, whose behaviour, formats and exit codes
are unchanged — so `0.3.2` also remains valid for everything in this
document. `0.3.0` was the first to
ship the installable executable (`0.2.0` was library-only); `0.3.0` and `0.3.1`
are both superseded, because their `verify-chain` trailers overstated what the
chain check covers — corrected in `0.3.2`, see section 3. crates.io versions
are immutable, so all remain downloadable forever; pin `0.3.2` or later.
Unlike the earlier pair, `0.3.2` is not the same library code with only a new
executable: that correction moved the tool's scope wording into a shared
`scope` module (`scope.rs`, exposed through `lib.rs`) and fixed two library doc
comments (`chain_export.rs`, `canonical.rs`); `0.3.3` goes further and adds
whole new modules — though none of it changes a result the checks in this
kit compute; see appendix A. Line endings differ across
releases: `0.3.1` alone shipped CRLF; `0.3.0`, `0.3.2` and `0.3.3` are LF
(verified against the published `.crate` bytes on 2026-07-27 — an earlier
revision of this kit misstated `0.3.2` as CRLF). So a `0.3.2`↔`0.3.3` diff
needs no normalisation, but any comparison INVOLVING `0.3.1` does, or the
diff reports every file as changed and tells you nothing. The published `Cargo.lock` also advanced a few patch versions
across releases, which affects `cargo install --locked` and not a library
consumer.

### 2.1 Route A — install from crates.io (primary)

```
cargo install seetrex-verifier --locked
```

Literal output, captured 2026-07-27 (build lines elided):

```
    Updating crates.io index
  Installing seetrex-verifier v0.3.3
    Finished `release` profile [optimized] target(s) in 45.37s
   Replacing .../bin/seetrex-verifier.exe
    Replaced package `seetrex-verifier v0.3.2` with `seetrex-verifier v0.3.3` (executable `seetrex-verifier.exe`)
```

(on a machine without a previous install the last lines read `Installing`/
`Installed package` instead of `Replacing`/`Replaced package`). To pin the
exact version this kit was captured with, add `--version 0.3.3`. Confirm
what you installed:

```
$ seetrex-verifier --version
seetrex-verifier 0.3.3
```

The executable has three subcommands — `verify-package <dir>
[--expected-verdict-hash <hex>]` and `verify-chain <file.json>`, used in
sections 3 and 4, and `verify-anchor <anchor.json> --kit <kit.json>
[--monitor <bundle>]`, new in `0.3.3` and documented by its own `--help`
output and the `CHANGELOG`; section 7 walks through what an auditor can and
cannot run against `verify-anchor` today. Running the tool with no or
incomplete arguments prints usage
and exits with code `2` (verified; distinct from every verification outcome).

### 2.2 Route B — build from the signed tag on GitHub

Source of truth: `https://github.com/seetrex-hq/seetrex-verifier`. Release
tags are GPG-signed with the Seetrex Compliance release-signing key. Verify
the tag before trusting the tree.

The current release is `0.3.3`; the walkthrough below verifies its signed tag
`seetrex-verifier-v0.3.3`.

```
# 1. Fetch the release-signing public key (see 2.3 for out-of-band pinning)
curl -fsSL -o seetrex-release-key.asc \
    https://seetrex.com/.well-known/release-signing-pubkey.asc

# 2. Inspect the key BEFORE importing — the fingerprint must be exactly the
#    one pinned in 2.3
gpg --show-keys --fingerprint seetrex-release-key.asc
```

Expected output (captured 2026-07-20):

```
pub   ed25519 2026-07-10 [SC] [expires: 2028-07-09]
      F028 DE16 D3B2 AA44 0FE2  6F05 CECC 5577 2959 6616
uid                      Seetrex Compliance Release Signing <release@seetrex.com>
```

```
# 3. Import, clone, verify the tag
gpg --import seetrex-release-key.asc
git clone https://github.com/seetrex-hq/seetrex-verifier
cd seetrex-verifier
git tag -v seetrex-verifier-v0.3.3
```

Expected output — literal capture, 2026-07-27:

```
object 8b61fe12c228225294bbaa9a883c96d35a9e7702
type commit
tag seetrex-verifier-v0.3.3
tagger Seetrex Compliance Release Signing <release@seetrex.com> 1785140802 +0000

seetrex-verifier-v0.3.3
gpg: Signature made Mon Jul 27 10:26:42 2026
gpg:                using EDDSA key F028DE16D3B2AA440FE26F05CECC557729596616
gpg: Good signature from "Seetrex Compliance Release Signing <release@seetrex.com>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: F028 DE16 D3B2 AA44 0FE2  6F05 CECC 5577 2959 6616
```

What to check in that output: the line `gpg: Good signature from "Seetrex
Compliance Release Signing <release@seetrex.com>"` AND that the printed
primary key fingerprint equals the pinned one (2.3), character for
character. The `WARNING: This key is not certified with a trusted signature`
line is *expected*: it says only that you have not personally certified the
key in your GPG web of trust — the out-of-band fingerprint comparison is the
check that replaces it. The earlier release tags (`seetrex-format-v1.0.0`,
`seetrex-verifier-v0.2.0`, `seetrex-verifier-v0.3.0`,
`seetrex-verifier-v0.3.1` and `seetrex-verifier-v0.3.2`) verify the same way
with the same key.

Then build in place — the repository pins its toolchain
(`rust-toolchain.toml`, channel `1.91.1`) and commits its `Cargo.lock`:

```
git checkout seetrex-verifier-v0.3.3
cargo test --locked          # all suites, including the CLI integration tests
cargo build --release --locked   # produces target/release/seetrex-verifier
```

Result on 2026-07-27 at the `seetrex-verifier-v0.3.3` tag: every suite passes
(format, verifier library, and CLI tests), zero failures.

### 2.3 Route C — pin the signing key out of band

Never trust a key only through the channel that served you the artifact it
signs. The release-signing key fingerprint is:

```
F028 DE16 D3B2 AA44 0FE2  6F05 CECC 5577 2959 6616
```

(ed25519, created 2026-07-10, expires 2028-07-09, uid `Seetrex Compliance
Release Signing <release@seetrex.com>`.)

Cross-check it through independent channels and require them to agree:

1. **This document** — the fingerprint printed above.
2. **The vendor's domain, over TLS** —
   `https://seetrex.com/.well-known/release-signing-pubkey.asc` (the full
   public key; run `gpg --show-keys --fingerprint` on it).
3. **The public repository** — `keys/release-signing-pubkey.asc` in the
   repository tree. Note the honest caveat: this copy is attested by tags
   signed with the very key it contains, so it is a consistency cross-check
   of what the repository claims about itself, not an independent trust
   root — the independent channels are (1) and (2) plus any channel of your
   own (e.g. asking `release@seetrex.com` to confirm the fingerprint over a
   medium you choose).

Compare keys **by fingerprint**, never by file bytes: armor line endings can
legitimately differ between channels (e.g. a git checkout normalizing line
endings), while the fingerprint is invariant. If any channel disagrees on the
fingerprint, stop and contact `release@seetrex.com` before trusting anything.

---

## 3. Verify the public chain

Every verdict appends one row to an append-only hash chain; the chain is
published as a JSON export on the vendor's Trust Center:

```
curl -fsSL -o chain.json https://seetrex.com/trust/seetrex-compliance-chain.json
seetrex-verifier verify-chain chain.json
```

Real output against the live public chain, captured 2026-07-27 with `0.3.3`
(the chain grows continuously — your row count and head hash will be at least
these):

```
Public chain package VERIFIED OFFLINE
  verdict_count:   287
  last_chain_hash: 43a5bb7a4cf44ceeeaf3b9843ad20130ce9b40136de6822e27b67261bbc7a4f2

Compare these two values against the vendor's public Trust Center page for this tenant. A match proves this file agrees with what the vendor publishes RIGHT NOW — nothing more. It does NOT prove rows were not removed: a vendor who republishes a truncated chain also republishes its shorter head, so both sides of this comparison move together. What catches removal is material you kept earlier — a copy of this export, or a verdict package whose verdict_hash (recompute it with `verify-package`) still appears in a row of the published chain. Each export you fetch should extend the prefix you already hold, not rewrite it; keeping and comparing that material is your step. This tool has no command for either comparison; you must keep the material and make it yourself.

NOT covered by this check: the human-readable columns of each row (verdict_outcome, ruleset_id, appended_at, verdict_id). They are not inputs to the chain link, so altering them keeps every link — and the hash above — valid. Two of them — verdict_outcome and ruleset_id — are committed inside that row's verdict_hash, recomputable only from that verdict's package (`verify-package`). The other two — appended_at and verdict_id — are committed NOWHERE: they are inputs neither to the chain link nor to verdict_hash, and no artifact we publish binds them. Treat all four as unverified metadata; the last two you cannot verify at all.
```

Exit code: `0`.

**What the tool checked** (spec section 8/8.1) before printing that: the
export parses with the closed eight-field row schema (unknown keys rejected);
ordinals are contiguous from 1; each row's `chain_prev_hash` equals the
previous row's `chain_hash` (`null` exactly and only at ordinal 1); and every
link recomputes — genesis rows hash the ASCII bytes of the `verdict_hash` hex
string alone, every later row hashes the concatenated ASCII hex bytes
`chain_prev_hash || verdict_hash`. Plain SHA-256, reimplementable in any
language (Appendix A does exactly that and reproduces the same head).

**What each output means.**

- `Public chain package VERIFIED OFFLINE` + exit `0`: this is the strong
  chain surface's success token (chain verification is one of the two
  surfaces the reserved token belongs to, spec section 9.6). It means the
  **links** of the observed history are intact: no row was inserted,
  removed or reordered, and no hash column was altered, without breaking a
  downstream link.

  **Read the scope of that sentence carefully, because it is narrower than
  it first sounds.** Only three of the eight columns are inputs to the link
  preimage: `verdict_hash`, `chain_prev_hash` and `chain_hash`. The four
  human-readable columns — `verdict_outcome`, `ruleset_id`, `appended_at`,
  `verdict_id` — are **not** hashed by this check. Edit them and every link
  still recomputes, the head hash is unchanged, and the tool still prints
  the banner above. An earlier revision of this document claimed "no row was
  altered"; an external evaluator falsified that by rewriting the head row's
  outcome from `SATISFIED` to `VIOLATED` and still obtaining exit `0` with
  the vendor's exact published head hash. The claim, not the tool, was
  wrong — and the wording here is now the corrected one.

  Those four columns are not unprotected in the record itself: each is
  committed inside its row's `verdict_hash` (preimage v2, spec section 7). But
  that binding is only recomputable from the verdict's **package**, which
  the chain export does not carry. So: treat the readable columns of an
  export as unverified metadata, and use `verify-package` on the package
  behind a row before you rely on the outcome it displays.
- `verdict_count` / `last_chain_hash`: the recomputed head. To bind the
  export to what the vendor currently publishes, compare both values against
  the Trust Center page (`https://seetrex.com/trust/`) — a channel you fetch
  yourself. The tool's own trailer says exactly this; the export alone does
  not prove freshness.
- Any `ERROR: ...` line + exit `1`: the named row fails the named check; the
  export cannot be trusted as-is. Exit `2` is usage error (no verification
  ran at all).

**Chain rows are also your external anchors.** Each row's `verdict_hash` is
the externally published value you feed to the package check in section 4.

---

## 4. Verify a verdict package

A verdict package is an extracted directory:

```
package/
  manifest.json          file listing, verdict_hash, chain fields, optional files_sha256
  verdict.json           the verdict record: outcome, canonical input, evidence_refs
  evidence/<uuid>.json   one file per evidence item
  ruleset.json           the evaluated ruleset, verbatim
```

Run:

```
seetrex-verifier verify-package <package-dir> --expected-verdict-hash <hex>
```

where `<hex>` is the verdict's `verdict_hash` taken from the public chain
export (section 3) — an anchor obtained **outside** the package. The
subcommand is a thin shell over the library function
`seetrex_verifier::package::verify_package` and runs **seven steps in order,
failing closed at the first divergence** (normative definition: spec section
9.6):

1. **Shape** — known `package_format_version`; every listed path is a plain
   relative path confined to the package; no missing and no undeclared files.
2. **`files_sha256`** — when the manifest carries the whole-file hash map, it
   must cover exactly the listed files and every stored-bytes hash must
   match (absent on pre-0.1.11 packages: warning, not failure).
3. **Evidence content hashes** — each evidence file's stored canonical
   payload re-hashes to both its own `content_hash` and the matching
   `evidence_refs` entry; evidence-file set and declared refs must match
   exactly; blob-reference evidence (payload not in the package) fails.
4. **Coherence and chain link** — `verdict_hash` agrees between manifest and
   verdict; the packaged chain link recomputes (genesis and non-genesis
   branches per section 3).
5. **Ruleset anchor** — `ruleset.json` passes the strict parser (unknown or
   duplicate keys are malformed) and its content hash equals the verdict's
   declared `ruleset_content_hash` when one is declared.
6. **Verdict-hash preimage** — selected by the verdict's `preimage_version`
   discriminator (v1: 8 members; v2: 10 members, adding the derivation
   clock and the ruleset anchor); the recomputed hash must reproduce the
   packaged `verdict_hash`.
7. **External anchor** — if you supplied an expected hash, the recomputed
   hash must equal it.

**Outcome vocabulary and exit codes** (binding per spec section 9.6):

| Token | Exit | Meaning |
|---|---|---|
| `INTEGRITY-OK (weak)` | `0` | all seven steps passed AND the recomputed hash matched an anchor you obtained **outside** the package. "weak" is honest labeling, not a defect: the record is intact and externally anchored, but nothing was re-derived — that is the closed-engine leg (section 5). |
| `SELF-CONSISTENT (unanchored)` | `4` | steps 1-6 passed and step 7 was **not performed** because you supplied no external anchor. |
| *(error line, no success token)* | `1` | a step failed; the line names the file and the expected vs observed values. The package cannot be trusted as-is. |

(Exit `2` = usage error; no verification ran.)

The failure path is loud and fail-closed. Real output of the installed
binary against a deliberately empty directory, captured 2026-07-20 (the OS
error text follows your system locale):

```
$ seetrex-verifier verify-package empty-pkg
ERROR: integrity check failed — cannot read empty-pkg\manifest.json: El sistema no puede encontrar la ruta especificada. (os error 3)
This check re-computes hashes only. It does NOT re-execute the inference engine (that is `replay --full`), and it does NOT prove this verdict's position in the chain or its freshness (that is `verify-chain` against the published chain export with an externally obtained anchor). Package-internal consistency alone is never a trust root.
```

Exit code: `1`. The scope statement after the error is printed on **every**
outcome, success and failure alike — it is the spec's honest-scope
requirement, so a reader can never mistake a package-integrity pass for a
full re-derivation or a freshness proof.

**Why `SELF-CONSISTENT (unanchored)` is NOT a failure.** Every hash inside
a package can be rewritten *consistently* by whoever rewrites the package —
an internally coherent forgery passes every self-contained check by
construction (spec section 9.3). So an unanchored pass is a true and useful
statement ("these bytes are internally coherent") that deliberately refuses
to be a verification. The distinct exit code `4` exists precisely so a
script can never mistake an unanchored pass for an anchored one. To upgrade
it: take the verdict's `verdict_hash` from the public chain export (section
3) and re-run with `--expected-verdict-hash`.

**Reserved vocabulary.** The token `VERIFIED` is reserved for the strong
surfaces — full re-derivation (`replay --full`, section 5) and chain
verification (`verify-chain`, section 3). The package-integrity check never
emits it, and additionally sanitizes it out of every printed line at its
output boundary, because failure messages can interpolate package-controlled
bytes (a planted filename, a hostile ruleset key) and downstream tooling
pattern-matches that substring as a strong pass.

### Example package

[example package: pending publication gate]

---

## 5. Reproduce the full derivation (NDA path)

Full replay (`replay --full`) adds the missing leg: it re-derives all facts
from the packaged evidence, re-executes the inference engine against the
packaged ruleset using the persisted derivation clock, and requires the
re-derived outcome, working memory, and hash to reproduce the packaged and
externally anchored values — proving the verdict is *re-derivable*, not
merely intact. It requires the inference engine, which is not open source;
it is available as a signed, reproducibly built binary (black box), or as a
source rebuild under NDA for regulators. To arrange either, contact
`release@seetrex.com`.

---

## 6. Provenance & trust anchors

| Artifact | Where it lives | How it is pinned |
|---|---|---|
| Release-signing GPG key | `https://seetrex.com/.well-known/release-signing-pubkey.asc` AND `keys/release-signing-pubkey.asc` in the public repository | fingerprint `F028 DE16 D3B2 AA44 0FE2 6F05 CECC 5577 2959 6616`, cross-checked over the independent channels of section 2.3 (this document / vendor domain over TLS / the repository copy as a self-consistency check); compare by fingerprint, not file bytes; ed25519, expires 2028-07-09 |
| Source repository | `https://github.com/seetrex-hq/seetrex-verifier` | GPG-signed release tags, verified with `git tag -v` against the pinned fingerprint: `seetrex-verifier-v0.3.3` at commit `8b61fe12c228…` (current); `seetrex-verifier-v0.3.2` at commit `54676db4e66b…` (previous, still valid for this kit's checks); superseded: `seetrex-verifier-v0.3.1` at commit `ecea6cc76f10…`, `seetrex-verifier-v0.3.0` at commit `719d0988a1bc…`, `seetrex-format-v1.0.0` and `seetrex-verifier-v0.2.0` at commit `f1dd053c82a1…` |
| `seetrex-format` `1.0.0` | crates.io | crates.io versions are immutable; pin with the exact requirement `=1.0.0` |
| `seetrex-verifier` `0.3.3` | crates.io | immutable; install with `cargo install seetrex-verifier --locked --version 0.3.3` (ships the executable), or pin `=0.3.3` as a library dependency (itself pins `seetrex-format =1.0.0`). `0.3.2` remains valid for every check in this kit (`0.3.3` is additive: it only adds `verify-anchor`). `0.3.0` and `0.3.1` stay downloadable forever and must not be used **as the executable**: their `verify-chain` trailers overstated the check's coverage (section 3). As a library they compute every hash and result identically, but their printed chain-scope wording (and two doc comments) carry the same overclaim `0.3.2` corrected — see appendix A |
| Package format spec | `docs/SPEC_VERDICT_PACKAGE_V1.md` in the source repository | covered by the signed tag; the normative reference for every check in this kit |
| Public chain export | `https://seetrex.com/trust/seetrex-compliance-chain.json` | self-verifying offline (section 3); head comparable against the Trust Center page (`verdict_count`, `last_chain_hash`), fetched over a channel you control |
| Build toolchain | `rust-toolchain.toml` (channel `1.91.1`) + committed `Cargo.lock` in the source repository | build and test with `--locked` from the signed tag |
| Verification code paths | the published crates | the shipped executable is a thin shell over the same library code the vendor's own CLI runs (not a reimplementation); its dependency purity — no engine, no network, no database — is enforced by intent tests inside the crate itself |

Independence rule, restated once: obtain the key fingerprint, the chain
export, and the expected verdict hashes through channels **you** choose and
control. The package is never its own trust root, and neither is any single
channel.

---

## 7. Anchor verification (`verify-anchor`): scope today, and a runnable demo

`verify-anchor` is the `0.3.3` subcommand that checks a producer's published
**anchor package** against a **pinned auditor kit** you supply — never
trusting the package for the tenant identity, genesis key or witness policy —
and reports two verdicts (its `--help` output is the authoritative wording):

- **CONSISTENCIA** (non-contradiction): confirmed fully offline. Every
  anchored leaf's inclusion proof and the checkpoint cosignatures ARE
  cryptographically verified.
- **COMPLETITUD** (nothing omitted): INCONCLUSIVE offline unless you supply
  `--monitor <bundle.json>` from an independent monitor. Even then, the
  monitor's enumeration completeness and recency are a TRUSTED input — the
  leaves it reports are proven, the claim that it saw everything is not.

### 7.1 What you cannot run yet (honest scope)

As of 2026-07-27 there is **no live anchor walkthrough**, because two of the
three inputs are not published:

| input | status |
|---|---|
| `<anchor.json>` (anchor package) | **not published.** The producer pipeline submits anchor leaves to the transparency log but does not yet emit the anchor-package file |
| `--kit <kit.json>` (pinned tenant slug, genesis key hash, log + witness public keys, quorum) | **values pinned in section 7.3 of this document** — compose the file yourself from that literal block; never fetch a kit from the host that serves the package |
| `--monitor <bundle.json>` | **available today**: `https://trust.seetrex.com/witness-bundle.json` is emitted in the exact `seetrex/anchor-monitor/v1` format this flag consumes (top-level `version` field, verified live 2026-07-27). Note its `observations` and `consistency_proof` arrays are currently published empty, which bounds how far COMPLETITUD can get |

When the anchor package is published, this section will be replaced by a
live walkthrough with captures, like sections 3 and 4.

### 7.2 What you can run today: the subcommand's own end-to-end suite

The published crate ships an end-to-end suite that builds valid and invalid
anchor packages with ephemeral keys and drives the **real installed-style
binary** through every `verify-anchor` outcome — confirmed, tenant mismatch,
malformed package (exit 1), malformed kit (exit 2), monitor-based COMPLETITUD
both downgrading and confirming. From the crate tree (extract the `.crate`
tarball from crates.io, or use the signed-tag checkout of section 2.2):

```
cargo test --test bin_e2e anchor
```

Literal output, captured 2026-07-27 against the crates.io `0.3.3` tree:

```
running 8 tests
test verify_anchor_malformed_kit_exits_2 ... ok
test test_scenario_verify_anchor_tenant_mismatch_fails ... ok
test test_scenario_verify_anchor_confirmed_offline_no_reserved_token ... ok
test verify_anchor_malformed_monitor_exits_2 ... ok
test verify_anchor_missing_kit_is_usage_error ... ok
test verify_anchor_malformed_package_exits_1 ... ok
test verify_anchor_empty_honest_monitor_confirms_completitud ... ok
test verify_anchor_real_monitor_completitud_downgrades ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 6 filtered out; finished in 0.42s
```

(the 6 filtered-out tests cover the other two subcommands, the CLI's
usage/version behaviour and the crate manifest; the monitor-based anchor
tests use or derive their `--monitor` input from the crate's embedded
`tests/fixtures/fb2c_enumeration_oracle.json`). Invoking the subcommand with missing arguments
exits `2`, distinct from every verification outcome (re-verified 2026-07-27):

```
$ seetrex-verifier verify-anchor
error: verify-anchor requires <anchor.json> and --kit <kit.json>
$ echo $?
2
```

### 7.3 Compose your `kit.json`: the pinned values

The kit is the TRUSTED side of the boundary `verify-anchor` enforces: the
tenant identity, the genesis key and the witness policy come from the kit you
supply, never from the package being checked. That is worth exactly as much
as the channel the values reach you by. The trusted channel for these values
is **this document, in the GPG-signed source repository** (section 2.2 —
verify the tag before trusting the tree). Deliberately, no `kit.json` file is
served on `trust.seetrex.com`: the host that serves the untrusted
`anchor.json` (and the monitor bundle) must never also be the source of the
pins that judge them — a compromised webroot would then control both sides of
the comparison. So: never fetch a kit from the same host that serves the
package; compose the file yourself from the block below.

<!-- kit-values:begin -->
The template follows. The ONLY per-tenant field is `tenant_slug`. Two tenants
are enrolled in the transparency log today: `seetrex-compliance` (the literal
value in the block) and `seetrex-trust-center` — substitute the slug of the
tenant you are auditing and leave every other value untouched.

```json
{
  "version": "seetrex/anchor-kit/v1",
  "tenant_slug": "seetrex-compliance",
  "genesis_key_hash": "f50f20fa74c509ff4d1bd197851eb1489a197bd4076295ab40302d9d888101f5",
  "policy": {
    "log_pubkey": "0ec7e16843119b120377a73913ac6acbc2d03d82432e2c36b841b09a95841f25",
    "witnesses": [
      "b2106db9065ec97f25e09c18839216751a6e26d8ed8b41e485a563d3d1498536",
      "15d6d0141543247b74bab3c1076372d9c894f619c376d64b29aa312cc00f61ad",
      "076be8c9ee7ea60916f0df3608c945d7730082ecb37749dad2c9ed339fea770c"
    ],
    "quorum_k": 2
  }
}
```
<!-- kit-values:end -->

These values are transcribed from the producer's pinned policy source, and
the transcription is enforced rather than trusted: an intent test in the
source tree extracts this literal block, parses it with the published crate's
`parse_auditor_kit`, and compares it field by field against the production
pins in code. A typo here is the one class of our error that would make
verdicts STRONGER on your machine (e.g. `quorum_k` `2`→`1` yields a valid kit
that silently weakens the cosignature quorum), so it fails CI instead of
waiting for a human diff.

**Provenance, value by value — and how to cross-check each one without us:**

| Field | What it is | Independent cross-checks |
|---|---|---|
| `version` | the `seetrex/anchor-kit/v1` schema constant | the published `seetrex-verifier` `0.3.3` source (`anchor_package.rs`, `ANCHOR_KIT_VERSION`), on crates.io and under the signed tag |
| `tenant_slug` | the tenant under audit (`seetrex-compliance` or `seetrex-trust-center` today) | the tenant's own chain-export name on the Trust Center (`<slug>-chain.json`) — a naming convention, not a security value |
| `genesis_key_hash` | SHA-256 of the raw 32-byte Ed25519 GENESIS submit public key, generated on the producer host (2026-07-26); no rotation has occurred since (see 7.4c) | none outside the vendor — this is the producer's self-declared identity root, and pinning it IS the point: every anchored leaf must trace to it (via any published rotations) or CONSISTENCIA fails. Its only publication channel is this signed document |
| `policy.log_pubkey` | the Ed25519 public key of the `seasalp.glasklar.is` Sigsum log | `https://www.sigsum.org/services/`; the Sigsum project's vetted policy `sigsum-generic-2025-1` (sigsum-go, `pkg/policy/builtin/`); Glasklar's own ops publication (`glasklar/services/sigsum-logs`, instance `seasalp.md`) |
| `policy.witnesses[0]` | witness `witness.glasklar.is` | the vetted policy; the operator's own publication (`glasklar/services/witnessing`, `witness.glasklar.is/about.md`); sigsum.org/services |
| `policy.witnesses[1]` | witness `witness.mullvad.net` | the vetted policy; the operator's own publication `https://witness.mullvad.net/about`; sigsum.org/services |
| `policy.witnesses[2]` | witness `tillitis.se/tillitis-witness-1` | the vetted policy; the operator's own publication (`github.com/tillitis/tillitis.se-tillitis-witness-1`, `about.md`). Not yet listed on sigsum.org/services — the vetted policy postdates that page |
| `policy.quorum_k` | `2` (of 3) | verbatim from the vetted policy's group rule (`group quorum-rule 2 …`) |

The log and witness keys are published by their operators as base64 `vkey`
lines; decode and compare the bytes, or diff against the vetted policy file
directly. Each of those pins was cross-checked byte-for-byte against the
operator's own publication when first pinned; make the same comparison
yourself — the table exists so you never have to take this document's word
for a key.

The chain of custody for this section bottoms out where section 2.3 does: the
release-signing fingerprint that authenticates the repository tags. Use the
independent routes section 2.3 lists. A dedicated fingerprint page on
`seetrex.com` — an origin distinct from both `github.com` and
`trust.seetrex.com` — ships with the release that turns on the anchor
surface, and will add one more independent route; until then, section 2.3's
routes are the ones available.

### 7.4 Reading the two verdicts: normative rules

The rules below are **normative** for interpreting `verify-anchor` results
against this producer's artifacts. They do not change what the tool computes;
they state what a computed result does and does not mean.

**(a) `observations` in the producer's bundle are SELF-REPORT — a COMPLETITUD
built on them certifies self-attested liveness.** The consumer contract
defines `observations` as the *auditor's own* liveness probes, and they are
the single input that can absolve an anchored head whose export is not being
served. The bundle published today carries `observations: []` (section 7.1);
the release that turns on the anchor surface populates them — and it
populates them **from the producer's own webroot directory**: `served: true`
means "the tenant's export file was present and parsed on the producer's
local filesystem at scan time". That is a filesystem read, not a probe of the
served edge — it would remain `true` with the public edge entirely down.
Therefore, at full force: a COMPLETITUD CONFIRMED whose `observations` come
from the producer certifies liveness as SELF-ATTESTED — the producer emits
`served: true` from its own local filesystem and is structurally incapable of
emitting `false` for a tenant in its expected set; `served: true` is THE
input that turns INCONCLUSIVE into CONFIRMED. For the strong verdict, replace
or cross-check `observations` with YOUR OWN probe of the served edge before
giving weight to the result. (CONSISTENCIA is unaffected: it never reads
`observations`.)

**(b) An empty `consistency_proof` is the CORRECT state; any tick skew is
INCONCLUSIVE by construction.** The per-tenant packages and the monitor
bundle are emitted in the same tick from the same cosigned checkpoint, so
`package.checkpoint` equals the bundle's `c_audit` (same size, same root) and
the freshness coupling passes with an empty proof — the rule's degenerate
case "the reference checkpoint IS the package's checkpoint", not a missing
proof. Both roots are authenticated independently (cosignatures verified on
each side), so a skew in ANY direction — bundle ahead of the package or
behind it — yields COMPLETITUD INCONCLUSIVE, never CONFIRMED. Practical
consequence, benign by design (a time-of-check/time-of-use artifact of
downloading two files): if your downloads straddled a publication, you can
see COMPLETITUD INCONCLUSIVE with exit `0` on otherwise valid artifacts. That
is not evidence of tampering — re-download BOTH artifacts and re-run.

**(c) A CONSISTENCIA FAILED "leaf under a key not in the producer identity
set" immediately after an ANNOUNCED key rotation may be a FALSE RED.**
`rotations: []` is the current, correct state: no key rotation has occurred,
so the identity set you derive from the pinned genesis is exactly that one
key. If the producer announces a rotation, a package emitted before its
packaging catches up with the rotation would still carry `rotations: []`, and
leaves signed under the new key would then fail CONSISTENCIA with exactly the
same message as a forgery. Immediately after an announced rotation,
cross-check that FAILED against the producer's rotation announcement (and its
rotation runbook) before concluding forgery: a mid-rotation packaging gap and
tampering are distinguished by whether the announced rotation accounts for
the new key. Absent any announced rotation, take the FAILED at face value.

---

## Appendix A. Verify the verifier: drive the library directly

You do not have to trust the shipped executable's plumbing: the verification
logic is a public library, and a program of your own can reproduce the
results. Both programs below were compiled against the published crates.io
release (`=0.3.0`) and run on 2026-07-20; the chain program independently
reproduced the exact head the installed binary printed for that day's chain
snapshot (151 rows, head `fcc388ce4e24…`). Section 3's capture is a later,
larger snapshot of the same growing chain — dated records of real runs are
left at the row count that produced them rather than restated.

The pins below say `=0.3.3` while that capture was taken with `=0.3.0`, and the
gap is stated rather than hidden. Across `0.3.0` through `0.3.3` every
hash, exit code and comparison result THESE programs compute is identical.
What `0.3.2` changed in the library was not behaviour but text (the shared
`scope` module and two doc-comment corrections); what `0.3.3` adds is a whole
new, ADDITIVE subsystem — anchor verification (`anchor.rs`, `merkle.rs`,
`checkpoint.rs`, `anchor_completitud.rs`, `anchor_package.rs`, a
`chain_export.rs` addition and the `verify-anchor` CLI arm) — so a `src/`
diff between `0.3.2` and `0.3.3` shows far more than the executable; none of
it touches what `verify-chain`, `verify-package` or the appendix programs
compute. Pin `=0.3.0`, `=0.3.1`, `=0.3.2` or `=0.3.3` and these programs
compute identically. Do not take that on our word: unpack the crates
and diff `src/`, normalising line endings first when `0.3.1` is involved
(`0.3.1` alone shipped CRLF; `0.3.0`, `0.3.2` and `0.3.3` are LF), or the
diff will mark every file as changed and you will have learned nothing.

### A.1 Chain export check (reimplements section 3)

`Cargo.toml`:

```toml
[package]
name = "chain-check"
version = "0.1.0"
edition = "2021"

[dependencies]
seetrex-verifier = "=0.3.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

`src/main.rs`:

```rust
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    schema_version: String,
    chain: Vec<Row>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Row {
    ordinal: u64,
    verdict_id: String,
    verdict_hash: String,
    chain_prev_hash: Option<String>,
    chain_hash: String,
    appended_at: String,
    ruleset_id: String,
    verdict_outcome: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: chain-check <chain-export.json>")?;
    let export: Export = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    if export.schema_version != "1.0" {
        return Err(format!("unknown schema_version: {}", export.schema_version).into());
    }
    let mut prev: Option<String> = None;
    for (i, row) in export.chain.iter().enumerate() {
        let expected = (i as u64) + 1;
        if row.ordinal != expected {
            return Err(format!("ordinal gap at index {i}: expected {expected}, got {}", row.ordinal).into());
        }
        if row.chain_prev_hash != prev {
            return Err(format!("row {}: chain_prev_hash does not equal the previous row's chain_hash", row.ordinal).into());
        }
        let recomputed = seetrex_verifier::chain::compute_chain_hash(
            row.chain_prev_hash.as_deref(),
            &row.verdict_hash,
        );
        if recomputed != row.chain_hash {
            return Err(format!(
                "row {}: recomputed link {} != persisted chain_hash {}",
                row.ordinal, recomputed, row.chain_hash
            ).into());
        }
        prev = Some(row.chain_hash.clone());
    }
    let head = prev.ok_or("empty chain")?;
    println!(
        "chain export: {} rows, ordinals contiguous from 1, every hash link recomputed OK",
        export.chain.len()
    );
    println!("head chain_hash: {head}");
    println!("scope: this proves the export's internal hash-link integrity only.");
    println!("It does not prove freshness, and it does not re-derive any verdict.");
    Ok(())
}
```

Real output against the same export as section 3, captured 2026-07-20:

```
chain export: 151 rows, ordinals contiguous from 1, every hash link recomputed OK
head chain_hash: fcc388ce4e245cc2a8e75d1dd6607724a20d969460419a62cc7ee0b2d6b5f555
scope: this proves the export's internal hash-link integrity only.
It does not prove freshness, and it does not re-derive any verdict.
```

Note the deliberate wording: this program prints its own neutral lines and
never the reserved strong token — reserve discipline applies to your tooling
too if you want its output to be read safely by scripts.

### A.2 Package check wrapper (reimplements the section 4 CLI arm)

A minimal conforming wrapper over the library function, implementing the
binding tokens, exit codes, output-boundary sanitizer, and honest-scope
statement of spec section 9.6 (compiled and failure-path-checked against the
published crate on 2026-07-20):

```rust
use seetrex_verifier::package::verify_package;
use std::path::Path;
use std::process::exit;

/// Reserved-vocabulary sanitizer at the output boundary (spec section 9.6):
/// a package-integrity check must never print the strong token, not even
/// via bytes an adversarial package plants inside an error message.
fn out(line: &str) {
    println!("{}", line.replace("VERIFIED", "VERIF[REDACTED]"));
}

fn scope_statement() {
    out("scope: hash integrity only — no engine re-execution (that is replay --full),");
    out("no chain position or freshness proof; package-internal consistency alone is");
    out("never a trust root.");
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = match args.next() {
        Some(d) => d,
        None => {
            eprintln!("usage: package-check <package-dir> [expected-verdict-hash]");
            exit(2);
        }
    };
    let anchor = args.next();
    match verify_package(Path::new(&dir), anchor.as_deref()) {
        Ok(report) => {
            for s in &report.steps {
                out(s);
            }
            for w in &report.warnings {
                out(&format!("WARNING: {w}"));
            }
            out(&format!("recomputed verdict_hash: {}", report.verdict_hash));
            scope_statement();
            if report.anchored {
                out("INTEGRITY-OK (weak)");
                exit(0);
            } else {
                out("SELF-CONSISTENT (unanchored) — no external anchor was supplied;");
                out("re-run with the verdict_hash taken from the public chain export.");
                exit(4);
            }
        }
        Err(e) => {
            out(&format!("{e}"));
            scope_statement();
            exit(1);
        }
    }
}
```

`Cargo.toml` dependencies: `seetrex-verifier = "=0.3.3"` only.
