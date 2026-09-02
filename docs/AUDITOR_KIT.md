# Seetrex Compliance — Auditor Kit

<!-- doc-revision:begin -->
**Document revision: `2026-09-01-recapture-0-3-7`.** If your copy lacks a
revision line at all it predates the genesis reset of 2026-08-24 (section 7.3)
and its kit pins a RETIRED identity. The current copy is the one under the NEWEST signed
tag of the public verifier repository named in section 2.2 whose date is on
or after 2026-08-24 — a tag dated earlier (such as `seetrex-verifier-v0.3.3`,
2026-07-27) carries the retired revision. The presence of this line does not
by itself prove the copy is the current one — a later revision carries a later
id when its day is later, and when two revisions carry the SAME day, as
`2026-09-01-verifier-0-3-7` and `2026-09-01-recapture-0-3-7` do, the tagger
INSTANT of the signed tag your copy came from decides; section 2.2 shows how
to read that instant, with `git tag -v`.
Re-obtain it before drawing any conclusion from an identity FAILED
(section 7.4c/d).
<!-- doc-revision:end -->

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
| `seetrex-verifier` | `0.3.7` | the offline verification core (verdict-hash preimages v1/v2, chain link, ruleset anchor, evidence content hash) **plus the `seetrex-verifier` executable** with the `verify-package`, `verify-chain`, `verify-anchor`, `emit-sbom` and `verify-sbom` subcommands |

Version `0.3.7` is the current release. It moves no command, no format and no
exit code over `0.3.6`: what it moves is the SUITE the published trees run. At
`0.3.6` neither of the two trees this channel publishes gave a green run — a
clone of the source repository and the unpacked `.crate` each failed tests
that cannot be run where they were shipped, which section 2.2 records and
which it calls a defect of the packaging — and `0.3.7` is that repair and
nothing else. Section 2.2 states the census of what each tree does not check,
and says which measurement of it you are being shown and against which tree it
was taken. `0.3.6` moved no command, no format and no exit code over `0.3.5`
either: what it added was a SECOND implementation of this format in Python and
the two lists that confront the two implementations against each other
(route E, section 2.5), now carried inside the crate, and it pinned the two
dependency versions the canonicalization of section 4.1 was measured against
(`rust_decimal` `=1.37.2` and `chrono` `=0.4.41`) — the published `0.3.4` and
`0.3.5` lock a later `rust_decimal` that canonicalizes three exponent-form
monetary values differently. `0.3.5` moved no command, no format and no exit
code over `0.3.4` either; what it added was outside the crate, and section 2.4
covers it: its signed tag was the first to carry prebuilt, signed executables.
`0.3.4` was ADDITIVE over `0.3.3`: it added
the `emit-sbom` and `verify-sbom` subcommands with their SBOM projection
library modules, and it gave `verify-anchor` the optional `--chain` input of
section 7.4(e) (see the `CHANGELOG`, which lives at the ROOT of the public
repository under the signed tag of section 2.2 and is NOT inside the published
`.crate`). `0.3.3` was ADDITIVE over `0.3.2` in the
same way: it added the `verify-anchor` subcommand and the anchor-verification
library modules. Every check of section 3 uses only
`verify-chain` and `verify-package`, whose behaviour, formats and exit codes
are unchanged across all of them — so `0.3.2`, `0.3.3`, `0.3.4`, `0.3.5` and
`0.3.6` remain valid there. Section 4 does NOT follow that sentence: its floor is
`0.3.6`, the first release to pin the `rust_decimal` the producing engine
emits with, and the three exponent-form values RUST-BUG-02 moves are named in
the section 6 crate row and in appendix A.
**Section 7 is the exception, and it is not a small one:** it drives
`verify-anchor`, which `0.3.2` does not have at all and which a `0.3.3` binary
answers WRONGLY once you supply an independent enumeration — 7.4(e.1) prints
that run. Install `0.3.4` or later if you intend to do section 7. `0.3.0` was the first to
ship the installable executable (`0.2.0` was library-only); `0.3.0` and `0.3.1`
are both superseded, because their `verify-chain` trailers overstated what the
chain check covers — corrected in `0.3.2`, see section 3. crates.io versions
are immutable, so all remain downloadable forever; `0.3.2` is the floor for
section 3, `0.3.6` is the floor for section 4, and `0.3.7` is what this
document is written against.
Unlike the earlier pair, `0.3.2` is not the same library code with only a new
executable: that correction moved the tool's scope wording into a shared
`scope` module (`scope.rs`, exposed through `lib.rs`) and fixed two library doc
comments (`chain_export.rs`, `canonical.rs`); `0.3.3` and `0.3.4` go further
and add whole new modules — though none of it changes a result the section 3
checks compute; what section 4 computes differently is not in that source at
all — see appendix A. The section 7 verdict is where `0.3.4`
does differ, and 7.4(e) is that difference. Line endings differ across
releases, and inside one of them: `0.3.1` alone shipped CRLF throughout;
`0.3.0`, `0.3.2`, `0.3.3` and `0.3.4` are LF throughout; `0.3.5`, `0.3.6` and
`0.3.7` are each LF except for ONE file — between `0.3.5` and `0.3.6` it is
**not the same file**, while `0.3.6` and `0.3.7` carry the SAME one.
Re-measured on 2026-08-31 by fetching both tarballs current that day from
`https://static.crates.io/crates/seetrex-verifier/` and counting, file by file,
the carriage returns each one contains: exactly one of the 74 files of the
`0.3.5` tarball — `tests/fixtures/fb2c_enumeration_oracle.json`, 156 carriage
returns — and exactly one of the 622 files of the `0.3.6` one —
`tests/fixtures/corpus/fs-present-ok/pkg/ruleset.json`, 31 carriage returns;
every one of them, in both, the CR of a CRLF pair. The `0.3.5` offender was
normalised: `fb2c_enumeration_oracle.json` holds zero carriage returns in
`0.3.6` and is byte-identical to the `0.3.5` copy once that copy's CRLF pairs
are folded to LF (measured, not promised). What replaced it is one file of the
corpus `0.3.6` adds. Both are JSON and no check in this kit reads either: their
CONTENT is unaffected and each parses to the same document either way. (An
earlier revision of this kit misstated `0.3.2` as CRLF; the same measurement
corrected it on 2026-07-27.) So a
`0.3.5`↔`0.3.6` diff
needs normalisation for exactly ONE path — `fb2c_enumeration_oracle.json`, the
only file that is in BOTH tarballs and differs only in its line endings; the
`0.3.6` offender is a corpus file that release ADDS, so it has no `0.3.5`
counterpart to normalise against.
Measured again on 2026-09-01 for the pair this revision is written against,
by the same method and with both downloads checked against the registry
sha256 first: exactly one of the 623 files of the `0.3.7` tarball —
`tests/fixtures/corpus/fs-present-ok/pkg/ruleset.json`, 31 carriage returns —
and that file is byte-identical to the `0.3.6` copy of the same path. So the
`0.3.6`↔`0.3.7` pair, unlike the one before it, DOES have a shared path
carrying CRLF; normalising it changes nothing, because the two copies already
agree byte for byte, and a diff of the two tarballs run with no normalisation
at all reports that path as identical. Any comparison
INVOLVING `0.3.1` needs it throughout, or the diff reports every file as
changed and tells you nothing. The published `Cargo.lock` also advanced a few patch versions
across releases, which affects `cargo install --locked` and not a library
consumer.

### 2.1 Route A — install from crates.io (primary)

```
cargo install seetrex-verifier --locked
```

Literal output, captured 2026-09-01 into an empty install root (build lines
elided):

```
 Downloading crates ...
  Downloaded seetrex-verifier v0.3.7
    Updating crates.io index
  Installing seetrex-verifier v0.3.7
    Finished `release` profile [optimized] target(s) in 34.50s
  Installing .../bin/seetrex-verifier.exe
   Installed package `seetrex-verifier v0.3.7` (executable `seetrex-verifier.exe`)
```

Over a previous install the last two lines read `Replacing`/`Replaced
package` instead. Captured on 2026-08-29, upgrading a `0.3.4` to the release
current that day:

```
   Replacing .../bin/seetrex-verifier.exe
    Replaced package `seetrex-verifier v0.3.4` with `seetrex-verifier v0.3.5` (executable `seetrex-verifier.exe`)
```

Both captures were taken with the version pinned explicitly; the unpinned
command above resolves to the NEWEST release at the moment it is run, which is
`0.3.7` today. The dated transcript above installed
`0.3.7`, the newest release on the day it was captured
(`https://crates.io/api/v1/crates/seetrex-verifier`
reported `max_version` `0.3.7` on 2026-09-01, published that day at
12:37:32Z and not yanked, a 568770-byte `.crate`). To reproduce THAT
transcript rather than the newest build, add `--version 0.3.7`. **That
capture is of the CURRENT release**: it was taken against the published
`0.3.7`, after publication, which is what makes it a capture rather than a
prediction — the revision that CUT this release could not have it and said so.
**The
install root was empty, but the machine was not clean**: the capture was taken
on the producer's own station into a fresh `--root`, with the default
`CARGO_HOME` — so its `Finished … in 34.50s` counts a warm dependency cache,
and a first build on a bare machine takes longer. Nothing else in the block
depends on that. The block below is what the CURRENT release prints, and
section 2.2 names its tag:

<!-- verifier-subcommands:begin -->
```
$ seetrex-verifier --version
seetrex-verifier 0.3.7
```

The executable has five subcommands — `verify-package <dir>
[--expected-verdict-hash <hex>]` and `verify-chain <file.json>`, used in
sections 3 and 4; `verify-anchor <anchor.json> --kit <kit.json>
[--monitor <bundle>] [--chain <chain.json>]`, used in section 7, whose
`--chain` input is new in `0.3.4` and whose other arguments are those of
`0.3.3`; and the two SBOM subcommands, new in `0.3.4`,
`emit-sbom --kind <cargo|composer|npm> --lockfile <path>
[--manifest <composer.json>] --subject <purl> --out <path>` and
`verify-sbom --kind <cargo|composer|npm> --lockfile <path>
[--manifest <composer.json>] --subject <purl> --sbom <path> [--third-party]
[--dep-v0 <elf>]`, which project a lockfile to a canonical SBOM and confront a
document with that projection. No check in this kit uses either of them; they
are enumerated because the tool offers them and an enumeration that stops
short is one an auditor cannot trust. The tool's top-level `--help` output
and the `CHANGELOG` document all five; the subcommands carry none of their
own.

<!-- EDITOR: the region below is pinned by an intent test in the producer's
     source tree, and only for its NUMBERS. Every published subcommand must be
     named here with the exit code measured for it, written as an integer in
     backticks with no letter and no digit between it and its subcommand; and
     the backticked integers of the whole region, counted, must be exactly one
     printing of each subcommand's own measured code. If a sentence here needs
     a number for any other reason, it belongs below the :end marker.
     ONE SENTENCE IS ALSO PINNED, whole: the provenance chain — the three
     earlier observations, the day and the release of each, and the count of
     observations it says the codes are unchanged across. That sentence prints
     the same measurement the vendored record's own header prints, and the two
     are bound to the same constants, so re-dating or re-attributing either one
     is red.
     WHAT NO TEST READS: every OTHER sentence here. Their wording, their
     polarity and their headline are human-reviewed prose like the rest of this
     document — a number written any way other than an integer between
     backticks is not seen either. Change one and a reviewer, not a red banner,
     is what stands between the change and an auditor. -->
<!-- subcommand-help-codes:begin -->
**Asking a subcommand for help is not uniform, and one of the answers collides
with a verification outcome.** The codes here were measured on 2026-09-01
against the PUBLISHED `0.3.7` — the tool sections 2.1 and 2.2 hand you today:
the binary was installed from crates.io into an empty root and each
subcommand's `--help` was run with it and its process exit status read. Every
one of the five is what the previous observation, made on 2026-08-31 against
the published `0.3.6`, had recorded, and what the two before it recorded on
2026-08-29 against the published `0.3.5` and on 2026-08-27 against the
published `0.3.4`: no subcommand is added, dropped or re-coded across the four.
The revision that CUT this release could not observe it — no `0.3.7` existed
then — so it DERIVED these codes from the tree being published and declared
the re-observation owed; this is that re-observation, and the derivation it
closes predicted every one of the five. `verify-package --help`
exits `2`, `verify-anchor --help` exits `2`, `emit-sbom --help` exits `2` and
`verify-sbom --help` exits `2`, while `verify-chain --help` exits
`1` — the code a FAILED verification returns, because that subcommand takes its
file positionally and tries to OPEN the argument as a path, printing
`ERROR: cannot read …` on stderr. Read the message, never the code, if you ever
type one of them. Each subcommand named above is reconciled against a record
that the producer's test suite measures by RUNNING the tool; this kit does not
check that that suite keeps running. The region publishes no other backticked
INTEGER — an integer is what the test counts, so a number written any other way
(spelled out, or with a `.` inside the backticks) is not seen at all. The
sentences around them are reviewed by a human, not by a test.
<!-- subcommand-help-codes:end -->

When were they observed, and against what: on 2026-09-01, against the tool
crates.io served as the newest release that day. The install command of section
2.1 was run into an empty root, each subcommand's `--help` was invoked with the
binary it produced, and its process exit status was read. The codes are not
derived from the producer's own tree, which is a superset of what is published.

Section 7 walks through the live `verify-anchor` run against the published
anchor packages. Running the tool with no or incomplete arguments prints usage
and exits with code `2`, which is distinct from every verification outcome.
<!-- verifier-subcommands:end -->

### 2.2 Route B — build from the signed tag on GitHub

Source of truth: `https://github.com/seetrex-hq/seetrex-verifier`. Release
tags are GPG-signed with the Seetrex Compliance release-signing key. Verify
the tag before trusting the tree.

The current release is `0.3.7`; its signed tag is `seetrex-verifier-v0.3.7`.
The walkthrough below IS a capture of that tag, run on 2026-09-01 from a clone
made after publication into an empty, throwaway GPG home holding nothing but
the key of step 2. The revision this release was cut from could not carry it —
it printed the PREVIOUS tag's capture and said so — and this revision replaces
that transcript with the one an auditor now reproduces. The earlier tags verify
by exactly the same commands and print the same lines with their own object
ids and their own tagger dates; only the tag name, the object it resolves to
and the date change.

<!-- verifier-tag-era:begin -->
**Tool release and document revision are two different things.** `0.3.7`
(tag dated 2026-09-01) is the current release of the VERIFIER, and every check
in this kit runs on it, except the dated 7.1 walkthrough, which says so in
place; `seetrex-verifier-v0.3.7` was signed at
`2026-09-01T12:35:16Z`, in the walkthrough below. **That date is a measurement
here and was not one in the revision this release was cut from**: a tool tag
is created when the release it publishes is cut, which is after the revision
being published is written, so that revision named no date at all rather than
predicting one — the same construction that stopped section 6 naming the
commit it resolves to. THIS revision is the recapture made against the release
as PUBLISHED, and it names both.
The document-revision id
above is a DIFFERENT identifier and it dates the REVISION, not the release: a
later revision carries a later id, and when two revisions carry the SAME
day the tagger instant of their signed tags orders them, which is the
selector this block names just below. A revision made against a
release as published is a later revision under a document tag of
its own. Select copies by the tag's own
date. When a tag's NAME carries one date and its SIGNATURE carries another —
as `seetrex-kit-2026-08-30-verifier-0-3-6` does — the SIGNATURE date is the
one that decides which copy is newest: it is the tagger instant `git tag -v`
prints. The date inside the name is only part of the identifier. The copy of THIS DOCUMENT carried by an EARLIER tag is a
different matter — under `seetrex-verifier-v0.3.3` (2026-07-27) it is the
RETIRED revision, and its section 7.3 pins the retired
genesis key. For the document, use the tag that publishes this revision: the
newest signed tag of this repository dated on or after 2026-08-24. This
revision cannot name that tag — a tag is created when the revision it carries
is published — so select it by DATE, not by version number, and confirm
against the revision line at the top of this document. Everything below in
this section is about obtaining the TOOL.
<!-- verifier-tag-era:end -->

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
git tag -v seetrex-verifier-v0.3.7
```

Expected output — literal capture, 2026-09-01:

```
object 2f7ab299f993cfb1f527aabe9b94e4398509b65e
type commit
tag seetrex-verifier-v0.3.7
tagger Seetrex Compliance Release Signing <release@seetrex.com> 1788266116 +0000

seetrex-verifier-v0.3.7
gpg: Signature made Tue Sep  1 14:35:16 2026
gpg:                using EDDSA key F028DE16D3B2AA440FE26F05CECC557729596616
gpg: Good signature from "Seetrex Compliance Release Signing <release@seetrex.com>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: F028 DE16 D3B2 AA44 0FE2  6F05 CECC 5577 2959 6616
```

One line of that block is not UTC. `gpg` renders `Signature made` in the
READER's own local zone, so a capture taken elsewhere prints a different clock
time for the very same signature; the instant itself is the `tagger` line
above it, which carries its offset explicitly (`1788266116 +0000`, that is
2026-09-01T12:35:16Z). The capture above was taken at UTC+02:00, which is why
its `Signature made` reads `Tue Sep  1 14:35:16 2026`. Compare zones, not
digits: the `Signature made` line is the only zone-dependent line of that
block, and every other line of it — `tagger` and the fingerprint included —
reads the same wherever the command is run.

What to check in that output: the line `gpg: Good signature from "Seetrex
Compliance Release Signing <release@seetrex.com>"` AND that the printed
primary key fingerprint equals the pinned one (2.3), character for
character. The `WARNING: This key is not certified with a trusted signature`
line is *expected*: it says only that you have not personally certified the
key in your GPG web of trust — the out-of-band fingerprint comparison is the
check that replaces it. The earlier release tags (`seetrex-format-v1.0.0`,
`seetrex-verifier-v0.2.0`, `seetrex-verifier-v0.3.0`,
`seetrex-verifier-v0.3.1`, `seetrex-verifier-v0.3.2`,
`seetrex-verifier-v0.3.3`, `seetrex-verifier-v0.3.4`,
`seetrex-verifier-v0.3.5` and `seetrex-verifier-v0.3.6`) verify the same way
with the same key, and so do the document tags of section 6.

Then build in place — the repository pins its toolchain
(`rust-toolchain.toml`, channel `1.91.1`) and commits its `Cargo.lock`:

```
git checkout seetrex-verifier-v0.3.7
cargo test --locked --no-fail-fast   # all suites, including the CLI integration tests
cargo build --release --locked       # produces target/release/seetrex-verifier
```

**Two records follow, and the order is deliberate: what the PREVIOUS release
shipped, and what the tag the fence above checks out measures today.** The
first is dated history and stays true of the artifacts that carry it; the
second is what an auditor running the command above now gets.

**Result on 2026-08-31 at the `seetrex-verifier-v0.3.6` tag: every suite passes
EXCEPT ONE, and the exception is not a defect of the verification code — it is a
test that cannot run outside the producer's own repository.** Passing:
`seetrex-format` 3, the verifier library 367, the executable's own unit target
0, the CLI integration suite `bin_e2e` 46, `corpus_equivalence` 3,
`grammar_probe` 1, `intent_public_crate_is_self_contained` 2,
`intent_sbom_corpus` 4, `intent_sbom_spec_matches_code` 12 and
`intent_spec_gaps_have_cases` 1; both doc-test runs are empty.
Failing: `intent_blind_transcript`, 0 passed / 1 failed —
`test_intent_blind_transcript_names_the_spec_it_saw`. It reads
`crates/verifier/reference/BLIND_TRANSCRIPT.md` and resolves each row's commit
with `git show <commit>:docs/SPEC_VERDICT_PACKAGE_V1.md`; those commits are
commits of the producer's PRIVATE tree, which the public export does not carry,
so in a clone of the public repository the very first row fails to resolve
(`fatal: invalid object name '7a221184'`). Run
`cargo test --locked --no-fail-fast` and read the run rather than the exit
status, or exclude that one target — every check this kit asks you to reproduce
lives in the suites above, and `bin_e2e` (the one section 7.2 quotes) is among
the passing ones. `cargo build --release --locked` finishes clean regardless and
writes `target/release/seetrex-verifier`.

**The unpacked `.crate` of that same release fares worse than "one target", and
the shortfall is measured here rather than left to the sentence above.** Run in
place from the published `0.3.6` tarball on 2026-08-31,
`cargo test --locked --no-fail-fast` exits `101` with 28 tests red across 5
targets, 15 of them unit tests of `src/sbom/compare.rs`. Four of those targets
READ a specification document; the fifth,
`intent_public_crate_is_self_contained`, reads neither and fails for the
adjacent reason — it requires every path the crate escapes to for a document
to RESOLVE, and asserting that a file exists is not the same obligation as
opening it. `cargo package` cannot carry a file
from outside the package directory, so neither document travels in the tarball.
The exclusion the paragraph above allows is advice for a CLONE of the public
repository; for the tarball it was always short. This is recorded, not excused:
a test shipped in a public crate that cannot pass in that crate is a defect of
the packaging, and the producer owes its repair.

**One environment caveat, and it is not a defect of the tree.** Two of the
crate's tests read the shipped Markdown specification and split it into
paragraphs on the two-newline sequence. If your Git checks the working tree
out with CRLF endings — the default of `core.autocrlf` `true`, which is what a
Windows install sets — that split never fires and
`test_intent_spec_allowed_top_level_keys_match_code` fails with a message
about finding nine top-level keys where the specification names seven.
Measured on 2026-08-31: the same tag, cloned with `core.autocrlf` `false`,
gives the run recorded above — that key test among the passing ones, and
`intent_blind_transcript` the only failure of that clone. Clone with
`git -c core.autocrlf=false clone …` (or set
it before cloning); nothing `cargo install` compiles carries a carriage return
in the published `.crate` — the one CRLF path section 2 records in the `0.3.6`
tarball is a test fixture — so `cargo install` is unaffected.

**The repair travelled in `0.3.7`, and what follows is measured against the
CHANNEL rather than against the producer's tree.** The revision that cut this
release could only measure the repair in the tree that was about to become it,
and dated the figures to that measurement rather than to a tag, because the
tag did not exist yet. It does now. Measured on 2026-09-01, after publication,
against the two trees the channel serves: a clone of the public repository
checked out at the signed tag `seetrex-verifier-v0.3.7` — the tag the
walkthrough above verifies — and the `.crate` crates.io serves for `0.3.7`,
downloaded, its sha256 checked against the registry and unpacked OUTSIDE the
producer's repository. `cargo test --locked --no-fail-fast` exits `0` in both:
in the clone, 13 targets, 440 passed and 0 failed; in the unpacked
tarball, 11 targets, 437 passed and 0 failed. Where the two differ is
not in what passes but in what each one is unable to check, and that is the
census:

1. **A clone of the public repository** runs the suite green, exit `0`, and
   skips EXACTLY ONE `skipped [` check, which announces itself on stderr:
   `skipped [SourceWithoutHistory]: transcript rows are not resolved against
   git blobs: anchor commit is unreachable here, so this tree does not carry
   the producer's history (the public repository is an export snapshot). The
   unconditional resolution lives in
   crates/witness/tests/intent_blind_transcript_history.rs`. What that clone
   cannot do is resolve the producer's blobs, because the public repository is
   an export snapshot and those objects were never in it. The rest of the
   blindness claim is checked there: the transcript's shape, and the hash of
   the specification its last row names.
2. **The unpacked `.crate`, unpacked OUTSIDE the producer's repository,** runs
   green too, exit `0`, and prints 28
   `skipped [Packaged]` lines: 15 for the SBOM reference vector, which is what
   the unit tests of `src/sbom/compare.rs` read — one group, not two — 10 for
   `intent_sbom_spec_matches_code`, 2 for the two legs of the transcript test
   — the git one and the specification-hash one — and 1 for the corpus's
   `# spec:` citations. Each line names the document it could not read.
   Where you unpack it decides exactly one of those lines: unpack the same
   tarball INSIDE the producer's repository — under `target/`, say — and the
   count is 27, because `git` run from there reaches the producer's objects,
   the anchor commit resolves and the transcript's git leg RUNS instead of
   skipping. That is one check more, not one fewer, and it is the only line of
   this census that moves with the location. That
   28 is NOT the 28 recorded above for the published `0.3.6` tarball: the
   earlier one counts tests that went RED over 5 targets, this one counts
   skips in a run that stays green, and the two sets differ in their members
   as well as in their meaning.
3. **The producer's own tree** skips nothing of this discipline: not one
   `skipped [` line in the whole run, every obligation of the three-tree
   classification executed. The guard the first line above names resolves the
   transcript's history there UNCONDITIONALLY — it has no skip branch at all —
   so the git leg cannot be switched off anywhere without that test going red
   in the one tree that can tell.

**A second, older family of skips exists, it is not part of that census, and
it prints in all three trees.** Fifteen tests are gated on the environment
variable `SEETREX_PRIVATE_TREE` (`crates/verifier/src/sbom/private_tree.rs`):
they project the lockfiles of the closed repository this crate is developed
in, which travel to no published tree at all. With the variable unset — which
is the default everywhere, including in the producer's own checkout — each of
them prints `skipped: SEETREX_PRIVATE_TREE not set - this test needs the
private repository` and passes. That gate PREDATES the three-tree repair
described here by several releases, and it is deliberately spelled `skipped:`
with NO bracket, which is what makes a census of the repair's discipline a
grep for `skipped [` rather than for the word. Measured in the producer's tree
on 2026-08-31 with the variable unset: 15 of these lines and zero
`skipped [` ones. The variable is unset in a public clone and in an unpacked
`.crate` too, so the same family appears there, over and above the counts of
one and 28 above.

**How a test decides which tree it is in**, because a skip is a check that did
not run and you are entitled to know what decides it. Both answers — packaged
or not, history or not — are read from evidence found IN THE TREE, and NEITHER
is ever decided by an environment variable; the `SEETREX_PRIVATE_TREE` family
above is a different mechanism gating a different set of tests, and it
classifies no tree. Both answers live in
`crates/verifier/tests/common/mod.rs`. A packaged tree is recognised by
`Cargo.toml.orig` — the copy of the manifest that `cargo package` writes beside
every crate it builds, and that no source checkout has. History is recognised
by resolving ONE anchor commit fixed in the test's own code (`7a221184`, the
commit of the transcript's first and oldest row), never a commit the transcript
under test nominates: a table that could nominate its own witness would let a
forged row name an object that does not resolve and be EXCUSED by the skip.
Because the anchor is chosen by the test and not by the data, a falsified row
stays a hard failure in every tree that has the history.

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
   public key; run `gpg --show-keys --fingerprint` on it), and the human
   page `https://seetrex.com/signing-key`, which prints the same
   fingerprint. Both come from the one domain, so together they still
   count as ONE channel.
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

### 2.4 Route D — the signed prebuilt binary

<!-- binary-route:begin -->
Route D is for the auditor with no Rust toolchain: take the executable we
built from the signed tag, and check where it came from with nothing but
`gpg` and `sha256sum`. Route B remains the strong path; the binary is a
convenience whose trust reduces to the same key and the same tag.

**What is published.** A release carries at most the two linux targets named
here, `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`: those two
are the whole of what the signing job is allowed to build, and a release may
carry just one of them, because a run can be asked for a single target. There
is no macOS or Windows binary published today; on those platforms use route A
(section 2.1) or route B (section 2.2). The artifacts of a release are
`seetrex-verifier-<version>-<target>`, one per target built, one `SHA256SUMS`
and one `SHA256SUMS.asc` — raw executables, no archives, so the hash you
compute is the hash of the bytes you run. The signed `SHA256SUMS` is what
tells you which of the two a given release actually carries. A tool tag whose
release carries no `SHA256SUMS` publishes no binary at all, and route A or
route B is the answer there.

A binary for a target the build host cannot execute is built and signed but is
not run against the tool's own end-to-end suite before it is published: the
build host is x86_64 linux, so the aarch64 executable leaves that job without
that check. The job refuses to publish such a target unless the dispatch says
so explicitly, which is the record of who decided it; what you get is the same
signed list over the same bytes, and one fewer check behind them.

**How you check it.** Verification is two commands and needs nothing beyond
`gpg` and `sha256sum`: `gpg --verify SHA256SUMS.asc SHA256SUMS`, then
`sha256sum --ignore-missing -c SHA256SUMS`.

`--ignore-missing` is there because the list names every published artifact
while you downloaded one: it skips the entry for the target you did not fetch,
so a healthy release does not report `FAILED open or read`. It does not soften
the check on the file you DID download — `sha256sum` still exits non-zero if
that file's hash differs from the list, and also if nothing you have is named
in the list at all, where it says `no file was verified` and fails.

```
# 1. Get the release-signing key and compare its fingerprint against the one
#    pinned in 2.3 BEFORE importing it. Same key as route B, same check.
curl -fsSL -o seetrex-release-key.asc https://seetrex.com/.well-known/release-signing-pubkey.asc
gpg --show-keys --fingerprint seetrex-release-key.asc
gpg --import seetrex-release-key.asc

# 2. Get the list, its signature, and the executable for your platform, from
#    the release of the tool tag you want. Substitute the release version and
#    one of the two target triples named above.
curl -fsSL -O https://github.com/seetrex-hq/seetrex-verifier/releases/download/seetrex-verifier-v<version>/SHA256SUMS
curl -fsSL -O https://github.com/seetrex-hq/seetrex-verifier/releases/download/seetrex-verifier-v<version>/SHA256SUMS.asc
curl -fsSL -O https://github.com/seetrex-hq/seetrex-verifier/releases/download/seetrex-verifier-v<version>/seetrex-verifier-<version>-<target>

# 3. Both commands, in this order. Either one alone proves nothing.
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

# 4. The list names the file by its published name, so keep that name until
#    the check has passed; rename it to seetrex-verifier afterwards if you
#    want the short form, then:
chmod +x seetrex-verifier
./seetrex-verifier --version
```

The signature covers the list and the list covers the bytes. Verifying the
signature and skipping `sha256sum --ignore-missing -c` proves nothing about the binary you are
about to run.

The key is the same key as route B's, checked the same way, through the
independent channels of 2.3. Expect the same `WARNING: This key is not
certified with a trusted signature` line that 2.2 explains, and give it the
same answer: the out-of-band fingerprint comparison is what replaces the web
of trust you do not have.

**Where the limits are.** Release assets on a hosting platform are
replaceable. What is not: the signed tag the binary was built from, and this
document under its own signed tag. On determinism this route hands you a
mechanism, not a result: the build job builds each target twice in the same
build directory, wiping the target's release tree in between so every
target-side artifact is recompiled, compares the two hashes, and refuses to
sign if the two differ. What
that constrains is one job on one machine at one moment; it is silent about
yours, and nothing here claims a different machine reproduces the same bytes.
Read no outcome into it: the guarantee is what the job will not do, never a
run you are being told about. A byte-for-byte result you obtain yourself is
route B (section 2.2), and that is still the reason route B is the strong
path.
<!-- binary-route:end -->

---

### 2.5 Route E — the Python reference implementation (no toolchain)

Route E is for the auditor with no Rust toolchain and no wish to install one:
a second implementation of this format, in a single Python file, readable end
to end in one sitting and runnable with the interpreter the machine already
has. It is a reference, not the product — route A or route B is what you
install; route E is what you read when you want a second opinion on what the
specification says.

**What it is.** `crates/verifier/reference/seetrex_verifier.py`, in the source
repository of section 2.2. Standard library only, tested on CPython 3.12: no
package to install, no `pip install`, no virtual environment, no compiled wheel. Its
sha256 is published in the provenance table of section 6, and the file is
covered by the same signed document tag as this document.

**Two ways to obtain it**, and they are the same bytes: clone the repository
of section 2.2, or unpack the published `.crate` of section 6 and read
`reference/seetrex_verifier.py` inside it. The second needs no `git` and no
Rust toolchain — `curl` the tarball and `tar xzf` it — and the sha256 of
section 6 identifies the file either way.

**How you run it.** Two subcommands, and the path in front of them depends on
which of the two ways above you obtained the file. From a checkout of the
repository:

```
python3 crates/verifier/reference/seetrex_verifier.py verify-package --package-dir <DIR> [--expected-verdict-hash <HEX>]
python3 crates/verifier/reference/seetrex_verifier.py verify-chain --chain-export <FILE> [--expected-last-chain-hash <HEX>]
```

From the root of the unpacked `.crate`, where the same bytes sit one level
shallower and no `git` was needed to get them:

```
python3 reference/seetrex_verifier.py verify-package --package-dir <DIR> [--expected-verdict-hash <HEX>]
python3 reference/seetrex_verifier.py verify-chain --chain-export <FILE> [--expected-last-chain-hash <HEX>]
```

`verify-package` exits `0` on an anchored pass, `4` on a pass that nothing
outside the package attested, and `1` on any failure — the three codes of the
specification's outcome table, kept apart so a scripted gate cannot read an
unanchored pass as an anchored one. `verify-chain` exits `0` on success and
`1` on failure — the two codes the specification itself states for that
subcommand (§8.1). They were the reference implementation's own choice when it
was written, because the document was silent then; `OPEN_QUESTIONS.md` records
that reading, and the sentence it prompted is now in the specification.

**Read this before treating the two tools as interchangeable.** The Python
implements the CLI shape the SPECIFICATION writes: the operand is the
`--package-dir` / `--chain-export` option above. The shipped executable takes
that operand POSITIONALLY instead — section 4 shows the form
`seetrex-verifier verify-package <package-dir>` — and answers a usage error to
an option it does not know. Where they disagree is on how the command is
typed, and that is a finding about the document rather than a defect in either
tool. Nothing here normalises it away.

**What "they agree" means, exactly.** On the 92-case corpus below and on the
528-value grammar probe list the two implementations agree on every hash,
token and exit code. Outside those two lists the document is the only
contract: agreement there is a claim nothing in this repository measures, and
the residual gaps the document does not close are listed in
`crates/verifier/reference/ALIGNMENT_NOTES_R1.md`. An unconditional "they
agree on everything" is what the earlier revision said, and a review found
divergent values it did not cover within the hour.

**The corpus: the same questions, answered twice.**
`crates/verifier/tests/fixtures/corpus/` holds 92 cases. Each one carries a
`cmd.txt` (the arguments) and an `expected.txt` (the answer the specification
gives, written by hand from the document and generated by neither
implementation). Both legs answer the same 92 cases:

```
python3 crates/verifier/reference/run_corpus.py
cargo test -p seetrex-verifier --test corpus_equivalence
```

Both commands are written for the ROOT of a checkout of the source
repository, which is where the paths above resolve. **The Python leg needs
no checkout.** Since `0.3.6` the runner, the reference and the whole corpus
travel inside the published `.crate`: unpack that tarball, run
`python3 reference/run_corpus.py` from its root, and it prints the same
`PYTHON LEG: 92/92` and exits `0` (measured 2026-08-31 against the published
`0.3.6` tarball). The runner resolves the corpus from its own location and
never climbs above the crate, which is why it travels intact. **The Rust leg
is the one that still wants the checkout**: run from the unpacked **`0.3.6`**
tarball its target answers all 92 cases and then fails ONE test of its own,
`test_intent_corpus_expectations_are_spec_derived_not_generated`, which reads
the specification at `../../docs/SPEC_VERDICT_PACKAGE_V1.md` — a path outside
the tarball. That is the packaging defect section 2.2 records, in the target
next to it, and this sentence is dated to `0.3.6` on purpose: **after the
repair that section describes, that test no longer fails from a tarball — it
SKIPS**, printing one `skipped [Packaged]` line naming the document it could
not read, and the target stays green. The Rust leg still wants the checkout to
MEASURE anything there; what changed is that not measuring is now announced
instead of red.

The first prints `PYTHON LEG: 92/92`; the second drives the binary this tree
builds over the identical cases. Because the expected answers come from the
document and not from either implementation, a disagreement surfaces as one
leg red and the corpus can indict the Rust as readily as the Python. The
workflow `.forgejo/workflows/spec-equivalence.yml` runs both legs on every
push that touches the specification, the reference, the corpus or the runner,
and again nightly.

**The grammar probe: the same boundary values, canonicalized twice.**
A corpus only answers the cases somebody thought to write down, and three
review rounds each found NEW boundary values it was blind to. So a second
instrument sits beside it. `crates/verifier/tests/fixtures/grammar_probes.txt`
is a flat list of 528 JSON scalars — the edges of every value grammar of
section 4.1: money signs, digit separators, exponents, scales around the
28-digit bound and mantissas around 2^96, rounding ties, dates and date-times
with every separator, offset and fraction width the grammar allows, duration
unit orders and overflow values, plain strings, JSON numbers past 2^53,
booleans, `null`, nested arrays and an object. Each value is canonicalized as
one working-memory entry by both implementations, and the answers are compared
PER VALUE, so a divergence names the input instead of a hash:

```
python3 crates/verifier/reference/run_grammar_probes.py target
cargo test -p seetrex-verifier --test grammar_probe
```

The Python writes `target/grammar_probe_python.txt`, the Rust test writes
`target/grammar_probe_rust.txt` and then compares them line by line, printing
every differing value before it fails. The same workflow runs both.

**Written from the document alone.** The Python was implemented by a reader
who had the specification and nothing else: no access to the Rust source, no
access to this repository, no search for any existing implementation of the
format. That is the point of it — a second implementation derived from the
same text is the evidence that the text is sufficient. Five markdown files
beside it carry what that produced, and they are worth more than the code to a
reader auditing the specification itself. Two more Python files sit there as
well — `crates/verifier/reference/run_corpus.py`, which answers the corpus
with it, and `crates/verifier/reference/run_grammar_probes.py`, which answers
the grammar probe list — and neither is part of the reference implementation:
they are runners.

- `crates/verifier/reference/OPEN_QUESTIONS.md` — every point the reader could
  not settle from the document, with the readings considered and the one
  implemented.
- `crates/verifier/reference/BLIND_TRANSCRIPT.md` — the instructions handed
  over, verbatim, and the sha256 of the specification copy the reader was
  given. That hash is the checkable part of the claim that the work was blind.
- `crates/verifier/reference/ALIGNMENT_NOTES.md` — one entry per behaviour
  that changed once those ambiguities were settled IN the specification, with
  the sentence that mandates it and the corpus case that exercises it.
- `crates/verifier/reference/ALIGNMENT_NOTES_R1.md` — the same record for the
  second alignment, after the first adversarial review widened the corpus
  (per-kind value grammar of section 4.1, ASCII duties, leap second, chain
  token). The residual gap it named — the rounding MODE of an over-precise
  monetary value — has since been pinned by the document (half away from zero,
  section 4.1), measured by the grammar probe below.
- `crates/verifier/reference/SELFTEST.md` — what the reader reproduced from
  the document alone, vector by vector, before either implementation had seen
  the other. It is a record of that run and is not re-executed afterwards.

**Where the limits are.** The file is a tracked source file, not a signed
release asset: it carries no detached signature of its own, and its anchor is
the sha256 in section 6 under the signed document tag. Since `0.3.6` the same
file also travels inside the published `.crate` on crates.io — an immutable
tarball whose registry checksum covers it (the section 6 crate row publishes
that checksum) — without becoming a release asset or gaining a signature of
its own. It implements `verify-package` and `verify-chain` only —
`verify-anchor`, `emit-sbom` and `verify-sbom` have no Python leg, and section
7 cannot be walked with it.

---

### 2.6 Route F — the offline browser page

<!-- web-route:begin -->
Route F is for the auditor with a browser and nothing else: one HTML file,
opened from disk with the network switched off. Route B remains the strong
path; the page is a convenience whose trust reduces to the same key, the same
signed list and the same two commands as route D.

**What it is.** `seetrex-verifier-offline.html`, ONE self-contained file. The
verification core inside it is a `wasm32-unknown-unknown` build of the SAME
library the executable of section 2.1 runs, carried in the page as a
lowercase-hexadecimal payload that the browser compiles from those bytes.
There is no second implementation here and no JavaScript rewriting of any
check: the page reads the files you give it, hands the bytes to that module,
and prints the lines the module returns — the same token strings, the same
reserved-token rules, the same scope sentences as the command line.

It makes no network request of any kind, which is checked as a property of the
file's text: no `<script src>`, no stylesheet, no font, no image, no `fetch`,
no `import`, no URL of any kind, and no separate `.wasm` to load. The
`Content-Security-Policy` the file carries (`default-src 'none'`) is the
browser refusing the same thing a second time — defence in depth, not the
proof. Open it as a `file://` document with the machine offline and nothing
about its answer changes.

**How you get it and check it.** The page is published as a release asset of a
signed tool tag, and a release may carry it or not. Verification is the two
commands of route D, over the page's own list:

```
# 1. Get the release-signing key and compare its fingerprint against the one
#    pinned in 2.3 BEFORE importing it. Same key as route B, same check.
curl -fsSL -o seetrex-release-key.asc https://seetrex.com/.well-known/release-signing-pubkey.asc
gpg --show-keys --fingerprint seetrex-release-key.asc
gpg --import seetrex-release-key.asc

# 2. Get the page, the list and its signature from the release of the tool tag
#    you want.
curl -fsSL -O https://github.com/seetrex-hq/seetrex-verifier/releases/download/seetrex-verifier-v<version>/seetrex-verifier-offline.SHA256SUMS
curl -fsSL -O https://github.com/seetrex-hq/seetrex-verifier/releases/download/seetrex-verifier-v<version>/seetrex-verifier-offline.SHA256SUMS.asc
curl -fsSL -O https://github.com/seetrex-hq/seetrex-verifier/releases/download/seetrex-verifier-v<version>/seetrex-verifier-offline.html

# 3. Both commands, in this order. Either one alone proves nothing.
gpg --verify seetrex-verifier-offline.SHA256SUMS.asc seetrex-verifier-offline.SHA256SUMS
sha256sum --ignore-missing -c seetrex-verifier-offline.SHA256SUMS
```

The signature covers the list and the list covers the bytes, so it is both
commands or neither: a signature you verified over a list you never compared
the file against says nothing about the file you are about to open.
`--ignore-missing` is explained in section 2.4 and does the same job here.
Only after both commands have passed, open the file in a browser.

**What it answers.** Two of the five subcommands, the two that need no network
and no clock:

- drop the verdict package DIRECTORY on the page (or pick it with the folder
  button) and it answers `verify-package`, with the optional expected verdict
  hash of section 4 typed into the field beside it;
- drop the single chain export `.json` and it answers `verify-chain`.

Both print the tool's own lines and its own outcome token, and the page marks
the token rather than inventing a word of its own. That is the whole of the
vocabulary: what the module says is what you read.

**What it does NOT do.** `verify-anchor`, `emit-sbom` and `verify-sbom` have no
browser leg — section 7 cannot be walked with this page, and the routes that
can walk it are A, B and D. The page fetches no chain export for you, resolves
no URL, and compares nothing against the Trust Center: every input is a file
you supply.

**Where the limits are.** The page is answered, before anything is hashed or
signed, against the same 92-case conformance corpus the two implementations of
route E answer (`crates/verifier/tests/fixtures/corpus/`), driven through the
very payload the shipped file carries; and it is built twice in the same job
and compared byte for byte, which constrains that job on that machine at that
moment and is silent about yours. What it is NOT is a second build of the tag
you verified: `crates/verifier-web`, the crate that hosts the core in the
browser, is not in the public repository, so the page is built from the
vendor's own tree and what binds it to the signed tag is a version
correspondence, not byte identity — the job refuses to run unless the tag's
own tree declares the same `seetrex-verifier` version and the tag is named for
it. A byte-for-byte result you obtain yourself is route B, and that is still
why route B is the strong path.

Two differences from the command line are semantic, not incidental, and
neither is a defect in either one. The page cannot refuse a symlinked package
member the way the command-line tool does: a browser hands over bytes, never
the fact that the operating system followed a link to find them, so that
refusal is a disk-only guarantee. And an empty directory is visible on one of the
page's two input routes and not on the other. The drag-and-drop area walks
directory ENTRIES, so it hands an empty one over and the page refuses the
package exactly as the executable does; but the folder picker cannot enumerate
an empty directory, because a `webkitdirectory` input hands the page a list of
FILES and an empty directory contributes none. A package whose only defect is
an empty directory therefore passes on the picker route and is refused by the
tool — the page says so, in its own diagnostics, whenever you use that route,
and dropping the directory on the area above is the answer. Finally, the page holds every
file of the package in the browser tab at once: the per-file and file-count
caps are the tool's own, but the TOTAL size it can answer is bound by the host
browser rather than by anything this specification states.
<!-- web-route:end -->

---

## 3. Verify the public chain

Every verdict appends one row to an append-only hash chain; the chain is
published as a JSON export on the vendor's Trust Center:

```
curl -fsSL -o chain.json https://trust.seetrex.com/seetrex-compliance-chain.json
seetrex-verifier verify-chain chain.json
```

Output shape, with the values of a chain captured 2026-07-27 with `0.3.3`:

<!-- section3-discontinuity:begin -->
> **Discontinuity notice (2026-08-24).** The chain captured below belongs to the
> RETIRED identity: on 2026-08-24 the producer wiped every chain row and
> restarted `seetrex-compliance` at ordinal 1 under a new genesis key (section
> 7.3). The `verdict_count` below is therefore NOT a floor for the live chain —
> a fresh export shows a small count that grows from 1. Any export or package
> you kept from before 2026-08-24 will not join the live chain, and the "extend
> the prefix" rule in the footer applies only to material captured after that
> date.
>
> **That loss is permanent, and it is the anti-omission check itself that is
> lost for the retired era.** No pre-reset export can ever extend the live
> chain's prefix, so a pre-reset export that fails to extend it — the exact
> signature this section teaches you to read as truncation — is now also the
> expected consequence of the reset, and no artifact this kit publishes tells
> the two apart for material captured before 2026-08-24. Nothing replaces it
> for that era. What survives of the retired era is on the transparency log,
> not in the chain: the leaves anchored under the retired genesis stay in
> `seasalp.glasklar.is` forever, explained by no published chain (section 7.3,
> the discontinuity note next to the kit template), and section 7.4(d) states
> exactly what a monitor enumeration that still carries them can and cannot
> say. For material captured on or after 2026-08-24 the rule below works
> unchanged.
<!-- section3-discontinuity:end -->

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
  the Trust Center page (`https://trust.seetrex.com/`) — a channel you fetch
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
| Source repository | `https://github.com/seetrex-hq/seetrex-verifier` | GPG-signed tags, verified with `git tag -v` against the pinned fingerprint (the seventeen this row names with a commit — seven document tags and ten tool tags — verified from a fresh clone on 2026-09-01; the clone carried others, and what is recorded here is what was checked). **Document tags** (`seetrex-kit-<date>-<reason>`, one per kit revision; they publish this document, not a tool release), newest first: `seetrex-kit-2026-09-01-verifier-0-3-7` at commit `2f7ab299f993…` (tag object `f8657bedfe3b…`, tagger 2026-09-01T12:35:17Z — the same commit `seetrex-verifier-v0.3.7` points at, signed one second later), `seetrex-kit-2026-08-30-verifier-0-3-6` at commit `ec29787c4ef0…` (tag object `3eccb1add82a…`, tagger 2026-08-31T10:45:29Z — the same commit `seetrex-verifier-v0.3.6` points at, signed one second later), `seetrex-kit-2026-08-29-recapture-0-3-5` at commit `c7a73b42283d…` (tag object `1e9865a72ecc…`, tagger 2026-08-29T08:47:17Z), `seetrex-kit-2026-08-28-signed-binaries` at commit `f0861a6900ae…` (tag object `786bd53e99e8…`, tagger 2026-08-28T22:01:48Z), `seetrex-kit-2026-08-27-full-enumeration` at commit `188324a10102…`, `seetrex-kit-2026-08-25-cvd-policy` at commit `e0627ed41e39…`, `seetrex-kit-2026-08-24-genesis-reset` at commit `f7ff1f6f3aef…`. **This list lags by exactly one entry, and does so by construction**: a document tag is created after the snapshot it signs, so the tag that publishes the copy in your hands can never appear in that copy. Read the top entry as the newest that existed when this snapshot was written, and select your document copy by tag DATE (section 2.2), never by this list. **Tool tags**: the newest tool tag, and the newest one verified from a fresh clone on 2026-09-01, is `seetrex-verifier-v0.3.7` at commit `2f7ab299f993…` (tag object `68ce03cbfa3d…`, tagger 2026-09-01T12:35:16Z). **The revision this release was cut from could name none of those three, by construction** — a tool tag is cut when the release it publishes is cut, which is after that snapshot was written — and it said so instead of predicting them; this revision is the one made after publication, so it names them as measurements. **The tag that publishes THIS revision still cannot be named here, and that is not an oversight**: it is created after the revision is written, which is also why the list of document tags above stops exactly one entry short of your copy. The tag `seetrex-verifier-v0.3.6` is at commit `ec29787c4ef0…` (tag object `7faf778e94e9…`, tagger 2026-08-31T10:45:28Z). The other tool tags: `seetrex-verifier-v0.3.5` at commit `f0861a6900ae…` (tag object `775f99972a8a…`, tagger 2026-08-28T22:01:47Z); `seetrex-verifier-v0.3.4` at commit `188324a10102…`, `seetrex-verifier-v0.3.3` at commit `8b61fe12c228…` and `seetrex-verifier-v0.3.2` at commit `54676db4e66b…` (still valid for the section 3 checks — see the crate row below for the section 4 and section 7 exceptions); superseded: `seetrex-verifier-v0.3.1` at commit `ecea6cc76f10…`, `seetrex-verifier-v0.3.0` at commit `719d0988a1bc…`, `seetrex-format-v1.0.0` and `seetrex-verifier-v0.2.0` at commit `f1dd053c82a1…` |
| Signed release binaries | attached to the tool tag's release in the public repository above, at most the two linux targets named here (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`) per release, and a release may carry just one of them; no macOS and no Windows binary is published. A tool tag whose release carries no `SHA256SUMS` publishes no binary at all — no release of that tag has one attached, and section 2.1 or section 2.2 is the answer there. A binary for a target the build host cannot execute is built and signed but is not run against the tool's own end-to-end suite before it is published; the job refuses to publish such a target unless the dispatch says so explicitly (section 2.4) | one `SHA256SUMS` lists every artifact and is GPG-signed as `SHA256SUMS.asc` with the release-signing key (fingerprint `F028 DE16 D3B2 AA44 0FE2 6F05 CECC 5577 2959 6616`); verify with `gpg --verify SHA256SUMS.asc SHA256SUMS` and then `sha256sum --ignore-missing -c SHA256SUMS` (section 2.4, where `--ignore-missing` is explained) — the signature covers the list and the list covers the bytes, so both commands or neither. Release assets sit on a platform that permits replacement, and the anchor of these bytes is the signed tag they were built from: this document names no digest of any release, what it anchors is the KEY that signs the list (fingerprint above, checked out of band per section 2.3), and re-deriving the bytes yourself is route B |
| `seetrex-format` `1.0.0` | crates.io | crates.io versions are immutable; pin with the exact requirement `=1.0.0` |
| `seetrex-verifier` `0.3.7` | crates.io | immutable; install with `cargo install seetrex-verifier --locked --version 0.3.7` (ships the executable), or pin `=0.3.7` as a library dependency (itself pins `seetrex-format =1.0.0`). Read back from the registry API on 2026-09-01: `max_version` `0.3.7`, published 2026-09-01T12:37:32Z, not yanked, a 568770-byte `.crate` whose sha256 checksum the registry reports as `e061e98b475eb3bde5d032ac11621795b604d1d89cf59808ce2205df2270b7af` — the value the downloaded tarball hashes to, measured. **The revision this release was cut from recorded none of those four**, because they do not exist until the crate is published; it said so and left the previous release's read-back standing. This revision is the read-back it deferred, and the registry now serves nine versions of this crate. Each release is ADDITIVE over the last (`0.3.3` added `verify-anchor`; `0.3.4` added `emit-sbom`, `verify-sbom` and `verify-anchor --chain`; `0.3.5` adds no subcommand, no option and no output, and moves no exit code; `0.3.6` adds none either — what it adds is the Python reference of section 2.5 inside the crate and an exact pin of the two dependencies section 4.1 was measured against; `0.3.7` adds none either — what it moves is the suite the published trees run, section 2.2), so `0.3.6`, `0.3.5`, `0.3.4`, `0.3.3` and `0.3.2` remain valid for every section 3 check. **They are not equivalent in section 4**: canonicalization (specification section 4.1) transcribes the behaviour of one exact `rust_decimal`, and `0.3.6` is the first release to pin it (`=1.37.2`) — the version the engine that PRODUCES these packages emits with. An earlier release pins nothing: the `.crate` published for `0.3.5` locks `rust_decimal` `1.42.1`, and as a library dependency the requirement floats to whatever is newest. Those two answer three exponent-form monetary values differently — `1.5e-28` is a `String` under `1.37.2` and the Money `0.0000000000000000000000000002` under `1.42.1`, while `0.5e-28` and `1.0e-28` are a `String` under `1.37.2` and the Money `0.0000000000000000000000000001` under `1.42.1` (parse each under each pin and print `normalize()`: five lines of your own reproduce all three) — so for a package carrying one of them the canonical form, the verdict-hash preimage and the `verdict_hash` itself all differ, and only `0.3.6` and later agree with production — `0.3.7` carries the same exact pin, which is why the section 4 floor stays at `0.3.6` and does not move with this release. Appendix A states the same boundary. **They are not equivalent in section 7 either**: with an independent enumeration a `0.3.3` binary reaches a truncation verdict the numbers do not support — 7.4(e.1) shows the run, and repairing it is what `0.3.4` is for. `0.3.0` and `0.3.1` stay downloadable forever and must not be used **as the executable**: their `verify-chain` trailers overstated the check's coverage (section 3). As a library they compute every hash and result identically, but their printed chain-scope wording (and two doc comments) carry the same overclaim `0.3.2` corrected — see appendix A |
| Offline browser page | <!-- web-route-row:begin -->attached to the tool tag's release in the public repository above, when a release carries one: ONE self-contained `seetrex-verifier-offline.html`, carrying a `wasm32-unknown-unknown` build of the same verification library as a lowercase-hexadecimal payload the browser compiles. A release may carry it or not, and a tool tag whose release carries no `seetrex-verifier-offline.SHA256SUMS` publishes no page at all — section 2.1, section 2.2 or section 2.4 is the answer there. It is built from the vendor's own tree and not from the tag's: `crates/verifier-web`, the crate that hosts the core in the browser, is not in the public repository, so what binds the file to the signed tag is a version correspondence, not byte identity — the job refuses to run unless the tag's own tree declares the same `seetrex-verifier` version and the tag is named for it | listed in a `seetrex-verifier-offline.SHA256SUMS` of its own — a name of its own, so it can never be confused with, or overwritten by, the binaries' bare `SHA256SUMS` on the same release — written by the job that builds the page and GPG-signed as `seetrex-verifier-offline.SHA256SUMS.asc` with the release-signing key (fingerprint `F028 DE16 D3B2 AA44 0FE2 6F05 CECC 5577 2959 6616`); verify with `gpg --verify seetrex-verifier-offline.SHA256SUMS.asc seetrex-verifier-offline.SHA256SUMS` and then `sha256sum --ignore-missing -c seetrex-verifier-offline.SHA256SUMS` (section 2.6, and section 2.4 where `--ignore-missing` is explained) — the signature covers the list and the list covers the bytes, so both commands or neither. The page answers `verify-package` and `verify-chain` only; it is built twice in the same job and compared byte for byte, and it is answered against the same 92-case conformance corpus at `crates/verifier/tests/fixtures/corpus/`, through the payload the shipped file carries, before anything is hashed or signed. It makes no network request of any kind, which is checked as a property of the file's text, and it cannot refuse a symlinked package member the way the command-line tool does. Its two input routes differ on ONE thing: the folder picker cannot enumerate an empty directory (a `webkitdirectory` input hands over FILES, and an empty directory contributes none), so a package whose only defect is one passes there and the page says so in its own diagnostics; the drag-and-drop area walks directory entries, hands the empty one over, and refuses the package as the tool does<!-- web-route-row:end --> |
| Package format spec | `docs/SPEC_VERDICT_PACKAGE_V1.md` in the source repository | covered by the signed tag; the normative reference for every check in this kit |
| Python reference verifier | `crates/verifier/reference/seetrex_verifier.py` in the source repository (section 2.5) | sha256 `a0ab8c8eda335367dcb8c6de039e2588f4f1c7208b834ac3e2b6ece13c47f5c6`, over the file as the repository stores it (LF line endings); a tracked file in the source repository, covered by the signed document tag; **not** a release asset — it carries no detached signature of its own. Since `0.3.6` it does travel inside the published `.crate` (the `seetrex-verifier` `0.3.7` row above), an immutable tarball whose registry checksum covers this file along with everything else in it. Its conformance corpus, 92 cases, sits beside it at `crates/verifier/tests/fixtures/corpus/`, and the grammar probe list it is also answered against, 528 values, at `crates/verifier/tests/fixtures/grammar_probes.txt` |
| Public chain export | `https://trust.seetrex.com/seetrex-compliance-chain.json` | self-verifying offline (section 3); head comparable against the Trust Center page (`verdict_count`, `last_chain_hash`), fetched over a channel you control |
| Build toolchain | `rust-toolchain.toml` (channel `1.91.1`) + committed `Cargo.lock` in the source repository, and the exact pins `rust_decimal = "=1.37.2"` and `chrono = "=0.4.41"` in the workspace `Cargo.toml` | build and test with `--locked` from the signed tag. The decimal library is pinned to an exact version on purpose: monetary canonicalization (specification section 4.1) was measured against `rust_decimal` 1.37.2, later releases answer a few exponent-form values differently, and a build that regenerates its own lockfile would otherwise float to one of them and compute different hashes for the same package. `chrono` (date and date-time grammar of the same section) is pinned for the same reason, pre-emptively: no divergence was observed between 0.4.41 and 0.4.45 |
| Verification code paths | the published crates | the shipped executable is a thin shell over the same library code the vendor's own CLI runs (not a reimplementation); its dependency purity — no engine, no network, no database — is enforced by intent tests inside the crate itself |

Independence rule, restated once: obtain the key fingerprint, the chain
export, and the expected verdict hashes through channels **you** choose and
control. The package is never its own trust root, and neither is any single
channel.

---

## 7. Anchor verification (`verify-anchor`): scope today, and a runnable demo

`verify-anchor`, introduced in `0.3.3` and given its optional `--chain` input
in `0.3.4`, is the subcommand that checks a producer's published
**anchor package** against a **pinned auditor kit** you supply — never
trusting the package for the tenant identity, genesis key or witness policy —
and reports two verdicts. The authoritative wording for them is the tool's
top-level `--help` output; the subcommand carries none of its own:

- **CONSISTENCIA** (non-contradiction): confirmed fully offline. Every
  anchored leaf's inclusion proof and the checkpoint cosignatures ARE
  cryptographically verified.
- **COMPLETITUD** (nothing omitted): INCONCLUSIVE offline unless you supply
  `--monitor <bundle.json>` from an independent monitor. Even then, the
  monitor's enumeration completeness and recency are a TRUSTED input — the
  leaves it reports are proven, the claim that it saw everything is not.

### 7.1 Walkthrough (illustrative transcript): verify the published anchor packages

Since witness `0.3.0` went live (2026-07-28) all three inputs are published,
and this walkthrough needs nothing but public artifacts — no host access,
reproduce it yourself: the verifier installed from crates.io and the kit
composed from the literal block in 7.3 of the **published, tag-signed** copy
of this document — never fetched from the host that serves the packages.

```
$ seetrex-verifier --version
seetrex-verifier 0.3.5

$ curl -sO https://trust.seetrex.com/seetrex-compliance-anchor.json
$ curl -sO https://trust.seetrex.com/witness-bundle.json
```

Compose `kit.json` from section 7.3 (`tenant_slug` is the only field that
changes if more tenants enroll), then run the verification. The transcript
below is a REAL run, captured on 2026-08-29 with the `0.3.5` binary — the
release that was current on that date, superseded since — against the
packages published that day. Its COUNTS are of that
day and nothing else: the chain was reset on 2026-08-24 and started at the
ENROLL leaf plus head ordinal 1, and it grows by one with every anchored
head — but only when the DAILY witness tick rebuilds the package, so the
newest anchored head you see normally trails the chain export by up to
~24.25 h (section 7.4(e)):

```
$ seetrex-verifier verify-anchor seetrex-compliance-anchor.json --kit kit.json --monitor witness-bundle.json
Anchor package CONSISTENCIA CONFIRMED OFFLINE
  tenant:                  "seetrex-compliance"
  anchored leaves checked: 54
  rotations checked:       0
  identity keys:           1 (genesis + accepted rotations)
  truncation reference:    package rows only, 78 rows (no --chain; heads past N are UNDECIDABLE)
  COMPLETITUD:             CONFIRMED OFFLINE (monitor supplied; enumeration completeness = trusted input)
$ echo $?
0
```

Read the COUNTS as yours to measure, never as values to expect: the same
command reported `anchored leaves checked: 7` on 2026-08-25, **20** on
2026-08-26, **35** on 2026-08-27 and **54** in the capture above, each after a
daily witness tick.
The FORM, however, is what your binary decides. A `0.3.3` binary prints this
same block WITHOUT the `truncation reference:` line, and rejects the `--chain`
argument that fills it in with exit `2`; both shipped in `0.3.4`, and
7.4(e) is the section that tells you which of the two you are holding and
why it matters. Supplying the published chain export as well
(`--chain seetrex-compliance-chain.json`) changed only that one line in the
same 2026-08-29 capture, to
`published chain export, 78 rows (package 78; reference N=78)`, leaving both
verdicts and the exit code untouched.

The run's explanatory footer states the boundary this walkthrough must not
blur:

```
CONSISTENCIA (offline) confirms only that the PRESENTED material does not contradict itself: every anchored leaf's inclusion under the cosigned checkpoint verifies, the producer identity chain derives from the PINNED genesis without a fork, and the chain JOIN holds. It does NOT prove COMPLETITUD: a vendor who OMITS a contradictory log leaf republishes a shorter, self-consistent history that still passes CONSISTENCIA — catching omission needs an INDEPENDENT monitor enumeration of the log. That second verdict, COMPLETITUD, is INCONCLUSIVE unless you supply such an enumeration (--monitor <bundle>); with one it becomes a REAL verdict (CONFIRMED / INCONCLUSIVE / FAILED) shown on the COMPLETITUD line above, and WITHOUT one a confirmed CONSISTENCIA is NOT a statement that the vendor anchored everything. A confirmed verdict over ZERO anchored leaves is VACUOUS — it asserts nothing about anchoring; read the 'anchored leaves checked' count. Surfaced anomalous rotations (e.g. unauthorized) do NOT lower CONSISTENCIA — their fatal mapping is enumeration-dependent (COMPLETITUD); investigate them separately. The witness policy and genesis key used here are PINNED inputs from your auditor kit, never from the package.
```

Read that footer against what this walkthrough actually fed it:
`witness-bundle.json` is the producer's OWN enumeration, downloaded from the
producer's own host — not an independent monitor. This COMPLETITUD CONFIRMED
is therefore self-attested in BOTH legs (the enumeration and, per 7.4(a),
the liveness observations). The strong, omission-ruling-out verdict needs an
enumeration that you or a third party ran under the pinned policy. **Expect a
different result when you run it, and expect it to depend on your build.**
Measured on 2026-08-25 against the live package: with a released `0.3.3`
binary an independent enumeration turns the COMPLETITUD line above into
`FAILED` with exit `1` — an accusation of truncation that the numbers do not
support.

<!-- completitud-ladder:begin -->
<!-- EDITOR: this region is pinned by an intent test in the producer's source
     tree. The liveness bullet below is FROZEN word for word (after whitespace
     flattening, so a rewrap is free and a rewording is not); the three bold
     inputs are a CLOSED set; every bullet's citation must resolve, quote what
     those lines say, and name identifiers that really occur in the cited
     code; and the number words in the region must equal what they count.
     WHAT NO TEST READS: whether a sentence is normative, hedged, or states a
     condition. Those are human-reviewed prose — the FROZEN literal above is
     what that decision looks like when it has to be enforced, and six rounds
     of word lists are why there is no list here. -->
**Why your own enumeration costs more than the transcript above — input by
input, because it is not a count.** These are the three inputs YOU SUPPLY. They
are not everything COMPLETITUD consults — the paragraph after them names
failure modes that are not about your inputs at all — but they are the three
you can do anything about. Each has its own condition, they do not rise and
fall together, and one of them has no condition at all:

- **a liveness observation for the slug** — required whenever your bundle
  carries an anchored head, which is every real bundle. There is no condition
  to escape here: the arm is `None if has_anchored_head` and it returns
  INCONCLUSIVE on the spot
  (`crates/verifier/src/anchor_completitud.rs:1041-1046`, "slug has an anchored
  head but its liveness was not probed"). The published enumerator does not
  write one — 7.4(d).
- **a consistency proof in the bundle** — required only when your `C_audit` is
  LARGER than the package's checkpoint. At EQUAL sizes the check demands an
  EMPTY proof and matching roots, so supplying none is the correct answer
  (`crates/verifier/src/merkle.rs:156-157`, "return proof.is_empty() &&
  first_root == second_root"). If your `C_audit` is SMALLER than the package
  checkpoint the check returns false outright and NO proof repairs it
  (`crates/verifier/src/merkle.rs:153-154`, "if first_size > second_size");
  re-enumerate against a fresher head instead. The published enumerator does
  not write a proof either — 7.4(d).
- **the published chain export as `--chain`** — required only when your highest
  enumerated head runs PAST the package's row count `N`; at or below `N` there
  is nothing to decide
  (`crates/verifier/src/anchor_completitud.rs:750-756`, "monitor enumerates
  HEAD@{m} (the highest head it saw for this slug)"). The flag is in the
  RELEASED binary from `0.3.4` on; a `0.3.3` binary rejects it with exit `2`
  — 7.4(e).

**The producer's own `witness-bundle.json` needs none of the three, and the
reason is the whole point of this paragraph: it already CARRIES an
observation.** Measured 2026-08-26: `observations` holds one entry for this
slug; `consistency_proof` is `[]`, which is correct because its `C_audit` size
62290 equals the package checkpoint 62290; and its highest head 42 equals `N` =
42, so there is no truncation question to decide. That is why the transcript
above is one command with no `--chain` at all, printing
`COMPLETITUD: CONFIRMED OFFLINE` at exit `0`.

**Change that one field and the transcript changes with it.** Set
`"observations": []` in the very same bundle, run the very same command on the
very same binary, and `CONFIRMED OFFLINE` becomes
`COMPLETITUD: INCONCLUSIVE — slug has an anchored head but its liveness was
not probed — cannot certify the export is served (fail-closed; supply a
SlugObservation)`, exit `0`. Neither of the other two conditions moved. That is
the input a reading of this paragraph as "two conditions" loses, and it is the
one YOUR enumeration will always be missing.

**Three of the ways COMPLETITUD fails are not about your inputs at all, and
this list is NOT exhaustive — it is what has been measured.** They are
properties of the material you were given, so no amount of supplying fixes
them; they are here so a FAILED is not read as your mistake:

- the cosigned checkpoint must authenticate under the pinned witness quorum
  (`crates/verifier/src/anchor_completitud.rs:1342-1346`, "C_audit not
  authenticated by pinned quorum"). Measured 2026-08-26 by dropping the 13
  cosignatures from the published bundle: `FAILED — C_audit not authenticated
  by pinned quorum: QuorumNotMet { have: 0, need: 2 }`, exit `1`.
- every head the PACKAGE publishes must appear in your enumeration
  (`crates/verifier/src/anchor_completitud.rs:979-983`, "but the floor-fresh
  monitor enumeration"). Measured the same day by dropping the
  `head@42` leaf: `FAILED — package published HEAD@42 but the floor-fresh
  monitor enumeration omits it — unattested anchoring (G-v6-2 coverage)`,
  exit `1`.
- your `C_audit` must not be SMALLER than the package checkpoint: below it the
  consistency check returns false outright and no input you supply repairs it
  (`crates/verifier/src/merkle.rs:153-154`, "if first_size > second_size").
  Re-enumerate against a fresher head instead.

**So what your own bundle needs depends on WHEN you enumerate.** Always the
observation. The consistency proof only if you enumerated after the package's
checkpoint was cut — the normal case, since the package is rebuilt once a day.
`--chain` only if a head has been submitted since that rebuild. Enumerate in
the minutes after a daily tick and two of the three are enough; enumerate late
in the day and you need all three.
<!-- completitud-ladder:end -->

Read 7.4(e) BEFORE you act on
any of this, and read 7.4(d) before you build the enumeration itself.

<!-- self-report-probe:begin -->
The strong reading of those COMPLETITUD lines is governed by 7.4: the
bundle's `observations` are the producer's SELF-REPORT, so finish with your
own probe of the same URLs and compare:

```
$ python -c "import json; print(json.load(open('witness-bundle.json'))['observations'])"
[{'served': True, 'slug': 'seetrex-compliance'}]
$ curl -s -o /dev/null -w "%{http_code}" https://trust.seetrex.com/seetrex-compliance-anchor.json
200
```
<!-- self-report-probe:end -->

The own probe agrees with the self-report. If your two downloads straddle a
producer tick, COMPLETITUD can come back INCONCLUSIVE from checkpoint skew —
that is the expected TOCTOU reading per 7.4(b): re-download BOTH files and
re-run. The witness ticks once a day and the pipeline republishes hourly, so
a fresh round almost never straddles a tick; if 2-3 fresh rounds still
return INCONCLUSIVE, it is not skew — stop and investigate. Note the exit
code stays `0` on an INCONCLUSIVE: a scripted gate must read the COMPLETITUD
line, not just the exit status. The same daily/hourly split is what makes the
package itself lag the chain, and with an independent enumeration that lag is
what `verify-anchor` reports today as a COMPLETITUD `FAILED` with exit 1;
7.4(e) states the lag, its size, that measured outcome, and what it does and
does not let you conclude.

### 7.2 The subcommand's own end-to-end suite, runnable without any download

The published crate ships an end-to-end suite that builds valid and invalid
anchor packages with ephemeral keys and drives the **real installed-style
binary** through every `verify-anchor` outcome — confirmed, tenant mismatch,
malformed package (exit 1), malformed kit (exit 2), monitor-based COMPLETITUD
both downgrading and confirming. From the crate tree (extract the `.crate`
tarball from crates.io, or use the signed-tag checkout of section 2.2):

```
cargo test --test bin_e2e anchor
```

Literal output, captured 2026-08-29 from the `0.3.5` `.crate` tarball
unpacked from crates.io — the tree `cargo install` compiled that day. Re-run
on 2026-09-01 from the published `0.3.7` `.crate`, downloaded from crates.io
and unpacked: the same 46-test `bin_e2e` suite, the same 21 selected by this
filter, 21 passed and 0 failed, and the twenty-one names below are the
twenty-one the run printed, compared as a set — unchanged by the two releases
since the capture:

```
running 21 tests
test test_intent_verify_anchor_chain_without_monitor_is_acknowledged ... ok
test test_intent_verify_anchor_declined_export_does_not_suppress_the_enumeration ... ok
test test_intent_verify_anchor_lag_without_chain_is_inconclusive_exit_0 ... ok
test test_intent_verify_anchor_declined_export_is_never_shown_as_the_reference ... ok
test test_intent_verify_anchor_real_truncation_with_chain_fails_exit_1 ... ok
test test_intent_verify_anchor_repeated_chain_is_usage_error ... ok
test test_intent_verify_anchor_without_chain_is_unchanged ... ok
test test_intent_verify_anchor_without_monitor_says_the_rule_was_not_reached ... ok
test test_intent_verify_anchor_repeated_kit_and_monitor_are_usage_errors ... ok
test test_scenario_verify_anchor_confirmed_offline_no_reserved_token ... ok
test test_scenario_verify_anchor_tenant_mismatch_fails ... ok
test verify_anchor_broken_chain_export_exits_1 ... ok
test verify_anchor_chain_without_value_is_usage_error ... ok
test verify_anchor_completitud_failed_before_the_truncation_rule_says_so ... ok
test verify_anchor_malformed_kit_exits_2 ... ok
test test_intent_verify_anchor_reference_rises_never_falls ... ok
test verify_anchor_malformed_monitor_exits_2 ... ok
test verify_anchor_contradictory_chain_export_is_declined ... ok
test verify_anchor_malformed_package_exits_1 ... ok
test verify_anchor_missing_kit_is_usage_error ... ok
test verify_anchor_empty_honest_monitor_confirms_completitud ... ok

test result: ok. 21 passed; 0 failed; 0 ignored; 0 measured; 25 filtered out; finished in 0.66s
```

The same filter returned 8 tests against the `0.3.3` tree on 2026-07-27.
Seven of those eight are still in the list above; the eighth,
`verify_anchor_real_monitor_completitud_downgrades`, is not, and the fourteen
that are new here are largely the `--chain` truncation reference of 7.4(e.2)
and its refusals. Neither the count nor the names are stable across releases:
read the run you get, not this list. (The 25 filtered-out tests
cover the other four subcommands, the CLI's usage/version behaviour and the
crate manifest; the monitor-based anchor tests use or derive their
`--monitor` input from the crate's embedded
`tests/fixtures/fb2c_enumeration_oracle.json`). Invoking the subcommand with missing arguments
exits `2`, distinct from every verification outcome (re-verified 2026-09-01
against the installed `0.3.7`):

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

<!-- kit-channel-era:begin -->
**Which signed copy — the era matters more than the version.** The values
below are the LIVE ones only in a copy of this document published on or after
the genesis reset of 2026-08-24. Take them from the tag that publishes this
revision — the newest signed tag of the repository in section 2.2 whose date
is on or after 2026-08-24 (section 2.2 explains why no version number can
name it). The tag `seetrex-verifier-v0.3.7` (2026-09-01) is the current
release of the TOOL, and nothing about the reset
changed the executable;
`0.3.6`, `0.3.5`, `0.3.4` and `0.3.3` stay downloadable and valid for the section 3 checks, and
for section 4 the floor is `0.3.6` (the section 6 crate row names BOTH
exceptions: section 4, where none of the older tools is equivalent, and
section 7, where `0.3.3` alone is not). But the
earlier tag `seetrex-verifier-v0.3.3` (2026-07-27) predates the reset, so
the copy of this document under it pins the RETIRED genesis key, and a kit
composed from it fails every live leaf (sections 7.4c and 7.4d).
<!-- kit-channel-era:end -->

<!-- kit-values:begin -->
The template follows. The ONLY per-tenant field is `tenant_slug`. One tenant
is enrolled in the transparency log today: `seetrex-compliance` (the literal
value in the block) — substitute the slug of the tenant you are auditing and
leave every other value untouched.

```json
{
  "version": "seetrex/anchor-kit/v1",
  "tenant_slug": "seetrex-compliance",
  "genesis_key_hash": "85b052121ca91072fecc37279ff503588e4f034ea1fd6405e0a59cbcbb2fc406",
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

<!-- identity-discontinuity:begin -->
**Genesis reset of 2026-08-24 (a discontinuity, not a rotation).** Before that
date the production anchor identity was the genesis key
`f50f20fa74c509ff4d1bd197851eb1489a197bd4076295ab40302d9d888101f5` (cut over
2026-07-26). On 2026-08-24 every test tenant, verdict and chain row was wiped
from production and a NEW genesis key was generated on the host:
`85b052121ca91072fecc37279ff503588e4f034ea1fd6405e0a59cbcbb2fc406`, the
value in the template above. There is NO `rotate` leaf joining the two
identities: the leaves anchored under the old key remain in
`seasalp.glasklar.is` forever, are explained by no published chain, and are
not part of the identity this kit pins. An auditor holding a chain export or
anchor package from before 2026-08-24 is looking at the retired identity — do
not expect it to join the live chain. The slug `seetrex-compliance` was
re-enrolled under the new key, so its chain restarts at ordinal 1.
<!-- identity-discontinuity:end -->
<!-- (the region above is pinned by an intent test in the producer's source
      tree: both key hashes, the "no rotate leaf" statement and the reset date
      must stay.) -->

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
| `version` | the `seetrex/anchor-kit/v1` schema constant | the published `seetrex-verifier` `0.3.7` source (`src/anchor_package.rs:443`, `ANCHOR_KIT_VERSION`), on crates.io and under the signed tag; re-checked against the `0.3.7` tarball on 2026-09-01 — same constant, same line as in `0.3.6` and in `0.3.5`; unchanged since `0.3.3` |
| `tenant_slug` | the tenant under audit (`seetrex-compliance` today — the only enrolled tenant since the 2026-08-24 reset) | the tenant's own chain-export name on the Trust Center (`<slug>-chain.json`) — a naming convention, not a security value |
| `genesis_key_hash` | SHA-256 of the raw 32-byte Ed25519 GENESIS submit public key, generated on the producer host on 2026-08-24 (the genesis reset — it REPLACED the 2026-07-26 key, see the discontinuity note above); no rotation has occurred since (see 7.4c) | none outside the vendor — this is the producer's self-declared identity root, and pinning it IS the point: every anchored leaf must trace to it (via any published rotations) or CONSISTENCIA fails. Its only publication channel is this signed document |
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
`seetrex.com` (`/signing-key`) shipped with the anchor-surface release;
being on the same domain as the `.well-known` copy it is a second surface
of route (2) in section 2.3, not an additional independent channel.

### 7.4 Reading the two verdicts: normative rules

The rules below are **normative** for interpreting `verify-anchor` results
against this producer's artifacts. They do not change what the tool computes;
they state what a computed result does and does not mean.

**(a) `observations` in the producer's bundle are SELF-REPORT — a COMPLETITUD
built on them certifies self-attested liveness.** The consumer contract
defines `observations` as the *auditor's own* liveness probes, and they are
the single input that can absolve an anchored head whose export is not being
served. Since witness `0.3.0` (2026-07-28) the published bundle carries one
observation per tenant of the expected set (section 7.1) — populated
**from the producer's own webroot directory**: `served: true`
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

**(c) A CONSISTENCIA FAILED "leaf submitter key is not in the pinned producer
identity set — inclusion in the shared log does not make the leaf ours"
immediately after an ANNOUNCED key rotation may be a FALSE RED.**
`rotations: []` is the current, correct state: no key rotation has occurred,
so the identity set you derive from the pinned genesis is exactly that one
key. If the producer announces a rotation, a package emitted before its
packaging catches up with the rotation would still carry `rotations: []`, and
leaves signed under the new key would then fail CONSISTENCIA with exactly the
same message as a forgery. Immediately after an announced rotation,
cross-check that FAILED against the producer's rotation announcement (and its
rotation runbook) before concluding forgery: a mid-rotation packaging gap and
tampering are distinguished by whether the announced rotation accounts for
the new key.
<!-- stale-kit-rule:begin -->
Absent any announced rotation, do NOT take the FAILED at face value yet: the
same FAILED is produced whenever kit and material come from different sides
of the genesis RESET of 2026-08-24 (section 7.3 — not a rotation, no `rotate`
leaf). The two cases are symmetric: (1) a kit composed from a copy of this
document signed BEFORE 2026-08-24 pins the RETIRED genesis (`f50f20fa…01f5`)
and fails every live leaf, which is signed under `85b05212…c406`; (2) an
anchor package you saved BEFORE 2026-08-24 carries leaves under the retired
genesis and fails under the current kit — and re-composing the kit does not
change that. **The rule: pair kit and material from the same era.** A FAILED
from a CROSS-era pair (kit from one side of 2026-08-24, material from the
other) is the discontinuity, benign by design, and proves nothing either
way. A FAILED from a SAME-era pair is a real finding within that era; the one
that is evidence of forgery against the LIVE identity is a FAILED obtained
with the kit of the current tag-signed copy of 7.3 AND material fetched after
2026-08-24. Re-compose the kit from the current tag-signed copy, re-fetch the
material, re-run — and confirm first that your copy of this document is the
current one (revision line at the top).
<!-- stale-kit-rule:end -->

<!-- completitud-reset-rule:begin -->
**(d) A COMPLETITUD FAILED "enumerated leaf under a key not in the producer
identity set — a key without an authorized rotate (G-v6-7)" whose only alien
key is the genesis of the OTHER side of the reset is the same discontinuity,
not an unauthorized rotation.**

This verdict exists only when you pass `--monitor`: with no bundle supplied
COMPLETITUD is INCONCLUSIVE (section 7) and nothing below applies.

The log keeps the leaves anchored under `f50f20fa…01f5` forever. A monitor
enumeration that carries leaves of the retired era — a bundle produced before
2026-08-24, or one whose submitter filter spans the reset because it
deliberately keeps the retired key "for history" — retains those leaves, and
against a kit+package of the live era — the identity set is the one your KIT
derives from the live genesis `85b05212…c406` — the verifier
reports exactly that G-v6-7 FAILED: the retired key has no `rotate` leaf
authorizing it, because it was never rotated — it was replaced.

**The rule is symmetric, exactly as in 7.4(c).** This gate compares the
bundle's leaves against the identity set your KIT derives, so the mirror image
yields the identical FAILED: a kit and a package of the RETIRED era, checked
against a bundle of the LIVE era, make `85b05212…c406` the alien key — and
that is the pair an auditor is most likely to assemble by accident, because
the bundle the producer publishes today carries live-era leaves only (its scan
filters by the live genesis) while a copy of this document signed before
2026-08-24 still yields a retired-era kit. Neither direction is evidence
against anyone. **Forgery is asserted only when kit, package AND bundle are
all of the same era**; a pair drawn from different sides of 2026-08-24 is
the discontinuity when its only alien key is the genesis of the other era,
and the era of a bundle is read from its keys with the command below.

**The message does not name the offending key.** It is a fixed literal,
byte-identical for every alien key, so there is nothing in it to read. Read
the keys from the bundle instead: every entry of its `leaves` array carries
`submitter_key_hash` as lowercase hex — the same field `verify-anchor` parses
— and the alien ones are those equal to neither your kit's `genesis_key_hash`
nor a key reached from it by an AUTHORIZED `rotate` lane of the same bundle
(one whose `key_hash_old` is the LAST key of the set and whose own
`submitter_key_hash` equals that `key_hash_old`; the derivation walks a LINEAR
chain from the genesis, so two authorized rotates off the same old key are a
FORK, not a branch to follow; with `rotations: []`, today's correct state, the
set is the genesis alone). G-v6-7 judges the non-`rotate`
leaves: a `rotate` lane feeds the identity derivation instead of being tested
against it, so exclude `lane.kind == "rotate"` from the read or you will
weigh a key the gate never looked at. The shape of that read (values here are
the two keys of the reset):

```
$ python -c "import json; print(sorted({l['submitter_key_hash'] for l in json.load(open('bundle.json'))['leaves'] if l['lane']['kind'] != 'rotate'}))"
['85b052121ca91072fecc37279ff503588e4f034ea1fd6405e0a59cbcbb2fc406', 'f50f20fa74c509ff4d1bd197851eb1489a197bd4076295ab40302d9d888101f5']
```

If the other era's genesis is the only alien key, the FAILED is the
discontinuity and says nothing against either identity. Any OTHER alien key is
what G-v6-7 exists to catch — a leaf minted under a key that never received an
authorized rotation — and it stays a finding for the era whose kit produced
it, whatever else the bundle contains.

**Do NOT narrow the enumeration to the live genesis to make the FAILED go
away.** An enumeration that collects exactly the leaves whose submitter is in
the set your kit derives satisfies this gate by construction: no other leaf
was collected, so no other leaf can fail it, and the COMPLETITUD it yields is
vacuous on precisely the one check that can surface a key without an
authorized rotate. Keep the filter broad, re-enumerate, and judge by WHICH
alien keys remain.

**Who can do that, and what to conclude if you cannot.** Re-enumerating is the
ENUMERATOR's act: the submitter filter belongs to whoever RUNS the monitor —
the producer, or the third party whose bundle you obtained (section 7.1) — and
the scanner that produces it is not among the tools this kit publishes. As the
holder of a published bundle you can read its keys with the command above, but
you cannot re-run its scan; ask the party that ran it, or run your own
enumeration of the log. And if you hold no bundle at all, this FAILED is not
your result: `verify-anchor` without `--monitor` reports COMPLETITUD
INCONCLUSIVE, which is the honest verdict for you — a cross-era FAILED
reported by someone else does not turn it into FAILED.
<!-- completitud-reset-rule:end -->

**What building your own enumeration actually costs today — measured, so this
kit does not send you after a capability the published tooling lacks.** The
scanner is not among the tools this kit publishes; the producer's own
`seetrex-witness enumerate` IS published, and on 2026-08-25 it did not yet emit
a bundle that a LAGGING package accepts. Two gaps, both in the bundle it
writes:

- `consistency_proof` is emitted **empty**, unconditionally, and the tool never
  takes a package checkpoint as input. Against a package older than your own
  `C_audit` the freshness gate then refuses:
  `COMPLETITUD: INCONCLUSIVE — C_audit (size 62274) is not a consistency-proven
  append-only extension of the package checkpoint (size 62090) — freshness not
  cryptographically established (G-v6-6)`. Closing it takes ONE more public
  request — `GET https://seasalp.glasklar.is/get-consistency-proof/<package
  checkpoint size>/<your C_audit size>` — whose `node_hash=` lines (14 of them
  for 62090 → 62274) are what `consistency_proof` wants.
- `observations` is emitted **empty for you**. It is populated only when the
  tool is run with `--emit-anchor-dir` and local export discovery ran — the
  producer's own staging configuration, not yours — so the flag that fills it
  is one an auditor has no reason to pass. A bundle with no liveness
  observation for the audited slug yields
  `COMPLETITUD: INCONCLUSIVE — slug has an anchored head but its liveness was
  not probed — cannot certify the export is served (fail-closed; supply a
  SlugObservation)`. That probe is yours to make (the `self-report-probe` block
  of 7.1) and yours to record.

Both messages above are what a build carrying the 2026-08-25 lag fix prints
(`0.3.4` and later); a `0.3.3` binary reaches the truncation verdict of
7.4(e.1) on the same bundle instead. Neither gap is something you can fix from outside, and neither
is promised fixed here. If you report on this producer, say so plainly: the
strong path exists and is worth walking, and the published tooling does not
walk it end to end for you.

<!-- anchor-lag-finding:begin -->
**(e) The package's newest anchored head is BEHIND the published chain. What
`verify-anchor` makes of that changed on 2026-08-25, and the change is in the
tool from `0.3.4` on while `0.3.3` stays installable — so read which build you
have before you read the verdict.** Everything below was measured on 2026-08-25 against the live
artifacts; nothing here is predicted.

*What you can check yourself, with two downloads and no host access:* fetch
`seetrex-compliance-anchor.json` and `seetrex-compliance-chain.json` in the
same second and compare the highest `head` ordinal among the package's
`anchored_leaves` with the highest `ordinal` in the chain export. On
2026-08-25 at 21:05 UTC both files carried the same
`last-modified: Tue, 25 Aug 2026 21:05:03 GMT`, and yet the package held 12
rows and 7 leaves whose newest was `head@12` (log leaf index 62089) under a
checkpoint of size 62090 cosigned at `2026-08-25T00:08:16Z`, while the chain
export was already at ordinal 39. At the 22:05 UTC republish the package was
byte-identical to that one (md5 `858aa644437c660d0c15788c488e7c33`) and the
export had reached ordinal 40.

*What the producer states as the cause* — producer-internal, NOT verifiable
from your side, and stated here only so the observation above is not read as
tampering: the package is rebuilt **once a day** by the witness enumerator,
which stamps it with the rows and the cosigned checkpoint of ITS OWN run
(`deploy/trust-center/seetrex-witness-enumerate.timer:15,21`,
"OnCalendar=*-*-* 00:00:00 UTC" + "RandomizedDelaySec=15min"; the unit's own
comment sizes it, `:20`: "worst case tick-to-tick is 24 h + 15 min"), while
the hourly Trust-Center pipeline does not rebuild it at all — it copies the
file the witness left behind and republishes it
(`scripts/trust-center-pipeline.sh:1315`, "anchor packages: staged
$anchor_pkg_count package(s) from $ANCHOR_PACKAGES_SRC_DIR"; the copy at
`:1123,1134`, the publish at `:1333`). **The published package therefore
trails the chain by up to ~24 h 15 min of witness cadence plus one hourly
republish — about 24.25 h.** A head appended at 20:05 cannot appear under a
checkpoint cosigned at 00:08 of that day; that is arithmetic, not a fault.

**(e.1) What a `0.3.3` binary does, and why its verdict is wrong.** `0.3.3` is
four releases back — `0.3.4` superseded it and `0.3.7` is the current release
— and it stays installable for ever:
`cargo install seetrex-verifier --locked --version 0.3.3` gives you exactly
it, and only
signed tags are releases (the project's `CHANGELOG.md` says so — it lives at
the root of the public repository under the signed tag, not inside the
published `.crate`). Run the
verification of 7.1 with an INDEPENDENT enumeration — the strong path 7.4(d)
sends you to — and a `0.3.3` binary prints:

```
  COMPLETITUD:             FAILED — monitor enumerates HEAD@14 but the published chain is only N=12 rows — rows were truncated while their tail leaf stays in the log (G-v6-2)
$ echo $?
1
```

**That accusation is wrong, and the producer says so rather than leaving you to
discover it.** The `N=12` is the row count of the PACKAGE, not of the chain
export, which carried 40 rows in the same measurement. Your monitor enumerated
`head@14` and every later head the log holds; the package's row list stops at
12 because it is a day old. Nothing was truncated. The check compared a
day-old artifact against a fresh enumeration and reported the only failure it
had a name for.

*What that means for you while you hold a `0.3.3` binary:* a scripted gate of
yours goes red, and it is red for the staleness described above and not for
removal. Do not report truncation on the strength of that wording — test it
instead, which you can: keep every export you fetch and check that the next one
EXTENDS the prefix you hold, ordinal by ordinal and `chain_hash` by
`chain_hash` (7.1, and the `verify-chain` trailer in section 3). It does NOT
lower CONSISTENCIA, which is confirmed on the same run.

**(e.2) What the tool does since 2026-08-25 — released in `0.3.4`.** The
comparison now takes an explicit reference. `verify-anchor` gained an optional
`--chain <chain.json>` and prints a new line naming what it compared against:

- **without `--chain`** the question is left open — a head beyond the package's
  N rows yields `COMPLETITUD: INCONCLUSIVE … (G-v6-2 UNDECIDED)` and **exit 0**,
  and the message names `--chain` as the input that decides it (the exit code
  staying 0 on an INCONCLUSIVE is the rule 7.1 already states);
- **with `--chain`**, a head at `k <= N(export)` is a LAG — the head's
  `chain_hash` is checked against export row `k` — and only `k > N(export)`
  is `FAILED` with the `G-v6-2` wording unchanged;
- an export that CONTRADICTS the package over the rows both reach is DECLINED
  rather than accused on, so a mistyped `--chain` path cannot manufacture a
  FAILED. A merely SHORTER export agrees over its overlap and is kept: that is
  the shape truncation actually has.

Measured 2026-08-25 on the live package and an independent enumeration **into
which a consistency proof and a liveness observation had already been added by
hand** — 7.4(d) says why you must, and that the published enumerator writes
neither. Given that bundle, the three runs below differ only in `--chain`:

```
  truncation reference:    package rows only (no --chain; heads past N are UNDECIDABLE)
  COMPLETITUD:             INCONCLUSIVE — monitor enumerates HEAD@14, beyond the anchor package's N=12 rows. … Supply the producer's published chain export (--chain <chain.json>) to decide it … (G-v6-2 UNDECIDED)
$ echo $?
0

  truncation reference:    published chain export, 40 rows
  COMPLETITUD:             CONFIRMED OFFLINE (monitor supplied; enumeration completeness = trusted input)
$ echo $?
0

  truncation reference:    published chain export, 13 rows          # export truncated by hand, as a control
  COMPLETITUD:             FAILED — monitor enumerates HEAD@14 but the producer's published chain export is only N=13 rows — rows were truncated while their tail leaf stays in the log (G-v6-2)
$ echo $?
1
```

The third run is the control that keeps the second from being vacuous: with a
deliberately truncated export the FAILED still fires, so `CONFIRMED` in the
second run is a verdict about the artifacts and not a check that stopped
checking.

**What `--chain` does NOT do, so the runs above are not read as more than they
are.** It changes the reference the truncation rule compares against. On a
bundle straight out of the published enumerator that leaves the verdict WORD
where it was — but not the printed line, and the difference is the whole point
of the flag. Measured 2026-08-26 against the live package, one bundle, only
`--chain` varying:

- **without it:** `INCONCLUSIVE — C_audit (size 62307) is not a
  consistency-proven append-only extension of the package checkpoint (size
  62290) — freshness not cryptographically established (G-v6-6); a stale or
  forked reference cannot certify completeness. ALSO UNDECIDED: monitor
  enumerates HEAD@44 (the highest head it saw for this slug), beyond the anchor
  package's N=42 rows. The package alone cannot tell a producer that TRUNCATED
  rows from a package that merely LAGS the log …, so nothing is concluded.
  Supply the producer's published chain export (--chain <chain.json>) to decide
  it … (G-v6-2 UNDECIDED)`, exit `0`;
- **with it:** the same `INCONCLUSIVE — C_audit (size 62307) is not a
  consistency-proven append-only extension of the package checkpoint (size
  62290) — freshness not cryptographically established (G-v6-6); a stale or
  forked reference cannot certify completeness` and NOTHING after it — the
  whole second clause is gone, exit `0`.

So `--chain` decided the truncation question and left the freshness one
standing — which is the only question it was ever about. Add the consistency
proof and the verdict moves to `INCONCLUSIVE — slug has an anchored head but
its liveness was not probed`; add the observation too and the run reaches
CONFIRMED. Three inputs, in that order, and two of them are yours to construct.

<!-- EDITOR: the region below is pinned by an intent test, and only by
     ADJACENCY, in two sentences: the code written after the instruction to
     run the tool's own --help, and the code written after the mention of
     verify-anchor --help, must each be the one measured for that command and
     must follow it with no letter and no digit between. This is NOT a count of
     the codes in the region: any FURTHER exit code written in this paragraph
     is checked by nothing, and neither is any sentence here. -->
<!-- top-level-help-code:begin -->
**Where (e.2) exists: in the release you install.** (e.2) was written on the
branch
`fix/completitud-lag-vs-truncation` of the vendor's PRIVATE repository
(introduced by its commit `75320e2d`), and that branch was folded
into that repository's `main`: **this tree now carries `--chain`**, and
**`--chain` ships in `0.3.4`**, and every release after it carries the flag,
`0.3.5`, `0.3.6` and `0.3.7` included. So the two paragraphs above are the two builds an auditor can
be holding, and which one you have follows from the version alone: `0.3.3` and
earlier are (e.1), `0.3.4` and later are (e.2). A `0.3.4` binary prints, in
its usage summary, exactly
`seetrex-verifier verify-anchor <anchor.json> --kit <kit.json> [--monitor <bundle.json>] [--chain <chain.json>]`
(indented four spaces in the real output, and wrapped before
`[--chain <chain.json>]`). `0.3.3` prints the same entry without that second
line, and crates.io keeps every version downloadable for ever, so (e.1) does
not stop being a state somebody is in — it stops being the newest one.
Do not take any of it from us either — check your own binary. **Run
`seetrex-verifier --help`** — exits `0`; it prints the tool's usage summary,
and its `verify-anchor` entry tells you at once which of the two you are
holding: an entry that ends at `[--monitor <bundle.json>]` is (e.1), and one
that continues onto a second indented line naming `--chain` is (e.2).
`verify-anchor --help` exits `2` — the code section 2 reserves
for your own invocation error — and is NOT the command to use here: the
subcommand rejects the argument, so its output would read as your mistake
rather than as an answer to the question. Only (e.2) prints the
`truncation reference:` line, so the flag and that line arrive together; if
your binary has neither, (e.1) is your section, and upgrading to `0.3.4` is
what moves you out of it. This revision of the kit is written against `0.3.7`.
<!-- top-level-help-code:end -->

*Do not read any of this as "inclusion in the log stops at ordinal 12."* It
does not, and the difference matters: what stops at the package's newest
anchored head is the proof **the producer publishes**, not what the log will
tell you. `seasalp.glasklar.is` answers for the current head to anybody, with
no host access and no producer file but the chain export:

1. build the leaf preimage from the export row — `seetrex/anchor/v1/head`
   `0x00` `<tenant_slug>` `0x00` `<ordinal>` `0x00` `<chain_hash>` — and take
   `checksum = SHA256(SHA256(preimage))`;
2. `GET https://seasalp.glasklar.is/get-leaves/<lo>/<hi>` and find the line
   `leaf=<checksum> <signature> <key_hash>` whose `key_hash` equals your kit's
   `genesis_key_hash`; the wire format carries no index, so the leaf's index is
   `lo` plus its position in the batch;
3. `GET https://seasalp.glasklar.is/get-inclusion-proof/<size>/<leaf_hash>`
   with `leaf_hash = SHA256(0x00 || checksum || signature || key_hash)` (RFC
   6962 over the 128-byte Sigsum leaf), and fold the returned audit path
   (RFC 9162, Section 2.1.3 on Merkle inclusion proofs — its subsection on
   VERIFYING one is the fold to run) against the `root_hash` of
   `GET https://seasalp.glasklar.is/get-tree-head`, whose log signature and
   witness cosignatures your kit's pinned `policy` authenticates.

Run on 2026-08-25 against the export served at 22:05:02 UTC: tree head size
**62274**, root `8dd7a28017b4d00a…3190ba5`, 13 cosignatures, log signature
valid and all three pinned witnesses cosigning against a quorum of 2. Under
that root, ordinal 38 sits at leaf index **62245**, ordinal 39 at **62261**,
ordinal 40 at **62273**, and the package's own `head@12` at **62089** — four
folds, the same root each time.

**What sits in the log is the tick HEAD, not every row — try this before you
try anything else, because looking for a row's own leaf is what will fail.**
Anchoring is per tick: one leaf for the head ordinal of each tick, none for the
rows behind it. Enumerated 2026-08-26 under the pinned `genesis_key_hash`,
**over the whole log at tree size 62299, against a chain export of 43 rows**,
the leaves are the `enroll` plus ordinals 2, 4, 6, 8, 10, 12, 14, 16, 18, 20,
22, 24, 26, 28, 38, 39, 40, 41, 42 and 43 — and nothing else AT THAT SIZE. Both
numbers are part of the claim: the log and the chain both grow, every later
tick adds one more head and nothing behind it, so a list without its tree size
and its chain length is a sentence that goes false on its own. **EIGHT of the
nine CRA rows, ordinals 30 to 37, have no leaf of their own** — and no later
tick will give them one. They are proved TRANSITIVELY, through the head that
commits them: `head@38` is in the log with the inclusion proof above, and
`chain_hash[38]` commits rows 1..38 through the links of section 3. That is
what "the rows are anchored" means here, and it is weaker than a per-row proof
in exactly one way — you must accept the link recomputation of section 3 to get
from the head to the row.

*The check that turns the lag from an explanation into a finding.* A lag is
benign only while it CLOSES. Re-fetch the package after the next daily tick
(the witness fires between 00:00 and 00:15 UTC, and the next hourly republish
carries it, so from the **01:05 UTC** republish onward) and confirm its newest
anchored head has advanced past the ordinal you recorded. **It did, and this
is the observation to hold the vendor to:** the package served at
`last-modified: Wed, 26 Aug 2026 01:05:03 GMT` carries **42 rows and 20
anchored leaves** under a checkpoint of size **62290**, against a chain export
of 43 rows at the same republish. The 12-row package of the paragraph above was
the lag; this is it closing, one daily tick later, exactly as the cadence
predicts. Nothing here asks you to take the closure on trust — it is two
downloads. If two consecutive daily ticks leave the newest anchored head where
it was while the chain export keeps growing, the lag is no longer cadence —
stop and raise it: that is the shape of a submitter that has silently stopped,
and it is indistinguishable from cadence in any single download.

*What this section does NOT promise.* It records behaviour measured on
2026-08-25 and 2026-08-26 with the two builds named above. The releases it
names, `0.3.4` and `0.3.5`, were already published when this revision was
written — the section REPORTS those releases, it does not announce them —
and past them this section promises nothing: no further release, no change
to the publication cadence, and nothing here is a reason to postpone the
checks. If a later revision of this document reports a
different outcome, that revision is the one to trust — and its date is the one
to read.
<!-- anchor-lag-finding:end -->

---

## Appendix A. Verify the verifier: drive the library directly

You do not have to trust the shipped executable's plumbing: the verification
logic is a public library, and a program of your own can reproduce the
results. Both programs below were compiled against the published crates.io
release (`=0.3.0`) and run on 2026-07-20; the chain program independently
reproduced the exact head the installed binary printed for that day's chain
snapshot (151 rows, head `fcc388ce4e24…`). That snapshot, like section 3's
2026-07-27 capture (287 rows, a later snapshot of the same chain), belongs to
the identity RETIRED on 2026-08-24 (section 7.3): the chain those numbers
describe was wiped, and the live chain restarted at ordinal 1 under a new
genesis. The programs and their logic are unchanged; run against a fresh
export they print a small row count that grows from 1. Dated records of real
runs are left at the row count that produced them rather than restated.

**Last re-run on 2026-08-29 under `=0.3.5`.** The A.1 program
was rebuilt from the two blocks printed here, unedited, against the release
published that day, and pointed at the live chain export of section 3. It
compiled clean and printed `78 rows, ordinals contiguous from 1, every hash
link recomputed OK` with head `0d27bcdf0a4f…` — character for character the
`last_chain_hash` the installed `0.3.5` executable printed for the same file
in the same minute. That agreement, not our word for it, is the whole claim
of this appendix.

**The pins below now say `=0.3.7` and that run was made under `=0.3.5`, and the
gap is stated rather than hidden** — as is the wider gap to the 2026-07-20
capture further down, taken with `=0.3.0`. Across `=0.3.0` through `=0.3.5`
every hash, exit code and comparison result THESE programs compute is
identical, and what `0.3.6` adds to the crate (below) touches none of it —
**but `=0.3.6` is NOT in that class, and the difference is not in the crate's
source at all.** These programs are their own small cargo projects and resolve
their OWN lockfile: a `=0.3.0`…`=0.3.5` pin lets `rust_decimal` float to the
newest compatible release (`1.42.1` today), while `=0.3.6` pins it exactly
(`=1.37.2`). Those two canonicalize three exponent-form monetary values
differently: `1.5e-28` is a `String` under `1.37.2` and the Money
`0.0000000000000000000000000002` under `1.42.1`, while `0.5e-28` and `1.0e-28`
are a `String` under `1.37.2` and the Money
`0.0000000000000000000000000001` under `1.42.1` (parse each under each pin and
print `normalize()`: five lines of your own reproduce all three). For a package
carrying one of them the canonical form, the verdict-hash preimage and the
`verdict_hash` differ between a `=0.3.5` build and a `=0.3.6` one, and
**`=0.3.6` is the one that agrees with the engine that produced the package** —
production emits with `rust_decimal` 1.37.2 — which is why the blocks below pin
it. Every other value is unaffected.
**Whether only the executable's source differs between two consecutive
published crates is a measurement, and the answer changes from release to
release.** An earlier revision of this appendix asserted it as a standing
property; it was already false at `0.3.3`, emphatically false at `0.3.4`, true
again for the `0.3.4`↔`0.3.5` pair — and **it is FALSE for the
`0.3.5`↔`0.3.6` pair, and false again for the `0.3.6`↔`0.3.7` pair.** Both
pairs are measured below. The second is the pair this revision is written
against, and the revision this release was cut FROM could not measure it: the
`0.3.7` tarball did not exist while that revision was being written, which is
what the recapture step of the producer's release runbook exists to close.
The OLDER pair, `0.3.5`↔`0.3.6`, is the one measured first, and its record
below is the one the `0.3.6` revision published, kept as it was measured.
Here is the
measurement, made on 2026-08-31 by unpacking both tarballs from
`https://static.crates.io/crates/seetrex-verifier/` and running `diff -rq`:
the `0.3.5` tarball holds 74 files and the `0.3.6` one holds 622. No path is
gone; **548 are new**, and ten of the shared ones differ — among them THREE
under `src/`: `src/lib.rs`, `src/package.rs` and the executable's own
`src/bin/seetrex-verifier.rs`. The other seven are `Cargo.lock`, `Cargo.toml`,
`Cargo.toml.orig`, `README.md`,
`tests/fixtures/fb2c_enumeration_oracle.json`,
`tests/fixtures/help_exit_codes.tsv` and
`tests/intent_public_crate_is_self_contained.rs`. So the advice "unpack the
crates and diff `src/`" does NOT return an empty diff for this pair, and a
reader who expected one would conclude something changed in the verification
logic. What actually changed: the crate gained a `reference/` directory (8
files — the Python reference verifier of section 2.5, its blind transcript and
its supporting notes), a conformance corpus under
`tests/fixtures/corpus/` (533 files), the fixtures `grammar_probes.txt` and
`spec_gap_ids.txt`, one new library module `src/cli_render.rs`, and four new
test targets (`corpus_equivalence.rs`, `grammar_probe.rs`,
`intent_blind_transcript.rs`, `intent_spec_gaps_have_cases.rs`); `Cargo.toml`
gained an `exclude = ["**/__pycache__"]` key, the four `[[test]]` stanzas, and
turned TWO dependency requirements into exact pins (`chrono` `=0.4.41` and
`rust_decimal` `=1.37.2`) and trimmed the FEATURES of TWO dependencies —
`chrono`, which it also pinned (`default-features = false`, `std` added), and
`uuid`, whose version it left unpinned (`default-features = false`, `std`
added, `v4` dropped); `rust_decimal`'s own features are untouched. Under `src/`, `lib.rs`
differs by exactly one added line (`pub mod cli_render;`); `package.rs` gains
a `PackageSource` seam with a `Dir` and a `Memory` arm, so the same check can
run over a package held in memory instead of on disk; and
`src/bin/seetrex-verifier.rs` is rewired onto the shared renderer that new
module holds. **No hash, no exit code and no comparison result THESE programs
compute moves BECAUSE OF THOSE SOURCE CHANGES** — but that is a claim about
BEHAVIOUR, no longer one you can check by an empty `src/` diff, and it is not
the whole story. What DOES move between the two crates is the `Cargo.toml`
line quoted just above: `rust_decimal` goes from unpinned to `=1.37.2`, and
with it the three exponent-form monetary values named at the head of this
appendix. That is why the pins below split into two classes rather than one.

**And here is the pair this revision is written against, `0.3.6`↔`0.3.7`,
measured on 2026-09-01 by the same method** — both `.crate`s downloaded from
crates.io, each one's sha256 checked against the registry read-back of section
6, unpacked and compared with `diff -rq`:
the `0.3.6` tarball holds 622 files and the `0.3.7` one holds 623. No path is
gone; **exactly one is new**, `tests/common/mod.rs`, and ten of the shared ones
differ — among them ONE under `src/`: `src/sbom/compare.rs`. The other nine are
`Cargo.lock`, `Cargo.toml`, `Cargo.toml.orig`, `README.md`,
`tests/corpus_equivalence.rs`, `tests/fixtures/help_exit_codes.tsv`,
`tests/intent_blind_transcript.rs`,
`tests/intent_public_crate_is_self_contained.rs` and
`tests/intent_sbom_spec_matches_code.rs`. Read that diff and it says what the
release is: all eighteen hunks of `src/sbom/compare.rs` — the count a plain
`diff` of the two unpacked trees reports, where `diff -u` merges two adjacent
blocks and reports seventeen — are ADDITIONS below
the `#[cfg(test)]` marker that opens its unit-test module — line 1138 of the
file in both tarballs, and the first added line lands after line 1141 — so the
library code a consumer compiles is byte-identical between the two crates, and
what those additions do is let fifteen of the seventeen unit tests of that
module SKIP, naming the
document they cannot read, where their reference vector does not travel —
which is the repair section 2.2 measures. `Cargo.toml` differs in ONE line,
the `version`: no dependency requirement moves, `rust_decimal` `=1.37.2` and
`chrono` `=0.4.41` are pinned identically in both, and that is why `=0.3.6`
and `=0.3.7` are one equivalence class and why the section 4 floor stays at
`0.3.6` rather than moving with this release.

Earlier pairs, for scale: across `0.3.3`↔`0.3.4` the same command reported
twelve shared files differing and seven paths new in `0.3.4` alone — among them
the whole `src/sbom/` module. What `0.3.2` changed in the library was not
behaviour but text (the shared `scope` module and two doc-comment corrections);
`0.3.3` added the ADDITIVE anchor-verification subsystem (`anchor.rs`,
`merkle.rs`, `checkpoint.rs`, `anchor_completitud.rs`, `anchor_package.rs`, a
`chain_export.rs` addition and the `verify-anchor` CLI arm), `0.3.4` the
equally additive SBOM projection (`src/sbom/`, two CLI arms and the optional
`--chain` input of 7.4(e)), and `0.3.5` no library or executable source at all.
Pin `=0.3.0`, `=0.3.1`,
`=0.3.2`, `=0.3.3`, `=0.3.4` or `=0.3.5` and these programs compute
identically to ONE ANOTHER; pin `=0.3.6` or `=0.3.7` — the blocks below pin `=0.3.7` — and they
compute identically to PRODUCTION, differing from that earlier class on the
three exponent-form monetary values named above and on nothing else. **The
second class has two members and that is a measurement, not a hope**: the
`0.3.6`↔`0.3.7` diff above shows the two crates pin the same `rust_decimal`
and the same `chrono` and differ under `src/` only in a test module, so a
`=0.3.6` build and a `=0.3.7` build of these programs answer identically.
Do not take that on our word: unpack the crates
and diff `src/` — reading the diff you get, not the empty one an earlier
revision of this appendix promised — normalising line endings first when
`0.3.1` is involved
(`0.3.1` alone shipped CRLF; `0.3.0`, `0.3.2`, `0.3.3` and `0.3.4` are LF, and
`0.3.5`, `0.3.6` and `0.3.7` are LF but for the one test fixture each that
section 2 names), or
the diff will mark every file as changed and you will have learned nothing.

### A.1 Chain export check (reimplements section 3)

`Cargo.toml`:

```toml
[package]
name = "chain-check"
version = "0.1.0"
edition = "2021"

[dependencies]
seetrex-verifier = "=0.3.7"
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

Real output captured 2026-07-20 against the retired chain's export of that day
(an earlier snapshot than section 3's 2026-07-27 capture; both belong to the
identity retired on 2026-08-24 — a fresh export gives a smaller count and
another head):

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

`Cargo.toml` dependencies: `seetrex-verifier = "=0.3.7"` only.
