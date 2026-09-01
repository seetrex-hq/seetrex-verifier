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

The two bullets below are kept here on purpose rather than moved into a
release entry. The offline page is built by a release job from the vendor's
tree, not from the crate, and no release — `0.3.6` or `0.3.7` — has carried
one yet: no `.crate` of this crate contains an `.html`, and the GitHub release
of `seetrex-verifier-v0.3.6` carries four assets, the two linux-musl
executables and the `SHA256SUMS`/`SHA256SUMS.asc` pair. They move to the entry
of the first release that does carry the page.

### Added
- A signed release may now carry an OFFLINE BROWSER PAGE,
  `seetrex-verifier-offline.html`: one self-contained HTML file with a
  `wasm32-unknown-unknown` build of this same library embedded in it, opened
  from disk with the network off. It answers `verify-package` and
  `verify-chain` only — `verify-anchor`, `emit-sbom` and `verify-sbom` have no
  browser leg — and it prints this crate's own lines and outcome tokens, with
  no second vocabulary of its own. It makes no network request of any kind,
  which is checked as a property of the file's text; it cannot refuse a
  symlinked package member the way the executable does (the declared limit of
  the in-memory arm recorded under `0.3.6` below); and it is built from the
  vendor's tree rather than from the signed tag, so what binds it to that tag
  is a version correspondence, not byte identity. Route F of `docs/AUDITOR_KIT.md`, section
  2.6, is the whole of it — how to obtain it, the two commands that check it,
  and where its limits are. A release may carry it or not.
- The release job that builds it (`release-verifier-web`) builds the page
  TWICE and compares the bytes, answers it against the 92-case conformance
  corpus through the very payload the shipped file carries, and only then
  hashes it into a `SHA256SUMS` GPG-signed as `SHA256SUMS.asc` under the same
  release-signing key as the prebuilt executables. Publication is a separate,
  explicit act: the dispatch defaults to a dry run.

## [seetrex-verifier 0.3.7] — 2026-09-01

The suite is green from every tree this channel publishes. `0.3.6` shipped it
red and said so: a clone of the public repository failed
`intent_blind_transcript`, and the unpacked `.crate` failed 28 tests across
five targets — recorded in `docs/AUDITOR_KIT.md` section 2.2 as a defect of the
packaging and a debt the producer owed. This release is that repair, and
nothing else: every check that reads a document from outside the package, or
resolves the transcript against git, now classifies the tree it runs in by
positive evidence before demanding an input that tree cannot have, and a check
that cannot run announces itself on one printed line instead of failing or
being excused in silence. Existing commands, formats and exit codes are
unchanged — measured, not assumed, and measurable by anyone: the executable's
source (`src/bin/`) and its integration suite (`tests/bin_e2e.rs`), in the tree
this release is cut from, are byte-identical to those of the published `0.3.6`
`.crate` — measured before publication, with an empty `diff -r` against that
unpacked tarball, so no subcommand, flag, output token or exit code moves.
Once `0.3.7` is itself on crates.io the same comparison is owed between the two
published artifacts: unpack both tarballs and `diff -r` those two paths at the
tarball ROOT (inside a `.crate` there is no `crates/verifier/` prefix), the way
appendix A of `docs/AUDITOR_KIT.md` compares them. An empty diff is what this
entry predicts, and the recapture is what confirms it. What the two
trees actually print is measured against the published channel after this
release, not before, and `docs/AUDITOR_KIT.md` section 2.2 says which
measurement it is showing.

### Fixed
- The test suite is now green from every tree the channel publishes, not only
  from the producer's private repository. Measured at the `0.3.6` tag: a clone
  of the public repository failed `intent_blind_transcript` (the transcript's
  rows name commits of the private history, which the export does not carry),
  and the unpacked `.crate` additionally failed every test that reads a
  document under `../../docs/`, plus the guard that requires those paths to
  resolve without reading them (`intent_public_crate_is_self_contained`) — 28
  tests across five targets, fifteen of them unit tests of
  `src/sbom/compare.rs`. Each check that reads a document from outside
  the package, or resolves the transcript against git, now classifies the tree
  it runs in by positive evidence before demanding an input that tree cannot
  have: a packaged tree is proven by `Cargo.toml.orig` at the crate root, and
  the git history by an anchor commit pinned in the test code — never by the
  row being checked, so a forged transcript row stays a hard failure wherever
  history exists. A check that cannot run skips out loud, on one printed line,
  in the shape `skipped [<tree>]: <reason>`; nothing is excused silently, and
  in the producer's tree not one of those lines is printed — every obligation
  of this classification runs there (plus a new private guard that has no skip
  branch at all). Two spellings of "skipped" therefore coexist in a run, and
  the bracket is what tells them apart: the older `skipped: …` belongs to the
  fifteen tests gated on the `SEETREX_PRIVATE_TREE` environment variable
  (`src/sbom/private_tree.rs`), which predate this change, project lockfiles
  no published tree carries, and print in all three trees with the variable
  unset.
- The `0.3.6` heading below dated that entry `2026-08-30`; its signed tag was
  made `2026-08-31T10:45:28Z`, and this preamble says an entry's release date
  is the date of its signed tag. Corrected here. The date on THIS entry's own
  heading is the same kind of claim and is not yet measured: it is the UTC day
  the `seetrex-verifier-v0.3.7` tag is cut, written before that tag exists. If
  the tag is signed on another day, the heading is amended to the tagger's day
  before the snapshot that carries it is pushed, so that no published copy of
  this file dates an entry by anything but its signed tag.
- The `0.3.6` entry below recorded the in-memory package seam under
  `[Unreleased]`, although the `.crate` published as `0.3.6` already shipped
  it, so the CHANGELOG published at that tag credited the release with less
  than it published. The seam moves into that entry here, under a second
  `### Added` heading dated with the day it was recorded, and is credited to
  the release that shipped it rather than to this one.

## [seetrex-verifier 0.3.6] — 2026-08-31

RUST-BUG-02, and the second implementation that found it. The published `0.3.4`
and `0.3.5` `.crate`s carry a `Cargo.lock` resolving `rust_decimal` 1.42.1
(their tree in the public repository does too, because the export regenerates
the lockfile), while the Money canonicalization of section 4.1 of
`SPEC_VERDICT_PACKAGE_V1.md` is a transcription of `rust_decimal` 1.37.2 -
the version the production emitter computes with. The two disagree on three
exponent-form monetary values (`1.5e-28`, `0.5e-28`, `1.0e-28`), which is a
different verdict hash for the same package, so the published verifier could
contradict the emitter on input neither of them is wrong about. The version is
now pinned exactly in the workspace, together with `chrono` `=0.4.41`, and this
is the first release whose lockfile resolves what the specification was
measured against. No command, format or exit code moves.

The release also ships, inside the crate, the Python reference implementation
that made the divergence visible, the 92-case conformance corpus and the
528-value differential grammar probe, and it carries the specification
clarifications of 2026-08-30 that those two instruments forced.

### Known limits
- RUST-BUG-01 is NOT fixed here and `crates/format` is untouched: a duration
  whose summed seconds exceed `i64::MAX / 1000` (while still fitting `i64`)
  PANICS with exit 101 instead of falling through to `String`. It is a
  declared reference limit - section 4.1 of the specification names the crash
  band, and `tests/grammar_probe.rs` records a panic inside it as
  `KNOWN_REFERENCE_DEFECT` and a panic outside it as a failure. It is carried
  as version-bump debt of the reference implementation, not as a fix owed to
  this release.

### Added
- `reference/seetrex_verifier.py`: a second implementation of the package
  format, in Python 3.9+ with the standard library alone (RFC 8785 JCS
  included), written from `docs/SPEC_VERDICT_PACKAGE_V1.md` and nothing else.
  It offers `verify-package` and `verify-chain` in the CLI shape the
  specification writes (`--package-dir`, `--chain-export`), which is NOT the
  positional shape of the shipped executable. Route E of the auditor kit
  documents it. Its `OPEN_QUESTIONS.md`, `BLIND_TRANSCRIPT.md`, `SELFTEST.md`
  and `ALIGNMENT_NOTES.md` sit beside it.
- `tests/fixtures/corpus/`: one conformance case per directory (see the corpus
  directory for the current count), each a `cmd.txt` and an
  `expected.txt` whose answer is derived from the specification by hand and
  generated by neither implementation, so a disagreement can indict either
  one. The directory carries `* -text` so a checkout never rewrites a fixture
  byte.
- `tests/corpus_equivalence.rs` and `reference/run_corpus.py`: the two legs
  that answer the same corpus. Both run in CI on every push that touches the
  specification, the reference, the corpus or either runner, and nightly.
- `tests/fixtures/grammar_probes.txt`, `tests/grammar_probe.rs` and
  `reference/run_grammar_probes.py`: the differential GRAMMAR PROBE. One JSON
  scalar per line covering the boundaries of every value grammar of section
  4.1; both implementations canonicalize each one as a single working-memory
  entry and the answers are compared PER VALUE, so a divergence names the
  input. Where the corpus answers the cases somebody wrote down, this answers
  the values nobody thought of. Same CI job, same nightly.

### Changed
Sixteen points the independent implementation could not settle from the
specification were clarified in it, plus one contradiction it exposed. No hash,
token or exit code of this crate moves; what changes is what the document
obliges a verifier to do.
- DIV-01, sections 4 and 7.1: recomputation recovers every
  `working_memory_canonical` value through the section 4.1 type inference and
  re-serializes it in its section 4 canonical form before JCS; canonicalizing
  the stored JSON verbatim is not conformant.
- Q1, section 8.1: `verify-chain` exits `0` when every link recomputes and `1`
  on any failure; there is no counterpart to the `4` of section 9.6.
- Q2, section 9.6: the terminal outcome token is printed after the warning
  block and before the honest-scope statement, and is matched as a line.
- Q3, section 2: uppercase hex is accepted in package-internal comparisons,
  never in a hash preimage.
- Q4, section 3.1: only `verdict_id`, `verdict_hash`, `chain_hash` and `files`
  are load-bearing; other manifest fields may be absent and unknown keys are
  ignored.
- Q5, section 3.3: an evidence record's identity is its `id` field, not its
  filename.
- Q6, section 3.2: the key sets of `verdict.json` and of the evidence files are
  OPEN, unlike the ruleset's; unknown keys are ignored and bound by no hash
  unless `files_sha256` is present.
- Q7, section 6.1: the Type column is normative -- a scalar whose JSON type
  does not match it is malformed and is rejected, not canonicalized.
- Q8, section 6.1: a non-canonical ruleset FACT value is recovered and
  re-serialized in canonical form before the completed document is
  canonicalized; the ruleset's plain string fields are carried verbatim.
- Q9, section 9.6 step 5: the warning set is exhaustive, so an absent ruleset
  anchor is reported on the step line and is not a WARNING.
- Q10, section 7.3: a verifier accepts every RFC 3339 spelling its library
  accepts, including a space separator and second `60`, and never rejects a
  value on the grammar alone.
- Q11, section 7.3: a wire value with more than six fractional digits is
  truncated toward zero to microseconds, not rejected.
- Q12, section 8.1: `schema_version` is a fail-closed discriminator; any value
  other than `"1.0"` is rejected by name before any link is recomputed.
- Q13, section 8.1: an export with zero rows fails -- it establishes no head.
- Q14, section 8.1: the row at position *i* must carry ordinal *i*, and a
  verifier must not sort the array to establish the order it then checks.
- Q15, section 9.6: the reserved-token mask is case-insensitive, covers every
  line of a `verify-package` surface including error text, and SHOULD print a
  legend once when it actually reached the output.
- Q16, section 8.1 and section 9.6 step 1: the chain export gets its own read
  cap (the reference caps it at 50 MiB), and "regular file" excludes symlinks,
  which are tested with `lstat` rather than followed.
- R2b, section 4.1 Money: the two sentences the grammar probe measured wrong
  were rewritten from what the reference actually does. A `_` is ignored once
  a digit has appeared anywhere earlier in the significand and need not be
  immediately preceded by one, so `1000._5` is a monetary value (`1000.5`) and
  not a string, while a separator inside the exponent (`1e_5`) is not; and
  surrounding whitespace is NOT trimmed, unlike date-time, date and duration.
  Without an exponent the candidate scale starts at `min(f, 28)` and is
  decremented, re-rounding from the original digits, until the mantissa is
  strictly below 2^96, so `9.9999999999999999999999999999` recovers as `10`
  and only a value with no workable scale reaches `String`. With an exponent
  and at most 28 fractional digits nothing is rounded and the written digit
  string, padded for a negative folded scale, must fit a 29-digit budget that
  leading zeros also spend (`5e28` is monetary, `0.5e29` is not, though they
  denote one value); with MORE than 28 fractional digits the mantissa is
  rounded and the exponent is DISCARDED, so
  `1.99999999999999999999999999999e1` recovers as `2` and not `20`. Four
  corpus cases and 84 probe values pin the rewritten sentences.
- `tests/grammar_probe.rs`: a Rust `PANIC` inside the crash band section 4.1
  DECLARES for the reference's millisecond-scaled duration representation
  (summed seconds of magnitude above `i64::MAX / 1000`, still within `i64`) is
  now recorded as `KNOWN_REFERENCE_DEFECT` and counts as agreement, provided
  the Python leg gives the specification's `String` fall-through; the values
  are printed. It is the ONLY tolerated crash, and it is carried as
  version-bump debt of the reference. A panic outside the band, a band value
  that does not panic, and any other Python answer for a band value all stay
  failures.
- R3, section 4.1 Money: the exponent rule is ONE bullet with three outcomes,
  decided by what the exponent-free rule does to the MANTISSA alone, not by
  the mantissa's fractional-digit count. If the mantissa does not fit at any
  scale the whole string reaches `String` whatever the exponent
  (`79228162514264337593543950336e-28`); if it fits EXACTLY the exponent is
  folded exactly, under the 29-digit written budget the previous revision
  already described; and if it fits only AFTER rounding, the rounded mantissa
  is the value and the exponent is DISCARDED. The old boundary was wrong for
  a measured family of twelve values with 28, 28, 2 and 1 fractional digits
  (`7.9228162514264337593543950336e*`, `9.9999999999999999999999999999e*`,
  `9999999999999999999999999999.99e*`, `79228162514264337593543950335.5e*`)
  and decided `7.9228162514264337593543950336e28` twice, in opposite
  directions; that value is decided once now, as
  `7.922816251426433759354395034`.
- R3, section 4.1 Money: the procedure names the decimal library version it
  was measured against (`rust_decimal` 1.37.2) and the fact that the reference
  pins it exactly. Later releases of that library canonicalize some
  exponent-form values differently.
- R3, section 4.1 Date: a year may carry a leading `+` or `-` sign, which the
  canonical four-digit form does not keep (`+2026-5-13` recovers as
  `2026-05-13`, `-0000-05-13` as `0000-05-13`); a signed year of more than
  four digits, a doubled sign and a trailing sign all reach `String`.
- R3, section 4.1 Date-time: the numeric offset may be written without the
  colon, in the four-digit `+HHMM` / `-HHMM` form, and means the same instant;
  the hour-only, unpadded and three-digit spellings reach `String`, and the
  range bound applies to this spelling too.
- `tests/fixtures/spec_gap_ids.txt` and
  `tests/intent_spec_gaps_have_cases.rs`: the identifier list of the review
  ledger now travels inside the crate, and a test asserts both directions --
  no corpus case may carry an identifier the list does not know, and every
  identifier whose family a package can exercise must be carried by at least
  one case.
- `tests/grammar_probe.rs`: the Rust leg ALWAYS regenerates the Python
  answers instead of reusing a file it finds, and the runner stamps a header
  naming the sha256 of the reference and of the probe list it read, which the
  Rust leg recomputes and refuses on mismatch. A sabotaged reference with a
  stale answer file beside it used to read green.

### Fixed
- The crate is published from the staging tree of the public export, and that
  export runs the Python reference of route E in its isolated build - which
  compiles it, leaving a `reference/__pycache__/*.pyc` behind, after the scan
  that would have seen it. Measured on this release's export: a machine-specific
  build artifact inside `cargo package --list`. The manifest now excludes
  `**/__pycache__`, so no release can carry one.
- RUST-BUG-02. The workspace pinned `rust_decimal` as `"1.33"`, so a build
  that resolves its own lockfile could pick any 1.x. It resolved 1.37.2 in the
  development tree and 1.42.1 in a fresh one - and a fresh one is what the
  public export and the published `.crate` carry - and the two disagree on the
  canonical form of three exponent-form monetary values, which is a different
  verdict hash for the same package. The version is now pinned exactly to
  `=1.37.2`, the one the specification's Money procedure was measured against,
  and `chrono` to `=0.4.41` for the same reason; no behaviour of this tree
  changes, and a freshly generated lockfile now resolves the same version the
  production emitter uses.
- CHANGELOG: the `0.3.5` entry below says the `.crate` published as `0.3.4`
  "still carries the wrong sentence" and that an auditor reads this file
  "inside that tarball". Measured against the tarballs crates.io serves, that
  is false: neither the `0.3.4` nor the `0.3.5` `.crate` contains this file at
  all (74 files each; the crate is packaged from a tree where this file has
  already been moved to the repository root). This file is published in the
  root of the public repository under each signed tag, and nowhere else; the
  `0.3.4` sentence about exit codes was therefore wrong in that place, never
  on crates.io. The `README.md` remark in the same entry is correct: that file
  does travel inside the `.crate`.
- `tests/fixtures/fb2c_enumeration_oracle.json` shipped with CRLF line
  endings in the `0.3.5` `.crate` and in the public tree at its tag - the only
  file of the 74 with a carriage return; every other file, and every file of
  `0.3.4`, is LF. The committed file was LF all along: the carriage returns
  came from the working copy of the machine that ran the export, which copies
  working files rather than committed blobs. The content is JSON, so nothing
  that reads it changes. The export path is what has to change; until it
  does, a release can carry the same defect again.
- CHANGELOG: the `0.3.5` entry below enumerates the files of this crate that
  differ from the `0.3.4` tag as five and names this file among them. Both
  halves of that list are wrong. This file does not live inside
  `crates/verifier` - it sits at the root of the public repository - so it
  cannot be one of that crate's differing files; and the entry omits
  `tests/fixtures/fb2c_enumeration_oracle.json`, which does differ. Measured
  in a fresh clone of the public repository with `git diff --name-only
  seetrex-verifier-v0.3.4 seetrex-verifier-v0.3.5 -- crates/verifier`, the
  list is exactly five paths, but not those five: `Cargo.toml`, `README.md`,
  `tests/bin_e2e.rs`, `tests/fixtures/fb2c_enumeration_oracle.json` and
  `tests/fixtures/help_exit_codes.tsv`. The scope of that count is the public
  repository TREE at the two signed tags. Comparing the two `.crate` tarballs
  instead is a different measurement with a different answer - the auditor
  kit's Appendix A reports seven differing files there, the same five plus
  `Cargo.lock` and `Cargo.toml.orig`, and neither tarball carries this file at
  all.

### Added (recorded 2026-09-01)

This entry was cut on 2026-08-30, the day before the `0.3.6` tag was signed,
but the `.crate` published as `0.3.6` was packaged from a later tree that
already carried the seam below: the `src/package.rs` of the published `0.3.6`
tarball is byte-identical to the one this tree publishes as `0.3.7`. That
addition therefore shipped in `0.3.6`, not in `0.3.7`, and it is recorded here
after the fact rather than credited to the later release.

- `package::PackageSource`, `package::PackageFiles` and
  `package::verify_package_files`: package integrity verification can now be
  driven from bytes already in memory, for a host that has no filesystem.
  `verify_package(&Path, …)` keeps its signature and becomes a one-line wrapper
  over the same seven steps, reading in the same order, with the same tokens
  and the same exit codes.

  Two separate things are measured, because a shipped binary has only ONE arm
  and no run of it can compare two:
  - **the binary did not move.** For the 83 corpus packages under
    `tests/fixtures/corpus/*/pkg/`, the `verify-package` stdout, stderr and
    exit code of the binary built from this tree are byte-identical to those
    of the binary built from the commit before the seam. The `Dir` arm is the
    only arm the CLI has, and it is unchanged.
  - **the two arms answer alike.** An in-crate test loads each of those same
    83 packages into a `PackageFiles` and compares `verify_package(dir)` with
    `verify_package_files(&files)`: equal steps, warnings, recomputed verdict
    hash and anchoring on success, the same error VARIANT on failure, and the
    same exit class either way. A second test does the same for the package
    shapes no corpus case has — a nested evidence tree, an EMPTY directory
    under `evidence/`, an empty directory at the package root, a core file
    absent, a manifest entry naming a directory, an oversized file no step
    reads.

  The two arms always agree on the error VARIANT and on the exit code. They do
  not always agree on the WORDING, and the differences are declared:
  - a file the steps read and cannot find is `Io` on both, but the `Dir` arm
    quotes the operating system (`… (os error 2)`) where the in-memory arm
    writes `no such file in the package`;
  - an entry that names a DIRECTORY is unreadable on both, and the in-memory
    arm says so in its own words (`is a directory, not a file in the package`)
    because there is no operating system to quote;
  - on Windows, the on-disk path an `Io`/`Malformed` message renders is now
    spelled with the platform separator throughout (`…\pkg\evidence\x.json`);
    steps 2 and 5 previously rendered the relative part verbatim
    (`…\pkg\evidence/x.json`) while step 3 did not. POSIX is unaffected.

  The in-memory arm cannot make step 1's symlink refusal: a host without a
  filesystem cannot report a symlink. Only the 8192-file cardinality cap moves
  to `PackageFiles::insert` (same value, same error value, an earlier point);
  the 10 MiB per-file cap stays where the reads are, on BOTH arms, so a package
  that merely LISTS an oversized file the seven steps never open is accepted by
  both instead of being a pass on disk and a refusal in memory.

  Two obligations fall on whatever BUILDS a `PackageFiles`, and neither can be
  discharged inside this crate:
  - **directories must be recorded**, `PackageFiles::insert_dir` for every one
    walked, EMPTY ones included. A directory is not a key: a map built from
    files alone can infer the directories that nest something, but not an
    empty `evidence/empty_sub/`, which `read_dir` sees and which the `Dir` arm
    refuses at step 3. A browser directory drop enumerates empty directories,
    so a loader that ignores them turns a refusal into a pass. Keys themselves
    are validated on the way in: `""`, `"evidence/"`, `"evidence//b.json"`,
    a backslash, a `.` or `..` component, or a name given as both a file and a
    directory are refused (`Shape`) rather than stored as something no
    directory walk could ever emit.
  - **total bytes must be bounded before the map is built.** Neither cap
    bounds a package's total size — 8192 files of 10 MiB is 80 GiB on the
    `Dir` arm too — and adding such a bound to the in-memory arm alone would
    be a divergence, not a shared limit. By the time `insert` is called the
    bytes are already allocated in the host's memory.

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
