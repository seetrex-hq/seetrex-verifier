// SPDX-License-Identifier: Apache-2.0
//! The RUST leg of the T10 conformance oracle.
//!
//! `tests/fixtures/corpus/<case>/` is a specification conformance corpus:
//! one directory per case, carrying the material under test (`pkg/` for a
//! package case, `export.json` for a chain-export case), the argv to run
//! (`cmd.txt`) and the answer the SPECIFICATION gives (`expected.txt`).
//! Every case is SELF-CONTAINED: nothing here resolves a path outside the
//! corpus directory, so the corpus travels with the crate and a case can
//! never be silently repointed at material that moved.
//!
//! `expected.txt` is authored BY HAND FROM `docs/SPEC_VERDICT_PACKAGE_V1.md`
//! and never generated from any implementation's output — see
//! [`test_intent_corpus_expectations_are_spec_derived_not_generated`]. This
//! file makes the Rust binary answer the corpus; a second (Python) leg
//! answers the same corpus from the same files. A divergence therefore shows
//! up as ONE leg red, and the corpus can indict either implementation — which
//! a corpus generated from one of them never could.
//!
//! The token line is read differently by the two subcommands, because the
//! specification binds them differently: 9.6 binds a `verify-package` token
//! as the run's terminal outcome LINE, while 8.1 binds the `verify-chain`
//! success token `VERIFIED OFFLINE` as a token CONTAINED in the success
//! line (the reference prints it inside a sentence). A failing chain run
//! must not carry that token at all.
//!
//! `expected.txt` may also carry `sanitize=ci`, which asserts the extra
//! obligation §9.6 states about the reserved-token sanitizer: the combined
//! stdout+stderr of the run must contain no `verified` CASE-INSENSITIVELY
//! once every `VERIF[REDACTED]` mask has been removed. It is checked in
//! addition to (never instead of) the exit code and the token, and the
//! Python leg (`reference/run_corpus.py`) reads the same line.
//!
//! **The CLI adapter (a declared finding, not a normalisation).** Spec §9.6
//! writes `verify-package --package-dir <DIR>` and §8.1's tooling note writes
//! `verify-chain --chain-export <FILE>`; the shipped binary takes a POSITIONAL
//! operand and exits 2 on any other `--` flag. `cmd.txt` is written in the
//! SPEC's shape, and [`adapt_to_rust_cli`] below is the five-line adapter that
//! maps it onto the binary. The mismatch is recorded in the divergence ledger
//! as `SPEC-GAP-9.6-CLI`; it is absorbed here in one visible place rather than
//! silently written out of the corpus.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_seetrex-verifier");

/// The specification under test. This is the ONE path this file resolves
/// outside the crate; it is on the export allowlist (`export_public.sh`) and
/// declared in `intent_public_crate_is_self_contained.rs::ALLOWED_ESCAPES`,
/// so the exported public tree resolves it too.
const SPEC_REL: &str = "../../docs/SPEC_VERDICT_PACKAGE_V1.md";

/// The two success tokens §9.6's binding table defines, plus the token §9.6
/// RESERVES for the strong surfaces. No failing run may print any of them.
const TOKEN_ANCHORED: &str = "INTEGRITY-OK (weak)";
const TOKEN_UNANCHORED: &str = "SELF-CONSISTENT (unanchored)";
const RESERVED_TOKEN: &str = "VERIFIED";

/// The success token 8.1 binds for `verify-chain`. `verify-chain` is one of
/// the two surfaces 9.6 RESERVES `VERIFIED` for, so the reserved-token check
/// of a failing run is a package-mode obligation; a chain FAIL is held to
/// this token's ABSENCE instead.
const TOKEN_CHAIN: &str = "VERIFIED OFFLINE";

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn spec_path() -> PathBuf {
    crate_root().join(SPEC_REL)
}

fn corpus_root() -> PathBuf {
    crate_root().join("tests/fixtures/corpus")
}

/// The outcome CLASS a case expects. `PASS_UNANCHORED` is deliberately NOT
/// folded into `PASS`: §9.6 gives it its own exit code precisely so scripts
/// cannot mistake an unanchored pass for an anchored one.
#[derive(Debug, PartialEq, Eq)]
enum Class {
    Pass,
    PassUnanchored,
    Fail,
}

#[derive(Debug)]
struct Case {
    name: String,
    dir: PathBuf,
    /// argv AFTER the subcommand, in the SPECIFICATION's shape, `{PKG}` still
    /// unsubstituted.
    cmd: Vec<String>,
    token: String,
    exit: i32,
    class: Class,
    /// The spec heading `expected.txt` cites, verbatim.
    spec_heading: String,
    /// The `SPEC-GAP-*` id this case carries, when it exercises one.
    gap: Option<String>,
    /// `sanitize=ci`: the run's combined output must carry no `verified`
    /// case-insensitively outside a `VERIF[REDACTED]` mask (§9.6).
    sanitize_ci: bool,
}

impl Case {
    /// The file or directory `{PKG}` stands for.
    fn subject(&self) -> PathBuf {
        let pkg = self.dir.join("pkg");
        if pkg.is_dir() {
            return pkg;
        }
        let export = self.dir.join("export.json");
        if export.is_file() {
            return export;
        }
        panic!(
            "case `{}` carries neither pkg/ nor export.json. Material that              ships elsewhere in the repository is COPIED into the case (the              corpus `.gitattributes` `* -text` preserves its bytes), never              resolved by an indirection out of the corpus.",
            self.name
        )
    }

    /// The subcommand the spec's argv names.
    fn subcommand(&self) -> &'static str {
        if self.cmd.iter().any(|a| a == "--package-dir") {
            "verify-package"
        } else if self.cmd.iter().any(|a| a == "--chain-export") {
            "verify-chain"
        } else {
            panic!(
                "case `{}`: cmd.txt names neither --package-dir nor --chain-export",
                self.name
            )
        }
    }
}

/// D-T10-8, the whole adapter: the spec's `--package-dir X` /
/// `--chain-export X` become the binary's POSITIONAL operand; every other
/// argument (`--expected-verdict-hash <hex>`) passes through untouched.
fn adapt_to_rust_cli(cmd: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(cmd.len());
    let mut it = cmd.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--package-dir" | "--chain-export" => out.push(
                it.next()
                    .unwrap_or_else(|| panic!("{arg} without a value"))
                    .clone(),
            ),
            other => out.push(other.to_string()),
        }
    }
    out
}

fn parse_expected(
    name: &str,
    text: &str,
) -> (String, i32, Class, String, Option<String>, bool) {
    let mut token = None;
    let mut exit = None;
    let mut class = None;
    let mut heading = None;
    let mut gap = None;
    let mut sanitize_ci = false;
    for line in text.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(rest) = line.strip_prefix("# spec:") {
            heading = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("# gap:") {
            gap = Some(rest.trim().to_string());
        } else if line.starts_with("# note:") {
            // Free prose: WHY the specification gives this answer, written
            // when the case was authored and before either binary ran. It is
            // ignored here on purpose -- an expectation is `token`/`exit`/
            // `class`, and the note is what a reader checks the derivation
            // against. A NAMED key, not a lenient catch-all: an unrecognised
            // line still aborts, which is what R1-B I-1 asked for.
        } else if let Some(rest) = line.strip_prefix("sanitize=") {
            match rest.trim() {
                "ci" => sanitize_ci = true,
                other => panic!("case `{name}`: unknown sanitize mode `{other}`"),
            }
        } else if let Some(rest) = line.strip_prefix("token=") {
            token = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("exit=") {
            exit = Some(
                rest.trim()
                    .parse()
                    .unwrap_or_else(|e| panic!("case `{name}`: exit= is not an integer: {e}")),
            );
        } else if let Some(rest) = line.strip_prefix("class=") {
            class = Some(match rest.trim() {
                "PASS" => Class::Pass,
                "PASS_UNANCHORED" => Class::PassUnanchored,
                "FAIL" => Class::Fail,
                other => panic!("case `{name}`: unknown class `{other}`"),
            });
        } else if !line.trim().is_empty() {
            panic!("case `{name}`: unrecognised line in expected.txt: {line:?}");
        }
    }
    (
        token.unwrap_or_else(|| panic!("case `{name}`: expected.txt has no `token=` line")),
        exit.unwrap_or_else(|| panic!("case `{name}`: expected.txt has no `exit=` line")),
        class.unwrap_or_else(|| panic!("case `{name}`: expected.txt has no `class=` line")),
        heading.unwrap_or_else(|| panic!("case `{name}`: expected.txt has no `# spec:` line")),
        gap,
        sanitize_ci,
    )
}

/// Every case directory of the corpus, sorted. A directory without BOTH
/// `cmd.txt` and `expected.txt` panics here rather than being skipped
/// (mutant M3: a case with no expectation must be loud, never invisible).
fn load_corpus() -> Vec<Case> {
    let root = corpus_root();
    let mut cases = Vec::new();
    let entries = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("read corpus root {}: {e}", root.display()));
    for entry in entries {
        let path = entry.expect("corpus dir entry").path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .expect("case dir name")
            .to_string_lossy()
            .into_owned();
        let cmd_text = std::fs::read_to_string(path.join("cmd.txt"))
            .unwrap_or_else(|e| panic!("case `{name}` has no readable cmd.txt: {e}"));
        let expected_text = std::fs::read_to_string(path.join("expected.txt"))
            .unwrap_or_else(|e| panic!("case `{name}` has no readable expected.txt: {e}"));
        let (token, exit, class, spec_heading, gap, sanitize_ci) =
            parse_expected(&name, &expected_text);
        cases.push(Case {
            name,
            dir: path,
            cmd: cmd_text.split_whitespace().map(str::to_string).collect(),
            token,
            exit,
            class,
            spec_heading,
            gap,
            sanitize_ci,
        });
    }
    cases.sort_by(|a, b| a.name.cmp(&b.name));
    assert!(
        cases.len() > 40,
        "only {} corpus cases found under {}; a suite that runs nothing passes \
         for the wrong reason",
        cases.len(),
        root.display()
    );
    cases
}

fn run(subcommand: &str, args: &[String]) -> Output {
    Command::new(BIN)
        .arg(subcommand)
        .args(args)
        .output()
        .expect("spawn seetrex-verifier binary")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Whether `text` carries `token` as a TOKEN LINE — a line whose whole
/// content is the token.
///
/// Substring matching is wrong here in both directions: the unanchored
/// pass's re-run HINT names `INTEGRITY-OK (weak)` in prose, so
/// `contains()` would read one mode's advice as the other mode's verdict,
/// and the honest-scope statement names both modes' vocabulary. §9.6 binds
/// the token as the run's terminal outcome line, which is what this reads.
fn has_token_line(text: &str, token: &str) -> bool {
    text.lines().any(|l| l.trim() == token)
}

/// Run one case through the binary and return `(argv, output)`.
fn run_case(case: &Case) -> (Vec<String>, Output) {
    let subject = case.subject();
    let subject = subject.to_string_lossy().into_owned();
    let spec_argv: Vec<String> = case
        .cmd
        .iter()
        .map(|a| a.replace("{PKG}", &subject))
        .collect();
    let argv = adapt_to_rust_cli(&spec_argv);
    let out = run(case.subcommand(), &argv);
    (argv, out)
}

/// The headings of the specification, as the text after the leading `#`s —
/// or `None` in an unpacked `.crate`, where the document does not travel.
///
/// `None` is returned ONLY on proof of packaging (`tests/common/mod.rs`).
/// Everywhere else the missing document panics exactly as it always has: a
/// source checkout without `docs/` is a broken tree, and a citation check
/// that quietly measured nothing would certify the corpus against an empty
/// set of headings.
fn spec_headings() -> Option<BTreeSet<String>> {
    let spec = spec_path();
    if !spec.is_file() {
        let tree = common::classify();
        assert_eq!(
            tree,
            common::Tree::Packaged,
            "the specification under test is not at {} and this is not an \
             unpacked `.crate` (`Cargo.toml.orig` is not beside the \
             manifest). The corpus expectations are checked against ITS \
             headings; with no document there is nothing to check.",
            spec.display()
        );
        common::skip(
            tree,
            "corpus `# spec:` citations are not resolved against \
             docs/SPEC_VERDICT_PACKAGE_V1.md: `cargo package` cannot carry a \
             file from outside the package directory, so the document does \
             not travel inside the .crate",
        );
        return None;
    }
    let text = std::fs::read_to_string(&spec).unwrap_or_else(|e| {
        panic!(
            "the specification under test is not readable at {}: {e}",
            spec.display()
        )
    });
    Some(
        text.lines()
            .filter_map(|l| l.strip_prefix('#'))
            .map(|l| l.trim_start_matches('#').trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
    )
}

// ─── T-T10-1: the corpus is the SPEC's answer, not an implementation's ───

/// INTENCION: `expected.txt` is the spec's answer, not either
///     implementation's output, so a divergence can indict the Rust as
///     readily as the Python. Mechanically: every `expected.txt` carries a
///     `# spec:` line naming a heading that RESOLVES in
///     `docs/SPEC_VERDICT_PACKAGE_V1.md`, so an expectation can only be
///     written by someone who found the sentence that decides it.
/// CONTEXTO: T10's verdict is «the spec is complete»; a corpus generated from
///     the reference implementation (the discarded alternative B2) can never
///     falsify that reference — it would agree with it by construction, and a
///     shared misreading of the spec would be invisible in both legs.
/// EXPIRA SI: the project rules the Rust normative and the spec descriptive,
///     at which point generating the corpus from the binary is the correct
///     design and this guard is the wrong one.
#[test]
fn test_intent_corpus_expectations_are_spec_derived_not_generated() {
    // The skip line, if any, has already been printed on this test's behalf.
    let Some(headings) = spec_headings() else {
        return;
    };
    assert!(
        headings.len() > 20,
        "only {} headings parsed out of the specification; the citation check \
         would pass for the wrong reason",
        headings.len()
    );

    let cases = load_corpus();
    let mut unresolved = Vec::new();
    for case in &cases {
        if !headings.contains(&case.spec_heading) {
            unresolved.push(format!("{}: `# spec: {}`", case.name, case.spec_heading));
        }
    }
    assert!(
        unresolved.is_empty(),
        "these cases cite a heading that does not resolve in {}. An expectation \
         whose citation does not resolve was not read out of the specification:\n{}",
        spec_path().display(),
        unresolved.join("\n")
    );

    // Every case cites SOMETHING, and the citations are not all one heading —
    // a corpus that cites a single section is not a conformance suite for the
    // document.
    let distinct: BTreeSet<&String> = cases.iter().map(|c| &c.spec_heading).collect();
    assert!(
        distinct.len() >= 10,
        "the corpus cites only {} distinct spec headings; §5 of the plan spans \
         thirteen sections",
        distinct.len()
    );

    // The gap ids that ARE carried must look like ledger ids, so a `# gap:`
    // line cannot decay into free prose.
    for case in &cases {
        if let Some(gap) = &case.gap {
            // Ledger ids (plan §6): `SPEC-GAP-<section>` found by reading,
            // `DIV-nn` found by running the two legs.
            assert!(
                gap.starts_with("SPEC-GAP-") || gap.starts_with("DIV-"),
                "case `{}` carries `# gap: {gap}`, which is not a ledger id",
                case.name
            );
        }
    }

    // CRLF: the corpus hashes STORED BYTES, so a Windows clone that rewrote a
    // fixture's line endings would break every evidence hash and every
    // `files_sha256` entry in it. `* -text` is what stops that, and it is a
    // file — assert it, because the failure it prevents only appears on a
    // fresh clone, where no test of ours ever runs.
    let attrs = corpus_root().join(".gitattributes");
    let attrs_text = std::fs::read_to_string(&attrs)
        .unwrap_or_else(|e| panic!("the corpus has no .gitattributes at {}: {e}", attrs.display()));
    assert!(
        attrs_text.lines().any(|l| l.trim() == "* -text"),
        "the corpus .gitattributes must carry `* -text` (same reason and \
         precedent as examples/verdict-package/.gitattributes); it reads:\n{attrs_text}"
    );
}

// ─── T-T10-2: the Rust leg of the oracle ────────────────────────────────

/// The whole corpus, through the binary. One assertion block per case; every
/// failure names the case, the argv actually spawned, and both streams.
#[test]
fn test_scenario_corpus_rust_leg_matches_the_spec_derived_expectations() {
    let cases = load_corpus();
    let mut failures = Vec::new();

    // (0) `class=` must agree with the `token=`/`exit=` beside it, BEFORE the
    //     binary is asked anything. The three axes are hand-written, so a case
    //     can declare a class its own token and exit contradict; that case then
    //     asserts something nobody intended and is green for the wrong reason.
    //     The Python leg has had this check since fix-pack R1 (`check_class`);
    //     it was missing here, so the two legs did not read `expected.txt`
    //     equally strictly (R2-B M-3).
    let mut malformed: Vec<String> = Vec::new();
    for case in &cases {
        let is_chain = case.subcommand() == "verify-chain";
        let want = match case.class {
            Class::Fail => ("", 1),
            Class::PassUnanchored => (TOKEN_UNANCHORED, 4),
            Class::Pass if is_chain => (TOKEN_CHAIN, 0),
            Class::Pass => (TOKEN_ANCHORED, 0),
        };
        if case.token != want.0 || case.exit != want.1 {
            malformed.push(format!(
                "case `{}`: class={:?} but token={:?} exit={}; that class is bound to                  token={:?} exit={}",
                case.name, case.class, case.token, case.exit, want.0, want.1
            ));
        }
    }
    assert!(
        malformed.is_empty(),
        "{} corpus case(s) state an expectation whose three axes contradict each          other:
{}",
        malformed.len(),
        malformed.join("
")
    );

    for case in &cases {
        let (argv, out) = run_case(case);
        let so = stdout(&out);
        let se = stderr(&out);
        let rendered = format!(
            "case `{}`\n  argv: {} {}\n  exit: {:?}\n  stdout:\n{}\n  stderr:\n{}",
            case.name,
            case.subcommand(),
            argv.join(" "),
            out.status.code(),
            so,
            se
        );

        // (1) The exit code. Always — an unanchored pass (4) and an anchored
        //     one (0) are DIFFERENT outcomes (§9.6).
        if out.status.code() != Some(case.exit) {
            failures.push(format!("EXIT expected {} — {rendered}", case.exit));
            continue;
        }

        // (1b) `sanitize=ci`: §9.6's sanitizer matches the reserved token
        //      CASE-INSENSITIVELY, so nothing that reads `verified` in any
        //      casing may survive to the output once the masks are removed.
        if case.sanitize_ci {
            let combined = format!("{so}{se}").replace("VERIF[REDACTED]", "");
            if combined.to_ascii_lowercase().contains("verified") {
                failures.push(format!(
                    "RESERVED TOKEN leaked in some casing past the sanitizer — {rendered}"
                ));
            }
        }

        // (2) The outcome token, on STDOUT, separately from the exit code.
        //     Exit-only lets a token regression through; token-only lets an
        //     exit 4 read as an exit 0.
        let is_chain = case.subcommand() == "verify-chain";
        match case.class {
            Class::Pass | Class::PassUnanchored => {
                if is_chain {
                    // 8.1: the success token is CONTAINED in the success
                    // line, which the reference writes as a sentence.
                    if !case.token.is_empty()
                        && !so.lines().any(|l| l.contains(case.token.as_str()))
                    {
                        failures.push(format!(
                            "TOKEN `{}` on no stdout line — {rendered}",
                            case.token
                        ));
                    }
                } else {
                    if !case.token.is_empty() && !has_token_line(&so, &case.token) {
                        failures.push(format!("TOKEN `{}` not on stdout — {rendered}", case.token));
                    }
                    // A pass must not carry the OTHER mode's token either.
                    let other = if case.token == TOKEN_ANCHORED {
                        TOKEN_UNANCHORED
                    } else {
                        TOKEN_ANCHORED
                    };
                    if !case.token.is_empty() && has_token_line(&so, other) {
                        failures.push(format!(
                            "TOKEN `{other}` leaked into a `{}` pass — {rendered}",
                            case.token
                        ));
                    }
                }
            }
            Class::Fail if is_chain => {
                // 8.1: `verify-chain` legitimately emits the reserved word,
                // so the reserve of 9.6 is not the check here; the check is
                // that a FAILING chain run emits no success token.
                if format!("{so}{se}").contains(TOKEN_CHAIN) {
                    failures.push(format!(
                        "SUCCESS TOKEN `{TOKEN_CHAIN}` printed by a FAILING chain                          verification — {rendered}"
                    ));
                }
            }
            Class::Fail => {
                // §9.6: a failing run prints an error line and NO success
                // token. Failures print on stderr (the token claim is about
                // stdout), so both streams are checked for the success
                // vocabulary; the RESERVED token is checked as a substring,
                // uppercased, because §9.6's whole point is that it must not
                // appear ANYWHERE in a weak check's output — interpolated
                // package bytes included.
                for forbidden in [TOKEN_ANCHORED, TOKEN_UNANCHORED] {
                    if has_token_line(&so, forbidden) || has_token_line(&se, forbidden) {
                        failures.push(format!(
                            "SUCCESS TOKEN `{forbidden}` printed by a FAILING run — {rendered}"
                        ));
                    }
                }
                if format!("{so}{se}")
                    .to_ascii_uppercase()
                    .contains(RESERVED_TOKEN)
                {
                    failures.push(format!(
                        "RESERVED TOKEN `{RESERVED_TOKEN}` leaked from a FAILING \
                         weak-mode run — {rendered}"
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} corpus cases disagree with the specification-derived \
         expectation. A red line here is a CANDIDATE DIVERGENCE, not a broken \
         test: classify it in the divergence ledger (T-T10-4) before touching \
         either the expectation or the implementation.\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

/// INTENCION: the verdict of a run is the PAIR (token, exit), and this suite
///     asserts the two SEPARATELY. Asserting the exit alone lets a token
///     regression through (a script reading stdout would mis-report);
///     asserting the token alone lets an exit 4 read as an exit 0.
/// CONTEXTO: spec §9.6 — the exit code `4` exists precisely «so scripts
///     cannot mistake an unanchored pass for an anchored one». The two
///     outcomes share a package and differ only in whether
///     `--expected-verdict-hash` was supplied.
/// EXPIRA SI: the spec collapses 0 and 4 into a single pass outcome, at which
///     point the pair degenerates and one assertion is enough.
#[test]
fn test_intent_rust_leg_asserts_stdout_and_exit_separately() {
    let cases = load_corpus();
    let find = |name: &str| {
        cases
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("the corpus lost its `{name}` case"))
    };
    let anchored = find("anchored-pass");
    let unanchored = find("unanchored-pass");

    // The two cases must differ on BOTH axes in the expectations themselves,
    // or this suite could satisfy them with one assertion.
    assert_ne!(anchored.exit, unanchored.exit, "the two passes share an exit code");
    assert_ne!(anchored.token, unanchored.token, "the two passes share a token");

    let (_, anchored_out) = run_case(anchored);
    let (_, unanchored_out) = run_case(unanchored);

    // Axis 1: the exit codes, measured, and DISTINCT.
    assert_eq!(
        anchored_out.status.code(),
        Some(0),
        "an anchored pass must exit 0; stderr={}",
        stderr(&anchored_out)
    );
    assert_eq!(
        unanchored_out.status.code(),
        Some(4),
        "an unanchored pass must exit 4; stderr={}",
        stderr(&unanchored_out)
    );

    // Axis 2: the tokens, on stdout, each ABSENT from the other run — so a
    // single token printed by both modes cannot satisfy this test.
    let anchored_so = stdout(&anchored_out);
    let unanchored_so = stdout(&unanchored_out);
    assert!(
        has_token_line(&anchored_so, TOKEN_ANCHORED),
        "the anchored token must print on STDOUT: {anchored_so}"
    );
    assert!(
        has_token_line(&unanchored_so, TOKEN_UNANCHORED),
        "the unanchored token must print on STDOUT: {unanchored_so}"
    );
    assert!(
        !has_token_line(&anchored_so, TOKEN_UNANCHORED),
        "the anchored run printed the unanchored token: {anchored_so}"
    );
    assert!(
        !has_token_line(&unanchored_so, TOKEN_ANCHORED),
        "the unanchored run printed the anchored token as a token line: {unanchored_so}"
    );
}
