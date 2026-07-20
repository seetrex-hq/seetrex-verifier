// SPDX-License-Identifier: Apache-2.0
//! `seetrex-verifier` — the pure, offline verification core for Seetrex
//! Compliance verdict packages.
//!
//! This crate holds the code that RECOMPUTES and VERIFIES the cryptographic
//! quantities of a compliance verdict from its canonical inputs — hash
//! integrity, NOT engine re-execution (full re-derivation is
//! `compliance-cli replay --full`, which consumes this crate and adds the
//! inference engine on top) — with zero database, zero network and zero
//! HTTP dependencies by design. It is the SAME code the
//! `compliance-cli` runs — not a replica — so an open-source auditor
//! compiles exactly what production ran.
//!
//! Modules:
//! - [`canonical`] — verdict preimage v1/v2: `VerdictCanonicalInput`, the
//!   JCS RFC 8785 + SHA-256 hashing (`compute_verdict_hash` /
//!   `compute_verdict_hash_v1`), the pinned `derived_at` encoding and the
//!   working-memory canonicalization helpers.
//! - [`chain`] — the audit-chain link primitive `compute_chain_hash`.
//! - [`chain_export`] — the public chain export (§8.1): envelope/row
//!   types and the OFFLINE verification `parse_and_verify_package` /
//!   `verify_public_chain`.
//! - [`rulesets`] — the ruleset anchor: `RulesetFile` parsing, strict
//!   unknown-key validation and `ruleset_content_hash_hex`.
//! - [`evidence`] — the evidence content-hash `canonicalize`, routed
//!   through the shared `seetrex-format` JCS primitive.
//! - [`hash`] — `sha256_hex`, the raw-bytes → lowercase-hex SHA-256
//!   primitive shared by package verification and the CLI replay path.
//! - [`package`] — `verify_package`: offline package-integrity
//!   verification — the logic the `verify-package` CLI subcommand is a
//!   thin shell over.
//! - [`types`] — `VerdictOutcome`, the closed set of the three verdicts.
//!
//! The crate depends on `seetrex-format` (the pure format layer: the
//! serde types of the verdict package + the shared JCS canonicalization
//! primitive). It MUST NOT depend on the inference engine
//! (`seetrex-core`, which stays closed-source — enforced by
//! `test_intent_verifier_no_longer_depends_on_engine`) nor on any service
//! stack (sqlx, axum, reqwest, tokio, aws-*, …) — enforced by
//! `test_intent_verifier_crate_dependency_purity`.

pub mod canonical;
pub mod chain;
pub mod chain_export;
pub mod evidence;
pub mod hash;
pub mod package;
pub mod rulesets;
pub mod types;

#[cfg(test)]
mod purity_tests {
    const FORBIDDEN: &[&str] = &[
        "sqlx", "axum", "reqwest", "tokio", "aws-config", "aws-sdk-s3", "hyper", "tower",
    ];

    /// True if `line` declares a Cargo dependency whose KEY is `dep`,
    /// robust to non-canonical TOML spacing and the quoted-key form.
    ///
    /// A declaration is: the TRIMMED line content starts with the dep name
    /// (bare or double-quoted) followed by optional whitespace and then `=`
    /// (assignment: `tokio = …`, `tokio="1"`, `tokio  =`) or `.` (dotted
    /// table key: `tokio.workspace = true`). A sibling dep whose name merely
    /// starts with a forbidden name (`tokio-console`, `tokio_util`) does NOT
    /// match — the char right after the name must be whitespace, `=` or `.`.
    fn line_declares_dep(line: &str, dep: &str) -> bool {
        let l = line.trim_start();
        // Quoted-key form: `"tokio" = …` / `"tokio".workspace = …`.
        if let Some(rest) = l.strip_prefix('"') {
            return rest
                .strip_prefix(dep)
                .and_then(|after| after.strip_prefix('"'))
                .map(|after_quote| {
                    let t = after_quote.trim_start();
                    t.starts_with('=') || t.starts_with('.')
                })
                .unwrap_or(false);
        }
        // Table-header form: `[dependencies.tokio]` / `[dev-dependencies.tokio]`
        // / `[target.'cfg(unix)'.dependencies.tokio]`.
        if let Some(header) = l.strip_prefix('[') {
            if let Some(inner) = header.trim_end().strip_suffix(']') {
                if let Some(tail) = inner.rsplit_once('.').map(|(_, tail)| tail) {
                    return tail.trim() == dep;
                }
            }
            return false;
        }
        // Bare-key form: `tokio = …` / `tokio="1"` / `tokio.workspace = …`.
        match l.strip_prefix(dep) {
            Some(after) => {
                let t = after.trim_start();
                // If nothing was trimmed AND the next char is not `=`/`.`,
                // it's a longer name (`tokio-util`) → not a match.
                t.starts_with('=') || t.starts_with('.')
            }
            None => false,
        }
    }

    /// True if `line` aliases the forbidden crate via a `package = …` key,
    /// robust to spacing, BOTH TOML string styles and the quoted-key form
    /// (same helper as the seetrex-format purity guard). Whitespace is
    /// collapsed before matching.
    fn line_aliases_dep(line: &str, dep: &str) -> bool {
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        [
            format!("package=\"{dep}\""),
            format!("package='{dep}'"),
            format!("\"package\"=\"{dep}\""),
            format!("\"package\"='{dep}'"),
        ]
        .iter()
        .any(|needle| compact.contains(needle.as_str()))
    }

    /// INTENT: the `seetrex-verifier` crate is the PURE verification
    ///   core — the open-source verifier must compile offline with no
    ///   service dependency whatsoever (DB, HTTP, cloud). This test
    ///   fails if anyone adds one of those deps to `Cargo.toml`.
    /// CONTEXT: the pure-crate boundary is part of the deliverable
    ///   (move code, don't replicate it; the auditor compiles THE SAME
    ///   code the CLI runs). The matcher is hardened on purpose: a
    ///   plain `dep =` / `dep.` prefix scan was evadable with
    ///   non-canonical spacing (`tokio="1"`, `tokio  =`).
    /// EXPIRES IF: the crate is deliberately re-scoped to include
    ///   service integration (in which case this list is revised in
    ///   the same PR that adds the dep).
    #[test]
    fn test_intent_verifier_crate_dependency_purity() {
        const CARGO_TOML: &str = include_str!("../Cargo.toml");

        // EVERY manifest line is inspected (a former
        // `split("[dependencies]")` scan was blind to dependency
        // sections placed BEFORE the first [dependencies] header — TOML
        // section order is free).
        for dep in FORBIDDEN {
            let hit = CARGO_TOML
                .lines()
                .any(|line| line_declares_dep(line, dep) || line_aliases_dep(line, dep));
            assert!(
                !hit,
                "forbidden service dependency `{dep}` declared (or aliased) in \
                 seetrex-verifier Cargo.toml — the pure verification core must \
                 stay offline-compilable. If the crate was deliberately \
                 re-scoped, update this guard in the same PR."
            );
        }
    }

    /// INTENT: the verifier does NOT depend on the inference engine.
    ///   After the format-layer extraction, its only platform
    ///   dependency is `seetrex-format` — the open/closed cut (engine
    ///   CLOSED, format + verifier open) must be true in the
    ///   dependency GRAPH, not just in intent. Two legs: (a) the
    ///   manifest declares `seetrex-core` in no form; (b) no file
    ///   under `src/` references the engine crate path.
    /// CONTEXT: an external auditor compiles the verifier from public
    ///   material without the engine. The verifier once imported
    ///   `AuditEntry`/`Fact`/`FactValue`/`Rule` and the JCS primitive
    ///   from the engine crate; all of that now lives in
    ///   `seetrex-format`.
    /// EXPIRES IF: the open-source cut is deliberately re-scoped to
    ///   open the engine (a decision that is explicitly CLOSED today).
    #[test]
    fn test_intent_verifier_no_longer_depends_on_engine() {
        // (a) Manifest: no engine NOR closed-workspace-crate dependency in
        // any TOML form — every line scanned, both spellings, `package = …`
        // alias in every quoting/spacing variant (a path-dep to
        // `compliance` would drag the whole service stack transitively
        // while staying green).
        const CARGO_TOML: &str = include_str!("../Cargo.toml");
        for dep in [
            "seetrex-core",
            "seetrex_core",
            "compliance",
            "aml-sured",
            "aml_sured",
        ] {
            assert!(
                !CARGO_TOML
                    .lines()
                    .any(|line| line_declares_dep(line, dep) || line_aliases_dep(line, dep)),
                "verifier Cargo.toml declares or aliases `{dep}` — the verifier \
                 must not depend on the inference engine nor any closed \
                 workspace crate."
            );
        }

        // (b) Source: zero references to the engine crate path anywhere in
        // src/. The needle is assembled at runtime so THIS test file does
        // not match itself.
        let needle = format!("{}{}", "seetrex_core", "::");
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src_dir];
        let mut checked = 0usize;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read verifier src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let src = std::fs::read_to_string(&path).expect("read source file");
                    // Collapse whitespace so an engine path split around the
                    // `::` (space/tab/newline) cannot bypass the literal
                    // match (same discipline as the service-layer
                    // boundary greps).
                    let collapsed: String =
                        src.split_whitespace().collect::<Vec<_>>().join("");
                    assert!(
                        !collapsed.contains(&needle),
                        "{} references the engine crate path `{needle}…` — the \
                         verifier must not touch the inference engine.",
                        path.display()
                    );
                    checked += 1;
                }
            }
        }
        assert!(
            checked >= 8,
            "expected to scan at least the 8 known verifier source files, \
             scanned {checked} — the walker is broken, fix it before trusting \
             this guard."
        );
    }

    /// Unit-test the spacing/quoting robustness of `line_declares_dep`
    /// directly: the bypass forms an old `starts_with("dep =")` /
    /// `starts_with("dep.")` matcher missed MUST be caught, and the
    /// look-alike sibling names MUST NOT false-positive.
    #[test]
    fn line_declares_dep_matches_spacing_and_quoting_variants() {
        // Positive: every one of these declares `tokio`.
        for positive in [
            "tokio = \"1\"",
            "tokio=\"1\"",
            "tokio  =",
            "tokio\t= \"1\"",
            "  tokio = { version = \"1\" }",
            "tokio.workspace = true",
            "tokio . workspace = true",
            "\"tokio\" = \"1\"",
            "\"tokio\".workspace = true",
            "[dependencies.tokio]",
            "[dev-dependencies.tokio]",
            "  [dependencies.tokio]  ",
            "[target.'cfg(unix)'.dependencies.tokio]",
        ] {
            assert!(
                line_declares_dep(positive, "tokio"),
                "should detect tokio declaration in: {positive:?}"
            );
        }

        // Negative: look-alike names and non-declarations must NOT match.
        for negative in [
            "tokio-console = \"0.1\"",
            "tokio_util = \"0.7\"",
            "some-tokio = \"1\"",
            "# tokio is forbidden",
            "version = \"1\"",
            "",
            "[dependencies.tokio-util]",
            "[dependencies]",
            "[dev-dependencies]",
        ] {
            assert!(
                !line_declares_dep(negative, "tokio"),
                "should NOT detect tokio declaration in: {negative:?}"
            );
        }
    }
}
