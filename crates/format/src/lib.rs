// SPDX-License-Identifier: Apache-2.0
//! `seetrex-format` — the serializable TYPES and the JCS canonicalization
//! primitive that define the Seetrex Compliance verdict-package format.
//!
//! This crate is the pure "format layer": everything that serializes
//! inside a published verdict package — `Fact`/`FactValue` (working
//! memory), `Rule`/`Condition`/`Operator` (ruleset shape), `AuditEntry`
//! (audit log) — plus the shared JCS RFC 8785 canonicalization/hashing
//! primitive. It carries NO inference logic: rule evaluation lives in
//! the (closed-source) inference engine, which depends on this crate
//! and re-exports these items on their historical paths.
//!
//! Purity contract: no database, no HTTP, no async runtime, no engine
//! dependency — enforced by `test_intent_format_crate_is_pure`.
//!
//! Modules:
//! - [`types`] — the serde types of the format (their serialized shape IS
//!   the public format; breaking it is a MAJOR version bump).
//! - [`hashing`] — `canonicalize` / `canonical_hash`, the single JCS
//!   RFC 8785 "JSON → canonical bytes" definition for the platform.

pub mod hashing;
pub mod types;

// Root aliases mirroring the engine crate's historical root re-exports
// (`Fact`, `FactValue`, `Rule`, `AuditEntry`, `Condition`, `Operator`) so
// consumers can use the short form.
pub use types::{
    format_humantime_duration, parse_humantime_duration, AuditEntry, Condition, Fact, FactValue,
    Operator, Rule,
};

#[cfg(test)]
mod purity_tests {
    // Forbidden dependency KEYS: the engine (both kebab and snake spelling),
    // the closed workspace crates (a path-dep to one of them would drag
    // sqlx/tokio transitively and violate the open/closed boundary while
    // both direct guards stayed green) and every service-stack root.
    // The format crate must compile offline with zero engine/DB/HTTP/async
    // coupling.
    const FORBIDDEN: &[&str] = &[
        "seetrex-core",
        "seetrex_core",
        "compliance",
        "aml-sured",
        "aml_sured",
        "sqlx",
        "reqwest",
        "tokio",
        "axum",
        "hyper",
        "tower",
        "aws-config",
        "aws-sdk-s3",
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
    /// (a naive two-variant `contains` would miss `package = 'x'` and free
    /// spacing). Whitespace is collapsed before matching, so no spacing
    /// variant can slip through. A comment line spelling the alias also
    /// trips the guard — fail-loud by design.
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

    /// INTENT: `seetrex-format` is the pure FORMAT layer — an external
    ///   auditor must be able to compile it offline with no engine, no
    ///   DB, no HTTP and no async runtime. This test fails if anyone
    ///   adds `seetrex-core` or a service dependency to `Cargo.toml`.
    /// CONTEXT: the open-source perimeter publishes only the format
    ///   (serializable types + JCS primitive) and the verifier; the
    ///   inference engine stays closed. If the format crate dragged the
    ///   engine in, that boundary would no longer hold in the dependency
    ///   graph.
    /// EXPIRES IF: the open-source perimeter is deliberately re-scoped
    ///   (in which case this list is revised in the same PR that adds
    ///   the dependency).
    #[test]
    fn test_intent_format_crate_is_pure() {
        const CARGO_TOML: &str = include_str!("../Cargo.toml");

        // EVERY manifest line is inspected (a scan keyed on the first
        // `[dependencies]` header would be blind to a
        // [build-dependencies]/[dev-dependencies]/[target.…] section placed
        // BEFORE it — TOML section order is free). `line_declares_dep`
        // cannot false-positive on comments (`#`-prefixed) or `[package]`
        // keys (`name`, `license`, …) for the names in FORBIDDEN.
        for dep in FORBIDDEN {
            let hit = CARGO_TOML
                .lines()
                .any(|line| line_declares_dep(line, dep) || line_aliases_dep(line, dep));
            assert!(
                !hit,
                "forbidden dependency `{dep}` declared (or aliased via \
                 `package = …`) in seetrex-format Cargo.toml — the pure format \
                 layer must stay engine-free and offline-compilable. If the \
                 crate was deliberately re-scoped, update this guard in the \
                 same PR."
            );
        }
    }

    /// Unit-test the spacing/quoting robustness of `line_declares_dep`
    /// (pattern shared with the seetrex-verifier purity guard): bypass
    /// forms MUST be caught, look-alike names MUST NOT match.
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

    /// Unit-test the alias-matcher hardening: every quoting/spacing
    /// variant of the `package = …` alias must be caught; look-alike
    /// keys must not.
    #[test]
    fn line_aliases_dep_matches_quoting_and_spacing_variants() {
        for positive in [
            "sc = { path = \"../seetrex-core\", package = \"seetrex-core\" }",
            "sc = { path = \"x\", package = 'seetrex-core' }",
            "sc = { package  =  \"seetrex-core\" }",
            "\"package\" = \"seetrex-core\"",
            "\"package\"\t=\t'seetrex-core'",
            "package='seetrex-core'",
        ] {
            assert!(
                line_aliases_dep(positive, "seetrex-core"),
                "should detect seetrex-core alias in: {positive:?}"
            );
        }
        for negative in [
            "package = \"seetrex-format\"",
            "name = \"seetrex-core\"",
            "packages = \"seetrex-core\"",
            "package = \"seetrex-core-facade\"",
            "",
        ] {
            assert!(
                !line_aliases_dep(negative, "seetrex-core"),
                "should NOT detect seetrex-core alias in: {negative:?}"
            );
        }
    }
}
