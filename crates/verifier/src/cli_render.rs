// SPDX-License-Identifier: Apache-2.0
//! The ONE place the `verify-package` and `verify-chain` output lines are
//! composed.
//!
//! Both surfaces that answer those two subcommands -- the `seetrex-verifier`
//! binary and the WASM host of the offline browser page -- render the SAME
//! lines, in the SAME order, with the SAME exit codes, because they call the
//! functions below instead of spelling the literals twice. A second spelling
//! of a §9.6 token is a second vocabulary an auditor would have to compare;
//! there is exactly one, and it lives here.
//!
//! What this module does NOT do is print. It returns a [`CommandOutput`]; the
//! caller decides whether that becomes `println!`/`eprintln!` (the binary) or
//! two JSON arrays (the page). The split is the whole point: the page has no
//! stdout.

use crate::chain_export::{ChainHead, PackageVerifyError as ChainVerifyError};
use crate::package::{
    sanitize_reserved_token, PackageReport, PackageVerifyError, RESERVED_TOKEN_MASK,
    SCOPE_STATEMENT,
};
use crate::scope::{SCOPE_LINK_CLAIM, SCOPE_NOT_COVERED};

/// The WEAK pass token §9.6 binds when an EXTERNAL anchor pinned the
/// recomputed hash (`--expected-verdict-hash` supplied and matched).
pub const TOKEN_ANCHORED: &str = "INTEGRITY-OK (weak)";

/// The token §9.6 binds when the package is only self-consistent: nothing
/// outside it attested the hash. Its own exit code (4) exists so a script
/// cannot mistake it for an anchored pass.
pub const TOKEN_UNANCHORED: &str = "SELF-CONSISTENT (unanchored)";

/// The success token §8.1 binds for `verify-chain`, CONTAINED in the banner
/// line rather than standing alone on it (the reference prints it inside a
/// sentence, and the corpus reads it that way).
pub const TOKEN_CHAIN: &str = "VERIFIED OFFLINE";

/// Read cap for a chain export, in bytes, in ONE spelling for the two
/// surfaces that answer `verify-chain`.
///
/// A real export is a few hundred bytes per row; 50 MiB is far beyond any
/// legitimate one without being unbounded. The binary applies it to the file
/// it opens, the browser page to the bytes it read out of the dropped file:
/// an export the tool refuses for its size must not verify in the page.
pub const CHAIN_EXPORT_MAX_BYTES: u64 = 50 * 1024 * 1024;

/// The ONE spelling of the byte-cap refusal, for every reader of it.
pub fn cap_refusal(len: u64, cap: u64) -> String {
    format!("{len} bytes exceeds the {cap} byte cap")
}

/// The bytes-to-text gate a `verify-chain` input passes BEFORE it reaches
/// the parser: the cap, then UTF-8.
///
/// Both surfaces call this. The binary reaches it with the bytes of a file
/// it opened; the page with the bytes of the dropped `File`. A page that
/// decoded its input as text first would have let the browser repair it --
/// `Blob.text()` strips a UTF-8 BOM and replaces every invalid byte with
/// U+FFFD -- and a BOM-prefixed or byte-corrupted export that the tool
/// refuses (exit 1) would have PASSED there. That is a different verdict,
/// not a different sentence, which is why the export crosses the page's ABI
/// as bytes.
pub fn chain_export_text(bytes: Vec<u8>, cap: u64) -> Result<String, String> {
    if bytes.len() as u64 > cap {
        return Err(cap_refusal(bytes.len() as u64, cap));
    }
    String::from_utf8(bytes).map_err(|e| format!("not valid UTF-8: {e}"))
}

/// Render the failure of [`chain_export_text`] as the run the binary
/// reports for an export it cannot read: one `ERROR: cannot read <name>:
/// <detail>` line on the diagnostic stream, exit 1, no outcome token.
///
/// `name` and `detail` both quote bytes the auditor did not choose (a
/// filename from argv or from a drop, a decoder's message about the file's
/// own contents), so both go through the output-boundary sanitizer every
/// other line does.
pub fn render_chain_read_failure(name: &str, detail: &str) -> CommandOutput {
    CommandOutput::new(
        Vec::new(),
        vec![format!(
            "ERROR: cannot read {}: {}",
            sanitize_reserved_token(name),
            sanitize_reserved_token(detail)
        )],
        1,
        None,
    )
}

/// The advice an unanchored pass prints, verbatim.
const UNANCHORED_HINT: &str = "HINT: pass --expected-verdict-hash <hex> (obtained \
                               from the published chain export or another external \
                               channel) to upgrade this to INTEGRITY-OK (weak) — \
                               the package can never be its own trust root.";

/// One rendered run: the lines a surface emits, and the code it exits with.
///
/// Each element is ONE `println!`/`eprintln!` of the binary, so an element
/// may itself contain newlines (the honest-scope statement and
/// [`SCOPE_NOT_COVERED`] are multi-sentence blocks printed by a single call).
/// Splitting them further here would change the binary's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Lines for the success stream, in order.
    pub stdout: Vec<String>,
    /// Lines for the diagnostic stream, in order.
    pub stderr: Vec<String>,
    /// The process exit code (0 pass, 1 failure, 4 unanchored pass).
    pub exit: u8,
    /// The §9.6 outcome token of the run, when it has one. `None` for a
    /// failing run: a failure has no token, which is exactly what the corpus
    /// asserts about it.
    pub token: Option<&'static str>,
    /// Whether the reserved-token MASK reached these lines.
    ///
    /// The condition is "the rendered text CARRIES the mask", not "this call
    /// replaced something": a report that arrives already redacted still
    /// earns the legend the caller prints once, at the end of the run.
    pub mask_used: bool,
}

impl CommandOutput {
    fn new(stdout: Vec<String>, stderr: Vec<String>, exit: u8, token: Option<&'static str>) -> Self {
        let mask_used = stdout
            .iter()
            .chain(stderr.iter())
            .any(|line| line.contains(RESERVED_TOKEN_MASK));
        Self {
            stdout,
            stderr,
            exit,
            token,
            mask_used,
        }
    }
}

/// Render a `verify-package` run.
///
/// A SELF-CONTAINED output boundary: EVERY line -- step/report lines,
/// WARNINGs, terminal tokens, the honest-scope statement and the error path
/// -- is routed through [`sanitize_reserved_token`], because a
/// [`PackageVerifyError`] (and, defensively, any report line) can embed
/// package-controlled bytes that would otherwise smuggle the reserved
/// strong-pass token into a WEAK check's output (§9.6).
pub fn render_verify_package(
    result: Result<PackageReport, PackageVerifyError>,
) -> CommandOutput {
    match result {
        Ok(report) => {
            let mut stdout = Vec::new();
            for step in &report.steps {
                stdout.push(sanitize_reserved_token(step));
            }
            for w in &report.warnings {
                stdout.push(sanitize_reserved_token(&format!("WARNING: {w}")));
            }
            if report.anchored {
                // Weak pass token (anchored) — binding per §9.6.
                stdout.push(sanitize_reserved_token(TOKEN_ANCHORED));
                stdout.push(sanitize_reserved_token(SCOPE_STATEMENT));
                CommandOutput::new(stdout, Vec::new(), 0, Some(TOKEN_ANCHORED))
            } else {
                stdout.push(sanitize_reserved_token(TOKEN_UNANCHORED));
                stdout.push(sanitize_reserved_token(SCOPE_STATEMENT));
                stdout.push(sanitize_reserved_token(UNANCHORED_HINT));
                // Exit 4 — an unanchored pass is NOT a verification (§9.6).
                CommandOutput::new(stdout, Vec::new(), 4, Some(TOKEN_UNANCHORED))
            }
        }
        Err(e) => CommandOutput::new(
            Vec::new(),
            vec![
                sanitize_reserved_token(&format!("ERROR: {e}")),
                // The honest-scope statement prints on EVERY terminal
                // outcome, failure included (§9.6).
                sanitize_reserved_token(SCOPE_STATEMENT),
            ],
            1,
            None,
        ),
    }
}

/// Render a `verify-chain` run over an already-read export.
///
/// Success prints the strong `VERIFIED` wording (§9.6 names this surface as
/// one of its two counterparts, so the reserve does not apply to it); the
/// FAILURE path IS sanitized — a hostile export could otherwise echo the
/// strong token into a failing run's diagnostics.
pub fn render_verify_chain(result: Result<ChainHead, ChainVerifyError>) -> CommandOutput {
    match result {
        Ok(head) => CommandOutput::new(
            vec![
                format!("Public chain package {TOKEN_CHAIN}"),
                format!("  verdict_count:   {}", head.verdict_count),
                format!("  last_chain_hash: {}", head.last_chain_hash),
                String::new(),
                // SCOPE, stated at the same volume as the banner. The link
                // preimage covers only `verdict_hash`, `chain_prev_hash` and
                // `chain_hash`; the human-readable columns of the export are
                // NOT inputs to it, so editing them leaves every link — and
                // this head hash — intact.
                format!(
                    "Compare these two values against the vendor's public Trust \
                     Center page for this tenant. {SCOPE_LINK_CLAIM}"
                ),
                String::new(),
                SCOPE_NOT_COVERED.to_string(),
            ],
            Vec::new(),
            0,
            Some(TOKEN_CHAIN),
        ),
        Err(e) => CommandOutput::new(
            Vec::new(),
            vec![sanitize_reserved_token(&format!("ERROR: {e}"))],
            1,
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::RESERVED_TOKEN_LEGEND;

    fn report(steps: &[&str], warnings: &[&str], anchored: bool) -> PackageReport {
        PackageReport {
            steps: steps.iter().map(|s| (*s).to_string()).collect(),
            warnings: warnings.iter().map(|s| (*s).to_string()).collect(),
            verdict_hash: "00".repeat(32),
            anchored,
        }
    }

    /// The legend, emitted the way BOTH surfaces emit it: once per run, at
    /// the end, iff the rendered text carries the mask. The binary does it
    /// in `emit`/`main` and the WASM host in `Response::from_output`; this
    /// is that one rule, applied to a rendered output so the test can count
    /// the result.
    fn stderr_with_legend(out: &CommandOutput) -> Vec<String> {
        let mut lines = out.stderr.clone();
        if out.mask_used {
            lines.push(RESERVED_TOKEN_LEGEND.to_string());
        }
        lines
    }

    /// INTENT: the ORDER of the lines a run prints, and the condition
    ///     that arms the reserved-token legend, are part of what an auditor
    ///     reads -- not an implementation detail. Three runs are pinned as
    ///     EXACT line vectors: an anchored pass (steps, then WARNINGs, then
    ///     the weak token, then the scope statement, exit 0), an unanchored
    ///     pass (token, scope statement, HINT, exit 4), and a failure whose
    ///     error text carries the reserved token (ERROR then the scope
    ///     statement on stderr, exit 1, `mask_used` set, and the legend
    ///     appearing EXACTLY ONCE once the caller's rule is applied).
    /// CONTEXT: `cli_render` is the one place both surfaces compose these
    ///     lines, so a reordering here moves the CLI and the offline page
    ///     together and no cross-surface test can see it. Measured before
    ///     this test existed: swapping the token and the scope statement,
    ///     and disarming the legend condition, both left the whole tree
    ///     green.
    /// EXPIRES IF: section 9.6 stops binding the terminal token as the last
    ///     line of the report, or the legend stops being a once-per-run
    ///     line the caller appends.
    #[test]
    fn test_intent_cli_render_line_order_and_legend() {
        // ---- an anchored pass -------------------------------------------
        let out = render_verify_package(Ok(report(
            &["STEP 1 manifest read", "STEP 7 verdict hash recomputed"],
            &["legacy package shape"],
            true,
        )));
        assert_eq!(
            out.stdout,
            vec![
                "STEP 1 manifest read".to_string(),
                "STEP 7 verdict hash recomputed".to_string(),
                "WARNING: legacy package shape".to_string(),
                TOKEN_ANCHORED.to_string(),
                SCOPE_STATEMENT.to_string(),
            ],
            "an anchored pass prints its steps, then its WARNINGs, then the weak \
             token, then the honest-scope statement -- in that order"
        );
        assert_eq!(out.stderr, Vec::<String>::new());
        assert_eq!(out.exit, 0);
        assert_eq!(out.token, Some(TOKEN_ANCHORED));
        assert!(!out.mask_used);
        assert_eq!(stderr_with_legend(&out).len(), 0, "no mask, no legend");

        // ---- an unanchored pass -----------------------------------------
        let out = render_verify_package(Ok(report(&["STEP 1 manifest read"], &[], false)));
        assert_eq!(
            out.stdout,
            vec![
                "STEP 1 manifest read".to_string(),
                TOKEN_UNANCHORED.to_string(),
                SCOPE_STATEMENT.to_string(),
                UNANCHORED_HINT.to_string(),
            ],
            "an unanchored pass prints the token, then the scope statement, then \
             the HINT that says how to upgrade it -- the HINT is advice ABOUT the \
             outcome and follows it"
        );
        assert_eq!(out.stderr, Vec::<String>::new());
        assert_eq!(out.exit, 4, "an unanchored pass is not a verification");
        assert_eq!(out.token, Some(TOKEN_UNANCHORED));
        assert!(!out.mask_used);

        // ---- a failure whose error text carries the reserved token -------
        let out = render_verify_package(Err(PackageVerifyError::Shape(
            "undeclared extra file `VERIFIED_x.txt`".to_string(),
        )));
        assert_eq!(
            out.stdout,
            Vec::<String>::new(),
            "a failing run prints nothing on the success stream"
        );
        assert_eq!(
            out.stderr,
            vec![
                format!(
                    "ERROR: integrity check failed — package shape: undeclared extra \
                     file `{RESERVED_TOKEN_MASK}_x.txt`"
                ),
                SCOPE_STATEMENT.to_string(),
            ],
            "a failure prints its ERROR and then the honest-scope statement, which \
             prints on EVERY terminal outcome"
        );
        assert_eq!(out.exit, 1);
        assert_eq!(out.token, None, "a failure has no outcome token");
        assert!(
            out.mask_used,
            "the rendered text CARRIES the mask, so the run must arm the legend"
        );
        assert!(
            !out
                .stderr
                .iter()
                .any(|l| l.contains(RESERVED_TOKEN_LEGEND)),
            "the legend is the CALLER's once-per-run line; rendering it here would \
             print it twice"
        );
        let with_legend = stderr_with_legend(&out);
        assert_eq!(
            with_legend
                .iter()
                .filter(|l| l.as_str() == RESERVED_TOKEN_LEGEND)
                .count(),
            1,
            "a mask on screen earns exactly one legend: {with_legend:?}"
        );
        assert_eq!(
            with_legend.last().map(String::as_str),
            Some(RESERVED_TOKEN_LEGEND),
            "the legend is the LAST line of the run: it explains a mask the reader \
             has already met"
        );

        // ---- verify-chain: the banner carries the token, not a bare line --
        let out = render_verify_chain(Err(ChainVerifyError::Parse(
            crate::chain_export::PackageParseError::Malformed {
                detail: "trailing comma".to_string(),
            },
        )));
        assert_eq!(out.exit, 1);
        assert_eq!(out.token, None);
        assert_eq!(out.stdout, Vec::<String>::new());
        assert_eq!(out.stderr.len(), 1, "a chain failure is one ERROR line");
    }
}
