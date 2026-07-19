// SPDX-License-Identifier: Apache-2.0
//! `VerdictOutcome` enum — the 3 verdicts the Compliance engine emits
//! when evaluating a ruleset.
//!
//! Matches byte-for-byte the SQL CHECK constraint
//! `verdict_outcome IN ('SATISFIED', 'AT_RISK', 'VIOLATED')` AND the
//! service-layer const `VERDICT_OUTCOME_VALUES` (a cross-Rust-SQL
//! invariant verified by
//! `test_intent_verdict_outcome_values_match_sql_check_constraint`).
//!
//! Does NOT derive `ToSchema` (utoipa) here — this crate carries no
//! HTTP stack; the service layer adds a newtype or adapter for OpenAPI
//! where it needs one. Keeping this type decoupled from the HTTP stack
//! lets lib tests run with no compile-time dep on the handler.

use serde::{Deserialize, Serialize};

/// Verdict outcome — the closed set of 3 verdicts the Compliance
/// engine emits when evaluating a ruleset (1-2 violations → AT_RISK,
/// ≥3 → VIOLATED; 0 → SATISFIED).
///
/// Serde representation: `SCREAMING_SNAKE_CASE` → JSON strings
/// `"SATISFIED"`, `"AT_RISK"`, `"VIOLATED"` (matches
/// `as_motor_string()` and the SQL CHECK constraint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictOutcome {
    Satisfied,
    AtRisk,
    Violated,
}

impl VerdictOutcome {
    /// Parses a fact value string emitted by the engine.
    ///
    /// The engine emits verdicts as `FactValue::String("SATISFIED")`
    /// (or `"AT_RISK"` or `"VIOLATED"`) in the `working_memory` when a
    /// rule fires its consequent. The service inference handler
    /// extracts the verdict outcome using this method to map the
    /// engine string → the type-safe enum.
    ///
    /// Unknown strings return `None` (NO panic) — the caller maps
    /// them to a malformed-verdict-string error that produces a
    /// 500-by-design (a ruleset-author or engine bug, not client
    /// input).
    pub fn from_motor_string(s: &str) -> Option<Self> {
        match s {
            "SATISFIED" => Some(Self::Satisfied),
            "AT_RISK" => Some(Self::AtRisk),
            "VIOLATED" => Some(Self::Violated),
            _ => None,
        }
    }

    /// Inverse of `from_motor_string`. Used by the persistence layer
    /// (the `verdict_outcome` column bind) and by
    /// `compute_verdict_hash` (the string enters the JCS canonical
    /// input).
    ///
    /// Returns `&'static str` to avoid allocations on the handler hot
    /// path — `format!`/`String::from` here would be waste.
    pub fn as_motor_string(&self) -> &'static str {
        match self {
            Self::Satisfied => "SATISFIED",
            Self::AtRisk => "AT_RISK",
            Self::Violated => "VIOLATED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INTENT: the serde representation of `VerdictOutcome` is
    ///         `SCREAMING_SNAKE_CASE` — round-trip JSON `"SATISFIED"`
    ///         ↔ `VerdictOutcome::Satisfied` etc. Without this test, a
    ///         future dev changing the `#[serde(rename_all = "...")]`
    ///         (e.g. to `lowercase`) would break the API contract with
    ///         no compile failure.
    /// CONTEXT: cross-check with `as_motor_string()`: both paths must
    ///          produce the same string. The engine emits via
    ///          `FactValue::String("SATISFIED")` (a plain string, not
    ///          serde JSON); the API handler emits the response body
    ///          via serde JSON. The two paths MUST produce the same
    ///          textual representation.
    /// EXPIRES IF: the SCREAMING_SNAKE_CASE convention is deliberately
    ///             replaced (update the enum + as_motor_string +
    ///             from_motor_string + the SQL CHECK constraint +
    ///             the VERDICT_OUTCOME_VALUES const simultaneously).
    #[test]
    fn test_intent_verdict_outcome_serde_screaming_snake_case() {
        // (1) Serialize: enum → JSON string.
        assert_eq!(
            serde_json::to_value(VerdictOutcome::Satisfied).unwrap(),
            serde_json::json!("SATISFIED")
        );
        assert_eq!(
            serde_json::to_value(VerdictOutcome::AtRisk).unwrap(),
            serde_json::json!("AT_RISK")
        );
        assert_eq!(
            serde_json::to_value(VerdictOutcome::Violated).unwrap(),
            serde_json::json!("VIOLATED")
        );

        // (2) Deserialize: JSON string → enum (round-trip).
        let s: VerdictOutcome = serde_json::from_value(
            serde_json::json!("SATISFIED")
        ).unwrap();
        assert_eq!(s, VerdictOutcome::Satisfied);
        let a: VerdictOutcome = serde_json::from_value(
            serde_json::json!("AT_RISK")
        ).unwrap();
        assert_eq!(a, VerdictOutcome::AtRisk);
        let v: VerdictOutcome = serde_json::from_value(
            serde_json::json!("VIOLATED")
        ).unwrap();
        assert_eq!(v, VerdictOutcome::Violated);

        // (3) Cross-check serde ↔ motor_string: both paths produce the
        // same string. Without this check, a future PR renaming
        // `Satisfied` → `Compliant` in the enum (without touching
        // serde rename_all) would produce two divergent strings: serde
        // would emit `"COMPLIANT"` but `as_motor_string` would return
        // the hardcoded `"SATISFIED"`.
        for v in [VerdictOutcome::Satisfied, VerdictOutcome::AtRisk, VerdictOutcome::Violated] {
            let serde_string: String = serde_json::to_value(v).unwrap()
                .as_str().unwrap().to_string();
            assert_eq!(
                serde_string,
                v.as_motor_string(),
                "serde representation must match as_motor_string() — \
                 if you rename a variant, ALSO update as_motor_string + \
                 from_motor_string + SQL CHECK + VERDICT_OUTCOME_VALUES"
            );
        }
    }

    /// INTENT: `from_motor_string ∘ as_motor_string == identity` for
    ///         the 3 variants. Without this test, a future dev adding
    ///         `Self::Pending => "PENDING"` to `as_motor_string`
    ///         without updating `from_motor_string` introduces a
    ///         silent asymmetry — the engine emits "PENDING" but the
    ///         extractor returns None and produces a 500-by-design.
    /// CONTEXT: the two conversion methods are a matched pair.
    /// EXPIRES IF: the enum is deliberately expanded (keep both
    ///             methods in sync).
    #[test]
    fn test_intent_verdict_outcome_from_motor_string_round_trip() {
        // The exhaustive match in the for-loop means that if a dev
        // adds a variant to the enum, this loop keeps iterating over
        // the 3 old ones and the new variant goes untested — but the
        // compile-time exhaustive match in `as_motor_string` already
        // catches the oversight.
        for v in [VerdictOutcome::Satisfied, VerdictOutcome::AtRisk, VerdictOutcome::Violated] {
            let s = v.as_motor_string();
            let parsed = VerdictOutcome::from_motor_string(s)
                .unwrap_or_else(|| panic!(
                    "round-trip broken: as_motor_string() returned `{s}` \
                     but from_motor_string couldn't parse it. Sync the \
                     two match arms."
                ));
            assert_eq!(parsed, v);
        }
    }

    /// INTENT: `from_motor_string` rejects unknown strings with
    ///         `None`. NO panic, NO arbitrary mapping to `Satisfied`
    ///         (which would be a security bug — an adversarial ruleset
    ///         emitting `"PENDING"` must not pass as SATISFIED).
    /// CONTEXT: the service handler maps `None` to a
    ///          malformed-verdict-string error → 500-by-design. A
    ///          ruleset-author bug is detected loud, not silently
    ///          coerced.
    /// EXPIRES IF: the outcome set is expanded (add the variant + a
    ///             round-trip test + update this test).
    #[test]
    fn test_intent_verdict_outcome_from_motor_string_rejects_unknown() {
        // Completely unrelated strings.
        assert_eq!(VerdictOutcome::from_motor_string("MAYBE"), None);
        assert_eq!(VerdictOutcome::from_motor_string("PENDING"), None);
        assert_eq!(VerdictOutcome::from_motor_string(""), None);

        // Case variants — the Postgres CHECK is case-sensitive; same
        // here. Otherwise an engine emitting `"satisfied"` (lowercase)
        // would pass the Postgres CHECK silently (because the extract
        // would return None → 500), while the ruleset dev thought the
        // outcome was SATISFIED. Better to fail loud at the extract.
        assert_eq!(VerdictOutcome::from_motor_string("satisfied"), None);
        assert_eq!(VerdictOutcome::from_motor_string("Satisfied"), None);
        assert_eq!(VerdictOutcome::from_motor_string("AtRisk"), None); // camelCase, NO SCREAMING_SNAKE
        assert_eq!(VerdictOutcome::from_motor_string("AT-RISK"), None); // hyphen, NO underscore

        // Whitespace / padding.
        assert_eq!(VerdictOutcome::from_motor_string(" SATISFIED"), None);
        assert_eq!(VerdictOutcome::from_motor_string("SATISFIED "), None);
        assert_eq!(VerdictOutcome::from_motor_string("\n"), None);
    }
}
