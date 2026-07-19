// SPDX-License-Identifier: Apache-2.0
//! Ruleset anchor — the pure parsing, strict unknown-key validation and
//! content-hash primitives for a Seetrex Compliance ruleset.
//!
//! Extracted from `compliance::rulesets` (the framework index, the pinned
//! set `PINNED_RULESETS`, the backlog dirs and the on-disk walker stay
//! there and re-export these items). These are the pieces an offline
//! verifier needs to recompute a ruleset's content anchor byte-for-byte
//! from the packaged `ruleset.json`, and to reject unknown keys exactly as
//! the reference loader does.

use seetrex_format::Rule;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// On-disk representation of one ruleset.
///
/// Metadata fields describe the control to a human operator (and to
/// `compliance-cli export-package` consumers). The `rules` field is
/// the only one the engine consumes.
///
/// `#[serde(deny_unknown_fields)]`:
/// a typo in a JSON key (`verdicts_emited` for `verdicts_emitted`)
/// would otherwise leave the affected field at its default value and
/// silently change the downstream semantics — fail-LOUD at parse time
/// is the right posture for a regulatory artifact. Forward-compat for
/// future fields will use a `version` discriminator at the file level
/// (not yet needed at v1), not silent ignorance of unknown keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RulesetFile {
    /// Stable identifier of the ruleset. Used as the FK in the
    /// `verdict` table and in the audit chain.
    pub ruleset_id: String,

    /// Regulatory framework — "CRA", "DORA", "NIS2", "SOC2",
    /// "ISO27001".
    pub framework: String,

    /// Article / section identifier within the framework (e.g. "14"
    /// for CRA Art. 14). Free-form string so DORA's RTS / ITS layout
    /// fits without schema churn.
    pub article: String,

    /// Control name within the article (`vulnerability_handling`,
    /// `incident_response`, ...). Allows multiple controls per article.
    pub control: String,

    /// Ruleset content version, bumped by the curator when rule logic
    /// changes. Distinct from `RulesetFile`'s schema version (which is
    /// implicit at v1 today).
    pub version: u32,

    /// `ENGINE_SEMANTIC_VERSION` floor — refuse to evaluate the ruleset
    /// against an engine older than this. Pins the assumption made by
    /// the rule authors about engine semantics (DNF, negation,
    /// confidence aggregation).
    pub engine_semantic_version_floor: u32,

    /// Human-readable description of what the control checks, what
    /// evidences it consumes, and what verdicts it can emit. Quoted
    /// verbatim in the reproduction package manifest.
    pub doc: String,

    /// IDs of the facts the rules consume. Operator-facing
    /// documentation; the engine does not enforce this list.
    pub facts_consumed: Vec<String>,

    /// Verdict strings the rules can emit (`SATISFIED`, `AT_RISK`,
    /// `VIOLATED`). Used by the API to validate payloads and by the
    /// CLI to pre-flight the replay command's `--expected-verdict`
    /// value.
    pub verdicts_emitted: Vec<String>,

    /// The actual ruleset, in the order the curator wrote it. The
    /// engine evaluates by priority then by id, so order in the file
    /// is presentational only.
    pub rules: Vec<Rule>,

    /// Literal legal source this ruleset instantiates. Present on
    /// production rulesets (auditor-facing); absent on fixture /
    /// backlog rulesets. The field carries the regulatory citation
    /// pattern: official EUR-Lex URL + RTS/ITS guidance refs + open
    /// interpretation caveats. An auditor in 2033 recovers this object
    /// from the reproduction package and verifies the literal citation
    /// against the Official Journal.
    ///
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]`:
    /// backward compat with rulesets that predate the field (parsing
    /// without the key is OK, re-serialization omits the key → the
    /// content hash is preserved for rulesets without a citation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulatory_source: Option<RegulatorySource>,
}

/// Literal citation of the legal source a ruleset instantiates.
///
/// **7-year auditability contract:** each field lets an auditor in
/// 2033 mechanically verify that the ruleset encodes the legal text it
/// claims to encode — without depending on our 2026 interpretation or
/// on a regulatory advisor being available.
///
/// **Open interpretation:** where the legal text leaves ambiguity
/// (e.g. "appropriate measures", "reasonable steps"), it is documented
/// literally in `interpretation_caveats` so an auditor knows those
/// interpretations are NOT hard rules imposed by the engine, but
/// descriptive evidence shown to the CCO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegulatorySource {
    /// Official name of the legislative act, e.g.
    /// `"Regulation (EU) 2022/2554"` (DORA),
    /// `"Regulation (EU) 2024/2847"` (CRA).
    pub regulation: String,

    /// Article within the act, e.g. `"Article 6"`, `"Article 28"`.
    /// Free-form string; DORA has sub-sections (§1-2 vs §3) that are
    /// distinguished via `paragraph`.
    pub article: String,

    /// Sub-section within the article, e.g. `"§1"`, `"§1-2"`, `"§3"`.
    /// Empty string is OK when the ruleset covers the whole article.
    pub paragraph: String,

    /// Official URL of the instrument's issuer (allows verifying the
    /// text 7 years later without depending on private mirrors). Must
    /// start with the issuer's official domain per framework —
    /// `https://eur-lex.europa.eu/` for EU frameworks,
    /// `https://www.aicpa-cima.com/` for SOC2 — per
    /// `test_intent_regulatory_source_url_official_is_issuer_official_domain`.
    pub url_official: String,

    /// URLs of additional official guidance (ESA RTS/ITS, ENISA,
    /// DG-CNECT, EBA/ESMA/EIOPA). Each entry must be a verifiable
    /// official EU domain — no regex is enforced over these because
    /// there are multiple legitimate domains (esa.europa.eu,
    /// eba.europa.eu, enisa.europa.eu, ...). Empty is OK when the
    /// article has no secondary guidance.
    pub guidance_refs: Vec<String>,

    /// Open interpretations of the legal text (e.g. Art. 6 §1
    /// "appropriate to their size and overall risk profile") that the
    /// ruleset does NOT encode as hard rules. Documented explicitly so
    /// an auditor knows Seetrex verifies, it does not decide
    /// regulatorily. Empty is OK when the article has a closed
    /// interpretation (e.g. the numeric threshold of Art. 18).
    pub interpretation_caveats: Vec<String>,
}

// ─── strict unknown-key validation ───────────────────────────────────
//
// `Rule`/`Condition` are format-layer types WITHOUT
// `deny_unknown_fields`, and serde does NOT propagate the
// `deny_unknown_fields` of `RulesetFile` to the nested levels: an
// unknown key INSIDE a rule/condition would be accepted and silently
// dropped, the `ruleset_content_hash` would be computed WITHOUT it
// (the JCS re-serialization of the struct loses it), and an
// independent verifier following the spec (which keeps the key from
// the raw JSON) would diverge PASS/FAIL. The fix lives HERE (the
// format-layer types stay untouched): strict validation over the raw
// `serde_json::Value` BEFORE the typed parse, in the TWO canonical
// constructors (`from_json` / `from_json_for_engine`) that ALL
// production parse paths converge on.
//
// **BIDIRECTIONAL table discipline**: each const is the EXACT mirror
// of the serde key set of its struct. If the struct gains/renames/
// loses a field, the table MUST be updated in the SAME PR — in the
// struct→table direction the sweep test
// (`test_intent_all_pinned_rulesets_pass_strict_unknown_key_validation`)
// catches it as soon as a ruleset uses the new field (the outdated
// table would reject it); in the table→struct direction, a key in the
// table the struct does not have would reopen the gap ONLY for that
// key — which is why the tables carry the line-by-line reference to
// the struct they mirror.

/// Keys of `RulesetFile` (this file, above).
const RULESET_FILE_ALLOWED_KEYS: &[&str] = &[
    "ruleset_id",
    "framework",
    "article",
    "control",
    "version",
    "engine_semantic_version_floor",
    "doc",
    "facts_consumed",
    "verdicts_emitted",
    "rules",
    "regulatory_source",
];

/// Keys of `RegulatorySource` (this file, above).
const REGULATORY_SOURCE_ALLOWED_KEYS: &[&str] = &[
    "regulation",
    "article",
    "paragraph",
    "url_official",
    "guidance_refs",
    "interpretation_caveats",
];

/// Keys of `seetrex_format::…::Rule` (format layer, `types.rs` — a
/// struct WITHOUT `deny_unknown_fields`; this mirror is the only
/// barrier).
const RULE_ALLOWED_KEYS: &[&str] = &[
    "id",
    "name",
    "conditions",
    "antecedents",
    "consequent",
    "consequent_value",
    "priority",
    "condition_groups",
];

/// Keys of `seetrex_format::…::Condition` (format layer, `types.rs` —
/// a struct WITHOUT `deny_unknown_fields`; this mirror is the only
/// barrier).
const CONDITION_ALLOWED_KEYS: &[&str] = &[
    "fact_id",
    "operator",
    "value",
    "negated",
];

/// Rejects keys not present in `allowed`, naming the field path.
fn check_object_keys(
    obj: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), String> {
    for k in obj.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("{path}: unknown key '{k}'"));
        }
    }
    Ok(())
}

/// Validates each Condition in an array (`conditions` or an inner
/// group of `condition_groups`).
fn check_condition_array(
    conditions: &[serde_json::Value],
    path_prefix: &str,
) -> Result<(), String> {
    for (j, cond) in conditions.iter().enumerate() {
        let path = format!("{path_prefix}[{j}]");
        let cond_obj = cond
            .as_object()
            .ok_or_else(|| format!("{path}: not a JSON object"))?;
        check_object_keys(cond_obj, CONDITION_ALLOWED_KEYS, &path)?;
    }
    Ok(())
}

/// STRICT unknown-key validation over the raw JSON of a ruleset, at
/// ALL levels: ruleset / rule / condition / condition_groups /
/// regulatory_source. Runs BEFORE the typed parse; it only validates
/// keys — type/required-field errors are still produced by the later
/// serde parse (not duplicated here).
///
/// Closes the "independent verifier diverges from the reference one"
/// class: the public spec (§6.1, closed key set) requires a verifier
/// to reject unknown keys; if the reference one accepted and dropped
/// them, the same `ruleset.json` would PASS here and FAIL there (or
/// vice versa with the anchor).
pub fn validate_ruleset_known_keys(root: &serde_json::Value) -> Result<(), String> {
    let obj = root
        .as_object()
        .ok_or_else(|| "ruleset: root is not a JSON object".to_string())?;
    check_object_keys(obj, RULESET_FILE_ALLOWED_KEYS, "ruleset")?;

    if let Some(rs) = obj.get("regulatory_source") {
        if !rs.is_null() {
            let rs_obj = rs.as_object().ok_or_else(|| {
                "regulatory_source: not a JSON object".to_string()
            })?;
            check_object_keys(rs_obj, REGULATORY_SOURCE_ALLOWED_KEYS, "regulatory_source")?;
        }
    }

    if let Some(rules) = obj.get("rules").and_then(|r| r.as_array()) {
        for (i, rule) in rules.iter().enumerate() {
            let rule_path = format!("rules[{i}]");
            let rule_obj = rule
                .as_object()
                .ok_or_else(|| format!("{rule_path}: not a JSON object"))?;
            check_object_keys(rule_obj, RULE_ALLOWED_KEYS, &rule_path)?;

            if let Some(conds) = rule_obj.get("conditions").and_then(|c| c.as_array()) {
                check_condition_array(conds, &format!("{rule_path}.conditions"))?;
            }
            if let Some(groups) =
                rule_obj.get("condition_groups").and_then(|g| g.as_array())
            {
                for (gi, group) in groups.iter().enumerate() {
                    if let Some(gconds) = group.as_array() {
                        check_condition_array(
                            gconds,
                            &format!("{rule_path}.condition_groups[{gi}]"),
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Failure modes of `RulesetFile::from_json_for_engine`.
#[derive(Debug, Error)]
pub enum RulesetLoadError {
    /// JSON didn't deserialize (malformed, unknown field, missing
    /// required field, type mismatch). The wrapped error keeps
    /// `serde_json`'s line/column diagnostic; the wrapper's
    /// `Display` is short and operator-facing.
    #[error("ruleset JSON parse failed (cause hidden — see #[source])")]
    Parse(#[source] serde_json::Error),

    /// The ruleset declares `engine_semantic_version_floor = floor`
    /// and the runtime is `ENGINE_SEMANTIC_VERSION = current` with
    /// `current < floor`. Evaluating the rules against an
    /// out-of-spec engine would produce verdicts whose semantics
    /// (DNF, negation, confidence aggregation) don't match the
    /// authors' assumptions — fail fast at load time so the caller
    /// surfaces a regulatory-grade error instead of silently
    /// computing the wrong verdict.
    #[error(
        "ruleset {ruleset_id:?} requires ENGINE_SEMANTIC_VERSION >= {floor}; \
         runtime carries {current}"
    )]
    EngineFloorViolated {
        ruleset_id: String,
        floor: u32,
        current: u32,
    },

    /// The JSON carries an unknown key at some level (ruleset/rule/
    /// condition/condition_groups/regulatory_source). The string is
    /// the exact path (e.g. "rules[3].conditions[0]: unknown key
    /// 'foo'"). The Display is EXPLICIT (not "cause hidden"): the
    /// content is a key name + path, not payload — and an operator/
    /// auditor needs the path to fix the artifact. Accept-and-drop in
    /// silence would diverge the anchor against an independent
    /// verifier that follows the spec.
    #[error("ruleset rejected — strict key validation failed: {0}")]
    UnknownKey(String),
}

impl RulesetFile {
    /// Parse a `RulesetFile` from JSON text. Trivial wrapper around
    /// `serde_json::from_str` that gives the call sites a stable
    /// signature so a future format bump can land here without
    /// changing every caller.
    ///
    /// **Prefer `from_json_for_engine`** for the read path that
    /// will hand the rules to the engine (`InferenceEngine`, in the
    /// closed seetrex-core crate). This
    /// raw `from_json` is kept for tests that explicitly want to
    /// observe the JSON layer alone (e.g. parser-conformance,
    /// round-trips) and for CLI inspection commands that do not run
    /// the engine.
    ///
    /// Strict unknown-key validation at EVERY level runs BEFORE the
    /// typed parse (`validate_ruleset_known_keys`) — the format
    /// layer's `Rule`/`Condition` lack `deny_unknown_fields` and serde
    /// does not propagate it, so without this gate a nested unknown
    /// key would be silently dropped and the content anchor would
    /// diverge from any spec-following independent verifier. The error
    /// type stays `serde_json::Error` (via `de::Error::custom`,
    /// message = exact field path) so the many existing call sites
    /// need no change.
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        let value: serde_json::Value = serde_json::from_str(s)?;
        validate_ruleset_known_keys(&value)
            .map_err(<serde_json::Error as serde::de::Error>::custom)?;
        // The typed parse goes over the ORIGINAL STRING, never
        // `from_value(value)` — `serde_json::Value` collapses
        // DUPLICATE keys last-wins BEFORE the walker sees them, and
        // the derived deserializer over text is the one that gives
        // "duplicate field" loud at every level (a duplicated
        // `"rules"` with the attacker payload first would collapse to
        // the original: anchor OK here, FAIL in a strict independent
        // verifier — the silent-divergence class again). The double
        // parse of the text is a trivial load-time cost and it also
        // keeps line/column in type errors.
        serde_json::from_str(s)
    }

    /// Parse a `RulesetFile` AND verify it is safe to evaluate
    /// against an engine at the given `current_engine_version`.
    ///
    /// The canonical site of the floor check is here — any code path
    /// that loads a ruleset to FEED THE ENGINE routes through this
    /// constructor, and the floor invariant is enforced once, not
    /// per-call-site. The API handlers use this too.
    pub fn from_json_for_engine(
        s: &str,
        current_engine_version: u32,
    ) -> Result<Self, RulesetLoadError> {
        // Strict key validation FIRST (typed variant so the path
        // surfaces loud in this constructor's Display; `from_json`
        // carries the same message inside a serde_json::Error).
        let value: serde_json::Value =
            serde_json::from_str(s).map_err(RulesetLoadError::Parse)?;
        validate_ruleset_known_keys(&value).map_err(RulesetLoadError::UnknownKey)?;
        // Typed parse over the ORIGINAL STRING (not `from_value`) —
        // restores the "duplicate field" rejection at every level that
        // `Value` collapses last-wins, and keeps line/column in
        // errors. See the twin comment in `from_json`.
        let ruleset =
            serde_json::from_str::<Self>(s).map_err(RulesetLoadError::Parse)?;
        if current_engine_version < ruleset.engine_semantic_version_floor {
            return Err(RulesetLoadError::EngineFloorViolated {
                ruleset_id: ruleset.ruleset_id,
                floor: ruleset.engine_semantic_version_floor,
                current: current_engine_version,
            });
        }
        Ok(ruleset)
    }
}

/// Content hash of a loaded ruleset: `serde_jcs` canonical form →
/// SHA-256, hex lowercase. This is the SAME formula the service
/// layer's pinned-ruleset hashes are computed with (the pin walker
/// parses the on-disk JSON into `RulesetFile` first, so hashing the
/// in-memory struct here and hashing the disk file there agree by
/// construction).
///
/// Production (not test-only) on purpose: the inference handler
/// persists this value per verdict
/// (`compliance_verdict.ruleset_content_hash`) so an offline replay
/// can anchor the packaged `ruleset.json` cryptographically instead of
/// by id+version alone.
pub fn ruleset_content_hash_hex(ruleset: &RulesetFile) -> Result<String, serde_json::Error> {
    use sha2::{Digest, Sha256};
    let canonical = serde_jcs::to_string(ruleset)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect())
}
