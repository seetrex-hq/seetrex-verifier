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

#[cfg(test)]
mod tests {
    use super::*;

    // ---------------------------------------------------------------
    // Encoding fixtures.
    //
    // Every non-ASCII character below is written as a Rust \u{..}
    // escape, and every JSON \uXXXX escape is built from U+005C
    // (REVERSE SOLIDUS) at runtime. This module's own source is
    // therefore pure ASCII: a fixture about character encoding must not
    // be at the mercy of the encoding an editor saves it in, nor of a
    // tool that "helpfully" rewrites an escape into its character.
    // ---------------------------------------------------------------

    /// Ruleset body with `__DOC__` (top-level `doc`) and `__NAME__`
    /// (nested `rules[0].name`) placeholders, keys in the on-disk order,
    /// indented.
    const TEMPLATE_INDENTED: &str = r#"{
  "ruleset_id": "sprint1-sbom-presence",
  "framework": "Sprint1Demo",
  "article": "1",
  "control": "sbom_presence",
  "version": 1,
  "engine_semantic_version_floor": 4,
  "doc": "__DOC__",
  "facts_consumed": ["sbom.present"],
  "verdicts_emitted": ["SATISFIED"],
  "rules": [
    {
      "id": "sprint1.sbom_present_check",
      "name": "__NAME__",
      "priority": 100,
      "antecedents": [],
      "conditions": [{"fact_id": "sbom.present", "operator": "Eq", "value": true}],
      "consequent": "sprint1.verdict_SATISFIED",
      "consequent_value": "SATISFIED"
    }
  ]
}"#;

    /// The SAME ruleset with the keys in a different order, no
    /// pretty-printing whatsoever, and an EXPLICIT
    /// `"regulatory_source": null`. Absent and null must be the same
    /// ruleset: the field is an `Option` with
    /// `skip_serializing_if = "Option::is_none"`, so a reimplementation
    /// that emits the key as null must still reach our anchor.
    const TEMPLATE_REORDERED_COMPACT_NULL_SOURCE: &str = r#"{"doc":"__DOC__","regulatory_source":null,"rules":[{"id":"sprint1.sbom_present_check","name":"__NAME__","priority":100,"antecedents":[],"conditions":[{"fact_id":"sbom.present","operator":"Eq","value":true}],"consequent":"sprint1.verdict_SATISFIED","consequent_value":"SATISFIED"}],"verdicts_emitted":["SATISFIED"],"facts_consumed":["sbom.present"],"engine_semantic_version_floor":4,"version":1,"control":"sbom_presence","article":"1","framework":"Sprint1Demo","ruleset_id":"sprint1-sbom-presence"}"#;

    /// The anchor every encoding of the fixture must produce.
    ///
    /// This constant is the BEHAVIOURAL half of the test. The equality
    /// assertions alone cannot fail while `ruleset_content_hash_hex`
    /// takes an already-parsed `RulesetFile`: the encoding is destroyed
    /// before the function is entered, so those assertions lock the
    /// ARCHITECTURE, not a computation. The pin DOES fail -- a
    /// `serde_jcs` bump that changes canonical output, a renamed or
    /// added `RulesetFile` field, or a different digest all move it. It
    /// doubles as a conformance vector an independent implementation can
    /// target.
    ///
    /// Regenerate ONLY deliberately: set it to "TBD", run the test, copy
    /// the `left` value from the failure, and say in the PR why the
    /// anchor of an unchanged ruleset moved.
    const PINNED_ANCHOR: &str =
        "0aa002b4f1f32f4f2b864945d10c9fecefe826a917f3393baa33d28d2d198849";

    fn anchor_of(json: &str) -> String {
        let parsed = RulesetFile::from_json(json).expect("fixture parses");
        ruleset_content_hash_hex(&parsed).expect("fixture hashes")
    }

    fn render(template: &str, doc: &str, name: &str) -> String {
        template
            .replacen("__DOC__", doc, 1)
            .replacen("__NAME__", name, 1)
    }

    /// INTENT: `ruleset_content_hash_hex` commits to the ruleset's
    ///         SEMANTICS, never to the bytes of the document that
    ///         carried it. Encodings of one ruleset differing in
    ///         whitespace, key order, \uXXXX escaping of non-ASCII
    ///         (including supplementary-plane characters, which JCS
    ///         escapes as UTF-16 surrogate pairs) and in an absent vs
    ///         explicitly-null optional field MUST all produce the same
    ///         anchor; changing what the ruleset SAYS must move it. This
    ///         is what lets an independent implementation recompute our
    ///         anchor with any conformant JSON library instead of ours
    ///         -- the property the published spec sells.
    ///
    ///         **Scope, stated precisely.** This is a claim about the
    ///         ANCHOR ONLY (`verify-package` STEP 5). It is NOT a claim
    ///         that a re-encoded package still verifies: a package also
    ///         carries `manifest.files_sha256`, deliberately a hash of
    ///         the STORED BYTES, checked at STEP 2 -- before the anchor
    ///         is ever computed. Re-encode a packaged `ruleset.json`
    ///         without recomputing that manifest entry and verification
    ///         fails at STEP 2 by design. Byte-exact storage and
    ///         semantic anchoring are two different guarantees; this
    ///         test locks only the second.
    ///
    /// CONTEXT: an earlier session filed a "canonicalisation divergence"
    ///          -- a legitimate package declared tampered once the em dash
    ///          in `doc` was escaped. A later session reproduced it: the
    ///          harness read the file with the Windows locale encoding
    ///          (cp1252) instead of UTF-8, decoding the three UTF-8
    ///          bytes of U+2014 as three separate characters. That is a
    ///          REAL content change, correctly rejected; no divergence
    ///          existed. The mojibake fixture below is that exact
    ///          corruption, kept as the negative half so this test
    ///          proves both directions at once. The corruption
    ///          round-trips symmetrically -- re-encoding it back THROUGH
    ///          CP1252 restores the original bytes -- which is why the
    ///          harness's own "raw" control looked green while sharing
    ///          the very defect it was meant to catch.
    ///
    /// EXPIRES IF: the anchor stops being JCS-over-the-typed-struct
    ///             (e.g. it moves to hashing stored bytes). That is a
    ///             preimage break requiring a spec bump, and this test
    ///             must be rewritten in the same PR.
    #[test]
    fn test_intent_ruleset_anchor_invariant_under_json_re_encoding() {
        let bs = '\u{5c}'; // U+005C REVERSE SOLIDUS

        // U+2014 EM DASH (BMP) and U+1F600 GRINNING FACE (supplementary
        // plane -- JCS escapes it as the surrogate pair d83d/de00, the
        // case where independent JCS implementations actually diverge).
        let raw_payload = "a \u{2014} b \u{1f600} c";
        let escaped_payload = format!("a {bs}u2014 b {bs}ud83d{bs}ude00 c");
        // The cp1252 corruption: the UTF-8 bytes of U+2014 (e2 80 94) read
        // back through cp1252 as three characters. ONLY the em dash is
        // corrupted, so the inequality below is attributable to it.
        let mojibake_payload =
            "a \u{00e2}\u{20ac}\u{201d} b \u{1f600} c";

        let raw_indented = render(TEMPLATE_INDENTED, raw_payload, raw_payload);
        let escaped_indented =
            render(TEMPLATE_INDENTED, &escaped_payload, &escaped_payload);
        let escaped_compact = render(
            TEMPLATE_REORDERED_COMPACT_NULL_SOURCE,
            &escaped_payload,
            &escaped_payload,
        );
        let mojibake =
            render(TEMPLATE_INDENTED, mojibake_payload, mojibake_payload);

        // Harness guard. A prior session lost two reproduction scripts to
        // exactly this failure mode: a generator that silently produced
        // identical inputs would make every assertion below hold
        // vacuously and report green without testing anything.
        let sources =
            [&raw_indented, &escaped_indented, &escaped_compact, &mojibake];
        for (i, a) in sources.iter().enumerate() {
            for b in sources.iter().skip(i + 1) {
                assert_ne!(
                    a.as_bytes(),
                    b.as_bytes(),
                    "fixtures must be byte-distinct or the invariant is untested"
                );
            }
        }
        // And the escapes must reach the parser AS escapes, not as
        // characters something upstream already resolved.
        assert!(
            escaped_indented.contains(&format!("{bs}ud83d{bs}ude00")),
            "the surrogate-pair escape must survive into the JSON document"
        );

        let anchor = anchor_of(&raw_indented);
        assert_eq!(
            anchor, PINNED_ANCHOR,
            "the anchor of this fixture moved. Nothing about the ruleset \
             changed, so something under it did: a serde_jcs bump, a \
             RulesetFile field added or renamed, a different digest. Every \
             anchor already published moved with it -- treat this as a \
             preimage break, not as a stale constant."
        );
        assert_eq!(
            anchor,
            anchor_of(&escaped_indented),
            "escaping non-ASCII must NOT move the anchor -- a \
             reimplementation whose JSON library escapes by default (e.g. \
             Python's `ensure_ascii=True`) has to reach our hash"
        );
        assert_eq!(
            anchor,
            anchor_of(&escaped_compact),
            "key order, whitespace and an explicitly-null optional field \
             must NOT move the anchor -- the hash is over the JCS form of \
             the parsed struct"
        );
        assert_ne!(
            anchor,
            anchor_of(&mojibake),
            "a REAL change to the text MUST move the anchor -- this is the \
             cp1252 corruption, and rejecting it is correct behaviour"
        );
    }
}
