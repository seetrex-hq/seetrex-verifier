// SPDX-License-Identifier: Apache-2.0
//! `compute_verdict_hash` — the central falsifiability primitive of
//! Seetrex Compliance. A pure function that produces a byte-for-byte
//! reproducible SHA-256 hash over the canonical `VerdictCanonicalInput`
//! via JCS RFC 8785.
//!
//! Regulatory reproducibility (7-year retention): an auditor who
//! recovers the `VerdictCanonicalInput` from the DB (via
//! `compliance_verdict.working_memory_canonical JSONB` + related
//! columns) can recompute this hash with `compute_verdict_hash` and
//! verify it matches the `verdict_hash` persisted in the row —
//! cryptographic proof that the engine produced that verdict over those
//! exact inputs, with no later alteration.
//!
//! Any deterministic engine + JCS + SHA-256 produces the same hash over
//! the same input — verifiable cross-implementation, cross-time,
//! cross-jurisdiction.

use std::collections::{BTreeMap, HashMap, HashSet};

use rust_decimal::Decimal;
use seetrex_format::types::{AuditEntry, Fact, FactValue};
use serde::{
    ser::{SerializeMap, SerializeStruct},
    Serialize, Serializer,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::types::VerdictOutcome;

/// Errors from canonicalizing the verdict input.
///
/// Deliberately does **not** derive `IntoResponse` — this crate carries
/// no HTTP stack. The service layer maps `CanonicalError` into its own
/// API error type (an engine-semantic 500 by design) with a structured
/// internal log; the client receives an opaque response.
///
/// The `Display` hides the cause: an attacker POSTing a payload crafted
/// to fail canonicalization must NOT learn which fact_id or which path
/// inside the List caused it. The internal log preserves the full
/// diagnostic.
#[derive(Debug, Error)]
pub enum CanonicalError {
    /// `FactValue::Number(f64)` is NaN or ±Infinity (RECURSIVE — also
    /// detected inside `FactValue::List`). JCS RFC 8785 mandates these
    /// values are NOT canonicalizable; they are rejected upstream with a
    /// clear diagnostic (fact_id) instead of waiting for serde_jcs to
    /// fail with an opaque error.
    #[error("non-canonical float in fact_id `{0}` (NaN or Infinity)")]
    NonCanonicalFloat(String),

    /// A `working_memory_canonical` key (fact_id) contains non-ASCII
    /// chars. JCS RFC 8785 accepts UTF-8, but the Compliance engine
    /// contract restricts fact_ids to ASCII alphanumerics plus dot
    /// (the same charset as the SQL prefix regex).
    #[error("non-ASCII fact_id `{0}`")]
    NonAsciiFactId(String),

    /// `FactValue::String(s)` contains non-ASCII chars (RECURSIVE
    /// inside List). Same reasoning as NonAsciiFactId.
    #[error("non-ASCII fact value in fact_id `{0}`")]
    NonAsciiFactValue(String),

    /// `serde_jcs::to_string` failed. Cause hidden in `Display` — the
    /// underlying message can echo payload fragments carrying PII.
    #[error("serialization failed (cause hidden)")]
    Serialize(#[source] serde_json::Error),
}

/// Reference to an Evidence consumed by the inference. Part of
/// `VerdictCanonicalInput.evidence_refs` — sorted by content_hash
/// (then by evidence_id as tie-break) so that two requests listing the
/// same evidence_ids in a different order produce the SAME
/// verdict_hash.
/// `Deserialize` is derived so `compliance-cli replay` can parse
/// `evidence_refs` from the reproduction package's `request.json`. The
/// Serialize→JSON→Deserialize round-trip is preserved by the serde
/// symmetry of the `Uuid` + `String` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct EvidenceRef {
    pub evidence_id: Uuid,
    pub content_hash: String,
}

/// Canonical verdict input, **preimage v2** — EVERYTHING that enters
/// the hash. Any field NOT present here (e.g. `inference_time_ms`,
/// `audit_log` timestamps, `verdict_id`, `preimage_version`) does NOT
/// affect the hash.
///
/// **Preimage v2**: the single deliberate `verdict_hash` break that
/// adds TWO fields to the 8-field preimage v1:
///
/// - `derived_at` — the persisted derivation clock (DB column
///   `inferred_at`; the emitter samples `Utc::now()` exactly ONCE and
///   truncates to microseconds). The name differs from the wire/column
///   name on PURPOSE: the column carries the historical name
///   `inferred_at`, while the preimage names the correct concept
///   ("derivation clock"). Mapping: `derived_at` (preimage) ←
///   `inferred_at` (column/wire).
///   Pinned encoding: RFC 3339 UTC with EXACTLY 6 fractional digits
///   and a `Z` suffix (`format_derived_at`) — NEVER `to_rfc3339()`,
///   whose variable precision would diverge the hash between the
///   in-memory value and the DB/package round-trip (systematic
///   false-FAIL). Normative wire→preimage rule: parse and re-format,
///   NEVER copy the wire string.
/// - `ruleset_content_hash` — lowercase hex SHA-256 of the ruleset's
///   JCS form (the same formula as
///   `rulesets::ruleset_content_hash_hex`). With this, the ruleset
///   anchor stops being self-attested (a package field) and becomes
///   committed by the externally anchored hash — a neutral forge of
///   the ruleset dies at the anchor.
///
/// The legacy preimage v1 (8 fields, verdicts emitted before the
/// `preimage_version` column existed) lives in
/// [`VerdictCanonicalInputV1`]; the per-row discriminator is the
/// `preimage_version` column (NULL=1). The v1 and v2 JCS key sets are
/// distinct → the preimage is self-describing by its bytes.
///
/// **`tenant_id` DOES enter the hash.** Without it, two distinct
/// tenants could carry the SAME verdict_hash when everything else
/// coincides — verifiable cross-tenant (one tenant could claim
/// another tenant's verdict). Including tenant_id ties the verdict to
/// its owner.
///
/// **Custom Serialize impl** (instead of derive): it must wrap
/// `FactValue::Money(Decimal)` via `MoneyNormalizingFactValue` so that
/// `1.00` and `1.0` produce the same hash, and serialize `derived_at`
/// with the pinned 6-digit formatter. The remaining variants delegate
/// to the format layer's default Serialize.
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictCanonicalInput {
    pub tenant_id: Uuid,
    pub ruleset_id: String,
    pub ruleset_version: u32,
    pub control_id: String,
    pub verdict_outcome: VerdictOutcome,
    pub evidence_refs: Vec<EvidenceRef>,
    pub engine_semantic_version: u32,
    /// Derivation clock (column/wire `inferred_at`; see the struct
    /// doc). The emitter truncates it to microseconds BEFORE any use;
    /// the serializer encodes it via [`format_derived_at`] (which also
    /// truncates — a value with residual nanos cannot diverge the
    /// hash, only the fact re-derivation; that is why truncation lives
    /// at the emitter).
    pub derived_at: chrono::DateTime<chrono::Utc>,
    /// Cryptographic anchor of the evaluated ruleset (lowercase hex
    /// SHA-256, 64 chars).
    pub ruleset_content_hash: String,
    pub working_memory_canonical: BTreeMap<String, FactValue>,
}

/// Preimage **v1** (LEGACY, 8 fields) — the exact preimage shape of
/// every verdict emitted before the `preimage_version` column existed
/// (`preimage_version` NULL). Verifiers (the weak replay and
/// `replay --full`) branch on `preimage_version` and reconstruct THIS
/// shape for legacy rows — including early real rows that carry a
/// non-NULL anchor with a v1 hash (the finding that motivated the
/// column).
///
/// The EMITTER never builds this shape (it only stamps the current
/// constant): it is a VERIFICATION surface, not an emission one.
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictCanonicalInputV1 {
    pub tenant_id: Uuid,
    pub ruleset_id: String,
    pub ruleset_version: u32,
    pub control_id: String,
    pub verdict_outcome: VerdictOutcome,
    pub evidence_refs: Vec<EvidenceRef>,
    pub engine_semantic_version: u32,
    pub working_memory_canonical: BTreeMap<String, FactValue>,
}

/// The ONE formatter for the derivation clock in the v2 preimage AND
/// on the wire (`verdict.json`/export — wire and preimage are
/// byte-identical; the spec documents ONE format): RFC 3339 UTC with
/// EXACTLY 6 fractional digits and a `Z` suffix, e.g.
/// `2026-07-18T12:00:00.123456Z`.
///
/// Why NOT `to_rfc3339()`: its precision is VARIABLE — an instant
/// whose micros are a multiple of 1000 (e.g. `.123000`) is shortened
/// to `.123`. An auditor building the preimage by copying that string
/// would diverge from the emitter on ~1/1000 of verdicts
/// (probabilistic false-FAIL). chrono's `%.6f` TRUNCATES (does not
/// round) the nanos to 6 digits — matching the emitter's
/// `trunc_subsecs(6)` and sqlx's binary encode (`num_microseconds`,
/// truncation toward zero) for every post-2000 instant.
pub fn format_derived_at(derived_at: &chrono::DateTime<chrono::Utc>) -> String {
    derived_at.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Canonicalize the textual representation of a `Decimal` after
/// `normalize()`: strip trailing zeros from the mantissa, then a
/// trailing dot. This is the platform's canonical Money form — the
/// emitter and every verifier must produce the exact same string, or
/// Money hashes diverge. Cross-impl coherence: if this algorithm ever
/// changes, every consumer pinning it (see the cross-impl coherence
/// tests) must be updated in the same PR.
///
/// Examples:
/// - `"1.00"` → `"1"`
/// - `"1.10"` → `"1.1"`
/// - `"100"` → `"100"` (no '.', unchanged)
/// - `"0.10"` → `"0.1"`
/// - `"-1.00"` → `"-1"`
/// - `"0.0"` → `"0"` (trailing dot also stripped)
fn trim_numeric_string(mut s: String) -> String {
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    s
}

/// Wrapper that serializes a `FactValue` applying `.normalize()` on
/// the Money variant. Without it, `FactValue::Money(Decimal::from_str("1.00").unwrap())`
/// and `FactValue::Money(Decimal::from_str("1.0").unwrap())` would
/// serialize as `"1.00"` vs `"1.0"` (Decimal preserves trailing zeros)
/// → distinct hashes for monetarily identical values.
///
/// The other 7 variants delegate to the format layer's Serialize
/// (which is already canonical: DateTime RFC 3339 Z, NaiveDate ISO
/// 8601, Duration deterministic humantime form via
/// `format_humantime_duration`, etc.).
struct MoneyNormalizingFactValue<'a>(&'a FactValue);

impl<'a> Serialize for MoneyNormalizingFactValue<'a> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            FactValue::Money(d) => {
                // Apply `trim_numeric_string` AFTER `.normalize()`:
                // `Decimal::from_str("1.00").normalize().to_string()`
                // can return `"1.0"` (NOT `"1"`), diverging from the
                // canonical Money form — an auditor reconstructing a
                // Money value from a persisted canonical field would
                // not match verdict_hash. Serialized as a STRING (not
                // f64) to preserve arbitrary precision.
                let normalized: Decimal = d.normalize();
                let trimmed = trim_numeric_string(normalized.to_string());
                ser.serialize_str(&trimmed)
            }
            FactValue::List(items) => {
                // RECURSIVE: each List item is serialized through the
                // same wrapper so Money normalization applies to a
                // FactValue::List containing FactValue::Money.
                //
                // **Item order is load-bearing for the CALLER** — two
                // `FactValue::List(vec![a,b])` vs
                // `FactValue::List(vec![b,a])` produce DIFFERENT
                // hashes. This is implicit in Vec semantics (insertion
                // order); documented here because a future
                // well-intentioned "defensive" sort added in this arm
                // would silently break the hash. Do NOT sort here.
                use serde::ser::SerializeSeq;
                let mut seq = ser.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(&MoneyNormalizingFactValue(item))?;
                }
                seq.end()
            }
            // Boolean, Number, DateTime, Date, Duration, String:
            // delegate to the default Serialize impls of
            // `seetrex_format::types`, which are already canonical:
            // - Number(f64) → JCS RFC 8785 via serde_jcs (NaN/Inf
            //   rejected earlier by validate_canonical; safe here).
            // - DateTime(Utc) → RFC 3339 with Z.
            // - Date(NaiveDate) → ISO 8601 YYYY-MM-DD.
            // - Duration → canonical humantime form (custom serde in
            //   seetrex-format).
            // - String → UTF-8 byte-level (ASCII validated upstream).
            // - Boolean → true/false literal.
            other => other.serialize(ser),
        }
    }
}

/// `working_memory_canonical` wrapper shared by BOTH Serialize impls
/// (v1/v2): a BTreeMap with `MoneyNormalizingFactValue` on the values.
/// The BTreeMap already orders keys lexicographically (Rust
/// invariant); JCS re-orders anyway.
struct WrappedWmMap<'a>(&'a BTreeMap<String, FactValue>);
impl<'a> Serialize for WrappedWmMap<'a> {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        let mut m = ser.serialize_map(Some(self.0.len()))?;
        for (k, v) in self.0 {
            m.serialize_entry(k, &MoneyNormalizingFactValue(v))?;
        }
        m.end()
    }
}

impl Serialize for VerdictCanonicalInput {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // 10 fields (preimage v2). JCS RFC 8785 orders keys
        // lexicographically at serialization time —
        // `serde_jcs::to_string` does the sort for us; this struct
        // only lists the fields in declaration order.
        let mut s = ser.serialize_struct("VerdictCanonicalInput", 10)?;
        s.serialize_field("tenant_id", &self.tenant_id)?;
        s.serialize_field("ruleset_id", &self.ruleset_id)?;
        s.serialize_field("ruleset_version", &self.ruleset_version)?;
        s.serialize_field("control_id", &self.control_id)?;
        s.serialize_field("verdict_outcome", &self.verdict_outcome)?;
        s.serialize_field("evidence_refs", &self.evidence_refs)?;
        s.serialize_field("engine_semantic_version", &self.engine_semantic_version)?;
        // The two v2 preimage fields. `derived_at` ALWAYS goes through
        // the pinned 6-digit formatter (NEVER chrono's serde default,
        // whose precision is variable).
        s.serialize_field("derived_at", &format_derived_at(&self.derived_at))?;
        s.serialize_field("ruleset_content_hash", &self.ruleset_content_hash)?;
        s.serialize_field(
            "working_memory_canonical",
            &WrappedWmMap(&self.working_memory_canonical),
        )?;

        s.end()
    }
}

impl Serialize for VerdictCanonicalInputV1 {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        // 8 fields — byte-identical to the historical v1 preimage.
        // NEVER add fields here: it would change the hash of every
        // legacy verdict already anchored in the public chain.
        let mut s = ser.serialize_struct("VerdictCanonicalInputV1", 8)?;
        s.serialize_field("tenant_id", &self.tenant_id)?;
        s.serialize_field("ruleset_id", &self.ruleset_id)?;
        s.serialize_field("ruleset_version", &self.ruleset_version)?;
        s.serialize_field("control_id", &self.control_id)?;
        s.serialize_field("verdict_outcome", &self.verdict_outcome)?;
        s.serialize_field("evidence_refs", &self.evidence_refs)?;
        s.serialize_field("engine_semantic_version", &self.engine_semantic_version)?;
        s.serialize_field(
            "working_memory_canonical",
            &WrappedWmMap(&self.working_memory_canonical),
        )?;
        s.end()
    }
}

/// Recursive pre-validation of a `FactValue` before invoking
/// `serde_jcs::to_string`. Operator-friendly diagnostic (which fact_id
/// causes the rejection) instead of an opaque serde_jcs error.
///
/// Descends into `FactValue::List` to detect nested NaN/Inf.
/// `serde_jcs::to_string` would also reject them, but its error
/// message does not include the originating fact_id.
fn validate_canonical(value: &FactValue, fact_id: &str) -> Result<(), CanonicalError> {
    match value {
        FactValue::Boolean(_) => Ok(()),
        FactValue::Number(n) => {
            if n.is_nan() || n.is_infinite() {
                Err(CanonicalError::NonCanonicalFloat(fact_id.to_string()))
            } else {
                Ok(())
            }
        }
        FactValue::Money(_) => Ok(()),
        FactValue::DateTime(_) => Ok(()),
        FactValue::Date(_) => Ok(()),
        FactValue::Duration(_) => Ok(()),
        FactValue::String(s) => {
            if !s.is_ascii() {
                Err(CanonicalError::NonAsciiFactValue(fact_id.to_string()))
            } else {
                Ok(())
            }
        }
        FactValue::List(items) => {
            for item in items {
                validate_canonical(item, fact_id)?;
            }
            Ok(())
        }
    }
}

/// Shared validation of the `working_memory_canonical` (pipeline steps
/// 1-2): ASCII fact_ids + recursive `FactValue` checks (NaN/Inf,
/// ASCII). NEVER `assert!` — pure functions return `Result`, they do
/// not panic.
fn validate_wm_canonical(
    wm: &BTreeMap<String, FactValue>,
) -> Result<(), CanonicalError> {
    for k in wm.keys() {
        if !k.is_ascii() {
            return Err(CanonicalError::NonAsciiFactId(k.clone()));
        }
    }
    for (k, v) in wm {
        validate_canonical(v, k)?;
    }
    Ok(())
}

/// Shared defensive sort of `evidence_refs` (step 3): by
/// `content_hash` (lex), tie-break by `evidence_id`. The caller should
/// pass them sorted, but sorting here closes the invariant
/// structurally — two requests with a different order produce the same
/// hash without relying on the caller.
fn sort_evidence_refs(refs: &mut [EvidenceRef]) {
    refs.sort_by(|a, b| {
        a.content_hash
            .cmp(&b.content_hash)
            .then_with(|| a.evidence_id.cmp(&b.evidence_id))
    });
}

/// Shared steps 4-5: JCS RFC 8785 (lexicographic keys, canonical
/// numbers) + SHA-256 over the canonical bytes.
fn jcs_sha256<T: Serialize>(canonical: &T) -> Result<[u8; 32], CanonicalError> {
    let canonical_json =
        serde_jcs::to_string(canonical).map_err(CanonicalError::Serialize)?;
    let mut hasher = Sha256::new();
    hasher.update(canonical_json.as_bytes());
    Ok(hasher.finalize().into())
}

/// Computes the canonical verdict-input hash — **preimage v2** (10
/// fields; the shape EVERY new verdict emits, `preimage_version = 2`).
///
/// Pipeline:
/// 1. Validate that fact_ids (working_memory_canonical keys) are ASCII.
/// 2. Validate each `FactValue` recursively (NaN/Inf in Number/List,
///    ASCII in String/List).
/// 3. Sort `evidence_refs` by `content_hash` (lex), tie-break by
///    `evidence_id` — defense in depth if the caller forgot to sort.
/// 4. Serialize via `serde_jcs::to_string` (JCS RFC 8785).
/// 5. SHA-256 over the canonical JSON bytes.
///
/// Byte-for-byte determinism: two calls with the same input return the
/// same `[u8; 32]`.
///
/// **The clock IS in the preimage**: `derived_at` (column
/// `inferred_at`, the single sample truncated to micros) enters the
/// hash with the pinned 6-digit encoding ([`format_derived_at`]) — a
/// tamper of the derivation clock changes the hash and dies against
/// the external anchor. `ruleset_content_hash` also enters: the
/// ruleset anchor stops being self-attested. Metadata that STAYS out:
/// `verdict_id`, `created_at`, `preimage_version` (an unauthenticated
/// discriminator by design — the v1/v2 JCS key sets differ, so the
/// preimage is self-describing by its bytes; the external anchor is
/// the second layer).
pub fn compute_verdict_hash(input: &VerdictCanonicalInput) -> Result<[u8; 32], CanonicalError> {
    validate_wm_canonical(&input.working_memory_canonical)?;
    let mut canonical = input.clone();
    sort_evidence_refs(&mut canonical.evidence_refs);
    jcs_sha256(&canonical)
}

/// Computes the canonical **preimage v1** hash (LEGACY, 8 fields) —
/// ONLY for VERIFYING verdicts emitted before the `preimage_version`
/// column existed (NULL). Same pipeline as [`compute_verdict_hash`]
/// (shared helpers, zero replication of the canonical discipline); the
/// only difference is the JCS object's key set (no `derived_at` nor
/// `ruleset_content_hash`). The emitter NEVER invokes this function.
pub fn compute_verdict_hash_v1(
    input: &VerdictCanonicalInputV1,
) -> Result<[u8; 32], CanonicalError> {
    validate_wm_canonical(&input.working_memory_canonical)?;
    let mut canonical = input.clone();
    sort_evidence_refs(&mut canonical.evidence_refs);
    jcs_sha256(&canonical)
}

/// Serializes a `BTreeMap<String, FactValue>` to a JCS canonical
/// string applying the `MoneyNormalizingFactValue` wrapper to each
/// value. The same canonical pipeline the custom `Serialize` impl of
/// `VerdictCanonicalInput` uses internally — required so the stored
/// JSONB (`compliance_verdict.working_memory_canonical`) matches
/// byte-for-byte what `compute_verdict_hash` consumed.
///
/// Why the wrapper is load-bearing: applying `serde_jcs::to_string`
/// directly over the `BTreeMap<String, FactValue>` would invoke
/// `FactValue`'s default `Serialize`, which preserves trailing zeros
/// in `FactValue::Money` (Decimal scale). The internal hash via
/// `compute_verdict_hash` uses `WrappedMap` +
/// `MoneyNormalizingFactValue`, which normalizes
/// (`.normalize() + trim_numeric_string`). Result: for verdicts
/// carrying `FactValue::Money`, the stored JSONB and the hash would
/// diverge — an auditor recomputing from the JSONB seven years later
/// would get a hash different from the persisted one.
///
/// The helper CAN be invoked from the service inference path for JSONB
/// persistence without re-implementing `WrappedMap` inline. Single
/// source of truth: the canonical discipline lives here.
///
/// Pure function: no I/O, deterministic.
pub fn serialize_wm_canonical_jcs(
    wm: &BTreeMap<String, FactValue>,
) -> Result<String, CanonicalError> {
    // Local newtype that applies MoneyNormalizingFactValue per entry.
    // Same pattern as `WrappedWmMap` but scoped to this function.
    struct WrappedMap<'a>(&'a BTreeMap<String, FactValue>);
    impl<'a> Serialize for WrappedMap<'a> {
        fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
            let mut m = ser.serialize_map(Some(self.0.len()))?;
            for (k, v) in self.0 {
                m.serialize_entry(k, &MoneyNormalizingFactValue(v))?;
            }
            m.end()
        }
    }
    serde_jcs::to_string(&WrappedMap(wm)).map_err(CanonicalError::Serialize)
}

/// Builds the `working_memory_canonical` that enters
/// `VerdictCanonicalInput.working_memory_canonical` from the engine's
/// raw result (`working_memory: HashMap<String, Fact>` +
/// `audit_log: &[AuditEntry]`).
///
/// Pure, deterministic function.
///
/// **Shape**: filters to ONLY the facts whose id appears in
/// `audit_log.iter().map(|e| e.produced).collect::<HashSet<_>>()` —
/// i.e. facts DERIVED by rules (via `consequent`), NOT request
/// antecedents (client inputs). For each fact_id in that set, inserts
/// `(fact_id, working_memory[fact_id].value.clone())` into the
/// BTreeMap.
///
/// **Discards**:
/// - `Fact.confidence`: deriver metadata (not an input to the hash).
/// - `Fact.id`: redundant (it is the BTreeMap key).
///
/// **Intermediates are included**: ALL facts produced per the
/// audit_log enter, INCLUDING "intermediates" from intermediate rules.
/// Reason: the ruleset author has no "intermediate vs final" marker; a
/// per-rule `expose_to_hash` opt-in remains explicit future work.
/// Documented trade-off: a ruleset refactor that splits one rule into
/// two with an intermediate changes the `verdict_hash` without
/// changing the `outcome` → the `ruleset_version` MUST be bumped when
/// this happens. Without the bump, two ruleset versions produce
/// distinct hashes over the same external inputs — silent drift.
///
/// **Determinism**: BTreeMap guarantees lexicographic key order; the
/// same `(working_memory, audit_log)` → the same BTreeMap
/// byte-for-byte (JCS serialization reorders keys anyway, but the
/// stable order here simplifies debugging).
pub fn build_working_memory_canonical(
    working_memory: &HashMap<String, Fact>,
    audit_log: &[AuditEntry],
) -> BTreeMap<String, FactValue> {
    // (1) Set of fact_ids produced by rules (HashSet O(N) lookup).
    let produced: HashSet<&str> = audit_log.iter().map(|e| e.produced.as_str()).collect();

    // (2) Filter working_memory to those fact_ids; insert (id, value)
    // into the BTreeMap.
    let mut canonical: BTreeMap<String, FactValue> = BTreeMap::new();
    for fact_id in &produced {
        if let Some(fact) = working_memory.get(*fact_id) {
            // Discard confidence + id (the BTreeMap key is the id).
            canonical.insert(fact_id.to_string(), fact.value.clone());
        }
        // If the engine emitted a `produced` that is NOT in
        // working_memory (rare: invariant violation), skip it silently
        // here. The verdict-outcome extraction detects it via
        // MalformedVerdictString when it was a verdict pattern.
    }

    canonical
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use std::str::FromStr;

    /// Deterministic fixture `derived_at`: a fixed instant with
    /// NON-round micros (`.123456`) so the pin exercises the full
    /// 6-digit encoding.
    fn fixture_derived_at() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 18, 12, 0, 0).unwrap()
            + chrono::Duration::microseconds(123_456)
    }

    /// Deterministic synthetic fixture anchor (64 hex lowercase).
    const FIXTURE_RULESET_CONTENT_HASH: &str =
        "cafe0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";

    /// Minimal canonical fixture (preimage v2, 10 fields) — used by
    /// multiple tests.
    fn fixture() -> VerdictCanonicalInput {
        let mut wm = BTreeMap::new();
        wm.insert(
            "sbom.present".to_string(),
            FactValue::Boolean(true),
        );
        wm.insert(
            "sprint1.verdict_SATISFIED".to_string(),
            FactValue::String("SATISFIED".to_string()),
        );
        VerdictCanonicalInput {
            tenant_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            ruleset_id: "sprint1-sbom-presence".to_string(),
            ruleset_version: 1,
            control_id: "sbom_presence".to_string(),
            verdict_outcome: VerdictOutcome::Satisfied,
            evidence_refs: vec![EvidenceRef {
                evidence_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                content_hash:
                    "aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
                        .to_string(),
            }],
            engine_semantic_version: 4,
            derived_at: fixture_derived_at(),
            ruleset_content_hash: FIXTURE_RULESET_CONTENT_HASH.to_string(),
            working_memory_canonical: wm,
        }
    }

    /// INTENT: `compute_verdict_hash` is **byte-for-byte
    ///         deterministic** — two calls with the same input return
    ///         the same hash. Without determinism, the product's
    ///         verification story collapses (an auditor cannot verify
    ///         reproducibility 7 years later).
    /// CONTEXT: the pinned hash is a literal hex value that freezes
    ///          the canonical contract — any change in JCS
    ///          serialization, the FactValue Serialize impl, or the
    ///          struct field order breaks loud.
    /// EXPIRES IF: the fixture changes OR JCS/SHA-256 are replaced by
    ///             another algorithm (regenerate the pin).
    #[test]
    fn test_intent_verdict_hash_pinned_with_fixed_inputs() {
        let input = fixture();
        let hash1 = compute_verdict_hash(&input).unwrap();
        let hash2 = compute_verdict_hash(&input).unwrap();
        assert_eq!(hash1, hash2, "compute_verdict_hash must be deterministic");

        // Pin the LITERAL hex. Without this, a major serde_jcs bump
        // (0.2 → 0.3) that changes internal field ordering, or a PR
        // that renames a struct field, would pass green silently (the
        // deterministic loop above keeps passing — it only verifies
        // that two calls produce the same hash, NOT that the hash is
        // the correct one).
        //
        // 7-year regulatory reproducibility depends on this pin: an
        // auditor recomputing the hash from the DB in 2033 must match
        // this literal exactly.
        //
        // **Regenerate deliberately** if the fixture changes:
        //   1. Temporarily set this const to "TBD".
        //   2. `cargo test test_intent_verdict_hash_pinned_with_fixed_inputs`
        //      → fails with "left=<actual_hex> right=TBD".
        //   3. Copy the `actual_hex` from the error message.
        //   4. Replace the const with the new hex.
        //   5. Re-run the test → pass.
        // This pin covers the v2 preimage (10 fields). It was
        // regenerated at the single deliberate hash break; the
        // previous v1-preimage pin over the same 8 base fields
        // (5fc9ad22…093744) now protects EXPECTED_HEX_V1 below.
        const EXPECTED_HEX: &str =
            "4ec1e30ae5e4460f7bfc805c747e7196e7abc2e94d16be44e75648e9dfb9abaa";

        let hex = hex_encode(&hash1);
        assert_eq!(
            hex.len(),
            64,
            "SHA-256 hex output must be 64 chars, got: {}",
            hex.len()
        );
        assert_eq!(
            hex, EXPECTED_HEX,
            "Hash drift detected — the fixture's canonical output moved \
             from the pin. If the change was DELIBERATE (e.g. fixture \
             bump, JCS struct refactor), update EXPECTED_HEX to the new \
             literal. If NOT, investigate: serde_jcs bump? renamed \
             struct field? changed MoneyNormalizingFactValue arm? The \
             pin protects 7-year regulatory reproducibility."
        );

        // The v1 preimage over the SAME 8 base fields must keep
        // producing the exact HISTORICAL pin (the value this test
        // protected before the deliberate break). This proves the
        // legacy verification path (`compute_verdict_hash_v1`)
        // reproduces byte-for-byte the hashes already anchored in the
        // public chain — the v2 break cannot move the v1 hashes.
        const EXPECTED_HEX_V1: &str =
            "5fc9ad226041b5d918f6e9fe0af36ea99494fd9a0db793c51b0bedb9b7093744";
        let v2 = fixture();
        let v1 = VerdictCanonicalInputV1 {
            tenant_id: v2.tenant_id,
            ruleset_id: v2.ruleset_id,
            ruleset_version: v2.ruleset_version,
            control_id: v2.control_id,
            verdict_outcome: v2.verdict_outcome,
            evidence_refs: v2.evidence_refs,
            engine_semantic_version: v2.engine_semantic_version,
            working_memory_canonical: v2.working_memory_canonical,
        };
        let v1_hex = hex_encode(&compute_verdict_hash_v1(&v1).unwrap());
        assert_eq!(
            v1_hex, EXPECTED_HEX_V1,
            "LEGACY preimage v1 drift — compute_verdict_hash_v1 must \
             reproduce the historical pinned hash byte-for-byte over \
             the same 8 base fields; every already-anchored \
             public-chain verdict depends on it. This pin must NEVER \
             be regenerated."
        );
    }

    /// INTENT: `derived_at` IS in the v2 preimage — a tamper of the
    ///         derivation clock (±1 microsecond is enough) CHANGES the
    ///         `verdict_hash`. This is the deliberate inversion of the
    ///         former guarantee that the hash was independent of the
    ///         clock: "the verdict date is alterable without
    ///         detection" is now closed and tested. The commitment
    ///         granularity is the MICROsecond: a nanoseconds-only
    ///         delta does NOT change the hash (pinned 6-digit
    ///         encoding — the emitter truncates before use, so
    ///         residual nanos never exist in a real verdict).
    /// CONTEXT: preimage v2 added `derived_at` (+
    ///          `ruleset_content_hash`) as the single deliberate hash
    ///          break, executed with zero external consumers.
    /// EXPIRES IF: a preimage v3 changes the encoding or the field
    ///             (regenerate pin + spec in the same PR).
    #[test]
    fn test_intent_derived_at_tampers_verdict_hash() {
        let input = fixture();
        let honest = compute_verdict_hash(&input).unwrap();

        // 1-microsecond tamper → the hash MUST change.
        let mut tampered = input.clone();
        tampered.derived_at += chrono::Duration::microseconds(1);
        let tampered_hash = compute_verdict_hash(&tampered).unwrap();
        assert_ne!(
            honest, tampered_hash,
            "derived_at MUST be committed by the v2 preimage — a 1µs \
             tamper of the derivation clock must change verdict_hash"
        );

        // 1-nanosecond delta → the hash does NOT change (the 6-digit
        // encoding truncates; documents the commitment granularity).
        let mut sub_micro = input.clone();
        sub_micro.derived_at += chrono::Duration::nanoseconds(1);
        let sub_micro_hash = compute_verdict_hash(&sub_micro).unwrap();
        assert_eq!(
            honest, sub_micro_hash,
            "sub-microsecond deltas must NOT change the hash — the \
             pinned encoding is exactly 6 fractional digits (truncating)"
        );
    }

    /// INTENT: DUAL round-trip of the derivation clock — the preimage
    ///         built from the truncated in-memory value is
    ///         byte-identical to the one built from BOTH persistence
    ///         paths: (a) DB (timestamptz = exact epoch-micros) and
    ///         (b) wire (`verdict.json` with VARIABLE-precision RFC
    ///         3339, parsed and RE-formatted — never copied). The
    ///         fixture that bites: micros that are multiples of 1000
    ///         (`.123000`), where `to_rfc3339()` shortens to `.123` —
    ///         without the pinned parse→format rule, ~1/1000 of
    ///         verdicts would false-FAIL probabilistically (a
    ///         long-fuse bomb). Also covers `.000000` (zero
    ///         subseconds) and "rich" micros (`.123456`).
    /// CONTEXT: the export path once used variable-precision
    ///          `to_rfc3339()`; it now uses the SAME pinned formatter.
    ///          Postgres/sqlx truncate to micros on the binary path
    ///          (`num_microseconds`) — same as `trunc_subsecs(6)` and
    ///          `%.6f`: no divergent rounding path exists for a
    ///          legitimate verdict.
    /// EXPIRES IF: the `derived_at` encoding changes (preimage v3) or
    ///             the column stops being timestamptz-micros.
    #[test]
    fn test_intent_derived_at_roundtrip_wire_and_db_paths_byte_identical() {
        use chrono::SubsecRound;

        let base = Utc.with_ymd_and_hms(2026, 7, 18, 12, 0, 0).unwrap();
        // (micros, expected encoding) — the three regimes.
        let cases: &[(i64, &str)] = &[
            (123_000, "2026-07-18T12:00:00.123000Z"), // multiple of 1000: to_rfc3339 would shorten
            (0, "2026-07-18T12:00:00.000000Z"),       // zero subseconds
            (123_456, "2026-07-18T12:00:00.123456Z"), // rich micros
        ];

        for (micros, expected_encoding) in cases {
            // In-memory: the emitter's sample, already truncated.
            let in_memory = (base + chrono::Duration::microseconds(*micros))
                .trunc_subsecs(6);
            let formatted = format_derived_at(&in_memory);
            assert_eq!(
                &formatted, expected_encoding,
                "pinned encoding must be RFC3339 UTC with EXACTLY 6 \
                 fractional digits and Z (micros={micros})"
            );

            // Path (a) DB: timestamptz stores exact epoch-micros.
            let db_roundtrip = chrono::DateTime::<Utc>::from_timestamp_micros(
                in_memory.timestamp_micros(),
            )
            .expect("in-range timestamp");
            assert_eq!(
                format_derived_at(&db_roundtrip),
                formatted,
                "DB round-trip (epoch-micros) must format byte-identical \
                 (micros={micros})"
            );

            // Path (b) wire: the JSON may carry VARIABLE precision
            // (e.g. an old producer using to_rfc3339()). The normative
            // rule is parse and RE-format — never copy the string.
            // `.123000` → to_rfc3339 emits `.123`.
            let wire_variable = in_memory.to_rfc3339();
            let wire_parsed: chrono::DateTime<Utc> = wire_variable
                .parse()
                .expect("variable-precision RFC3339 parses");
            assert_eq!(
                format_derived_at(&wire_parsed),
                formatted,
                "wire round-trip (variable-precision string, parse → \
                 re-format) must be byte-identical (micros={micros}; \
                 wire form was {wire_variable})"
            );

            // And the underlying property: all THREE paths produce the
            // SAME verdict_hash.
            let mut mem_input = fixture();
            mem_input.derived_at = in_memory;
            let mut db_input = fixture();
            db_input.derived_at = db_roundtrip;
            let mut wire_input = fixture();
            wire_input.derived_at = wire_parsed;
            let h_mem = compute_verdict_hash(&mem_input).unwrap();
            let h_db = compute_verdict_hash(&db_input).unwrap();
            let h_wire = compute_verdict_hash(&wire_input).unwrap();
            assert_eq!(h_mem, h_db, "memory vs DB preimage diverged (micros={micros})");
            assert_eq!(h_mem, h_wire, "memory vs wire preimage diverged (micros={micros})");
        }
    }

    /// INTENT: reordering `evidence_refs` PRE-call does not affect the
    ///         hash — `compute_verdict_hash` sorts defensively by
    ///         content_hash.
    /// CONTEXT: two requests listing the same evidences in a different
    ///          order must produce the same hash.
    /// EXPIRES IF: the sort discipline moves entirely to the caller
    ///             (unlikely — defense in depth has zero cost).
    #[test]
    fn test_intent_verdict_hash_invariant_under_evidence_ref_reorder() {
        let mut input1 = fixture();
        input1.evidence_refs = vec![
            EvidenceRef {
                evidence_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                content_hash: "aaaa".to_string() + &"0".repeat(60),
            },
            EvidenceRef {
                evidence_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                content_hash: "bbbb".to_string() + &"0".repeat(60),
            },
        ];
        let mut input2 = input1.clone();
        input2.evidence_refs.reverse(); // now bbbb before aaaa.

        let hash1 = compute_verdict_hash(&input1).unwrap();
        let hash2 = compute_verdict_hash(&input2).unwrap();
        assert_eq!(
            hash1, hash2,
            "evidence_refs order pre-call must not affect hash — \
             compute_verdict_hash sorts defensively"
        );
    }

    /// INTENT: `tenant_id` enters the hash. Without this, two tenants
    ///         with identical verdicts produce the same hash, enabling
    ///         a cross-tenant claim ("this verdict is mine").
    /// CONTEXT: multi-tenant deployment — the hash must bind the
    ///          verdict to its owner.
    /// EXPIRES IF: the architecture is redesigned to single-tenant.
    #[test]
    fn test_intent_verdict_hash_includes_tenant_id() {
        let input1 = fixture();
        let mut input2 = input1.clone();
        input2.tenant_id = Uuid::parse_str("99999999-9999-9999-9999-999999999999").unwrap();

        let hash1 = compute_verdict_hash(&input1).unwrap();
        let hash2 = compute_verdict_hash(&input2).unwrap();
        assert_ne!(
            hash1, hash2,
            "tenant_id MUST be part of verdict hash — without it, \
             cross-tenant verdict claim is possible"
        );
    }

    /// INTENT: NaN or Infinity in `FactValue::Number` → `Err`.
    ///         RECURSIVE inside `FactValue::List`.
    /// CONTEXT: JCS RFC 8785 cannot canonicalize NaN/Infinity.
    /// EXPIRES IF: the contract is deliberately relaxed (unlikely —
    ///             NaN is not canonicalizable).
    #[test]
    fn test_intent_verdict_hash_rejects_nan_infinity_recursive() {
        // Direct NaN.
        let mut input = fixture();
        input.working_memory_canonical.insert(
            "bad.nan".to_string(),
            FactValue::Number(f64::NAN),
        );
        let r = compute_verdict_hash(&input);
        assert!(matches!(r, Err(CanonicalError::NonCanonicalFloat(_))));

        // Direct Infinity.
        let mut input = fixture();
        input.working_memory_canonical.insert(
            "bad.inf".to_string(),
            FactValue::Number(f64::INFINITY),
        );
        let r = compute_verdict_hash(&input);
        assert!(matches!(r, Err(CanonicalError::NonCanonicalFloat(_))));

        // RECURSIVE — NaN inside a List.
        let mut input = fixture();
        input.working_memory_canonical.insert(
            "bad.list_with_nan".to_string(),
            FactValue::List(vec![
                FactValue::Number(1.0),
                FactValue::Number(f64::NAN),
            ]),
        );
        let r = compute_verdict_hash(&input);
        assert!(
            matches!(r, Err(CanonicalError::NonCanonicalFloat(_))),
            "validate_canonical must descend into List recursively"
        );
    }

    /// INTENT: non-ASCII fact_id → `Err` (NOT panic). Pure functions
    ///         NEVER panic — always Result.
    /// CONTEXT: the fact_id charset is ASCII alphanumerics plus dot.
    /// EXPIRES IF: the fact_id charset is deliberately expanded.
    #[test]
    fn test_intent_verdict_hash_rejects_non_ascii_fact_id() {
        let mut input = fixture();
        input.working_memory_canonical.insert(
            "bad.ñ".to_string(), // non-ASCII fact id.
            FactValue::Boolean(true),
        );
        let r = compute_verdict_hash(&input);
        assert!(matches!(r, Err(CanonicalError::NonAsciiFactId(ref id)) if id == "bad.ñ"));
    }

    /// INTENT: canonical f64 via JCS — `1.0_f64`, `1e21`, `0.1+0.2`
    ///         produce canonical representations per RFC 8785.
    /// CONTEXT: number canonicalization is delegated to serde_jcs.
    /// EXPIRES IF: serde_jcs is replaced by another implementation.
    #[test]
    fn test_intent_verdict_hash_f64_canonical_jcs_compliant() {
        // Same f64 values produce the same hash (otherwise JCS would be broken).
        let mut input1 = fixture();
        input1
            .working_memory_canonical
            .insert("n".to_string(), FactValue::Number(1.0));
        let mut input2 = fixture();
        input2.working_memory_canonical.insert(
            "n".to_string(),
            FactValue::Number(0.1 + 0.2), // != 0.3 in IEEE-754
        );

        let h1 = compute_verdict_hash(&input1).unwrap();
        let h2 = compute_verdict_hash(&input2).unwrap();
        // Distinct f64 values produce distinct hashes (sanity check).
        assert_ne!(h1, h2);

        // The same f64 produces the same hash (idempotency).
        let h1b = compute_verdict_hash(&input1).unwrap();
        assert_eq!(h1, h1b);
    }

    /// INTENT: `Money(1.00)`, `Money(1.0)`, `Money(1)` post-normalize+trim
    ///         produce the SAME hash, across 5 equivalence classes —
    ///         without this breadth, a future rust_decimal version
    ///         where `normalize()` retains `"1.0"` (scale=1) would
    ///         pass a simple `1.00 == 1.0` test but break equivalence
    ///         with `Money(1)` (no decimal point).
    /// CONTEXT: cross-implementation coherence with the engine's
    ///          decimal canonicalization. The
    ///          MoneyNormalizingFactValue Money arm applies
    ///          `.normalize() + trim_numeric_string` to match the
    ///          canonical Money form.
    /// EXPIRES IF: the Decimal serde representation changes OR the
    ///             engine's decimal canonicalization changes — update
    ///             both in the same PR.
    #[test]
    fn test_intent_verdict_hash_money_normalizes_decimal() {
        // Equivalence classes: each group must produce the same hash.
        // Every pair within a group is compared.
        let equivalence_classes: &[&[&str]] = &[
            &["1.00", "1.0", "1"],          // positive integer
            &["0.10", "0.1"],                // positive fractional
            &["100.00", "100.0", "100"],    // large integer
            &["-1.00", "-1.0", "-1"],       // negative integer
            &["0.0", "0", "0.00"],          // zero
        ];

        for class in equivalence_classes {
            // Compute the hash for each representation in the class.
            let hashes: Vec<[u8; 32]> = class
                .iter()
                .map(|s| {
                    let mut input = fixture();
                    input.working_memory_canonical.insert(
                        "amount".to_string(),
                        FactValue::Money(Decimal::from_str(s).unwrap()),
                    );
                    compute_verdict_hash(&input).unwrap()
                })
                .collect();

            // All hashes in the class must be equal.
            let first = hashes[0];
            for (i, h) in hashes.iter().enumerate().skip(1) {
                assert_eq!(
                    h, &first,
                    "Money equivalence class {:?}: representation `{}` \
                     (index {}) produces a hash different from `{}` \
                     (index 0). Check trim_numeric_string is applied \
                     correctly.",
                    class, class[i], i, class[0]
                );
            }
        }

        // Sanity: two distinct classes produce distinct hashes.
        let class_a_hash = {
            let mut input = fixture();
            input.working_memory_canonical.insert(
                "amount".to_string(),
                FactValue::Money(Decimal::from_str("1").unwrap()),
            );
            compute_verdict_hash(&input).unwrap()
        };
        let class_b_hash = {
            let mut input = fixture();
            input.working_memory_canonical.insert(
                "amount".to_string(),
                FactValue::Money(Decimal::from_str("0.1").unwrap()),
            );
            compute_verdict_hash(&input).unwrap()
        };
        assert_ne!(
            class_a_hash, class_b_hash,
            "Sanity: Money(1) and Money(0.1) are distinct values → distinct hashes"
        );
    }

    /// INTENT: the `trim_numeric_string` helper strips trailing zeros
    ///         + a trailing dot. Tests the algorithm directly to cover
    ///         edge cases without the compute_verdict_hash overhead.
    /// CONTEXT: cross-implementation coherence of the canonical Money
    ///          form.
    /// EXPIRES IF: the helper changes or is imported from elsewhere.
    #[test]
    fn test_intent_trim_numeric_string_strips_trailing_zeros_and_dot() {
        assert_eq!(trim_numeric_string("1.00".to_string()), "1");
        assert_eq!(trim_numeric_string("1.10".to_string()), "1.1");
        assert_eq!(trim_numeric_string("100".to_string()), "100"); // no '.' → no change
        assert_eq!(trim_numeric_string("0.10".to_string()), "0.1");
        assert_eq!(trim_numeric_string("-1.00".to_string()), "-1");
        assert_eq!(trim_numeric_string("0.0".to_string()), "0");
        // Additional edge cases.
        assert_eq!(trim_numeric_string("123.456".to_string()), "123.456"); // no trailing zeros
        assert_eq!(trim_numeric_string("".to_string()), "");
        assert_eq!(trim_numeric_string("0".to_string()), "0");
    }

    /// INTENT: compile-time exhaustive match over `FactValue` —
    ///         guarantees all 8 variants have documented
    ///         canonicalization. If the format layer adds a 9th
    ///         variant, this match breaks (E0004) and the dev MUST
    ///         decide its canonical form.
    /// CONTEXT: every variant that can enter the hash needs a
    ///          canonical form decided on purpose, not by default.
    /// EXPIRES IF: FactValue is redesigned.
    #[test]
    fn test_intent_verdict_hash_covers_all_factvalue_variants() {
        // Compile-time exhaustive match. If the format layer adds a
        // 9th variant, this code stops compiling — the dev MUST update
        // MoneyNormalizingFactValue + validate_canonical + this match.
        fn _exhaustive(v: FactValue) -> &'static str {
            match v {
                FactValue::Boolean(_) => "Boolean",
                FactValue::Number(_) => "Number",
                FactValue::Money(_) => "Money",
                FactValue::DateTime(_) => "DateTime",
                FactValue::Date(_) => "Date",
                FactValue::Duration(_) => "Duration",
                FactValue::String(_) => "String",
                FactValue::List(_) => "List",
            }
        }
        // 8 documented variants.
        let _ = _exhaustive;
    }

    /// INTENT: struct shape pinned via exhaustive destructuring. If a
    ///         dev adds/renames/removes a VerdictCanonicalInput field,
    ///         the pattern breaks (E0027).
    /// CONTEXT: the preimage field set is a wire-level contract.
    /// EXPIRES IF: the canonical shape is deliberately redesigned.
    #[test]
    fn test_intent_verdict_canonical_input_struct_fingerprint_pinned() {
        let input = fixture();
        // Preimage v2: exactly 10 fields.
        let VerdictCanonicalInput {
            tenant_id,
            ruleset_id,
            ruleset_version,
            control_id,
            verdict_outcome,
            evidence_refs,
            engine_semantic_version,
            derived_at,
            ruleset_content_hash,
            working_memory_canonical,
        } = input;
        let _ = (
            tenant_id,
            ruleset_id,
            ruleset_version,
            control_id,
            verdict_outcome,
            evidence_refs,
            engine_semantic_version,
            derived_at,
            ruleset_content_hash,
            working_memory_canonical,
        );

        // Preimage v1 (legacy): exactly 8 fields — frozen forever
        // (verification of legacy verdicts).
        let v1 = VerdictCanonicalInputV1 {
            tenant_id: Uuid::nil(),
            ruleset_id: String::new(),
            ruleset_version: 0,
            control_id: String::new(),
            verdict_outcome: VerdictOutcome::Satisfied,
            evidence_refs: Vec::new(),
            engine_semantic_version: 0,
            working_memory_canonical: BTreeMap::new(),
        };
        let VerdictCanonicalInputV1 {
            tenant_id: _,
            ruleset_id: _,
            ruleset_version: _,
            control_id: _,
            verdict_outcome: _,
            evidence_refs: _,
            engine_semantic_version: _,
            working_memory_canonical: _,
        } = v1;
    }

    /// INTENT: `FactValue::DateTime` only accepts UTC. The type
    ///         enforces `DateTime<Utc>` (compile-time) — this test
    ///         documents the UTC-only contract so a future PR that
    ///         switches to `DateTime<FixedOffset>` breaks loud (does
    ///         not compile; this test stops being valid).
    /// CONTEXT: canonical timestamps are UTC with a Z suffix.
    /// EXPIRES IF: the FactValue::DateTime type changes.
    #[test]
    fn test_intent_verdict_hash_datetime_rejects_non_utc() {
        // Compile-time check: the variant is `DateTime(DateTime<Utc>)`.
        // Without Utc, this code does not compile.
        let dt: chrono::DateTime<Utc> = Utc.with_ymd_and_hms(2026, 6, 22, 15, 30, 0).unwrap();
        let _value = FactValue::DateTime(dt);
        // If a dev changes it to
        // FactValue::DateTime(DateTime<chrono::FixedOffset>), the
        // annotated `let dt: DateTime<Utc>` stops compiling — fail
        // loud.
    }

    /// INTENT: the hash changes when a working_memory key changes
    ///         (sanity check that ALL the content enters the hash).
    /// CONTEXT: the working memory is the core of the preimage.
    /// EXPIRES IF: working_memory stops entering the hash (unlikely).
    #[test]
    fn test_intent_verdict_hash_includes_working_memory_canonical() {
        let input1 = fixture();
        let mut input2 = input1.clone();
        input2.working_memory_canonical.insert(
            "extra.fact".to_string(),
            FactValue::Boolean(false),
        );
        let h1 = compute_verdict_hash(&input1).unwrap();
        let h2 = compute_verdict_hash(&input2).unwrap();
        assert_ne!(h1, h2, "working_memory_canonical MUST be part of hash");
    }

    /// Helper to convert a [u8; 32] into a hex string in tests.
    fn hex_encode(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Tests for build_working_memory_canonical.

    /// Builds a minimal AuditEntry with the given `produced`.
    fn audit_entry_producing(produced: &str) -> AuditEntry {
        AuditEntry {
            timestamp: 0,
            rule_id: "test".to_string(),
            rule_name: "test".to_string(),
            triggered_by: Vec::new(),
            produced: produced.to_string(),
        }
    }

    /// Builds a Fact with the given value and an arbitrary confidence
    /// (to verify that confidence is discarded).
    fn fact_with_confidence(id: &str, value: FactValue, conf: f64) -> (String, Fact) {
        (
            id.to_string(),
            Fact {
                id: id.to_string(),
                value,
                confidence: conf,
            },
        )
    }

    /// INTENT: `build_working_memory_canonical` filters out facts
    ///         whose id does NOT appear in `audit_log.produced`. Those
    ///         facts are request antecedents (client inputs, NOT
    ///         rule-derived) and must not enter the canonical hash —
    ///         if they did, the hash would leak the raw input (which
    ///         is not the regulatory property the verdict_hash
    ///         certifies).
    /// CONTEXT: the canonical/raw separation is a preimage invariant.
    /// EXPIRES IF: the canonical contract changes to include
    ///             antecedents (not recommended).
    #[test]
    fn test_intent_working_memory_canonical_excludes_antecedent_facts() {
        // 3 facts in working_memory; only 2 produced by rules.
        let wm: HashMap<String, Fact> = [
            fact_with_confidence(
                "sbom.present",
                FactValue::Boolean(true),
                1.0,
            ), // request antecedent — must NOT enter.
            fact_with_confidence(
                "rule1.verdict_SATISFIED",
                FactValue::String("SATISFIED".to_string()),
                1.0,
            ), // produced — MUST enter.
            fact_with_confidence(
                "rule1.intermediate_flag",
                FactValue::Boolean(false),
                0.5,
            ), // produced intermediate — MUST enter (intermediates are included by contract).
        ]
        .into();

        // audit_log lists only the 2 rule-produced facts.
        let log = vec![
            audit_entry_producing("rule1.verdict_SATISFIED"),
            audit_entry_producing("rule1.intermediate_flag"),
        ];

        let canonical = build_working_memory_canonical(&wm, &log);

        assert_eq!(canonical.len(), 2, "canonical must include only produced facts");
        assert!(canonical.contains_key("rule1.verdict_SATISFIED"));
        assert!(canonical.contains_key("rule1.intermediate_flag"));
        assert!(
            !canonical.contains_key("sbom.present"),
            "antecedent `sbom.present` NO must enter canonical \
             (it's a request input, not a derived fact)"
        );
    }

    /// INTENT: `build_working_memory_canonical` discards
    ///         `Fact.confidence` — only the `FactValue` enters the
    ///         BTreeMap. Confidence is deriver metadata (the fact's
    ///         probability/uncertainty) that must not affect the
    ///         verdict_hash; two engines with different confidence
    ///         computation (but producing the same FactValue) must
    ///         generate the same hash.
    /// CONTEXT: the hash certifies derived values, not deriver
    ///          metadata.
    /// EXPIRES IF: the canonical hash starts depending on confidence
    ///             (unlikely — confidence is derivative).
    #[test]
    fn test_intent_working_memory_canonical_excludes_confidence() {
        // Same FactValue + DIFFERENT confidence → same BTreeMap.
        let wm1: HashMap<String, Fact> = [fact_with_confidence(
            "rule.produced",
            FactValue::Boolean(true),
            0.5,
        )]
        .into();
        let wm2: HashMap<String, Fact> = [fact_with_confidence(
            "rule.produced",
            FactValue::Boolean(true),
            0.99,
        )]
        .into();
        let log = vec![audit_entry_producing("rule.produced")];

        let c1 = build_working_memory_canonical(&wm1, &log);
        let c2 = build_working_memory_canonical(&wm2, &log);
        assert_eq!(
            c1, c2,
            "confidence must NOT affect canonical — distinct confidence \
             same FactValue → same BTreeMap"
        );

        // Sanity: the BTreeMap value is the FactValue, NOT a struct with confidence.
        let value = c1.get("rule.produced").unwrap();
        assert!(matches!(value, FactValue::Boolean(true)));
    }

    /// INTENT: the output is deterministic — the same
    ///         `(working_memory, audit_log)` produces the SAME
    ///         BTreeMap byte-for-byte. BTreeMap guarantees
    ///         lexicographic key order (Rust invariant); the HashMap
    ///         iterator is non-deterministic but the filter + collect
    ///         into a BTreeMap normalizes the order.
    /// CONTEXT: prerequisite of `compute_verdict_hash`, which
    ///          serializes the BTreeMap via JCS (which also orders
    ///          keys); the determinism here simplifies debugging.
    /// EXPIRES IF: BTreeMap changes its iteration order (not
    ///             foreseen).
    #[test]
    fn test_intent_working_memory_canonical_deterministic_order() {
        // 5 facts produced in NON-lex order.
        let wm: HashMap<String, Fact> = [
            fact_with_confidence("z.produced", FactValue::Boolean(true), 1.0),
            fact_with_confidence("a.produced", FactValue::Number(1.0), 1.0),
            fact_with_confidence("m.produced", FactValue::String("foo".to_string()), 1.0),
            fact_with_confidence("b.produced", FactValue::Boolean(false), 1.0),
            fact_with_confidence("k.produced", FactValue::Number(2.0), 1.0),
        ]
        .into();
        let log = vec![
            audit_entry_producing("z.produced"),
            audit_entry_producing("a.produced"),
            audit_entry_producing("m.produced"),
            audit_entry_producing("b.produced"),
            audit_entry_producing("k.produced"),
        ];

        // Build N times; all outputs must be equal.
        let c1 = build_working_memory_canonical(&wm, &log);
        let c2 = build_working_memory_canonical(&wm, &log);
        let c3 = build_working_memory_canonical(&wm, &log);
        assert_eq!(c1, c2);
        assert_eq!(c2, c3);

        // Sanity: keys in lex order (BTreeMap invariant).
        let keys: Vec<&String> = c1.keys().collect();
        assert_eq!(
            keys,
            vec!["a.produced", "b.produced", "k.produced", "m.produced", "z.produced"]
        );
    }

    /// INTENT: `serialize_wm_canonical_jcs` applies the
    ///         `MoneyNormalizingFactValue` wrapper to each entry —
    ///         `Money(1.00)` and `Money(1)` produce the SAME JCS
    ///         string (after normalize + trim). Without the wrapper,
    ///         the stored JSONB would diverge from the internal hash
    ///         computed via `compute_verdict_hash`.
    /// CONTEXT: structural closure of byte-for-byte JSONB↔hash
    ///          fidelity on the JSONB path. The pure function is
    ///          invoked by the service inference path before the
    ///          INSERT into
    ///          `compliance_verdict.working_memory_canonical`.
    /// EXPIRES IF: the canonical Money contract changes (i.e. the
    ///             wrapper stops applying normalize+trim).
    #[test]
    fn test_intent_serialize_wm_canonical_jcs_applies_money_normalization() {
        // Money equivalence classes: each group must produce the same
        // JCS output (after normalize + trim).
        let cases: &[(&str, &str)] = &[
            // (Money input string, expected normalized literal in JCS)
            ("1.00", "\"1\""),
            ("1.0", "\"1\""),
            ("1", "\"1\""),
            ("0.10", "\"0.1\""),
            ("100.0", "\"100\""),
            ("-1.00", "\"-1\""),
            ("0.0", "\"0\""),
        ];

        for (input, expected_money_literal) in cases {
            let mut wm = BTreeMap::new();
            wm.insert(
                "amount".to_string(),
                FactValue::Money(Decimal::from_str(input).unwrap()),
            );
            let jcs = serialize_wm_canonical_jcs(&wm).unwrap();
            assert!(
                jcs.contains(expected_money_literal),
                "Money({input}) should normalize to {expected_money_literal} in JCS output; got: {jcs}"
            );
        }

        // Sanity: two equivalent Money values produce the SAME JCS
        // string byte-for-byte.
        let mut wm1 = BTreeMap::new();
        wm1.insert(
            "a".to_string(),
            FactValue::Money(Decimal::from_str("1.00").unwrap()),
        );
        let mut wm2 = BTreeMap::new();
        wm2.insert("a".to_string(), FactValue::Money(Decimal::from_str("1").unwrap()));
        let jcs1 = serialize_wm_canonical_jcs(&wm1).unwrap();
        let jcs2 = serialize_wm_canonical_jcs(&wm2).unwrap();
        assert_eq!(
            jcs1, jcs2,
            "Money(1.00) and Money(1) should produce IDENTICAL JCS bytes"
        );
    }

    /// INTENT: `serialize_wm_canonical_jcs(wm)` is DETERMINISTIC (two
    ///         consecutive invocations produce identical bytes) AND
    ///         its output parses as a valid JSON object via
    ///         `serde_json::from_str` — a prerequisite for the sqlx
    ///         JSONB bind. **This test does NOT execute the full
    ///         end-to-end round-trip** (fetch the JSONB from the DB →
    ///         rebuild `VerdictCanonicalInput` →
    ///         `compute_verdict_hash` → match the persisted
    ///         `verdict_hash`); that round-trip requires a real
    ///         Postgres and lives as a service-layer integration test.
    /// CONTEXT: the structural property (Money normalization on the
    ///          JCS path) is covered here; end-to-end JSONB↔hash
    ///          fidelity is delegated to the DB integration test.
    /// EXPIRES IF: the JSONB↔hash pipeline is redesigned (unlikely).
    #[test]
    fn test_intent_serialize_wm_canonical_jcs_roundtrip_preserves_bytes() {
        let mut wm = BTreeMap::new();
        wm.insert("a.bool".to_string(), FactValue::Boolean(true));
        wm.insert("b.string".to_string(), FactValue::String("hello".to_string()));
        wm.insert(
            "c.money".to_string(),
            FactValue::Money(Decimal::from_str("99.00").unwrap()),
        );
        wm.insert("d.num".to_string(), FactValue::Number(42.0));

        let jcs1 = serialize_wm_canonical_jcs(&wm).unwrap();
        let jcs2 = serialize_wm_canonical_jcs(&wm).unwrap();
        assert_eq!(jcs1, jcs2, "deterministic byte-by-byte");

        // Round-trip via serde_json::Value (simulates JSONB storage).
        let value: serde_json::Value =
            serde_json::from_str(&jcs1).expect("JCS string parses as JSON");
        // Re-serialize via serde_json::to_string (NOT JCS) — Postgres
        // JSONB normalizes on disk; on read-back via sqlx, the text is
        // the same object. For an auditor to recompute the hash, they
        // must re-construct the `VerdictCanonicalInput` from this
        // Value and invoke `compute_verdict_hash` — that applies the
        // JCS wrapper AGAIN, producing identical bytes.
        let _shape: serde_json::Map<String, serde_json::Value> =
            value.as_object().expect("object").clone();
    }

    /// INTENT: empty audit_log → empty BTreeMap. Happy-path edge case
    ///         (no rules fired, nothing in canonical).
    /// CONTEXT: robustness of the canonical builder.
    /// EXPIRES IF: the contract changes (unlikely).
    #[test]
    fn test_intent_working_memory_canonical_empty_audit_log_returns_empty() {
        let wm: HashMap<String, Fact> = [fact_with_confidence(
            "antecedent.fact",
            FactValue::Boolean(true),
            1.0,
        )]
        .into();
        let log: Vec<AuditEntry> = Vec::new();
        let canonical = build_working_memory_canonical(&wm, &log);
        assert!(canonical.is_empty(), "empty audit_log → empty canonical");
    }
}
