// SPDX-License-Identifier: Apache-2.0
//! Public chain export — parsing and OFFLINE verification.
//!
//! The public artifact of the Trust Center is a tenant's audit chain as
//! **hashes + non-payload metadata only** (spec `SPEC_VERDICT_PACKAGE_V1.md`
//! §8.1): an auditor downloads the tenant's `<slug>-chain.json` and
//! recomputes every SHA-256 link OFFLINE with [`parse_and_verify_package`]
//! — no database, no network, no vendor involvement.
//!
//! Extracted from the closed service crate (which re-exports these items,
//! keeping its DB fetch paths private): the auditor compiles the SAME
//! verification code the reference CLI runs — not a replica.
//!
//! Hard redaction property of the format itself: NO evidence payload field
//! (`canonical_inline`, blob keys, working memory, evidence refs) ever
//! appears in this export — the row is a closed 8-field allowlist, pinned
//! by `test_intent_public_chain_export_has_no_payload_fields`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::chain::compute_chain_hash;

/// Version of the public chain export schema. Bump = new reviewed
/// allowlist + verify dispatch.
pub const PUBLIC_CHAIN_SCHEMA_VERSION: &str = "1.0";

/// One PUBLIC row of the tenant audit chain — the closed 8-field
/// allowlist (§8.1). Hashes are commitments over the evidence; the
/// evidence itself NEVER appears here.
///
/// Three data classes. The public verify page declares the split
/// between the reproducible and the self-attested ones:
/// - `verdict_hash`/`chain_prev_hash`/`chain_hash`: reproducible
///   offline by the auditor (this module's [`verify_public_chain`]).
/// - `ruleset_id`/`verdict_outcome`: self-attested here, but
///   committed inside `verdict_hash` — recomputable from the
///   verdict's PACKAGE, which this export does not carry.
/// - `verdict_id`/`appended_at`: committed NOWHERE. Inputs neither
///   to the chain link nor to `VerdictCanonicalInput` (v1 or v2),
///   so no artifact we publish binds them.
/// `ordinal` is hashed nowhere either, but is not free: this module
/// requires it contiguous 1..=N. That contiguity is internal to the
/// file you hold; it does not pin N against a shorter file, so
/// truncation from the end verifies — `verify_public_chain` returns
/// `verdict_count` = the rows PRESENT, not a claimed total.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicChainRow {
    /// 1-based position in append order (spec §8.1).
    pub ordinal: u32,
    pub verdict_id: Uuid,
    /// SHA-256 (hex lowercase) of the verdict canonical input.
    pub verdict_hash: String,
    /// `chain_hash` of the previous row; `None` for genesis.
    pub chain_prev_hash: Option<String>,
    /// `SHA256(chain_prev_hash || verdict_hash)` per
    /// [`compute_chain_hash`] (single source of truth).
    pub chain_hash: String,
    pub appended_at: DateTime<Utc>,
    pub ruleset_id: String,
    pub verdict_outcome: String,
}

/// The public export envelope: `{schema_version, chain}` — nothing else.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicChainExport {
    pub schema_version: String,
    pub chain: Vec<PublicChainRow>,
}

impl PublicChainExport {
    pub fn new(chain: Vec<PublicChainRow>) -> Self {
        Self {
            schema_version: PUBLIC_CHAIN_SCHEMA_VERSION.to_string(),
            chain,
        }
    }
}

/// Verified head of a public chain package: the two values the auditor
/// compares against the public page.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainHead {
    pub last_chain_hash: String,
    pub verdict_count: u32,
}

/// Failure modes of the OFFLINE package verification. Every variant is
/// fail-loud with the ordinal where the chain broke — mirroring the
/// reference verify-chain diagnostics.
///
/// Display texts interpolate FILE-CONTROLLED strings (a hostile export
/// controls every hash field), so every such value is rendered with the
/// `Debug` formatter — control bytes (ESC, newlines) come out escaped,
/// never raw, and cannot forge or mangle terminal output.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainPackageError {
    /// Zero rows — "head of nothing" is not a verifiable claim.
    Empty,
    /// Genesis row (ordinal 1) carries a `chain_prev_hash`.
    GenesisHasPrev { declared: String },
    /// `row[i].chain_prev_hash` does not match `row[i-1].chain_hash`
    /// (or is None on a non-genesis row) — history rewritten between
    /// two rows.
    LinkSevered {
        ordinal: u32,
        declared: Option<String>,
        expected: String,
    },
    /// Recomputing `SHA256(prev || verdict_hash)` does not reproduce
    /// the row's own `chain_hash`.
    RowInconsistent {
        ordinal: u32,
        persisted: String,
        recomputed: String,
    },
    /// Ordinals are not contiguous 1..=N in order.
    OrdinalMismatch { expected: u32, found: u32 },
}

impl std::fmt::Display for ChainPackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainPackageError::Empty => {
                write!(f, "package contains ZERO chain rows — nothing to verify")
            }
            ChainPackageError::GenesisHasPrev { declared } => write!(
                f,
                "CHAIN BROKEN at ordinal 1: genesis row must have chain_prev_hash = null, \
                 got {declared:?}"
            ),
            ChainPackageError::LinkSevered {
                ordinal,
                declared,
                expected,
            } => write!(
                f,
                "CHAIN BROKEN at ordinal {ordinal}: chain_prev_hash declared in this row \
                 ({declared:?}) does NOT match the chain_hash of the previous row \
                 ({expected:?}) — the link is severed"
            ),
            ChainPackageError::RowInconsistent {
                ordinal,
                persisted,
                recomputed,
            } => write!(
                f,
                "CHAIN BROKEN at ordinal {ordinal}: per-row self-consistency violated \
                 (persisted chain_hash {persisted:?}, recomputed {recomputed})"
            ),
            ChainPackageError::OrdinalMismatch { expected, found } => write!(
                f,
                "MALFORMED package: expected ordinal {expected}, found {found} — \
                 ordinals must be contiguous 1..=N"
            ),
        }
    }
}

impl std::error::Error for ChainPackageError {}

/// Verify a public chain package OFFLINE: recompute every SHA-256 link
/// with the production algorithm and return the head the auditor
/// compares against the page. No DB, no network.
pub fn verify_public_chain(rows: &[PublicChainRow]) -> Result<ChainHead, ChainPackageError> {
    if rows.is_empty() {
        return Err(ChainPackageError::Empty);
    }

    let mut previous_chain_hash: Option<&str> = None;
    for (idx, row) in rows.iter().enumerate() {
        let expected_ordinal = (idx + 1) as u32;
        if row.ordinal != expected_ordinal {
            return Err(ChainPackageError::OrdinalMismatch {
                expected: expected_ordinal,
                found: row.ordinal,
            });
        }

        // Cross-row linkage BEFORE per-row self-consistency (a row can be
        // self-consistent while its link to the previous row is severed).
        match (idx, row.chain_prev_hash.as_deref(), previous_chain_hash) {
            (0, None, _) => {}
            (0, Some(declared), _) => {
                return Err(ChainPackageError::GenesisHasPrev {
                    declared: declared.to_string(),
                })
            }
            (_, declared, Some(prev_real)) if declared != Some(prev_real) => {
                return Err(ChainPackageError::LinkSevered {
                    ordinal: row.ordinal,
                    declared: declared.map(str::to_string),
                    expected: prev_real.to_string(),
                });
            }
            _ => {}
        }

        // Per-row self-consistency via the single source of truth.
        let recomputed = compute_chain_hash(row.chain_prev_hash.as_deref(), &row.verdict_hash);
        if recomputed != row.chain_hash {
            return Err(ChainPackageError::RowInconsistent {
                ordinal: row.ordinal,
                persisted: row.chain_hash.clone(),
                recomputed,
            });
        }

        previous_chain_hash = Some(row.chain_hash.as_str());
    }

    Ok(ChainHead {
        last_chain_hash: rows
            .last()
            .expect("non-empty checked above")
            .chain_hash
            .clone(),
        verdict_count: rows.len() as u32,
    })
}

/// Failure modes of parsing an auditor-supplied package file.
#[derive(Debug)]
pub enum PackageParseError {
    /// Not valid JSON, or JSON that does not match the envelope
    /// (including unknown fields — `deny_unknown_fields`).
    Malformed { detail: String },
    /// The package declares a schema_version this verifier does not
    /// implement — fail loud BEFORE any hash work.
    UnsupportedSchemaVersion { found: String },
}

impl std::fmt::Display for PackageParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageParseError::Malformed { detail } => {
                write!(f, "package is not a valid public chain export: {detail}")
            }
            PackageParseError::UnsupportedSchemaVersion { found } => write!(
                f,
                "package schema_version {found:?} is not supported by this verifier \
                 (supported: {PUBLIC_CHAIN_SCHEMA_VERSION}) — upgrade your verifier \
                 tooling"
            ),
        }
    }
}

impl std::error::Error for PackageParseError {}

/// Errors surfaced by [`parse_and_verify_package`]: parse-level or
/// chain-level, both fail-loud.
#[derive(Debug)]
pub enum PackageVerifyError {
    Parse(PackageParseError),
    Chain(ChainPackageError),
}

impl std::fmt::Display for PackageVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackageVerifyError::Parse(e) => e.fmt(f),
            PackageVerifyError::Chain(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for PackageVerifyError {}

impl From<PackageParseError> for PackageVerifyError {
    fn from(e: PackageParseError) -> Self {
        PackageVerifyError::Parse(e)
    }
}

/// Parse an auditor-supplied package (the downloaded `<slug>-chain.json`)
/// and verify it OFFLINE. This is the pure core the `verify-chain`
/// CLI surfaces are thin wrappers over — no DB, no network.
pub fn parse_and_verify_package(raw: &str) -> Result<ChainHead, PackageVerifyError> {
    let export: PublicChainExport =
        serde_json::from_str(raw).map_err(|e| PackageParseError::Malformed {
            detail: format!("json deserialize failed at line {} col {}", e.line(), e.column()),
        })?;
    if export.schema_version != PUBLIC_CHAIN_SCHEMA_VERSION {
        return Err(PackageParseError::UnsupportedSchemaVersion {
            found: export.schema_version,
        }
        .into());
    }
    verify_public_chain(&export.chain).map_err(PackageVerifyError::Chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn sample_row(ordinal: u32, prev: Option<&str>) -> PublicChainRow {
        let verdict_hash = format!("{ordinal:064x}");
        let chain_hash = compute_chain_hash(prev, &verdict_hash);
        PublicChainRow {
            ordinal,
            verdict_id: Uuid::nil(),
            verdict_hash,
            chain_prev_hash: prev.map(str::to_string),
            chain_hash,
            appended_at: Utc.with_ymd_and_hms(2026, 7, 9, 12, 0, 0).unwrap(),
            ruleset_id: "demo-sbom-presence".to_string(),
            verdict_outcome: "SATISFIED".to_string(),
        }
    }

    /// Build a VALID n-row chain via the production hash algorithm.
    fn valid_chain(n: u32) -> Vec<PublicChainRow> {
        let mut rows = Vec::with_capacity(n as usize);
        let mut prev: Option<String> = None;
        for ordinal in 1..=n {
            let row = sample_row(ordinal, prev.as_deref());
            prev = Some(row.chain_hash.clone());
            rows.push(row);
        }
        rows
    }

    /// INTENT: the public chain export contains EXACTLY the 8 allowlisted
    ///         fields per row — hashes + non-payload metadata — and the
    ///         envelope EXACTLY {schema_version, chain}. Any new field is
    ///         a REVIEWED decision, never an accident: an evidence payload
    ///         field leaking here would publish tenant material on the
    ///         public page.
    /// CONTEXT: the export row allowlist is part of the public format
    ///          contract (§8.1) an independent verifier relies on.
    /// EXPIRES IF: the export schema is versioned up (schema_version 2.x)
    ///             with its own reviewed allowlist.
    #[test]
    fn test_intent_public_chain_export_has_no_payload_fields() {
        let export = PublicChainExport::new(valid_chain(1));
        let value = serde_json::to_value(&export).expect("serializable");

        let envelope_keys: Vec<&str> = value
            .as_object()
            .expect("envelope is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            envelope_keys,
            vec!["chain", "schema_version"],
            "envelope allowlist violated (BTreeMap-sorted keys expected)"
        );

        let row = &value["chain"][0];
        let mut row_keys: Vec<&str> = row
            .as_object()
            .expect("row is an object")
            .keys()
            .map(String::as_str)
            .collect();
        row_keys.sort_unstable();
        assert_eq!(
            row_keys,
            vec![
                "appended_at",
                "chain_hash",
                "chain_prev_hash",
                "ordinal",
                "ruleset_id",
                "verdict_hash",
                "verdict_id",
                "verdict_outcome",
            ],
            "public chain row allowlist violated — a field was added or \
             renamed without a reviewed decision"
        );
    }

    /// INTENT: offline verification recomputes every link with the
    ///         PRODUCTION algorithm (`compute_chain_hash`, single source
    ///         of truth) and reports head + count — the two values the
    ///         auditor compares against the public page.
    /// CONTEXT: the self-service audit cycle must actually exist offline.
    /// EXPIRES IF: the chain hash algorithm is versioned (then verify
    ///             must dispatch per schema_version).
    #[test]
    fn test_intent_verify_public_chain_happy_path_reports_head_and_count() {
        let rows = valid_chain(3);
        let expected_head = rows.last().unwrap().chain_hash.clone();
        let head = verify_public_chain(&rows).expect("valid chain verifies");
        assert_eq!(head.verdict_count, 3);
        assert_eq!(head.last_chain_hash, expected_head);
    }

    /// A genesis row carrying a chain_prev_hash is tampering — fail loud.
    #[test]
    fn verify_public_chain_rejects_genesis_with_prev_hash() {
        let mut rows = valid_chain(1);
        rows[0].chain_prev_hash = Some("f".repeat(64));
        // keep per-row self-consistency so ONLY the genesis rule trips
        rows[0].chain_hash =
            compute_chain_hash(rows[0].chain_prev_hash.as_deref(), &rows[0].verdict_hash);
        let err = verify_public_chain(&rows).expect_err("genesis with prev must fail");
        assert!(matches!(err, ChainPackageError::GenesisHasPrev { .. }));
    }

    /// A severed cross-row link (row[i].chain_prev_hash != row[i-1]
    /// .chain_hash) fails loud even when the row is self-consistent.
    #[test]
    fn verify_public_chain_rejects_severed_link() {
        let mut rows = valid_chain(3);
        rows[2].chain_prev_hash = Some("e".repeat(64));
        rows[2].chain_hash =
            compute_chain_hash(rows[2].chain_prev_hash.as_deref(), &rows[2].verdict_hash);
        let err = verify_public_chain(&rows).expect_err("severed link must fail");
        assert!(matches!(err, ChainPackageError::LinkSevered { ordinal: 3, .. }));
    }

    /// Per-row self-consistency: persisted chain_hash must equal the
    /// recomputation from (prev, verdict_hash).
    #[test]
    fn verify_public_chain_rejects_inconsistent_row_hash() {
        let mut rows = valid_chain(2);
        rows[1].chain_hash = "d".repeat(64);
        let err = verify_public_chain(&rows).expect_err("bad row hash must fail");
        assert!(matches!(
            err,
            ChainPackageError::RowInconsistent { ordinal: 2, .. }
        ));
    }

    /// An EMPTY package must not verify OK: "head of nothing" is not a
    /// verifiable claim.
    #[test]
    fn verify_public_chain_rejects_empty_chain() {
        let err = verify_public_chain(&[]).expect_err("empty chain must fail");
        assert!(matches!(err, ChainPackageError::Empty));
    }

    /// Ordinals must be contiguous 1..=N in order — a package whose
    /// ordinals skip or repeat is malformed even if the hash links
    /// happen to close (defense in depth; presentational field kept
    /// honest).
    #[test]
    fn verify_public_chain_rejects_non_contiguous_ordinals() {
        let mut rows = valid_chain(2);
        rows[1].ordinal = 7;
        let err = verify_public_chain(&rows).expect_err("ordinal gap must fail");
        assert!(matches!(
            err,
            ChainPackageError::OrdinalMismatch {
                expected: 2,
                found: 7
            }
        ));
    }

    /// INTENT: the auditor-facing entry point round-trips — a package
    ///         serialized by the emitter parses and verifies OFFLINE to
    ///         the same head. Serialization → parse → verify is the exact
    ///         cycle the public verify page instructs.
    /// CONTEXT: the CLI `verify-chain` surfaces are thin wrappers over
    ///          this pure function.
    /// EXPIRES IF: schema_version 2.x introduces its own parser.
    #[test]
    fn test_intent_package_roundtrip_serialize_parse_verify() {
        let rows = valid_chain(4);
        let expected_head = rows.last().unwrap().chain_hash.clone();
        let json = serde_json::to_string_pretty(&PublicChainExport::new(rows))
            .expect("export serializes");
        let head = parse_and_verify_package(&json).expect("roundtrip verifies");
        assert_eq!(head.verdict_count, 4);
        assert_eq!(head.last_chain_hash, expected_head);
    }

    /// An unsupported schema_version fails loud BEFORE any hash work —
    /// a future v2 package must not silently half-verify under v1 rules.
    #[test]
    fn parse_package_rejects_unknown_schema_version() {
        let mut export = PublicChainExport::new(valid_chain(1));
        export.schema_version = "9.9".to_string();
        let json = serde_json::to_string(&export).unwrap();
        let err = parse_and_verify_package(&json).expect_err("unknown schema must fail");
        assert!(matches!(
            err,
            PackageVerifyError::Parse(PackageParseError::UnsupportedSchemaVersion { .. })
        ));
    }

    /// Unknown fields in the package are rejected (deny_unknown_fields):
    /// an auditor must never be handed a file with extra data the
    /// verifier silently ignores.
    #[test]
    fn parse_package_rejects_unknown_fields() {
        let json = r#"{"schema_version":"1.0","chain":[],"extra":"smuggled"}"#;
        let err = parse_and_verify_package(json).expect_err("unknown field must fail");
        assert!(matches!(
            err,
            PackageVerifyError::Parse(PackageParseError::Malformed { .. })
        ));
    }

    /// INTENT: error Displays render FILE-CONTROLLED strings with the
    ///         Debug formatter, so injected control bytes (ESC for ANSI
    ///         forgery, newlines for line splicing) come out ESCAPED —
    ///         a hostile export cannot forge or mangle the terminal
    ///         output of a failing verify-chain run.
    /// CONTEXT: review fix of the first CLI release — GenesisHasPrev and
    ///          RowInconsistent interpolated the raw strings.
    /// EXPIRES IF: error rendering stops interpolating file bytes
    ///             entirely (structured machine output only).
    #[test]
    fn test_intent_error_display_escapes_injected_control_bytes() {
        let hostile = "\x1b[32mfake\nline".to_string();

        let genesis = ChainPackageError::GenesisHasPrev {
            declared: hostile.clone(),
        }
        .to_string();
        let row = ChainPackageError::RowInconsistent {
            ordinal: 2,
            persisted: hostile.clone(),
            recomputed: "a".repeat(64),
        }
        .to_string();
        let severed = ChainPackageError::LinkSevered {
            ordinal: 3,
            declared: Some(hostile.clone()),
            expected: hostile.clone(),
        }
        .to_string();

        for (name, rendered) in [("GenesisHasPrev", genesis), ("RowInconsistent", row), ("LinkSevered", severed)] {
            assert!(
                !rendered.contains('\x1b') && !rendered.contains('\n'),
                "{name} Display leaked raw control bytes: {rendered:?}"
            );
            assert!(
                rendered.contains("\\u{1b}") && rendered.contains("\\n"),
                "{name} Display must show the ESCAPED forms: {rendered:?}"
            );
        }
    }

    /// Malformed JSON fails loud with the parse error class.
    #[test]
    fn parse_package_rejects_malformed_json() {
        let err = parse_and_verify_package("{not json").expect_err("garbage must fail");
        assert!(matches!(
            err,
            PackageVerifyError::Parse(PackageParseError::Malformed { .. })
        ));
    }
}
