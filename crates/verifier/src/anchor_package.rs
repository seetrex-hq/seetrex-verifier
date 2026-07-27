// SPDX-License-Identifier: Apache-2.0
//! `anchor.json` transport + the package-level anchor orchestration —
//! the wiring that turns the sealed primitives (the JOIN in
//! [`crate::anchor`], inclusion + cosigned checkpoint in [`crate::merkle`] /
//! [`crate::checkpoint`], and the identity
//! derivation) into a single OFFLINE `CONSISTENCIA` verdict over a producer's
//! published package.
//!
//! Two pinned design rules govern this module: the submitter key_hash and the
//! rotate payload key hashes are DIFFERENT things (and the producer identity
//! set is followed from the PINNED genesis via `rotate`); and the witness
//! policy is a PINNED artifact of the AUDITOR KIT, never carried in the
//! untrusted package. Identity uniqueness and the never-collapsing two
//! verdicts come from the same signed design.
//!
//! ## The trust boundary this module enforces (the security core)
//!
//! `anchor.json` is PUBLIC, adversary-produced material. It carries ONLY public
//! evidence: the chain rows, the anchored leaves + inclusion proofs, the
//! `rotate` leaves + proofs, and the checkpoint. It does NOT — and MUST NOT —
//! carry the witness policy, the pinned genesis key, or the audited tenant slug:
//! those are supplied to [`verify_anchored_package`] as SEPARATE parameters from
//! the pinned auditor kit. If the package could name its own witnesses or its
//! own genesis, an attacker would authenticate their own forgery. The serde DTOs
//! use `deny_unknown_fields`, so a package that tries to smuggle a `policy` /
//! `genesis` field fails to parse.
//!
//! ## The inclusion obligation, discharged here
//!
//! `derive_producer_identity_set` is sound ONLY over rotations
//! whose inclusion under the cosigned checkpoint is verified first (its module
//! note pins this). This module verifies each `rotate` leaf via
//! [`crate::checkpoint::verify_rotate_inclusion`] BEFORE building the
//! `RotationRecord`s it feeds to the derivation — so `submitter_key_hash` is
//! log-attested, not attacker-asserted.
//!
//! ## Real-crypto coverage of BOTH rotation branches
//!
//! Two REAL `test.sigsum.org` rotate vectors are tested end-to-end at the
//! PACKAGE level: leaf 196056 is *Unauthorized* (`submitter b112398d… ≠ payload
//! old fa358019…`) — surfaced as an anomaly, the set stays at genesis; and leaf
//! 196700 is *Authorized* (`submitter == payload old`, submitted under the very
//! key the payload names as old) — from a genesis pinned to that key the set
//! EXTENDS to the new key. Both are round-trips against real log-attested crypto
//! (inclusion under a cosigned checkpoint), so a wiring bug specific to EITHER
//! branch is caught by a real-vector test here, not only by synthetic records
//! in `crate::anchor::tests`. Both vectors were captured from the live log
//! with reproducible tooling.
//!
//! Residual (honest, NOT claimed closed): the DERIVATION of both branches now has
//! real coverage, but a DOWNSTREAM per-tenant anchored leaf signed under a
//! ROTATED-IN key then passing `verify_anchored_inclusion` still has only a
//! synthetic positive — the sole real anchored-leaf positive anchors
//! `genesis == submitter`. That is a distinct path from the identity derivation.

use crate::anchor::{
    derive_producer_identity_set, serialize_preimage, verify_consistencia, IdentitySet, Lane, Mode,
    PreimageError, RotationRecord, Verdict,
};
use crate::anchor_completitud::{verify_completitud, MonitorEnumeration, SlugObservation};
use crate::chain_export::PublicChainRow;
use crate::checkpoint::{
    verify_anchored_inclusion, verify_checkpoint, verify_rotate_inclusion, AnchoredLeaf,
    Checkpoint, Cosignature, WitnessPolicy,
};
use serde::{Deserialize, Serialize};

// ---- wire schema (`seetrex/anchor/v1`) — DTOs with hex strings -------------

/// The only accepted `anchor.json` version. A different version is a future
/// epoch and is rejected (the byte conventions could differ).
pub const ANCHOR_JSON_VERSION: &str = "seetrex/anchor/v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CosignatureDto {
    key_hash: String,
    timestamp: u64,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointDto {
    size: u64,
    root: String,
    log_signature: String,
    cosignatures: Vec<CosignatureDto>,
}

/// Lane DTO — the closed carrier set, tagged by `kind`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum LaneDto {
    Head {
        slug: String,
        ordinal: u64,
        chain_hash: String,
    },
    Enroll {
        slug: String,
        mode: String,
    },
    Retired {
        slug: String,
        ordinal_final: u64,
        chain_hash_final: String,
    },
    Rotate {
        rot_ordinal: u64,
        key_hash_old: String,
        key_hash_new: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchoredLeafDto {
    lane: LaneDto,
    submitter_signature: String,
    submitter_key_hash: String,
    index: u64,
    inclusion_proof: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorPackageDto {
    version: String,
    tenant_slug: String,
    rows: Vec<PublicChainRow>,
    checkpoint: CheckpointDto,
    anchored_leaves: Vec<AnchoredLeafDto>,
    rotations: Vec<AnchoredLeafDto>,
}

/// A parsed, structurally-valid `anchor.json` package — the PUBLIC evidence a
/// producer publishes. It carries NO policy and NO genesis (those are pinned
/// auditor-kit inputs to [`verify_anchored_package`], never from the package).
#[derive(Debug, Clone)]
pub struct AnchorPackage {
    pub tenant_slug: String,
    pub rows: Vec<PublicChainRow>,
    pub checkpoint: Checkpoint,
    /// Per-tenant anchored facts (`head`/`enroll`/`retired`) with inclusion evidence.
    pub anchored_leaves: Vec<AnchoredLeaf>,
    /// `rotate` leaves with inclusion evidence, feeding the identity derivation.
    pub rotations: Vec<AnchoredLeaf>,
}

/// Why an `anchor.json` could not be parsed into a structurally-valid package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorJsonError {
    /// `serde_json` rejected the document (malformed JSON, unknown field, wrong
    /// type, missing field). Carries the message (not the non-`PartialEq` error).
    Json(String),
    /// `version` is not [`ANCHOR_JSON_VERSION`].
    UnsupportedVersion { got: String },
    /// A hex byte field is not exactly the expected length of lowercase hex.
    InvalidHex { field: &'static str, value: String },
    /// An `enroll` `mode` is neither `attested` nor `revocable`.
    InvalidMode { value: String },
}

/// Decode a lowercase-hex string of exactly `N` bytes (`2*N` chars). Uppercase
/// or wrong length ⇒ error (a package we would emit is canonical lowercase; a
/// non-canonical encoding is not ours — fail closed).
fn hex_fixed<const N: usize>(field: &'static str, s: &str) -> Result<[u8; N], AnchorJsonError> {
    let is_lower_hex = s.len() == 2 * N
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_lower_hex {
        return Err(AnchorJsonError::InvalidHex {
            field,
            value: s.to_string(),
        });
    }
    let bytes = hex::decode(s).map_err(|_| AnchorJsonError::InvalidHex {
        field,
        value: s.to_string(),
    })?;
    bytes.try_into().map_err(|_| AnchorJsonError::InvalidHex {
        field,
        value: s.to_string(),
    })
}

impl LaneDto {
    /// Move the DTO into a [`Lane`]. The lane's OWN hash/slug fields stay as
    /// `String` (validated downstream by `serialize_preimage`); only `mode` is
    /// resolved to its closed enum here.
    fn into_lane(self) -> Result<Lane, AnchorJsonError> {
        Ok(match self {
            LaneDto::Head {
                slug,
                ordinal,
                chain_hash,
            } => Lane::Head {
                slug,
                ordinal,
                chain_hash,
            },
            LaneDto::Enroll { slug, mode } => {
                let mode = match mode.as_str() {
                    "attested" => Mode::Attested,
                    "revocable" => Mode::Revocable,
                    _ => return Err(AnchorJsonError::InvalidMode { value: mode }),
                };
                Lane::Enroll { slug, mode }
            }
            LaneDto::Retired {
                slug,
                ordinal_final,
                chain_hash_final,
            } => Lane::Retired {
                slug,
                ordinal_final,
                chain_hash_final,
            },
            LaneDto::Rotate {
                rot_ordinal,
                key_hash_old,
                key_hash_new,
            } => Lane::Rotate {
                rot_ordinal,
                key_hash_old,
                key_hash_new,
            },
        })
    }
}

impl AnchoredLeafDto {
    fn into_leaf(self) -> Result<AnchoredLeaf, AnchorJsonError> {
        let proof = self
            .inclusion_proof
            .iter()
            .map(|p| hex_fixed::<32>("inclusion_proof", p))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AnchoredLeaf {
            lane: self.lane.into_lane()?,
            submitter_signature: hex_fixed::<64>("submitter_signature", &self.submitter_signature)?,
            submitter_key_hash: hex_fixed::<32>("submitter_key_hash", &self.submitter_key_hash)?,
            index: self.index,
            inclusion_proof: proof,
        })
    }
}

impl CheckpointDto {
    fn into_checkpoint(self) -> Result<Checkpoint, AnchorJsonError> {
        let cosignatures = self
            .cosignatures
            .into_iter()
            .map(|c| {
                Ok(Cosignature {
                    key_hash: hex_fixed::<32>("cosignature.key_hash", &c.key_hash)?,
                    timestamp: c.timestamp,
                    signature: hex_fixed::<64>("cosignature.signature", &c.signature)?,
                })
            })
            .collect::<Result<Vec<_>, AnchorJsonError>>()?;
        Ok(Checkpoint {
            size: self.size,
            root: hex_fixed::<32>("checkpoint.root", &self.root)?,
            log_signature: hex_fixed::<64>("checkpoint.log_signature", &self.log_signature)?,
            cosignatures,
        })
    }
}

/// Parse an `anchor.json` document into a structurally-valid [`AnchorPackage`].
/// Validates the version, every hex byte field (lowercase, exact length) and the
/// closed lane/mode sets; `deny_unknown_fields` throughout rejects a package that
/// tries to carry anything we would not emit (notably a policy or a genesis).
pub fn parse_anchor_package(json: &str) -> Result<AnchorPackage, AnchorJsonError> {
    let dto: AnchorPackageDto =
        serde_json::from_str(json).map_err(|e| AnchorJsonError::Json(e.to_string()))?;
    if dto.version != ANCHOR_JSON_VERSION {
        return Err(AnchorJsonError::UnsupportedVersion { got: dto.version });
    }
    let anchored_leaves = dto
        .anchored_leaves
        .into_iter()
        .map(AnchoredLeafDto::into_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    let rotations = dto
        .rotations
        .into_iter()
        .map(AnchoredLeafDto::into_leaf)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AnchorPackage {
        tenant_slug: dto.tenant_slug,
        rows: dto.rows,
        checkpoint: dto.checkpoint.into_checkpoint()?,
        anchored_leaves,
        rotations,
    })
}

// ---- emit (`anchor.json`) — the INVERSE of `parse_anchor_package` ----------

/// Why an [`AnchorPackage`] could not be emitted as a byte-valid `anchor.json`.
/// An honest producer NEVER publishes what the auditor would mark FAILED, so a
/// leaf whose lane does not re-serialize to a canonical `v1` preimage is
/// fail-closed here — symmetric to the verifier's "unexplained leaf ⇒
/// FAILED" rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmitError {
    /// A lane in the package does not re-serialize to a canonical `v1` preimage
    /// (via [`serialize_preimage`], the SAME validator the verifier runs). The
    /// producer refuses to emit an unexplained leaf — the one the verifier would
    /// reject — so the whole package is rejected rather than partially published.
    UnexplainedLeaf(PreimageError),
    /// `serde_json` failed to serialize the DTO. Unreachable for well-formed
    /// DTOs (every field is an owned `String`/integer); degrades to an error
    /// rather than panic.
    Json(String),
}

/// Build the wire [`LaneDto`] from a public [`Lane`]. The lane's own hash/slug
/// fields are carried through as-is; only [`Mode`] is rendered to its canonical
/// lowercase string (the exact tokens `into_lane` accepts back).
fn lane_to_dto(lane: &Lane) -> LaneDto {
    match lane {
        Lane::Head {
            slug,
            ordinal,
            chain_hash,
        } => LaneDto::Head {
            slug: slug.clone(),
            ordinal: *ordinal,
            chain_hash: chain_hash.clone(),
        },
        Lane::Enroll { slug, mode } => LaneDto::Enroll {
            slug: slug.clone(),
            mode: match mode {
                Mode::Attested => "attested".to_string(),
                Mode::Revocable => "revocable".to_string(),
            },
        },
        Lane::Retired {
            slug,
            ordinal_final,
            chain_hash_final,
        } => LaneDto::Retired {
            slug: slug.clone(),
            ordinal_final: *ordinal_final,
            chain_hash_final: chain_hash_final.clone(),
        },
        Lane::Rotate {
            rot_ordinal,
            key_hash_old,
            key_hash_new,
        } => LaneDto::Rotate {
            rot_ordinal: *rot_ordinal,
            key_hash_old: key_hash_old.clone(),
            key_hash_new: key_hash_new.clone(),
        },
    }
}

/// Build an [`AnchoredLeafDto`] from a public [`AnchoredLeaf`], fail-closed on a
/// lane that does not re-serialize. Byte fields are emitted as LOWERCASE hex
/// (the canonical encoding [`parse_anchor_package`] accepts).
fn leaf_to_dto(leaf: &AnchoredLeaf) -> Result<AnchoredLeafDto, EmitError> {
    // Fail closed: never emit a leaf whose lane the verifier would reject as
    // "unexplained". `serialize_preimage` is the SAME validator the verifier
    // runs, so an emitted package can never contain a leaf that fails there.
    serialize_preimage(&leaf.lane).map_err(EmitError::UnexplainedLeaf)?;
    Ok(AnchoredLeafDto {
        lane: lane_to_dto(&leaf.lane),
        submitter_signature: hex::encode(leaf.submitter_signature),
        submitter_key_hash: hex::encode(leaf.submitter_key_hash),
        index: leaf.index,
        inclusion_proof: leaf.inclusion_proof.iter().map(hex::encode).collect(),
    })
}

/// Build the wire [`CheckpointDto`] from a public [`Checkpoint`] — pure byte
/// re-encoding, no crypto invented.
fn checkpoint_to_dto(cp: &Checkpoint) -> CheckpointDto {
    CheckpointDto {
        size: cp.size,
        root: hex::encode(cp.root),
        log_signature: hex::encode(cp.log_signature),
        cosignatures: cp
            .cosignatures
            .iter()
            .map(|c| CosignatureDto {
                key_hash: hex::encode(c.key_hash),
                timestamp: c.timestamp,
                signature: hex::encode(c.signature),
            })
            .collect(),
    }
}

/// Emit a byte-valid `anchor.json` from an [`AnchorPackage`] — the INVERSE of
/// [`parse_anchor_package`], sharing the ONE private DTO definition so producer
/// and verifier can never drift apart on the wire format.
///
/// The producer COMPUTES nothing the log must sign; it serializes the tenant
/// chain + lane facts + already-obtained inclusion evidence. A dishonest
/// producer can only OMIT — every emitted leaf's correctness is gated downstream
/// by the real inclusion proof under the cosigned checkpoint. Fail-closed: a
/// lane that does not re-serialize to a canonical `v1` preimage is NEVER emitted
/// ([`EmitError::UnexplainedLeaf`]) — the producer never publishes what the
/// auditor would mark FAILED.
///
/// Determinism: fields serialize in struct-definition order via `serde_json`;
/// the emitted document re-parses via [`parse_anchor_package`]. Byte-exact JCS
/// canonicalization (RFC 8785) is a possible refinement but NOT required here —
/// the canonicity that is load-bearing is the PREIMAGE's, already enforced by
/// [`serialize_preimage`] (deferred, documented, not silenced).
pub fn emit_anchor_package(pkg: &AnchorPackage) -> Result<String, EmitError> {
    let anchored_leaves = pkg
        .anchored_leaves
        .iter()
        .map(leaf_to_dto)
        .collect::<Result<Vec<_>, _>>()?;
    let rotations = pkg
        .rotations
        .iter()
        .map(leaf_to_dto)
        .collect::<Result<Vec<_>, _>>()?;
    let dto = AnchorPackageDto {
        version: ANCHOR_JSON_VERSION.to_string(),
        tenant_slug: pkg.tenant_slug.clone(),
        rows: pkg.rows.clone(),
        checkpoint: checkpoint_to_dto(&pkg.checkpoint),
        anchored_leaves,
        rotations,
    };
    serde_json::to_string(&dto).map_err(|e| EmitError::Json(e.to_string()))
}

// ---- auditor kit (`seetrex/anchor-kit/v1`) — the PINNED trusted inputs ------

/// The only accepted auditor-kit version.
pub const ANCHOR_KIT_VERSION: &str = "seetrex/anchor-kit/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessPolicyDto {
    log_pubkey: String,
    witnesses: Vec<String>,
    quorum_k: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditorKitDto {
    version: String,
    tenant_slug: String,
    genesis_key_hash: String,
    policy: WitnessPolicyDto,
}

/// The PINNED auditor-kit inputs to [`verify_anchored_package`]: the audited
/// tenant slug, the pinned genesis key hash, and the witness policy. Supplied
/// out-of-band by the auditor,
/// in a file SEPARATE from the untrusted `anchor.json` — the package can never
/// name its own witnesses or its own genesis. Test tier = a synthetic genesis
/// and the Glasklar `sigsum-test1-2025` policy; production values are pinned
/// operator artifacts.
#[derive(Debug, Clone)]
pub struct AuditorKit {
    pub tenant_slug: String,
    pub genesis_key_hash: [u8; 32],
    pub policy: WitnessPolicy,
}

/// Why an auditor kit could not be parsed into a structurally-valid
/// [`AuditorKit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitError {
    /// `serde_json` rejected the document (malformed JSON, unknown field, wrong
    /// type, missing field). Carries the message (not the non-`PartialEq` error).
    Json(String),
    /// `version` is not [`ANCHOR_KIT_VERSION`].
    UnsupportedVersion { got: String },
    /// A hex byte field is not exactly the expected length of lowercase hex.
    InvalidHex { field: &'static str, value: String },
    /// `quorum_k` is 0 — a pinned policy MUST require at least one witness
    /// cosignature. A 0 threshold accepts the log's signature alone, defeating
    /// the split-view protection (the [`WitnessPolicy`] invariant).
    InvalidQuorum,
    /// `quorum_k` exceeds the number of witnesses — an UNSATISFIABLE pinned
    /// policy. Caught here (a kit CONFIG error) rather than let every non-vacuous
    /// package fail closed as a spurious `QuorumNotMet` on the vendor-failure
    /// channel: a mis-provisioned witness set is exactly the auditor foot-gun the
    /// exit-2 kit channel exists to isolate.
    QuorumExceedsWitnesses { quorum_k: usize, witnesses: usize },
}

/// Map an `InvalidHex` from the shared [`hex_fixed`] into the kit's own error
/// type. `hex_fixed` only ever returns `InvalidHex`, so the other arm is
/// unreachable in practice; it degrades to a `Json` message rather than panic.
fn kit_hex(e: AnchorJsonError) -> KitError {
    match e {
        AnchorJsonError::InvalidHex { field, value } => KitError::InvalidHex { field, value },
        other => KitError::Json(format!("unexpected hex-decode error: {other:?}")),
    }
}

/// Parse an auditor-kit document into a structurally-valid [`AuditorKit`].
/// Validates the version, every hex byte field (lowercase, exact length), and
/// the pinned-policy invariant `quorum_k >= 1`; `deny_unknown_fields` throughout
/// rejects a kit carrying anything we would not emit.
///
/// This is the TRUSTED counterpart to [`parse_anchor_package`]: the two are
/// deliberately separate readers over separate files, so the untrusted package
/// can never supply the witness policy or the genesis (the trust boundary this
/// module enforces).
pub fn parse_auditor_kit(json: &str) -> Result<AuditorKit, KitError> {
    let dto: AuditorKitDto =
        serde_json::from_str(json).map_err(|e| KitError::Json(e.to_string()))?;
    if dto.version != ANCHOR_KIT_VERSION {
        return Err(KitError::UnsupportedVersion { got: dto.version });
    }
    if dto.policy.quorum_k == 0 {
        return Err(KitError::InvalidQuorum);
    }
    let genesis_key_hash =
        hex_fixed::<32>("genesis_key_hash", &dto.genesis_key_hash).map_err(kit_hex)?;
    let log_pubkey =
        hex_fixed::<32>("policy.log_pubkey", &dto.policy.log_pubkey).map_err(kit_hex)?;
    let witnesses = dto
        .policy
        .witnesses
        .iter()
        .map(|w| hex_fixed::<32>("policy.witnesses", w).map_err(kit_hex))
        .collect::<Result<Vec<_>, _>>()?;
    if dto.policy.quorum_k > witnesses.len() {
        return Err(KitError::QuorumExceedsWitnesses {
            quorum_k: dto.policy.quorum_k,
            witnesses: witnesses.len(),
        });
    }
    Ok(AuditorKit {
        tenant_slug: dto.tenant_slug,
        genesis_key_hash,
        policy: WitnessPolicy {
            log_pubkey,
            witnesses,
            quorum_k: dto.policy.quorum_k,
        },
    })
}

// ---- monitor bundle (`seetrex/anchor-monitor/v1`) — the COMPLETITUD input ---

/// The only accepted monitor-bundle version.
pub const ANCHOR_MONITOR_VERSION: &str = "seetrex/anchor-monitor/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SlugObservationDto {
    slug: String,
    served: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonitorBundleDto {
    version: String,
    c_audit: CheckpointDto,
    leaves: Vec<AnchoredLeafDto>,
    /// Each element = a 32-byte lowercase-hex consistency-proof node.
    consistency_proof: Vec<String>,
    observations: Vec<SlugObservationDto>,
}

/// A parsed, structurally-valid monitor bundle: the enumeration under the
/// tenant's identity plus the per-slug liveness observations, ready to be
/// borrowed by a [`MonitorAudit`] and fed to
/// [`crate::anchor_completitud::verify_completitud`].
pub struct ParsedMonitor {
    pub enumeration: MonitorEnumeration,
    pub observations: Vec<SlugObservation>,
}

/// Why a monitor bundle could not be parsed into a structurally-valid
/// [`ParsedMonitor`]. Distinct, faithful variants: the bundle is the auditor's
/// OWN trusted artifact, so a parse failure maps to a CONFIG exit code in the
/// CLI (a mis-provisioned monitor input, not a package-verification verdict).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MonitorError {
    /// `serde_json` rejected the document (malformed JSON, unknown field, wrong
    /// type, missing field). Carries the message (not the non-`PartialEq` error).
    Json(String),
    /// `version` is not [`ANCHOR_MONITOR_VERSION`].
    UnsupportedVersion { got: String },
    /// A hex/leaf/checkpoint conversion failed (wraps [`AnchorJsonError`]).
    Convert(String),
}

/// Parse a monitor-bundle document into a structurally-valid [`ParsedMonitor`].
/// Validates the version and every hex byte field (via the shared, reused
/// [`CheckpointDto`]/[`AnchoredLeafDto`]/[`hex_fixed`] conversions);
/// `deny_unknown_fields` throughout rejects a bundle carrying anything we would
/// not emit. Mirrors [`parse_auditor_kit`]: `serde_json::from_str` → `Json`;
/// version check → `UnsupportedVersion`; field conversions → `Convert`.
pub fn parse_monitor_audit(json: &str) -> Result<ParsedMonitor, MonitorError> {
    let dto: MonitorBundleDto =
        serde_json::from_str(json).map_err(|e| MonitorError::Json(e.to_string()))?;
    if dto.version != ANCHOR_MONITOR_VERSION {
        return Err(MonitorError::UnsupportedVersion { got: dto.version });
    }
    let convert = |e: AnchorJsonError| MonitorError::Convert(format!("{e:?}"));
    let c_audit = dto.c_audit.into_checkpoint().map_err(convert)?;
    let leaves = dto
        .leaves
        .into_iter()
        .map(AnchoredLeafDto::into_leaf)
        .collect::<Result<Vec<_>, _>>()
        .map_err(convert)?;
    let consistency_proof = dto
        .consistency_proof
        .iter()
        .map(|p| hex_fixed::<32>("consistency_proof", p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(convert)?;
    let observations = dto
        .observations
        .into_iter()
        .map(|o| SlugObservation {
            slug: o.slug,
            served: o.served,
        })
        .collect();
    Ok(ParsedMonitor {
        enumeration: MonitorEnumeration {
            c_audit,
            leaves,
            consistency_proof,
        },
        observations,
    })
}

// ---- package-level orchestration -------------------------------------------

/// The package anchor report. Like [`crate::anchor::AnchorReport`] the two
/// verdicts never collapse; additionally it surfaces the derived
/// [`IdentitySet`] (with its anomalous rotations) when the identity derivation
/// ran to completion — a published rotation nobody accounts for is where
/// tampering hides, so it is reported, not hidden. `identity` is `None` only on
/// a `Failed` reached BEFORE derivation completes: the tenant-slug mismatch
/// guard, a `rotate` leaf whose inclusion did not verify, or a derivation error
/// (fork/cycle/bad-hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredPackageReport {
    pub consistencia: Verdict,
    pub completitud: Verdict,
    pub identity: Option<IdentitySet>,
}

/// The auditor's monitor-side inputs to [`verify_anchored_package`],
/// supplied together: an enumeration is only meaningful with the liveness
/// observations that resolve its 404s. Grouped into ONE named struct so that "a
/// monitor was supplied" is atomic and the two inputs cannot drift apart — the
/// same anti-footgun discipline as
/// [`crate::anchor_completitud::FreshnessProof`]. Absent (`None`) ⇒ the top-level
/// COMPLETITUD stays `INCONCLUSO`.
pub struct MonitorAudit<'a> {
    /// The monitor's enumeration under our historic identity at `S(C_audit)`,
    /// with `C_audit`'s cosignature + inclusion proofs (authenticated in
    /// [`verify_completitud`]).
    pub enumeration: &'a MonitorEnumeration,
    /// The auditor's per-slug liveness probes. A slug with an anchored head but
    /// NO probe is fail-closed to `INCONCLUSO`, never silently treated as served.
    pub observations: &'a [SlugObservation],
}

/// Verify a producer's published anchor package OFFLINE. `tenant_slug`,
/// `genesis_key_hash` and `policy` are PINNED auditor-kit inputs (production
/// values are pinned operator artifacts) — they are NEVER read from `pkg`.
///
/// `CONSISTENCIA` = `Verified` iff ALL hold:
///  1. every `rotate` leaf's inclusion under the cosigned checkpoint verifies
///     (the rotate-inclusion gate), and the identity chain derives without
///     fork/cycle;
///  2. every per-tenant anchored leaf passes [`verify_anchored_inclusion`]
///     against the DERIVED producer identity set and the audited tenant;
///  3. the package JOIN ([`verify_consistencia`]) over the anchored lanes
///     holds.
///
/// `COMPLETITUD` is `INCONCLUSO` UNLESS the auditor supplies a `monitor`:
/// with `None` the two verdicts never collapse; with `Some` this
/// authenticates the package checkpoint and runs [`verify_completitud`], returning
/// its real verdict (or `INCONCLUSO` if that checkpoint does not authenticate).
/// It is evaluated only on the offline success path — a package already
/// contradicted by CONSISTENCIA keeps the INCONCLUSO default (fail-fast). A
/// supplied monitor's `Verified` is CONDITIONAL on the enumeration being COMPLETE
/// and RECENT (both
/// TRUSTED inputs deferred to the live monitor), not an unconditional
/// completeness proof.
/// Anomalous rotations (unauthorized / off-chain) are SURFACED in `identity`, not
/// fatal offline (their FAILED mapping is enumeration-dependent).
///
/// NB (scope of a `Verified` CONSISTENCIA): it asserts NON-CONTRADICTION of the
/// PRESENTED material — not that any anchoring occurred. A well-formed chain with
/// ZERO anchored leaves verifies vacuously; detecting OMITTED contradictory log
/// leaves is `COMPLETITUD`, which stays `INCONCLUSO`.
pub fn verify_anchored_package(
    tenant_slug: &str,
    genesis_key_hash: [u8; 32],
    policy: &WitnessPolicy,
    pkg: &AnchorPackage,
    monitor: Option<&MonitorAudit>,
) -> AnchoredPackageReport {
    let completitud = Verdict::Inconclusive {
        reason: "COMPLETITUD not evaluated — enumeration-dependent; either no \
                 monitor was supplied or the offline CONSISTENCIA verdict did not complete"
            .to_string(),
    };

    // (0) Category-error guard: the package's self-declared subject must be the
    // tenant under audit. The PINNED `tenant_slug` parameter is authoritative
    // (every leaf is bound to it in step 2); this fail-closed cross-check stops a
    // package published for a DIFFERENT tenant from being silently audited as
    // this one (an auditor-error / mislabelling footgun, not a crypto control).
    if pkg.tenant_slug != tenant_slug {
        return AnchoredPackageReport {
            consistencia: Verdict::Failed {
                reason: format!(
                    "package tenant_slug {:?} does not match the audited tenant {tenant_slug:?}",
                    pkg.tenant_slug
                ),
            },
            completitud,
            identity: None,
        };
    }

    // (1) Identity — the rotate-inclusion gate FIRST: verify each rotate
    // leaf's inclusion,
    // then derive from the pinned genesis. A rotate leaf whose inclusion does not
    // verify means we would build a RotationRecord on unattested material — fail
    // closed, never construct the record.
    let mut records: Vec<RotationRecord> = Vec::with_capacity(pkg.rotations.len());
    for leaf in &pkg.rotations {
        match verify_rotate_inclusion(policy, &pkg.checkpoint, leaf) {
            Ok(record) => records.push(record),
            Err(verdict) => {
                return AnchoredPackageReport {
                    consistencia: verdict,
                    completitud,
                    identity: None,
                }
            }
        }
    }
    let identity = match derive_producer_identity_set(genesis_key_hash, &records) {
        Ok(set) => set,
        Err(e) => {
            return AnchoredPackageReport {
                consistencia: Verdict::Failed {
                    reason: format!("producer identity derivation failed: {e:?}"),
                },
                completitud,
                identity: None,
            }
        }
    };

    // (2) Per-tenant leaf inclusion, gated by the DERIVED identity set and the
    // audited tenant. Any Failed short-circuits CONSISTENCIA.
    for leaf in &pkg.anchored_leaves {
        let verdict = verify_anchored_inclusion(
            tenant_slug,
            &identity.keys,
            policy,
            &pkg.checkpoint,
            leaf,
        );
        if let Verdict::Failed { .. } = verdict {
            return AnchoredPackageReport {
                consistencia: verdict,
                completitud,
                identity: Some(identity),
            };
        }
    }

    // (3) The package JOIN over the per-tenant anchored lanes (rotate
    // lanes are not per-tenant facts and do not enter the JOIN).
    let lanes: Vec<Lane> = pkg.anchored_leaves.iter().map(|l| l.lane.clone()).collect();
    let consistencia = verify_consistencia(&pkg.rows, &lanes);

    // (4) COMPLETITUD. No monitor ⇒ the two verdicts do not
    // collapse (INCONCLUSO). With a monitor, run the real rules here on the
    // success path — computed regardless of the step-3 JOIN result (that axis is
    // independent). NB: the earlier CONSISTENCIA-failure early-returns do NOT
    // evaluate COMPLETITUD (fail-fast — a package already contradicted offline, or
    // audited under the wrong tenant, is not additionally audited for omission);
    // they keep the INCONCLUSO default above.
    //
    // The package checkpoint anchors the freshness reference (R8's `first_root`),
    // a HARD caller obligation of verify_completitud: it MUST be the COSIGNED
    // checkpoint, never a producer-declared scalar. Its cosig is only checked
    // inside the inclusion loops above — a zero-rotation / zero-leaf package skips
    // them, reaching here with the checkpoint UNAUTHENTICATED. Authenticate it
    // explicitly and fail closed if it does not verify, so an unauthenticated
    // checkpoint can never certify COMPLETITUD.
    let completitud = match monitor {
        None => completitud,
        Some(m) => match verify_checkpoint(policy, &pkg.checkpoint) {
            Err(e) => Verdict::Inconclusive {
                reason: format!(
                    "package checkpoint not authenticated ({e:?}) — no freshness \
                     reference to establish COMPLETITUD against"
                ),
            },
            Ok(root) => verify_completitud(
                tenant_slug,
                &pkg.rows,
                &lanes,
                pkg.checkpoint.size,
                root,
                genesis_key_hash,
                m.enumeration,
                policy,
                m.observations,
            ),
        },
    };

    AnchoredPackageReport {
        consistencia,
        completitud,
        identity: Some(identity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::{leaf_checksum, AnomalyReason};
    use crate::chain::compute_chain_hash;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    // ---- REAL frozen oracle vectors (inlined; the published crate stays
    // self-contained — the capture tooling is not in the crate package).
    // Source: the same frozen oracles the checkpoint tests transcribe
    // (HEAD leaf 196053, rotate leaf 196056). Both are
    // REAL test.sigsum.org data — the log/witnesses made these signatures, so
    // a passing test is not Rust-verifying-Rust. Two real rotate vectors are
    // inlined: 196056 is *Unauthorized* (submitter ≠ payload old), and 196700
    // is *Authorized* — submitted under a throwaway
    // key whose key_hash IS the payload key_hash_old ⇒ submitter == old ⇒ the
    // authorized-extends-set path (the `submitter == key_hash_old` branch of
    // `derive_producer_identity_set`) now has REAL coverage, not only synthetic
    // (`crate::anchor::tests`). Both rotation branches are exercised end-to-end
    // against real log-attested crypto.

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn h64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    const LOG_PK: &str = "4644af2abd40f4895a003bca350f9d5912ab301a49c77f13e5b6d905c20a5fe6";
    const WIT_NISSE: &str = "1c25f8a44c635457e2e391d1efbca7d4c2951a0aef06225a881e46b98962ac6c";
    const WIT_RGDD: &str = "28c92a5a3a054d317c86fc2eeb6a7ab2054d6217100d0be67ded5b74323c5806";
    const WIT_SMARTIT: &str = "f4855a0f46e8a3e23bb40faf260ee57ab8a18249fa402f2ca2d28a60e1a3130e";
    const KH_NISSE: &str = "1c997261f16e6e81d13f420900a2542a4b6a049c2d996324ee5d82a90ca3360c";
    const KH_RGDD: &str = "70b861a010f25030de6ff6a5267e0b951e70c04b20ba4a3ce41e7fba7b9b7dfc";
    const KH_SMARTIT: &str = "42351ad474b29c04187fd0c8c7670656386f323f02e9a4ef0a0055ec061ecac8";

    const CP_SIZE: u64 = 196372;
    const CP_ROOT: &str = "848aff0ecb7315a0fc1cc4a00c1065b51b4c269ff871dc2f048711892739a06e";
    const CP_LOG_SIG: &str = "c551769caf05b2cf2358d6b93f9582e1e878e2eb3ac65b06d20315dbf7ef78b0f9b956e82a215e61abe2f06d2b30d407e81e2f4247f3e0d03daa4436434c0503";
    const CP_TS: u64 = 1784740225;
    const COSIG_SMARTIT: &str = "e8859da78c26b746a2a0c3350fe0e9984c0b99233887d50dff9f2738a8b88b77026b7022e0fc73d690c450fd5affad18db2d535178e2773e3e8d7738813b740d";
    const COSIG_NISSE: &str = "da97cf997439732bbee15c4cf32d5a1040ff393e2a0fa05e14586f59ab6a387fd85f235014ccd2c9eee033b098cb5cfabd1a2c45f095deac08174c715c079b02";
    const COSIG_RGDD: &str = "b2fa95af7a17239fe2ea4a8bada2dcf36c480ee8eda4e3061fe8fb7c299825f6650bbd606cbd6ba6a7a40f92fbca20db4dd40f6063bb9432d3a55c9147a9090b";

    // Shared throwaway submitter for all 4 real captured leaves.
    const SUBMITTER_KH: &str = "b112398d0e531a2a1e49ac5a7e2d8d7cd80ab69485e7c97f36ad893ca543717d";

    // HEAD leaf 196053 (pinned head-leaf layout: head@42 example-tenant,
    // synthetic chain_hash).
    const HEAD_INDEX: u64 = 196053;
    const HEAD_CHAIN_HASH: &str =
        "5fe66186d8e2100608f5b914fe260f08c57cc894087966a637f452a0f606c689";
    const HEAD_SIG: &str = "9bb51335303c5c0a6cc7917ea97fbc5490b25b7f5bf320bdb8d678c688cc04a706d2c57e31824d6f80e6e1616666b7d871d7453c4830fc4440ab478a42015507";
    const HEAD_PROOF: &[&str] = &[
        "57954ec27540bec161ffebe796ad23ca9d3769cc131245e395fb0a3a397d130e",
        "771576ed460260a46ab3737e206f54beff92230ca8811f278deac631447e0470",
        "c5b5a29c5c1b4c04a558f70e40bc9577d2324cbea66e1c859bc3d4f26c58d83e",
        "1f86b8529603e401c6e43f17dd0d3c4ab1b6699052c9b04ffb9267b0836fb26f",
        "6d341bc07fafaf60392044e64cf9eaa12bdd97b589a645c860f2d2c9c2925aac",
        "86e3e828b940919b1fe34cbf238eaae3d4561dcaf974e828a855175d8b65fdeb",
        "e8678a6c7e857d489d6fcefd4bbfcf6c9168b2b4e29395d7aa5f8371ae610737",
        "e029a3edb1e91b2f65f569627fd19a592fe3a9221ce01819f58dc7bd31ae98ad",
        "60f3a15100b723cb4b37c79e1b39b0f3bf39326fbb810c59e13fe32d14105fe0",
        "7f45ba88ef99f21b0fd081a401fa0a8782954be5458ef916f7e9e46cfb49c9e4",
        "ce7d3d60bddef51351c90ed469c5140030a6e8f87a87d6b4f20cd8eaf6c55081",
        "425bdfab555c08a4ca2f753da727ffc34f01c568eb0bd7cf27603bd8a29d55f3",
        "2ebbadd1c82f077533f2904f4cc3e89fa9112d97ac982115b4f92d08e759b5ce",
        "2f22287841aca348a0e5e38650bfc1506744dc6acc06b5812bdce30c399ead98",
        "84b0f8a1d9c6e04ab627cde4506c9a7105683a935e8a3d988176d12b191e3f28",
        "20065aca59c5b73c0fd5cf20ddeecc66b5f054b6bcf13c6a05bc0e374ab8423c",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    // ROTATE leaf 196056 (pinned rotate-leaf layout). Payload old ≠ submitter
    // ⇒ Unauthorized.
    const ROTATE_INDEX: u64 = 196056;
    const ROTATE_SIG: &str = "bf93e2454755ad71d54c2b31d93199907a18a87baeb27cf56ff7cf458d7f372826592c4fde26a787d486520ee6245795112f5aef36b6c22e039e68ec75f57403";
    const ROTATE_OLD: &str = "fa3580190786e1de2c17600bc6ce2e2785656b6b7c20154f14de9f39927bde77";
    const ROTATE_NEW: &str = "b1a5b27125d5774fa89405492bab3ef3b2a941f0307e21b0b0116668a161d2c4";
    const ROTATE_PROOF: &[&str] = &[
        "14020122279afd01f4ae7e54bd8482453cc5a8b1d6c91ef26e6721076a1be0c8",
        "aa069aabd8ec74fff7edc10388706f1f8dd6b5f5093cf8cda0840c07adfb7c4c",
        "a99f3c8c69c4842f0f117aeef8638f512c6aaf9f2a6b318532e96f1351c0bd5a",
        "30e0bba48fe634f6815ae77c2d457e78f6593a983225957efb10373d16263c98",
        "6d341bc07fafaf60392044e64cf9eaa12bdd97b589a645c860f2d2c9c2925aac",
        "86e3e828b940919b1fe34cbf238eaae3d4561dcaf974e828a855175d8b65fdeb",
        "e8678a6c7e857d489d6fcefd4bbfcf6c9168b2b4e29395d7aa5f8371ae610737",
        "e029a3edb1e91b2f65f569627fd19a592fe3a9221ce01819f58dc7bd31ae98ad",
        "60f3a15100b723cb4b37c79e1b39b0f3bf39326fbb810c59e13fe32d14105fe0",
        "7f45ba88ef99f21b0fd081a401fa0a8782954be5458ef916f7e9e46cfb49c9e4",
        "ce7d3d60bddef51351c90ed469c5140030a6e8f87a87d6b4f20cd8eaf6c55081",
        "425bdfab555c08a4ca2f753da727ffc34f01c568eb0bd7cf27603bd8a29d55f3",
        "2ebbadd1c82f077533f2904f4cc3e89fa9112d97ac982115b4f92d08e759b5ce",
        "2f22287841aca348a0e5e38650bfc1506744dc6acc06b5812bdce30c399ead98",
        "84b0f8a1d9c6e04ab627cde4506c9a7105683a935e8a3d988176d12b191e3f28",
        "20065aca59c5b73c0fd5cf20ddeecc66b5f054b6bcf13c6a05bc0e374ab8423c",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    // ---- The REAL *AUTHORIZED* rotate leaf (submitter == old) --------------
    // Captured from the live log with reproducible tooling: a throwaway
    // K_old signed a rotate leaf
    // whose payload key_hash_old is K_old's OWN key_hash (= submitter) => the
    // rotation is AUTHORIZED and, from a genesis pinned to K_old, EXTENDS the set
    // to K_new. The leaf sits above the 196372 checkpoint, so a fresh cosigned
    // checkpoint (size 196702, all 3 policy witnesses cosigned; policy quorum is
    // 2-of-3) was captured and is authenticated here.
    const CP2_SIZE: u64 = 196702;
    const CP2_ROOT: &str = "2c0b0f5d8afb2cfd01747695f8020323c16df3f09b0acc25bf132006e45b4797";
    const CP2_LOG_SIG: &str = "b03940224af24a971f4a9563bf4a4216e48f20c0f606b54dcf7b50dab512b7ece3c39957cdcd5df724d87367d4ed70fcd82a5fda121c7bcb0b925c38850b010d";
    const CP2_TS: u64 = 1784801045;
    const COSIG2_NISSE: &str = "d38f9a0ce1f306cc3b34211cacbf10ba9e6bacd7aed25572456a1d5ca8afa58250f630c577da15b79f64300e677af6034636db7d4db2e323f244c9306b48e30d";
    const COSIG2_RGDD: &str = "4834afb904ff4124806b3185870a004b83dcc77bddf5609e69a97fe7ef62216f6b0fe10452fc944b97ed0dd7b54f8ec9ec677b13e7857ec70ef8b4668d25870f";
    const COSIG2_SMARTIT: &str = "c4593878da71059f806b6de7af7b9b63421649e08591c4910a4336cb75028df32c503874d2e6ce84678963d26b318da394ae7aa266ce46c14719c5920f66fb06";

    const ROT2_INDEX: u64 = 196700;
    const ROT2_SIG: &str = "7dc0167164586471a6e002498713c96c5ce805137f0fdc2da4f43b462cad22c448cc999c350565284d587f77cada5f24e49b0f34451081ce04acee9a2f226e0a";
    // The submitter's key_hash == the payload key_hash_old (the AUTHORIZED bit).
    const ROT2_KH_OLD: &str = "3b2508e66767c64723a65a9a969974a33a27722b2c6d0364cdd0300f1db5c348";
    const ROT2_KH_NEW: &str = "0b6fa72f66f1d863f87bbee56445cc960269304f2938827afe406a7650c7b002";
    const ROT2_ORDINAL: u64 = 9;
    const ROT2_PROOF: &[&str] = &[
        "5685194918d5ff6483773bf7fd6639be529de6290f12ba627a1ca2f19675db0b",
        "4a4b189af81912082dc35867e417d78a5313fda6b17392604d8725189a18915a",
        "83b61a91a637779396cfb7b5307ed7e214cfd83c091bc4b3d4871b650874e061",
        "d68c57b636b95339088eb00f5d5f525b149d8c59b3b07cdf6965b44ee2de841e",
        "4f51e122c348b76c72fc8a401fec9a2a070ead30fd47a98ef85866b73efb5ff2",
        "2387f1500f0756070e7a9c67f417f6036effa82f96c2fbc782cb869c7e144d85",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    fn real_policy() -> WitnessPolicy {
        WitnessPolicy {
            log_pubkey: h32(LOG_PK),
            witnesses: vec![h32(WIT_NISSE), h32(WIT_RGDD), h32(WIT_SMARTIT)],
            quorum_k: 2,
        }
    }

    fn real_checkpoint_n3() -> Checkpoint {
        Checkpoint {
            size: CP2_SIZE,
            root: h32(CP2_ROOT),
            log_signature: h64(CP2_LOG_SIG),
            cosignatures: vec![
                Cosignature {
                    key_hash: h32(KH_NISSE),
                    timestamp: CP2_TS,
                    signature: h64(COSIG2_NISSE),
                },
                Cosignature {
                    key_hash: h32(KH_RGDD),
                    timestamp: CP2_TS,
                    signature: h64(COSIG2_RGDD),
                },
                Cosignature {
                    key_hash: h32(KH_SMARTIT),
                    timestamp: CP2_TS,
                    signature: h64(COSIG2_SMARTIT),
                },
            ],
        }
    }

    fn real_authorized_rotate_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Rotate {
                rot_ordinal: ROT2_ORDINAL,
                key_hash_old: ROT2_KH_OLD.to_string(),
                key_hash_new: ROT2_KH_NEW.to_string(),
            },
            submitter_signature: h64(ROT2_SIG),
            submitter_key_hash: h32(ROT2_KH_OLD), // submitter == old ⇒ AUTHORIZED
            index: ROT2_INDEX,
            inclusion_proof: ROT2_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    // ---- The REAL end-to-end HEAD leaf (producer round-trip → VERIFIED) ----
    // Captured from the live log with reproducible tooling:
    // a throwaway genesis key K signed a head@1 leaf whose chain_hash is that of a
    // REAL 1-row genesis chain (chain_hash = SHA256(verdict_hash)); submitter == K's
    // key_hash == genesis ⇒ in the derived identity set. inclusion + identity + JOIN
    // all pass ⇒ VERIFIED — the piece leaf 196053 lacks (its chain_hash is synthetic,
    // so the JOIN is structurally unsatisfiable). The leaf sits above the 196372/
    // 196702 checkpoints, so a fresh cosigned checkpoint (size 196830, all 3 policy
    // witnesses cosigned; policy quorum is 2-of-3) was captured and is authenticated.
    const FC2_CP_SIZE: u64 = 196830;
    const FC2_CP_ROOT: &str = "5f37d9f47d9ab07ad151de58dd51ec192f85598128a28e34d3570757de7384ec";
    const FC2_CP_LOG_SIG: &str = "93d3747cfcb8450fcc4b4d1468ecd76e59645a2a1bfcd77fdb4f111b60bc505f9b32bc36b264a2ecf48f3dda27136bd0b849294c0331471105f77131ba88ca09";
    const FC2_TS: u64 = 1784815728;
    const FC2_COSIG_NISSE: &str = "092401a54bbdf32ea42dd23c02338f3387851b1b676b7b0e5855432ee8bb5a797ba11bd57a2c63c96f54d3a56329aaa557b9ebddd3f908140625df7489290004";
    const FC2_COSIG_RGDD: &str = "93d293a51d1cd286bcb22d549b35c9481191c91e57677bfd1d83c310df137d2ab43f30d53e7304a52f2dd37064405f65de02e21da9a620596a9eb0e44af19a0e";
    const FC2_COSIG_SMARTIT: &str = "bd471dc835a9c35f43a8f579dc813252a8c853232fd8e04d0f606447a7607cbe32edc9a90a20fd89a369e3788990f3a405404b36dcc8f6e93b6e495d312a4c0d";

    const FC2_HEAD_INDEX: u64 = 196829;
    // genesis_key_hash == submitter key_hash == SHA256(pk_K).
    const FC2_HEAD_KH: &str = "3ec01c5d15f5624fa554aa103934056103f3860237582396fcd327403bfdb86d";
    const FC2_HEAD_SIG: &str = "336cd348dd8e5ac7fbcfa10ea6258c3fbacf1ea94aa3bfb23844327db88113b1b654274ab76fc8af569d8c5f35d20ea8ad8ea095d63168a62e462618b035bf0c";
    const FC2_SLUG: &str = "fc2-head-tenant";
    const FC2_VERDICT_HASH: &str =
        "01e6e490651adaf36abf0f1991bc576f4d9b8c50030d030f60c106f23baee247";
    // = compute_chain_hash(None, FC2_VERDICT_HASH); carried by head@1 for the JOIN.
    const FC2_CHAIN_HASH: &str =
        "93263f71d3ff2b4a724439cd262722881d9928555232c62874c69140d71ed8b2";
    const FC2_HEAD_PROOF: &[&str] = &[
        "4f30569b08cedbab25bcd7d6f297145200bac34b8856d146a6b4c4fa1c65fbf0",
        "1f9c0067ae59a2b51bee2fa99ac5a3cf7ad58973d5806239d0815d59d370253a",
        "a39c5385ae4008712b87ae3a4b4175a05b93cf21d3b42beee1472ec2095d7391",
        "6bfaa881b0adfb6b4c2789fb5382f238b3616b5bcb365fda2fb78de04322356a",
        "796bc23d12a5244a0f09f2efd6be94c2ecfc094e23d89787a6cd4cfc1b1bbe05",
        "bcfdac2599bd8ddfe4908ff4c27b4c02a7a7916df9e22a5b1c3b6d02207251dc",
        "2387f1500f0756070e7a9c67f417f6036effa82f96c2fbc782cb869c7e144d85",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    fn fc2_checkpoint() -> Checkpoint {
        Checkpoint {
            size: FC2_CP_SIZE,
            root: h32(FC2_CP_ROOT),
            log_signature: h64(FC2_CP_LOG_SIG),
            cosignatures: vec![
                Cosignature {
                    key_hash: h32(KH_NISSE),
                    timestamp: FC2_TS,
                    signature: h64(FC2_COSIG_NISSE),
                },
                Cosignature {
                    key_hash: h32(KH_RGDD),
                    timestamp: FC2_TS,
                    signature: h64(FC2_COSIG_RGDD),
                },
                Cosignature {
                    key_hash: h32(KH_SMARTIT),
                    timestamp: FC2_TS,
                    signature: h64(FC2_COSIG_SMARTIT),
                },
            ],
        }
    }

    fn fc2_head_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Head {
                slug: FC2_SLUG.to_string(),
                ordinal: 1,
                chain_hash: FC2_CHAIN_HASH.to_string(),
            },
            submitter_signature: h64(FC2_HEAD_SIG),
            submitter_key_hash: h32(FC2_HEAD_KH), // == genesis ⇒ in the identity set
            index: FC2_HEAD_INDEX,
            inclusion_proof: FC2_HEAD_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    /// A well-formed 1-row genesis chain for `verdict_hash` — its chain_hash is
    /// recomputed with the production algorithm, so `verify_public_chain` accepts
    /// it and the ONLY variable the JOIN sees is whether row 1 matches head@1.
    fn fc2_rows_with_verdict(verdict_hash: &str) -> Vec<PublicChainRow> {
        let chain_hash = compute_chain_hash(None, verdict_hash);
        vec![PublicChainRow {
            ordinal: 1,
            verdict_id: Uuid::nil(),
            verdict_hash: verdict_hash.to_string(),
            chain_prev_hash: None,
            chain_hash,
            appended_at: Utc.with_ymd_and_hms(2026, 7, 23, 12, 0, 0).unwrap(),
            ruleset_id: "demo-sbom-presence".to_string(),
            verdict_outcome: "SATISFIED".to_string(),
        }]
    }

    // ---- FROZEN oracle: REAL end-to-end LIFECYCLE (enroll+head+retired) ----
    // One throwaway genesis key K signs all three leaves, so genesis_key_hash ==
    // SHA256(pk_K) == submitter key_hash for each ⇒ all in the identity set
    // (rotations empty). One 1-row genesis chain: head@1 and retired's
    // chain_hash_final both carry chain_hash == SHA256(verdict_hash) == row1. The
    // leaves are REALLY included (197019/197020/197021) under the cosigned
    // 197022 root, captured from the live log. Closes a documented gap: before
    // these vectors, enroll/retired were JOIN-only with no real inclusion
    // vectors.
    const FC3_CP_SIZE: u64 = 197022;
    const FC3_CP_ROOT: &str = "0cb19a49f8516e1141e6246b7166d05b32c12e3286737f715973f5de0a3b7550";
    const FC3_CP_LOG_SIG: &str = "3501cc3c8233c90a465b468cecdffea58e7b5a834612ae20bbc971cac4a09b9ca73d3c77cad73b2f65914150cb91b9115ae6435d9651e380aa73d69163cf7404";
    const FC3_TS: u64 = 1784829480;
    const FC3_COSIG_NISSE: &str = "f2187f0409118cee68b8f05b5afd3d17147655cec87cbec04f6cb2fac5c76c3e33305b6c73798c8080e4925a23891f6da6c4d6e9f759dc9c6ba86b440560a408";
    const FC3_COSIG_RGDD: &str = "704a78fc5686129327abbca5030cf74e345caa6027eef71068400192f95acb1b49fee5d1628f8d6d4172668a8ed9ef408b6b8ccc7d2cda32562118421b26a70b";
    const FC3_COSIG_SMARTIT: &str = "174619e12d9fe1ffeae20733953ac1f8d2a5733adfb9391ec8e923594bb5ae2347acc1e9ab16905d3058cb4389452dbf4fc0fce2ed2a9927f47052576a07de00";

    const FC3_SLUG: &str = "fc3-lifecycle";
    // genesis_key_hash == submitter key_hash == SHA256(pk_K) for ALL three leaves.
    const FC3_KH: &str = "2a390a3439cfcaae5da9564a36e03db6841847a3e9261a01aede3691c1c81794";
    const FC3_VERDICT_HASH: &str =
        "d51d6203cec57b951d61efc166310b030c40539cc4708c216e45b91deb11d362";
    // = compute_chain_hash(None, FC3_VERDICT_HASH); carried by head@1 AND retired's
    // chain_hash_final for the JOIN + retired cross-check.
    const FC3_CHAIN_HASH: &str =
        "d0679ecd0af525491f031a9fb4bb2029575fc7f2a73add0904ffbd72b4c7f109";

    const FC3_ENROLL_INDEX: u64 = 197019;
    const FC3_ENROLL_SIG: &str = "e7e8df6f2f4b3d474f8ed19936fa3add493f9411aa31d880e172be9d6665474747dcb24c8f60470e92b094b5974010c8574737f89d566c2b702a97cc8575f307";
    const FC3_ENROLL_PROOF: &[&str] = &[
        "a8259100117dc73edde73413999638853360b0ca344f0d732fec74e10f7694e2",
        "8f38db8fe8b8cd6cf50758bbc31330ff128b4184f71211369a826ad8ef31b709",
        "fd21aacbf407401265406fd3a3f0f8983d592ab699a7e974ddaad525b02d822e",
        "91e8174e4121cbf13e71064330072b9a66174c74afdbc389bcd77b4dc504dd7a",
        "3058b547c728c35b389b2484f6f15b5001dd96e3a3aa367a978a28249f682dc1",
        "06d71eb1a0b39ac28b5c9aefb97955264702e8ec12b58e5da818974f2f7805ac",
        "b51c5a754ba8b884674f87a6b41b0a1361dfecd26cafdeac99e8ed91991d9125",
        "2387f1500f0756070e7a9c67f417f6036effa82f96c2fbc782cb869c7e144d85",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    const FC3_HEAD_INDEX: u64 = 197020;
    const FC3_HEAD_SIG: &str = "0710a3136da6ea8e6483a0d3f3eaefd51a87b1a08c5e94105b3231a3ad8c0106b3e411936193ec3b850a307575d45ef78d1d1b09233d682abb987234a8c7b40a";
    const FC3_HEAD_PROOF: &[&str] = &[
        "9c587016219bb249ec0fed05889f25512854df472f1c3a4cfe02363fc1bd2dc9",
        "2446f318566c081a727ceba167e3eaaa1638e05147a8ab7b07769f9b11cdbaee",
        "91e8174e4121cbf13e71064330072b9a66174c74afdbc389bcd77b4dc504dd7a",
        "3058b547c728c35b389b2484f6f15b5001dd96e3a3aa367a978a28249f682dc1",
        "06d71eb1a0b39ac28b5c9aefb97955264702e8ec12b58e5da818974f2f7805ac",
        "b51c5a754ba8b884674f87a6b41b0a1361dfecd26cafdeac99e8ed91991d9125",
        "2387f1500f0756070e7a9c67f417f6036effa82f96c2fbc782cb869c7e144d85",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    const FC3_RETIRED_INDEX: u64 = 197021;
    const FC3_RETIRED_SIG: &str = "acfd6fc3e5c0c4a5cdcd4c0758e765bdb06efcb2f94070b80dcffc246ddcc1f68c4f371bd4dfae3a9ef317023c8dfa692ba14052ad9751e576193876943b6509";
    const FC3_RETIRED_PROOF: &[&str] = &[
        "35b3d4e2b05b68ca5cefbf68676c4f0221ee92376b7af509a76dba1f34d12598",
        "2446f318566c081a727ceba167e3eaaa1638e05147a8ab7b07769f9b11cdbaee",
        "91e8174e4121cbf13e71064330072b9a66174c74afdbc389bcd77b4dc504dd7a",
        "3058b547c728c35b389b2484f6f15b5001dd96e3a3aa367a978a28249f682dc1",
        "06d71eb1a0b39ac28b5c9aefb97955264702e8ec12b58e5da818974f2f7805ac",
        "b51c5a754ba8b884674f87a6b41b0a1361dfecd26cafdeac99e8ed91991d9125",
        "2387f1500f0756070e7a9c67f417f6036effa82f96c2fbc782cb869c7e144d85",
        "43bd28c79dec46786a85bdf0fe72eac3985a8fa172979cdbf7dc04d6c506d43d",
    ];

    fn fc3_checkpoint() -> Checkpoint {
        Checkpoint {
            size: FC3_CP_SIZE,
            root: h32(FC3_CP_ROOT),
            log_signature: h64(FC3_CP_LOG_SIG),
            cosignatures: vec![
                Cosignature {
                    key_hash: h32(KH_NISSE),
                    timestamp: FC3_TS,
                    signature: h64(FC3_COSIG_NISSE),
                },
                Cosignature {
                    key_hash: h32(KH_RGDD),
                    timestamp: FC3_TS,
                    signature: h64(FC3_COSIG_RGDD),
                },
                Cosignature {
                    key_hash: h32(KH_SMARTIT),
                    timestamp: FC3_TS,
                    signature: h64(FC3_COSIG_SMARTIT),
                },
            ],
        }
    }

    fn fc3_enroll_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Enroll {
                slug: FC3_SLUG.to_string(),
                mode: Mode::Attested,
            },
            submitter_signature: h64(FC3_ENROLL_SIG),
            submitter_key_hash: h32(FC3_KH), // == genesis ⇒ in the identity set
            index: FC3_ENROLL_INDEX,
            inclusion_proof: FC3_ENROLL_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    fn fc3_head_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Head {
                slug: FC3_SLUG.to_string(),
                ordinal: 1,
                chain_hash: FC3_CHAIN_HASH.to_string(),
            },
            submitter_signature: h64(FC3_HEAD_SIG),
            submitter_key_hash: h32(FC3_KH),
            index: FC3_HEAD_INDEX,
            inclusion_proof: FC3_HEAD_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    fn fc3_retired_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Retired {
                slug: FC3_SLUG.to_string(),
                ordinal_final: 1, // == M (the head's ordinal)
                chain_hash_final: FC3_CHAIN_HASH.to_string(),
            },
            submitter_signature: h64(FC3_RETIRED_SIG),
            submitter_key_hash: h32(FC3_KH),
            index: FC3_RETIRED_INDEX,
            inclusion_proof: FC3_RETIRED_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    fn real_checkpoint() -> Checkpoint {
        Checkpoint {
            size: CP_SIZE,
            root: h32(CP_ROOT),
            log_signature: h64(CP_LOG_SIG),
            cosignatures: vec![
                Cosignature {
                    key_hash: h32(KH_SMARTIT),
                    timestamp: CP_TS,
                    signature: h64(COSIG_SMARTIT),
                },
                Cosignature {
                    key_hash: h32(KH_NISSE),
                    timestamp: CP_TS,
                    signature: h64(COSIG_NISSE),
                },
                Cosignature {
                    key_hash: h32(KH_RGDD),
                    timestamp: CP_TS,
                    signature: h64(COSIG_RGDD),
                },
            ],
        }
    }

    fn real_head_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Head {
                slug: "example-tenant".to_string(),
                ordinal: 42,
                chain_hash: HEAD_CHAIN_HASH.to_string(),
            },
            submitter_signature: h64(HEAD_SIG),
            submitter_key_hash: h32(SUBMITTER_KH),
            index: HEAD_INDEX,
            inclusion_proof: HEAD_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    fn real_rotate_leaf() -> AnchoredLeaf {
        AnchoredLeaf {
            lane: Lane::Rotate {
                rot_ordinal: 7,
                key_hash_old: ROTATE_OLD.to_string(),
                key_hash_new: ROTATE_NEW.to_string(),
            },
            submitter_signature: h64(ROTATE_SIG),
            submitter_key_hash: h32(SUBMITTER_KH),
            index: ROTATE_INDEX,
            inclusion_proof: ROTATE_PROOF.iter().map(|p| h32(p)).collect(),
        }
    }

    /// A VALID n-row chain built with the production hash algorithm.
    fn valid_rows(n: u32) -> Vec<PublicChainRow> {
        let mut rows = Vec::with_capacity(n as usize);
        let mut prev: Option<String> = None;
        for ordinal in 1..=n {
            let verdict_hash = format!("{ordinal:064x}");
            let chain_hash = compute_chain_hash(prev.as_deref(), &verdict_hash);
            rows.push(PublicChainRow {
                ordinal,
                verdict_id: Uuid::nil(),
                verdict_hash,
                chain_prev_hash: prev.clone(),
                chain_hash: chain_hash.clone(),
                appended_at: Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap(),
                ruleset_id: "demo-sbom-presence".to_string(),
                verdict_outcome: "SATISFIED".to_string(),
            });
            prev = Some(chain_hash);
        }
        rows
    }

    // ---- serde (`anchor.json`) --------------------------------------------

    /// A minimal but structurally-complete anchor.json (1-row chain, real
    /// checkpoint, no leaves) that MUST parse.
    fn minimal_json() -> String {
        format!(
            r#"{{
              "version": "seetrex/anchor/v1",
              "tenant_slug": "example-tenant",
              "rows": [
                {{"ordinal":1,"verdict_id":"00000000-0000-0000-0000-000000000000",
                  "verdict_hash":"0000000000000000000000000000000000000000000000000000000000000001",
                  "chain_prev_hash":null,
                  "chain_hash":"{ch}",
                  "appended_at":"2026-07-22T12:00:00Z","ruleset_id":"demo","verdict_outcome":"SATISFIED"}}
              ],
              "checkpoint": {{"size":{sz},"root":"{root}","log_signature":"{lsig}",
                "cosignatures":[{{"key_hash":"{kh}","timestamp":{ts},"signature":"{csig}"}}]}},
              "anchored_leaves": [],
              "rotations": []
            }}"#,
            ch = compute_chain_hash(
                None,
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            sz = CP_SIZE,
            root = CP_ROOT,
            lsig = CP_LOG_SIG,
            kh = KH_SMARTIT,
            ts = CP_TS,
            csig = COSIG_SMARTIT,
        )
    }

    #[test]
    fn parse_minimal_valid_package() {
        let pkg = parse_anchor_package(&minimal_json()).expect("valid package parses");
        assert_eq!(pkg.tenant_slug, "example-tenant");
        assert_eq!(pkg.checkpoint.size, CP_SIZE);
        assert_eq!(pkg.checkpoint.root, h32(CP_ROOT));
        assert_eq!(pkg.rows.len(), 1);
        assert!(pkg.anchored_leaves.is_empty() && pkg.rotations.is_empty());
    }

    #[test]
    fn parse_rejects_unsupported_version() {
        let json = minimal_json().replace("seetrex/anchor/v1", "seetrex/anchor/v2");
        assert_eq!(
            parse_anchor_package(&json).unwrap_err(),
            AnchorJsonError::UnsupportedVersion {
                got: "seetrex/anchor/v2".to_string()
            }
        );
    }

    #[test]
    fn parse_rejects_unknown_envelope_field() {
        // A smuggled `policy` field (the exact attack the trust boundary blocks).
        let json = minimal_json().replace(
            r#""anchored_leaves": [],"#,
            r#""policy": {"witnesses": []}, "anchored_leaves": [],"#,
        );
        assert!(matches!(
            parse_anchor_package(&json),
            Err(AnchorJsonError::Json(_))
        ));
    }

    #[test]
    fn parse_rejects_bad_hex_root() {
        let json = minimal_json().replace(CP_ROOT, "zz");
        assert!(matches!(
            parse_anchor_package(&json),
            Err(AnchorJsonError::InvalidHex {
                field: "checkpoint.root",
                ..
            })
        ));
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        // Non-canonical (uppercase) hex is not a package we would emit.
        let json = minimal_json().replace(CP_ROOT, &CP_ROOT.to_uppercase());
        assert!(matches!(
            parse_anchor_package(&json),
            Err(AnchorJsonError::InvalidHex { .. })
        ));
    }

    #[test]
    fn parse_round_trips_all_lane_kinds() {
        // Build a package carrying one of each lane in anchored_leaves/rotations
        // (structure only; crypto is exercised by the orchestration tests).
        let leaf = |lane_json: &str| {
            format!(
                r#"{{"lane":{lane_json},"submitter_signature":"{sig}",
                   "submitter_key_hash":"{kh}","index":1,"inclusion_proof":[]}}"#,
                sig = HEAD_SIG,
                kh = SUBMITTER_KH,
            )
        };
        let anchored = format!(
            "[{},{},{}]",
            leaf(r#"{"kind":"head","slug":"example-tenant","ordinal":42,"chain_hash":"5fe66186d8e2100608f5b914fe260f08c57cc894087966a637f452a0f606c689"}"#),
            leaf(r#"{"kind":"enroll","slug":"example-tenant","mode":"attested"}"#),
            leaf(r#"{"kind":"retired","slug":"example-tenant","ordinal_final":128,"chain_hash_final":"bdb9175e8d400bcbb455f95046eaad430f7129a779b9b0a60fa2bb3641a6083c"}"#),
        );
        let rotations = format!(
            "[{}]",
            leaf(r#"{"kind":"rotate","rot_ordinal":7,"key_hash_old":"fa3580190786e1de2c17600bc6ce2e2785656b6b7c20154f14de9f39927bde77","key_hash_new":"b1a5b27125d5774fa89405492bab3ef3b2a941f0307e21b0b0116668a161d2c4"}"#),
        );
        let json = minimal_json()
            .replace(r#""anchored_leaves": [],"#, &format!(r#""anchored_leaves": {anchored},"#))
            .replace(r#""rotations": []"#, &format!(r#""rotations": {rotations}"#));
        let pkg = parse_anchor_package(&json).expect("all lane kinds parse");
        assert_eq!(pkg.anchored_leaves.len(), 3);
        assert_eq!(pkg.rotations.len(), 1);
        assert!(matches!(pkg.anchored_leaves[0].lane, Lane::Head { .. }));
        assert!(matches!(pkg.anchored_leaves[1].lane, Lane::Enroll { mode: Mode::Attested, .. }));
        assert!(matches!(pkg.rotations[0].lane, Lane::Rotate { .. }));
    }

    #[test]
    fn parse_rejects_bad_enroll_mode() {
        let json = minimal_json().replace(
            r#""anchored_leaves": [],"#,
            &format!(
                r#""anchored_leaves": [{{"lane":{{"kind":"enroll","slug":"example-tenant","mode":"bogus"}},
                   "submitter_signature":"{HEAD_SIG}","submitter_key_hash":"{SUBMITTER_KH}",
                   "index":1,"inclusion_proof":[]}}],"#
            ),
        );
        assert_eq!(
            parse_anchor_package(&json).unwrap_err(),
            AnchorJsonError::InvalidMode {
                value: "bogus".to_string()
            }
        );
    }

    // ---- auditor kit (`seetrex/anchor-kit/v1`) ----------------------------

    /// A minimal valid kit: synthetic pinned genesis + the REAL Glasklar
    /// `sigsum-test1-2025` policy (3 witnesses, quorum 2).
    fn minimal_kit_json() -> String {
        format!(
            r#"{{ "version": "seetrex/anchor-kit/v1", "tenant_slug": "example-tenant",
               "genesis_key_hash": "{gen}",
               "policy": {{ "log_pubkey": "{log}",
                 "witnesses": ["{w1}", "{w2}", "{w3}"], "quorum_k": 2 }} }}"#,
            gen = "11".repeat(32),
            log = LOG_PK,
            w1 = WIT_NISSE,
            w2 = WIT_RGDD,
            w3 = WIT_SMARTIT,
        )
    }

    #[test]
    fn parse_valid_kit() {
        let kit = parse_auditor_kit(&minimal_kit_json()).expect("valid kit parses");
        assert_eq!(kit.tenant_slug, "example-tenant");
        assert_eq!(kit.genesis_key_hash, [0x11u8; 32]);
        assert_eq!(kit.policy.log_pubkey, h32(LOG_PK));
        assert_eq!(kit.policy.witnesses.len(), 3);
        assert_eq!(kit.policy.quorum_k, 2);
    }

    #[test]
    fn kit_rejects_unsupported_version() {
        let json = minimal_kit_json().replace("anchor-kit/v1", "anchor-kit/v2");
        assert_eq!(
            parse_auditor_kit(&json).unwrap_err(),
            KitError::UnsupportedVersion {
                got: "seetrex/anchor-kit/v2".to_string()
            }
        );
    }

    #[test]
    fn kit_rejects_unknown_policy_field() {
        // An extra field inside `policy` (deny_unknown_fields on the DTO) — a
        // kit we would not emit is malformed even though the kit is trusted.
        let json = minimal_kit_json().replace(r#""quorum_k": 2 }"#, r#""quorum_k": 2, "extra": true }"#);
        assert!(matches!(parse_auditor_kit(&json), Err(KitError::Json(_))));
    }

    #[test]
    fn kit_rejects_zero_quorum() {
        // quorum_k = 0 would accept the log signature alone (no split-view
        // protection) — the pinned-policy invariant this parser enforces.
        let json = minimal_kit_json().replace(r#""quorum_k": 2"#, r#""quorum_k": 0"#);
        assert_eq!(
            parse_auditor_kit(&json).unwrap_err(),
            KitError::InvalidQuorum
        );
    }

    #[test]
    fn kit_rejects_quorum_exceeding_witnesses() {
        // quorum 4 over 3 witnesses = unsatisfiable ⇒ a CONFIG error (exit-2
        // channel), not a silent policy that fails every package as a spurious
        // vendor failure (blind crypto-review LOW-1).
        let json = minimal_kit_json().replace(r#""quorum_k": 2"#, r#""quorum_k": 4"#);
        assert_eq!(
            parse_auditor_kit(&json).unwrap_err(),
            KitError::QuorumExceedsWitnesses {
                quorum_k: 4,
                witnesses: 3
            }
        );
    }

    #[test]
    fn kit_rejects_bad_hex_genesis() {
        let json = minimal_kit_json().replace(&"11".repeat(32), "zz");
        assert!(matches!(
            parse_auditor_kit(&json),
            Err(KitError::InvalidHex {
                field: "genesis_key_hash",
                ..
            })
        ));
    }

    // ---- orchestration (verify_anchored_package) --------------------------

    #[test]
    fn package_rotate_only_verifies_and_surfaces_anomaly() {
        // Real rotate leaf (Unauthorized: submitter != old), no tenant leaves, a
        // valid chain ⇒ CONSISTENCIA Verified, COMPLETITUD Inconclusive, and the
        // rotation SURFACED as an anomaly (not fatal offline).
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![real_rotate_leaf()],
        };
        let genesis = [0x11u8; 32]; // synthetic pinned genesis, not the submitter
        let report = verify_anchored_package("example-tenant", genesis, &real_policy(), &pkg, None);
        assert_eq!(report.consistencia, Verdict::Verified);
        assert!(matches!(report.completitud, Verdict::Inconclusive { .. }));
        let identity = report.identity.expect("identity derived");
        assert_eq!(identity.keys, vec![genesis]);
        assert_eq!(identity.anomalous_rotations.len(), 1);
        assert_eq!(
            identity.anomalous_rotations[0].reason,
            AnomalyReason::Unauthorized
        );
    }

    #[test]
    fn test_intent_real_authorized_rotation_extends_identity_set() {
        // INTENT: the AUTHORIZED-rotation branch (`anchor.rs`: `submitter ==
        // key_hash_old` ⇒ extend the producer set) is exercised end-to-end
        // against REAL log-attested crypto, not only synthetic RotationRecords.
        // CONTEXT: the only prior REAL rotate vector (196056) is Unauthorized
        // by construction (submitter ≠ payload old), so before this vector no
        // REAL leaf ever grew the identity set — that branch had synthetic
        // coverage only, a documented caveat.
        // EXPIRES IF: the identity model stops deriving the producer set from
        // genesis + authorized rotations (e.g. a different authorization rule).
        // (The vector is a FROZEN inline oracle, so it is independent of the live
        // test log's later state.)
        //
        // Leaf 196700 was submitted under K_old whose key_hash IS its payload
        // key_hash_old ⇒ submitter == old ⇒ AUTHORIZED. Its inclusion under the
        // real cosigned 196702 checkpoint is the round-trip; from a genesis pinned
        // to K_old the derivation must extend the set to include K_new.
        let genesis = h32(ROT2_KH_OLD);
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint_n3(),
            anchored_leaves: vec![],
            rotations: vec![real_authorized_rotate_leaf()],
        };
        let report =
            verify_anchored_package("example-tenant", genesis, &real_policy(), &pkg, None);
        assert_eq!(report.consistencia, Verdict::Verified);
        let identity = report.identity.expect("identity derived");
        // The set GREW: genesis (K_old) + the authorized successor (K_new).
        assert!(identity.keys.contains(&genesis), "genesis retained");
        assert!(
            identity.keys.contains(&h32(ROT2_KH_NEW)),
            "new key added by the authorized rotation"
        );
        assert_eq!(
            identity.keys.len(),
            2,
            "exactly genesis + one authorized successor"
        );
        // AUTHORIZED ⇒ NOT surfaced as an anomaly (contrast the 196056 test).
        assert!(
            identity.anomalous_rotations.is_empty(),
            "an authorized rotation is not an anomaly"
        );
    }

    #[test]
    fn package_tenant_slug_mismatch_fails_closed() {
        // The package declares tenant "example-tenant" but the auditor is auditing
        // "other-tenant" ⇒ category-error guard ⇒ FAILED before any crypto, no
        // identity derived. (Blind crypto-review LOW: pkg.tenant_slug must not be
        // silently ignored.)
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![],
        };
        let report = verify_anchored_package("other-tenant", [0x11u8; 32], &real_policy(), &pkg, None);
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("does not match the audited tenant"),
                "expected a tenant-mismatch failure, got: {reason}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(report.identity, None);
    }

    #[test]
    fn package_head_leaf_submitter_not_in_identity_fails() {
        // The head leaf's inclusion crypto is REAL and valid, but the pinned
        // genesis identity set does NOT contain its submitter ⇒ FAILED. Proves
        // step-2 is gated by the DERIVED identity set (shared-log forgery guard).
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![real_head_leaf()],
            rotations: vec![],
        };
        let not_the_submitter = [0x11u8; 32];
        let report =
            verify_anchored_package("example-tenant", not_the_submitter, &real_policy(), &pkg, None);
        // Assert the FAILURE REASON so this isolates step-2 (identity gating),
        // which runs and short-circuits BEFORE the JOIN — not the JOIN failure.
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("producer identity set"),
                "expected an identity-gating failure, got: {reason}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn package_head_leaf_included_but_join_fails() {
        // Pin genesis = the real submitter, so the head leaf's inclusion PASSES
        // (step 2). But the chain is only 3 rows while the leaf is head@42 ⇒ the
        // package JOIN FAILS (ordinal beyond N). Proves inclusion alone is not
        // enough and the JOIN is wired.
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![real_head_leaf()],
            rotations: vec![],
        };
        let genesis = h32(SUBMITTER_KH); // the head leaf's real submitter
        let report = verify_anchored_package("example-tenant", genesis, &real_policy(), &pkg, None);
        // Assert the JOIN reason: this isolates step-3 (the head leaf's inclusion
        // PASSED step-2, so the only remaining failure is the package JOIN).
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("beyond chain length"),
                "expected a JOIN (truncation) failure, got: {reason}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn package_tampered_rotate_leaf_fails() {
        // A rotate leaf whose inclusion proof is tampered ⇒ the rotate-inclusion gate fails ⇒
        // CONSISTENCIA Failed, identity None (no record built on unattested data).
        let mut bad = real_rotate_leaf();
        bad.inclusion_proof[0][0] ^= 0x01;
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![bad],
        };
        let report = verify_anchored_package("example-tenant", [0x11u8; 32], &real_policy(), &pkg, None);
        assert!(matches!(report.consistencia, Verdict::Failed { .. }));
        assert_eq!(report.identity, None);
    }

    /// INTENT: with NO monitor supplied (`None`), the two verdicts never collapse
    ///   — even a fully offline-verifying package keeps COMPLETITUD
    ///   INCONCLUSO. A VERIFIED CONSISTENCIA must never be read as completeness
    ///   (that needs a monitor enumeration).
    /// CONTEXT: the whole point of the v6 redesign — a single "VERIFIED OFFLINE"
    ///   was misread as completeness it never proved. A SUPPLIED
    ///   monitor CAN raise COMPLETITUD; the DEFAULT (`None`) must still not.
    /// EXPIRES IF: the no-monitor default stops being INCONCLUSO (e.g. the report
    ///   is redesigned to carry a distinct "no-monitor" state instead).
    #[test]
    fn test_intent_package_completitud_never_collapses() {
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![real_rotate_leaf()],
        };
        let report = verify_anchored_package("example-tenant", [0x11u8; 32], &real_policy(), &pkg, None);
        assert_eq!(report.consistencia, Verdict::Verified);
        assert!(
            matches!(report.completitud, Verdict::Inconclusive { .. }),
            "COMPLETITUD must be INCONCLUSO with no monitor even when the offline half verifies"
        );
    }

    // ---- COMPLETITUD wiring -----------------------------------------------
    // These prove the PLUMBING: `None` preserves INCONCLUSO (above), `Some` runs
    // the real rules and can RAISE (Verified) or DOWNGRADE (Failed) the top-level
    // verdict, and the package checkpoint feeding the freshness reference is
    // authenticated first. The rich non-vacuous served-head Verified is proven at
    // the rules level (anchor_completitud::tests::
    // verify_completitud_end_to_end_real_crypto_served_verifies — the
    // anti-tautology split).

    #[test]
    fn package_with_honest_monitor_raises_completitud_to_verified() {
        // A producer that anchored NOTHING (valid chain, zero leaves/rotations) +
        // an honest fresh monitor (real cosigned C_audit == the package checkpoint
        // ⇒ degenerate consistency) ⇒ CONSISTENCIA Verified (vacuous) AND
        // COMPLETITUD Verified — the wire raises the verdict off the fixed
        // INCONCLUSO. Genesis is irrelevant (no leaves to identity-gate).
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![],
        };
        let enumeration = MonitorEnumeration {
            c_audit: real_checkpoint(),
            leaves: vec![],
            consistency_proof: vec![],
        };
        let monitor = MonitorAudit {
            enumeration: &enumeration,
            observations: &[],
        };
        let report = verify_anchored_package(
            "example-tenant",
            [0x11u8; 32],
            &real_policy(),
            &pkg,
            Some(&monitor),
        );
        assert_eq!(report.consistencia, Verdict::Verified);
        assert_eq!(
            report.completitud,
            Verdict::Verified,
            "an honest fresh monitor must raise COMPLETITUD off INCONCLUSO"
        );
    }

    #[test]
    fn package_with_monitor_enumerating_alien_key_downgrades_to_failed() {
        // The producer anchored nothing (CONSISTENCIA verifies vacuously), but the
        // monitor enumerates a REAL leaf whose submitter is NOT in the pinned
        // identity set (genesis != the leaf's real submitter) ⇒ G-v6-7 ⇒
        // COMPLETITUD Failed. Proves a supplied monitor can DOWNGRADE the verdict —
        // the omission/fork signal the offline half is structurally blind to.
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![],
        };
        let enumeration = MonitorEnumeration {
            c_audit: real_checkpoint(),
            leaves: vec![real_head_leaf()], // submitter = SUBMITTER_KH
            consistency_proof: vec![],
        };
        let monitor = MonitorAudit {
            enumeration: &enumeration,
            observations: &[],
        };
        // Pinned genesis is a synthetic key, NOT the leaf's real submitter.
        let report = verify_anchored_package(
            "example-tenant",
            [0x11u8; 32],
            &real_policy(),
            &pkg,
            Some(&monitor),
        );
        assert_eq!(report.consistencia, Verdict::Verified);
        assert!(
            matches!(report.completitud, Verdict::Failed { .. }),
            "an enumerated alien-key leaf must FAIL COMPLETITUD, got {:?}",
            report.completitud
        );
    }

    /// INTENT: the package checkpoint that anchors R8's freshness reference MUST be
    ///   authenticated before it is fed to `verify_completitud` — even for a
    ///   package with ZERO rotations and ZERO anchored leaves, where the
    ///   CONSISTENCIA path verifies vacuously and never touches the checkpoint
    ///   cosig. Without the explicit `verify_checkpoint` guard, a forged-cosig
    ///   checkpoint's size/root would satisfy R8's HARD caller obligation for free
    ///   and a supplied monitor could green-light COMPLETITUD against a checkpoint
    ///   the witnesses never signed.
    /// CONTEXT: `verify_completitud` PINS `package_checkpoint_{size,root}` as the
    ///   cosigned checkpoint; the orchestrator must DISCHARGE that obligation, not
    ///   assume it. The zero-leaf package is exactly the path that skips the
    ///   inclusion loops that would otherwise authenticate the checkpoint.
    /// EXPIRES IF: the checkpoint cosig becomes authenticated unconditionally
    ///   upstream of the COMPLETITUD branch (then this explicit guard is redundant).
    #[test]
    fn test_intent_package_checkpoint_must_authenticate_before_completitud() {
        // Break the quorum entirely so verify_checkpoint fails; leave the root
        // untouched so a MISSING guard would feed the real root and spuriously
        // pass R8 (the mutation that must turn this test RED).
        let mut bad_cp = real_checkpoint();
        for cosig in &mut bad_cp.cosignatures {
            cosig.signature[0] ^= 0x01;
        }
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: bad_cp,
            anchored_leaves: vec![],
            rotations: vec![],
        };
        let enumeration = MonitorEnumeration {
            c_audit: real_checkpoint(),
            leaves: vec![],
            consistency_proof: vec![],
        };
        let monitor = MonitorAudit {
            enumeration: &enumeration,
            observations: &[],
        };
        let report = verify_anchored_package(
            "example-tenant",
            [0x11u8; 32],
            &real_policy(),
            &pkg,
            Some(&monitor),
        );
        // CONSISTENCIA still verifies vacuously (it never authenticated the cp).
        assert_eq!(report.consistencia, Verdict::Verified);
        // COMPLETITUD must fail closed: the freshness reference is unauthenticated.
        assert!(
            matches!(report.completitud, Verdict::Inconclusive { .. }),
            "an unauthenticated package checkpoint must not certify COMPLETITUD, got {:?}",
            report.completitud
        );
    }

    /// INTENT: the witness policy and the pinned genesis are AUDITOR-KIT inputs,
    ///   NEVER carried in the untrusted `anchor.json`. The wire schema has no
    ///   field for either (they are parameters of `verify_anchored_package`), and
    ///   `deny_unknown_fields` rejects any package that tries to smuggle one.
    /// CONTEXT: if a package could name its own witnesses or its own genesis, an
    ///   attacker would authenticate their own forgery (the pinned witness
    ///   policy and the pinned genesis identity chain) — the entire
    ///   external-anchor trust model would collapse.
    /// EXPIRES IF: the policy/genesis distribution model changes (e.g. a signed,
    ///   pinned policy bundle is embedded — then this test is revised in the same
    ///   PR that adds the trusted embedding).
    #[test]
    fn test_intent_policy_and_genesis_are_pinned_not_from_package() {
        // (a) A package naming a policy fails to parse (deny_unknown_fields).
        let with_policy = minimal_json().replace(
            r#""rotations": []"#,
            r#""rotations": [], "policy": {"witnesses": [], "quorum_k": 1}"#,
        );
        assert!(matches!(
            parse_anchor_package(&with_policy),
            Err(AnchorJsonError::Json(_))
        ));
        // (b) A package naming a genesis key also fails to parse.
        let with_genesis = minimal_json().replace(
            r#""rotations": []"#,
            r#""rotations": [], "genesis_key_hash": "0000000000000000000000000000000000000000000000000000000000000000""#,
        );
        assert!(matches!(
            parse_anchor_package(&with_genesis),
            Err(AnchorJsonError::Json(_))
        ));
    }

    #[test]
    fn parse_monitor_audit_happy_and_rejections() {
        // 64-byte all-zero log_signature (128 zero chars) + real 32-byte root, so
        // `into_checkpoint`'s hex_fixed::<64>/<32> both succeed on the happy path.
        let ok = r#"{"version":"seetrex/anchor-monitor/v1","c_audit":{"size":196372,
            "root":"848aff0ecb7315a0fc1cc4a00c1065b51b4c269ff871dc2f048711892739a06e",
            "log_signature":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","cosignatures":[]},"leaves":[],"consistency_proof":[],
            "observations":[{"slug":"acme-corp","served":true}]}"#;
        let parsed = parse_monitor_audit(ok).expect("well-formed bundle parses");
        assert_eq!(parsed.enumeration.c_audit.size, 196372);
        assert_eq!(parsed.observations.len(), 1);

        let bad_ver = ok.replace("anchor-monitor/v1", "anchor-monitor/v2");
        assert!(matches!(
            parse_monitor_audit(&bad_ver),
            Err(MonitorError::UnsupportedVersion { .. })
        ));

        let extra = ok.replace(r#""observations""#, r#""surprise":1,"observations""#);
        assert!(matches!(
            parse_monitor_audit(&extra),
            Err(MonitorError::Json(_))
        ));

        let bad_hex = ok.replace("848aff0ecb7315a0", "848aff0ecb7315a");
        assert!(matches!(
            parse_monitor_audit(&bad_hex),
            Err(MonitorError::Convert(_))
        ));
    }

    // ---- emit (`emit_anchor_package`) --------------------------------------
    // The producer is the INVERSE of the parser and shares the ONE DTO
    // definition (format agreement is the SPEC, not the falsifiable claim). The
    // falsifiable oracle is the REAL test.sigsum.org log: a package built from
    // real inclusion evidence must round-trip to VERIFIED, and any lane-field
    // mutation must break the real inclusion proof (anti-tautology).

    /// A producer derives the `head` lane from the tenant chain's LAST row —
    /// `ordinal = N`, `chain_hash = row N`. The honest linkage the JOIN checks.
    fn head_lane_from_chain(rows: &[PublicChainRow]) -> Lane {
        let last = rows.last().expect("non-empty chain");
        Lane::Head {
            slug: "example-tenant".to_string(),
            ordinal: u64::from(last.ordinal),
            chain_hash: last.chain_hash.clone(),
        }
    }

    // ---- T1: round-trip to VERIFIED against REAL crypto + mutation ---------

    #[test]
    fn emit_roundtrip_rotate_only_reaches_verified() {
        // Central falsifier: a REAL rotate-only package → emit → parse → verify
        // must reach CONSISTENCIA Verified (mirrors
        // package_rotate_only_verifies_and_surfaces_anomaly, but THROUGH the
        // producer). The rotate leaf's inclusion proof is REAL test.sigsum.org
        // data, so a passing round-trip is not Rust-verifying-Rust.
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![real_rotate_leaf()],
        };
        let json = emit_anchor_package(&pkg).expect("honest package emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report =
            verify_anchored_package("example-tenant", [0x11u8; 32], &real_policy(), &reparsed, None);
        assert_eq!(report.consistencia, Verdict::Verified);
    }

    #[test]
    fn emit_roundtrip_mutated_rotate_lane_fails_inclusion() {
        // The mutation that proves T1 is not a tautology: flip a rotate LANE
        // field (rot_ordinal 7→8) BEFORE emitting. The emitted lane still
        // serializes (8 is a valid ordinal), but its re-derived checksum no
        // longer matches the REAL inclusion proof captured for rot_ordinal 7 ⇒
        // the rotate-inclusion gate FAILS ⇒ CONSISTENCIA Failed. Same package as the
        // GREEN test, one field changed — the falsifiable difference is the real
        // log, not our code.
        let mut leaf = real_rotate_leaf();
        match &mut leaf.lane {
            Lane::Rotate { rot_ordinal, .. } => *rot_ordinal = 8, // was 7
            _ => panic!("real_rotate_leaf must be a rotate lane"),
        }
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(3),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![],
            rotations: vec![leaf],
        };
        let json = emit_anchor_package(&pkg).expect("a valid-ordinal lane still emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report =
            verify_anchored_package("example-tenant", [0x11u8; 32], &real_policy(), &reparsed, None);
        // Pin the FAILED reason to the INCLUSION gate specifically — otherwise the
        // test name ("fails_inclusion") is stronger than its assertion: any other
        // Failed path (e.g. identity derivation) would satisfy a bare `Failed{..}`.
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("not included in the authenticated tree"),
                "a mutated lane must fail at the inclusion gate, got reason: {reason:?}"
            ),
            other => panic!("expected Failed at the inclusion gate, got {other:?}"),
        }
    }

    // ---- the `head` lane reaches VERIFIED end-to-end via REAL inclusion ----

    #[test]
    fn test_intent_real_head_lane_reaches_verified_via_inclusion() {
        // INTENT: the `head` lane reaches CONSISTENCIA=Verified END-TO-END through
        // the producer (emit → parse → verify), with all THREE gates passing. The
        // DECISIVE crypto is LOG-ATTESTED: the leaf's inclusion (196829) under the
        // real cosigned 196830 root (checkpoint authenticated by the log signature +
        // 2-of-3 pinned witnesses). Identity (submitter == genesis) and the JOIN
        // (head@1 == row 1) are checked against a LOCALLY-built genesis chain — but
        // the JOIN's chain_hash is itself committed into the real anchored leaf's
        // checksum, so the linkage rides on log-attested data, not just local config.
        // CONTEXT: before this vector, `head` had only a BYTE-ORACLE — leaf 196053
        // carries a SYNTHETIC chain_hash, so no real chain reproduces it and the
        // JOIN was structurally unsatisfiable; no head package ever reached
        // Verified — a documented caveat until this test.
        // EXPIRES IF: the per-tenant lane pipeline stops requiring real inclusion,
        // or the JOIN stops binding head@k to row k's chain_hash.
        // (Vector = FROZEN inline oracle captured from the live log; independent
        // of the log's later state, like the rotate oracle.)
        let genesis = h32(FC2_HEAD_KH);
        let pkg = AnchorPackage {
            tenant_slug: FC2_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC2_VERDICT_HASH),
            checkpoint: fc2_checkpoint(),
            anchored_leaves: vec![fc2_head_leaf()],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("honest head package emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC2_SLUG, genesis, &real_policy(), &reparsed, None);
        assert_eq!(report.consistencia, Verdict::Verified);
    }

    #[test]
    fn emit_roundtrip_mutated_head_proof_fails_inclusion() {
        // Anti-tautology: flip ONE node of the head leaf's REAL inclusion
        // proof BEFORE emitting. The lane still serializes and the chain still
        // matches the JOIN, but the RFC 6962 fold no longer reaches the real
        // cosigned 196830 root ⇒ inclusion FAILS. The falsifiable difference is the
        // log's Merkle proof, not our code — a passing GREEN test is not self-proof.
        let mut leaf = fc2_head_leaf();
        leaf.inclusion_proof[0][0] ^= 0x01; // corrupt one byte of one proof node
        let pkg = AnchorPackage {
            tenant_slug: FC2_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC2_VERDICT_HASH),
            checkpoint: fc2_checkpoint(),
            anchored_leaves: vec![leaf],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("a structurally-valid leaf still emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC2_SLUG, h32(FC2_HEAD_KH), &real_policy(), &reparsed, None);
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("not included in the authenticated tree"),
                "a corrupted proof must fail at the inclusion gate, got reason: {reason:?}"
            ),
            other => panic!("expected Failed at the inclusion gate, got {other:?}"),
        }
    }

    #[test]
    fn emit_roundtrip_head_row_mismatch_fails_join() {
        // JOIN isolation (the axis that kept `head` stuck): keep the REAL head leaf
        // (inclusion + identity still pass) but pair it with a DIFFERENT well-formed
        // 1-row chain (verdict_hash all-zeros ⇒ a valid but different chain_hash).
        // head@1 no longer matches row 1 ⇒ the JOIN FAILS — proving the linkage to a
        // real chain is load-bearing, not just the inclusion crypto.
        let other_verdict = "0000000000000000000000000000000000000000000000000000000000000001";
        let pkg = AnchorPackage {
            tenant_slug: FC2_SLUG.to_string(),
            rows: fc2_rows_with_verdict(other_verdict),
            checkpoint: fc2_checkpoint(),
            anchored_leaves: vec![fc2_head_leaf()],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("honest package emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC2_SLUG, h32(FC2_HEAD_KH), &real_policy(), &reparsed, None);
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("chain_hash does not match row"),
                "a mismatched chain must fail at the JOIN gate, got reason: {reason:?}"
            ),
            other => panic!("expected Failed at the JOIN gate, got {other:?}"),
        }
    }

    // ---- `retired` and `enroll` lanes reach VERIFIED via REAL inclusion ----

    #[test]
    fn test_intent_real_retired_lane_reaches_verified_via_inclusion() {
        // INTENT: the `retired` lane reaches CONSISTENCIA=Verified END-TO-END through
        // the producer, with ALL THREE gates passing. retired needs a HEAD leaf in the
        // package to fix M (verify_consistencia step 4); both leaves are REALLY included
        // (197020/197021) under the cosigned 197022 root, both signed by the genesis key
        // (identity), and the cross-check binds retired to the real chain
        // (ordinal_final == M == 1, chain_hash_final == row1.chain_hash). The DECISIVE
        // crypto is LOG-ATTESTED (inclusion under the 2-of-3 cosigned root); the JOIN's
        // chain_hash_final is committed into the real retired leaf's checksum, so the
        // linkage rides on log-attested data, not just local config.
        // CONTEXT: enroll/retired were documented as JOIN-only, with no real
        // inclusion vectors and explicitly NOT claimed closed. This is that
        // closing slice for retired.
        // EXPIRES IF: the per-tenant lane pipeline stops requiring real inclusion, or the
        // retired cross-check stops binding (ordinal_final, chain_hash_final) to head@M.
        let genesis = h32(FC3_KH);
        let pkg = AnchorPackage {
            tenant_slug: FC3_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC3_VERDICT_HASH),
            checkpoint: fc3_checkpoint(),
            anchored_leaves: vec![fc3_head_leaf(), fc3_retired_leaf()],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("honest retired package emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC3_SLUG, genesis, &real_policy(), &reparsed, None);
        assert_eq!(report.consistencia, Verdict::Verified);
    }

    #[test]
    fn test_intent_real_enroll_lane_reaches_verified_via_inclusion() {
        // INTENT: the `enroll` lane reaches CONSISTENCIA=Verified END-TO-END through
        // the producer, with its TWO falsifiable gates passing: INCLUSION (real Merkle
        // proof of leaf 197019 under the cosigned 197022 root) and IDENTITY (submitter
        // == genesis key_hash). `enroll` has NO JOIN by lane design — verify_consistencia
        // has no Enroll branch (it only re-serializes the lane, step 2). We do NOT claim
        // a JOIN it does not have: enroll's honest VERIFIED rests entirely on real log
        // inclusion + real producer identity, which is the COMPLETE claim for this lane.
        // CONTEXT: enroll was documented as JOIN-only without a real inclusion
        // vector. This closes it — the enroll leaf is now genuinely log-attested.
        // EXPIRES IF: `enroll` gains a JOIN binding in verify_consistencia (then a chain
        // linkage assertion would also be required here), or inclusion stops being enforced.
        let genesis = h32(FC3_KH);
        let pkg = AnchorPackage {
            tenant_slug: FC3_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC3_VERDICT_HASH),
            checkpoint: fc3_checkpoint(),
            anchored_leaves: vec![fc3_enroll_leaf()],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("honest enroll package emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC3_SLUG, genesis, &real_policy(), &reparsed, None);
        assert_eq!(report.consistencia, Verdict::Verified);
    }

    #[test]
    fn test_scenario_fc3_full_lifecycle_enroll_head_retired() {
        // SCENARIO: a coherent single-tenant LIFECYCLE anchored to the real log —
        // enroll(attested) -> head@1 (one verdict) -> retired(ordinal_final=1). All three
        // leaves in one package, all really included under the cosigned root, all signed
        // by the one genesis key. Exercises the interaction of the three per-tenant lanes:
        // enroll (no JOIN — only re-serialization, step 2), head@1 == row1 (JOIN), retired cross-check
        // (ordinal_final == M == 1, chain_hash_final == row1). Reaching VERIFIED proves the
        // whole lifecycle is consistent against log-attested crypto, not just each lane in
        // isolation.
        let genesis = h32(FC3_KH);
        let pkg = AnchorPackage {
            tenant_slug: FC3_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC3_VERDICT_HASH),
            checkpoint: fc3_checkpoint(),
            anchored_leaves: vec![fc3_enroll_leaf(), fc3_head_leaf(), fc3_retired_leaf()],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("honest lifecycle package emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC3_SLUG, genesis, &real_policy(), &reparsed, None);
        assert_eq!(report.consistencia, Verdict::Verified);
    }

    #[test]
    fn emit_roundtrip_mutated_retired_proof_fails_inclusion() {
        // Anti-tautology for retired: flip ONE node of the retired leaf's REAL
        // inclusion proof BEFORE emitting. The lane still serializes and the cross-check
        // still matches, but the RFC 6962 fold no longer reaches the cosigned 197022 root
        // ⇒ inclusion FAILS. The falsifiable difference is the log's Merkle proof, not our
        // code. (The head leaf is kept intact so only retired's inclusion is at issue.)
        let mut retired = fc3_retired_leaf();
        retired.inclusion_proof[0][0] ^= 0x01;
        let pkg = AnchorPackage {
            tenant_slug: FC3_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC3_VERDICT_HASH),
            checkpoint: fc3_checkpoint(),
            anchored_leaves: vec![fc3_head_leaf(), retired],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("a structurally-valid leaf still emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC3_SLUG, h32(FC3_KH), &real_policy(), &reparsed, None);
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("not included in the authenticated tree"),
                "a corrupted retired proof must fail at the inclusion gate, got: {reason:?}"
            ),
            other => panic!("expected Failed at the inclusion gate, got {other:?}"),
        }
    }

    #[test]
    fn emit_roundtrip_mutated_enroll_proof_fails_inclusion() {
        // Anti-tautology for enroll — the ONLY decisive crypto enroll has: flip ONE
        // node of the enroll leaf's REAL inclusion proof. Identity still passes (submitter
        // == genesis), but the fold no longer reaches the cosigned 197022 root ⇒ inclusion
        // FAILS. Since enroll has no JOIN, this is the load-bearing falsifier for the lane.
        let mut enroll = fc3_enroll_leaf();
        enroll.inclusion_proof[0][0] ^= 0x01;
        let pkg = AnchorPackage {
            tenant_slug: FC3_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC3_VERDICT_HASH),
            checkpoint: fc3_checkpoint(),
            anchored_leaves: vec![enroll],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("a structurally-valid leaf still emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC3_SLUG, h32(FC3_KH), &real_policy(), &reparsed, None);
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("not included in the authenticated tree"),
                "a corrupted enroll proof must fail at the inclusion gate, got: {reason:?}"
            ),
            other => panic!("expected Failed at the inclusion gate, got {other:?}"),
        }
    }

    #[test]
    fn emit_roundtrip_enroll_alien_submitter_fails_identity() {
        // Identity isolation for enroll: keep the REAL enroll leaf but replace its
        // submitter_key_hash with a key NOT in the pinned identity set. The inclusion
        // gate's identity step (verify_anchored_inclusion 0b) rejects it BEFORE the Merkle
        // check — "inclusion in the shared log does not make the leaf ours". Proves the
        // submitter==genesis binding is load-bearing, not decorative.
        let mut enroll = fc3_enroll_leaf();
        enroll.submitter_key_hash = [0xAB; 32]; // not the genesis key
        let pkg = AnchorPackage {
            tenant_slug: FC3_SLUG.to_string(),
            rows: fc2_rows_with_verdict(FC3_VERDICT_HASH),
            checkpoint: fc3_checkpoint(),
            anchored_leaves: vec![enroll],
            rotations: vec![],
        };
        let json = emit_anchor_package(&pkg).expect("a structurally-valid leaf still emits");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        let report = verify_anchored_package(FC3_SLUG, h32(FC3_KH), &real_policy(), &reparsed, None);
        match report.consistencia {
            Verdict::Failed { reason } => assert!(
                reason.contains("not in the pinned producer identity set"),
                "an alien submitter must fail at the identity gate, got: {reason:?}"
            ),
            other => panic!("expected Failed at the identity gate, got {other:?}"),
        }
    }

    #[test]
    fn fc3_retired_forged_chain_hash_final_fails_join() {
        // JOIN isolation for the RETIRED cross-check (verify_consistencia step 4), pure
        // chain logic (no inclusion crypto): a well-formed head links row 1, but the
        // retired lane's chain_hash_final is a valid-but-wrong hash ⇒ step 4 FAILS with
        // its specific reason. This is the axis that kept retired JOIN-only. It cannot be
        // isolated END-TO-END in this 1-row construction for TWO reasons: (a) the field is
        // committed into the real leaf's checksum, so mutating the leaf breaks inclusion
        // first; and (b) retired's target (chain_hash_final == row1) COINCIDES with head@M's
        // (ordinal_final = M = 1, same chain_hash), so any mutation of the LOCAL chain would
        // trip head's JOIN (step 3) first and never reach retired's reason (step 4). Hence we
        // isolate it here — mirroring producer_head_lane_linked_to_chain_passes_join.
        let rows = fc2_rows_with_verdict(FC3_VERDICT_HASH);
        let m = u64::from(rows.last().unwrap().ordinal);
        let head = Lane::Head {
            slug: FC3_SLUG.to_string(),
            ordinal: m,
            chain_hash: rows.last().unwrap().chain_hash.clone(),
        };
        let forged = Lane::Retired {
            slug: FC3_SLUG.to_string(),
            ordinal_final: m, // ordinal matches M, so step 4 reaches the chain_hash check
            chain_hash_final: "0".repeat(64), // valid hex, but not row M
        };
        match verify_consistencia(&rows, &[head, forged]) {
            Verdict::Failed { reason } => assert!(
                reason.contains("RETIRED chain_hash_final does not match head@M"),
                "a forged retired chain_hash_final must fail the cross-check, got: {reason:?}"
            ),
            other => panic!("expected retired cross-check FAIL, got {other:?}"),
        }
    }

    // ---- T2: byte-fidelity against the REAL §3 oracle + chain→lane linkage --

    #[test]
    fn producer_head_lane_matches_real_105_byte_oracle() {
        // The head lane the producer builds re-serializes to the EXACT 105-byte
        // preimage fixed by the pinned head-leaf layout and its leaf_checksum
        // equals the REAL
        // included leaf's checksum (index 196053, test.sigsum.org). Oracle = the
        // real log bytes, not this crate's code: SHA256∘SHA256 is collision-
        // resistant, so a matching checksum proves the serialization is
        // byte-exact — AND we pin the full 105 bytes, not merely their length.
        let preimage = serialize_preimage(&real_head_leaf().lane).expect("head lane serializes");
        assert_eq!(preimage.len(), 105, "the pinned head-leaf layout is 105 bytes");
        assert_eq!(
            hex::encode(&preimage),
            "736565747265782f616e63686f722f76312f68656164006578616d706c652d74656e616e740034320035666536363138366438653231303036303866356239313466653236306630386335376363383934303837393636613633376634353261306636303663363839",
            "must equal the pinned head-leaf preimage bytes"
        );
        assert_eq!(
            hex::encode(leaf_checksum(&preimage)),
            "7980a962d631ff148d741308a9853a63a165de056ca1255fe3a9bfc7b277c792",
            "must equal the real included leaf's checksum (index 196053)"
        );
    }

    #[test]
    fn producer_head_lane_linked_to_chain_passes_join() {
        // The producer's head lane, derived from the chain's last row, satisfies
        // the package JOIN (ordinal ≤ N, chain_hash == row N). Breaking the
        // chain_hash linkage makes the verifier's JOIN FAIL — the honest link is
        // load-bearing (this isolates the JOIN, no inclusion crypto needed).
        let rows = valid_rows(5);
        let linked = head_lane_from_chain(&rows);
        assert_eq!(
            verify_consistencia(&rows, std::slice::from_ref(&linked)),
            Verdict::Verified,
            "a head lane linked to the chain passes the JOIN"
        );
        let broken = match linked {
            Lane::Head { slug, ordinal, .. } => Lane::Head {
                slug,
                ordinal,
                chain_hash: "0".repeat(64), // valid hex, but not row N
            },
            _ => unreachable!(),
        };
        assert!(
            matches!(verify_consistencia(&rows, &[broken]), Verdict::Failed { .. }),
            "a head lane whose chain_hash does not match row N must FAIL the JOIN"
        );
    }

    // ---- T3: fail-closed emitter + all four lane kinds ---------------------

    #[test]
    fn emit_refuses_unexplained_leaf() {
        // A leaf whose lane cannot re-serialize (slug too short for the §2.2
        // charset) ⇒ emit fails closed with EmitError::UnexplainedLeaf, NEVER
        // producing JSON with an unexplained leaf (symmetric to the verifier: an
        // honest producer does not publish what the auditor would mark FAILED).
        let bad = AnchoredLeaf {
            lane: Lane::Head {
                slug: "short".to_string(), // < 8 chars ⇒ InvalidSlug
                ordinal: 1,
                chain_hash: "a".repeat(64),
            },
            submitter_signature: [0u8; 64],
            submitter_key_hash: [0u8; 32],
            index: 0,
            inclusion_proof: vec![],
        };
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows: valid_rows(1),
            checkpoint: real_checkpoint(),
            anchored_leaves: vec![bad],
            rotations: vec![],
        };
        assert!(matches!(
            emit_anchor_package(&pkg),
            Err(EmitError::UnexplainedLeaf(PreimageError::InvalidSlug { .. }))
        ));
    }

    #[test]
    fn emit_covers_all_four_lanes_and_join_verifies() {
        // Emission handles ALL FOUR lane kinds. head/enroll/retired are derived
        // consistent with a real chain so the package JOIN over them VERIFIES;
        // the rotate reuses the REAL authorized rotate evidence (leaf 196700).
        // emit → parse must round-trip EVERY lane byte-identically (emit is the
        // inverse of parse), and the per-tenant lanes must pass the JOIN.
        let rows = valid_rows(6);
        let last_ordinal = u64::from(rows.last().unwrap().ordinal);
        let last_hash = rows.last().unwrap().chain_hash.clone();
        let head = AnchoredLeaf {
            lane: Lane::Head {
                slug: "example-tenant".to_string(),
                ordinal: last_ordinal,
                chain_hash: last_hash.clone(),
            },
            submitter_signature: [0u8; 64],
            submitter_key_hash: [0u8; 32],
            index: 0,
            inclusion_proof: vec![],
        };
        let enroll = AnchoredLeaf {
            lane: Lane::Enroll {
                slug: "example-tenant".to_string(),
                mode: Mode::Revocable,
            },
            submitter_signature: [1u8; 64],
            submitter_key_hash: [2u8; 32],
            index: 1,
            inclusion_proof: vec![],
        };
        let retired = AnchoredLeaf {
            lane: Lane::Retired {
                slug: "example-tenant".to_string(),
                ordinal_final: last_ordinal,
                chain_hash_final: last_hash,
            },
            submitter_signature: [3u8; 64],
            submitter_key_hash: [4u8; 32],
            index: 2,
            inclusion_proof: vec![],
        };
        let pkg = AnchorPackage {
            tenant_slug: "example-tenant".to_string(),
            rows,
            checkpoint: real_checkpoint_n3(),
            anchored_leaves: vec![head.clone(), enroll.clone(), retired.clone()],
            rotations: vec![real_authorized_rotate_leaf()],
        };
        let json = emit_anchor_package(&pkg).expect("all four lane kinds emit");
        let reparsed = parse_anchor_package(&json).expect("emitted json re-parses");
        // emit is the inverse of parse: every lane survives byte-identically.
        assert_eq!(reparsed.anchored_leaves.len(), 3);
        assert_eq!(reparsed.anchored_leaves[0].lane, head.lane);
        assert_eq!(reparsed.anchored_leaves[1].lane, enroll.lane);
        assert_eq!(reparsed.anchored_leaves[2].lane, retired.lane);
        assert_eq!(reparsed.rotations.len(), 1);
        assert_eq!(
            reparsed.rotations[0].lane,
            real_authorized_rotate_leaf().lane
        );
        // The per-tenant lanes pass the package JOIN (head+enroll+retired all
        // chain-consistent: M = ordinal_final = N, chain_hash_final = head@N).
        // rotate is not a per-tenant fact and is not part of the JOIN.
        let lanes: Vec<Lane> = reparsed
            .anchored_leaves
            .iter()
            .map(|l| l.lane.clone())
            .collect();
        assert_eq!(
            verify_consistencia(&reparsed.rows, &lanes),
            Verdict::Verified
        );
    }
}
