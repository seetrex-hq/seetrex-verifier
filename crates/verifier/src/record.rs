// SPDX-License-Identifier: Apache-2.0
//! `seetrex.record.v1`: the file a repository's run downloads, and the OFFLINE
//! walk from its chain head to one leaf of a public transparency log.
//!
//! Third-party chains are not anchored one leaf per repository. Each tick, the
//! changed heads become the leaves of one RFC 6962 tree, and the root of that
//! tree is the `verdict_hash` of a row of a chain of its own, `oss-batches`,
//! whose head goes to the log through the ordinary `head` lane. So a head is
//! proved by this path, and this module checks every hop:
//!
//! ```text
//! row k of the record           leaf = SHA256(0x00 || "seetrex/oss-batch/v1\0"
//!   -> batch root                        || slug \0 ordinal \0 chain_hash)
//!   -> batch row N .. batch row M  (the links up to the row that is anchored)
//!   -> `head` fact of `oss-batches` at M
//!   -> Sigsum leaf -> cosigned checkpoint under the pinned witness policy
//! ```
//!
//! What it adds to the existing commands and what it leaves alone: the lane set,
//! `anchor.json` and the chain export do not change. The proof is a CUT, not an
//! anchor package, because a package would carry every batch row ever written. It
//! is therefore verified by a function of its own over the same primitives
//! ([`crate::merkle::verify_inclusion`], [`crate::checkpoint`]).
//!
//! The proof is on the LAST row of the tenant that has one, not on the head: the
//! anchor reaches the log with a delay, so the head rarely has one. The rows after
//! it are linked to it but not anchored, and the report counts them. The row of a
//! batch without a leaf of its own is proved by the links to the next one anchored.
//!
//! The trust boundary is the one of [`crate::anchor_package`]: the record is
//! untrusted, the kit is not, and the witness policy and the genesis key are read
//! from the kit alone. A record never names them, and `deny_unknown_fields` refuses
//! one that tries.
//!
//! Declared limits. It proves existence, not completeness: nobody outside can see
//! that a repository was left out of a batch, and a chain cut back from the end is
//! a shorter chain that still holds. `results`, `repository_as_told` and
//! `generated_at` are not bound to anything, and the `verdict_outcome`, `ruleset_id`,
//! `appended_at` and `verdict_id` of a chain row are inputs to no hash this command
//! recomputes. Setting `anchor` to null gives exit 4 even to a file whose proof would
//! fail, so exit 4 says nothing about a proof. `rotations` is material the presenter
//! chose: with no monitor, a fork left out is not seen; a rotated key is not revoked,
//! and a surfaced anomalous rotation does not move the exit code. The submitter
//! signature of the anchored leaf and of every followed rotation is verified under the
//! public keys of the kit, so a proof needs a kit v2; the witnesses cosign consistency,
//! not the validity of a leaf, and the operator of the log can still withhold or delay
//! leaves, so it stays part of what is trusted. A batch row's
//! `verdict_hash` has no
//! section 7 preimage; it is a Merkle root, which is why the proof carries no
//! `ruleset_id` or `verdict_outcome` of that row: those two are metadata the export
//! format imposes on a batch row, and a batch row in a customer's record must not
//! read as a verdict.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer};

use crate::anchor::{derive_producer_identity_set, is_valid_slug, Lane, Verdict};
use crate::anchor_package::{
    hex_fixed, AnchorJsonError, AnchoredLeafDto, AuditorKit, CheckpointDto,
};
use crate::chain::compute_chain_hash;
use crate::chain_export::{
    verify_public_chain, ChainHead, ChainPackageError, PublicChainExport,
    PUBLIC_CHAIN_SCHEMA_VERSION,
};
use crate::checkpoint::{
    check_submitter_signatures, verify_anchored_inclusion_under_root, verify_checkpoint,
    verify_rotate_inclusion_under_root, AnchoredLeaf, Checkpoint, SignatureFailure,
};
use crate::merkle::{leaf_hash, verify_inclusion};

/// The longest `repository_as_told` printed as a name, and the part of a longer
/// one printed as hex.
pub const REPOSITORY_NAME_MAX_BYTES: usize = 256;

/// The most rotations a proof may carry. One producer rotates its key rarely, and
/// each rotation is a leaf it paid for: this is far above any honest history.
pub const MAX_PROOF_ROTATIONS: usize = 256;

/// The most cosignatures a proof's checkpoint may carry. The cost of a checkpoint
/// is one signature check per entry naming a witness of the policy, and a log has
/// a handful of witnesses.
pub const MAX_PROOF_COSIGNATURES: usize = 64;

/// The only accepted record schema.
pub const RECORD_SCHEMA: &str = "seetrex.record.v1";

/// The only accepted version of the proof a record carries in `anchor`.
pub const RECORD_PROOF_VERSION: &str = "seetrex/oss-batch-proof/v1";

/// The slug of the batch chain: the only tenant whose leaf can prove a record.
pub const BATCH_CHAIN_SLUG: &str = "oss-batches";

/// Domain tag of a batch leaf, NUL included.
const BATCH_LEAF_DOMAIN: &[u8] = b"seetrex/oss-batch/v1\0";

/// The leaf of a head inside a batch:
/// `SHA256(0x00 || "seetrex/oss-batch/v1\0" || slug \0 ordinal \0 chain_hash)`,
/// ordinal in decimal, `chain_hash` in hex. The slug has no NUL by the charset
/// [`is_valid_slug`] enforces on a record, so the separators are unambiguous.
pub fn batch_leaf_hash(slug: &str, ordinal: u64, chain_hash: &str) -> [u8; 32] {
    let mut data = Vec::with_capacity(BATCH_LEAF_DOMAIN.len() + slug.len() + chain_hash.len() + 22);
    data.extend_from_slice(BATCH_LEAF_DOMAIN);
    data.extend_from_slice(slug.as_bytes());
    data.push(0);
    data.extend_from_slice(ordinal.to_string().as_bytes());
    data.push(0);
    data.extend_from_slice(chain_hash.as_bytes());
    leaf_hash(&data)
}

/// serde treats a missing `Option` field as `None` unless a deserializer is named.
/// `anchor: null` is a statement; a key that is not there is a malformed file.
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(d)
}

/// One batch row inside a record: the closed five-field cut of the row of
/// `oss-batches-chain.json`. `ruleset_id` and `verdict_outcome` are out on purpose,
/// and `verdict_id` adds nothing to the proof.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchRowCut {
    ordinal: u64,
    /// The batch root.
    verdict_hash: String,
    #[serde(deserialize_with = "present")]
    chain_prev_hash: Option<String>,
    chain_hash: String,
    #[allow(dead_code)] // Closed list. Bound to nothing, so nothing here reads it.
    appended_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordAnchorDto {
    version: String,
    /// The row of `chain` this proof is about.
    proved_ordinal: u64,
    leaf_index: u64,
    batch_size: u64,
    audit_path: Vec<String>,
    /// From the batch of the member up to the row the log holds, in order.
    batch_rows: Vec<BatchRowCut>,
    anchored_leaf: AnchoredLeafDto,
    rotations: Vec<AnchoredLeafDto>,
    checkpoint: CheckpointDto,
}

#[derive(Debug, Deserialize)]
struct SchemaProbe {
    schema: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDto {
    #[allow(dead_code)] // Read through `SchemaProbe`, before this shape is applied.
    schema: String,
    repository_as_told: String,
    slug: String,
    #[allow(dead_code)] // Closed list. Bound to nothing, so nothing here reads it.
    generated_at: String,
    chain: PublicChainExport,
    #[serde(deserialize_with = "present")]
    anchor: Option<RecordAnchorDto>,
    /// Self-attested output of the route; no command checks it, and it is typed
    /// as `Value` so that the verifier does not freeze its shape.
    #[allow(dead_code)]
    results: serde_json::Value,
}

/// How far the anchor reaches into the chain of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorStatus {
    /// `anchor: null`: nothing outside the file attests the chain.
    NotYetAnchored,
    /// Row `proved_ordinal` was traced to a leaf of the cosigned log.
    Confirmed {
        proved_ordinal: u64,
        /// The batch row holding the member.
        member_batch_ordinal: u64,
        /// The batch row the log holds.
        anchored_batch_ordinal: u64,
        log_leaf_index: u64,
        checkpoint_size: u64,
        /// Rotations not followed into the identity chain.
        anomalous_rotations: usize,
    },
}

/// A record that verified. Nothing else comes out of [`verify_record`], so there
/// is no way of reading an unverified head.
#[derive(Debug, PartialEq, Eq)]
pub struct RecordReport {
    pub slug: String,
    /// As the client told it: not signed, not chained. This is the form to print,
    /// from [`repository_for_display`]; the file's own text does not come out.
    pub repository_as_told: String,
    pub head: ChainHead,
    pub anchor: AnchorStatus,
}

/// Why a record did not verify. The `Kit*` variants are the auditor's own
/// input; everything else is the vendor's material, and the text of the file a
/// variant carries has been through [`file_text`], so the reason is safe to print.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Not JSON, or not this shape (unknown field, missing key, bad hex).
    Malformed { detail: String },
    UnsupportedSchema { found: String },
    UnsupportedChainSchema { found: String },
    UnsupportedProofVersion { found: String },
    /// The slug cannot be one the storage layer admits, and could carry a NUL
    /// into the leaf preimage.
    InvalidSlug { slug: String },
    /// The chain of the record does not hold.
    Chain(ChainPackageError),
    /// The proof does not reach the log; the reason says at which hop.
    Anchor { reason: String },
    /// The record carries a proof and no kit was supplied to check it with.
    KitRequired,
    /// The kit is pinned for a tenant other than the batch chain.
    KitNotForBatches { tenant: String },
    /// The record carries a proof and the kit is a v1: it has no public key to
    /// check a signature with, and a proof is not confirmed without one.
    KitLacksIdentityKeys,
    /// The proof derives an identity key the kit has no public key for.
    KitMissingIdentityKey { key_hash: String },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::Malformed { detail } => {
                write!(f, "not a valid {RECORD_SCHEMA} file: {detail}")
            }
            RecordError::UnsupportedSchema { found } => write!(
                f,
                "record schema {found:?} is not supported by this verifier \
                 (supported: {RECORD_SCHEMA}) - upgrade your verifier tooling"
            ),
            RecordError::UnsupportedChainSchema { found } => write!(
                f,
                "chain schema_version {found:?} is not supported by this verifier \
                 (supported: {PUBLIC_CHAIN_SCHEMA_VERSION})"
            ),
            RecordError::UnsupportedProofVersion { found } => write!(
                f,
                "proof version {found:?} is not supported by this verifier \
                 (supported: {RECORD_PROOF_VERSION})"
            ),
            RecordError::InvalidSlug { slug } => write!(f, "invalid record slug {slug:?}"),
            RecordError::Chain(e) => e.fmt(f),
            RecordError::Anchor { reason } => write!(f, "anchor proof FAILED: {reason}"),
            RecordError::KitRequired => write!(
                f,
                "this record carries an anchor proof, which is checked against YOUR pinned \
                 kit: pass --kit <kit.json>"
            ),
            RecordError::KitNotForBatches { tenant } => write!(
                f,
                "the kit is pinned for tenant {tenant:?}; a record is proved through \
                 {BATCH_CHAIN_SLUG:?}, so the kit must name that tenant"
            ),
            RecordError::KitLacksIdentityKeys => write!(
                f,
                "this record carries an anchor proof, and a v1 kit pins no public key to check \
                 its signatures with: use a seetrex/anchor-kit/v2 kit"
            ),
            RecordError::KitMissingIdentityKey { key_hash } => write!(
                f,
                "the proof derives the identity key {key_hash} and the kit pins no public key \
                 for it: add it to identity_pubkeys, from a source you trust"
            ),
        }
    }
}

impl std::error::Error for RecordError {}

fn anchor_failed(reason: impl Into<String>) -> RecordError {
    RecordError::Anchor {
        reason: reason.into(),
    }
}

fn malformed_hex(e: AnchorJsonError) -> RecordError {
    let e = match e {
        AnchorJsonError::Json(detail) => AnchorJsonError::Json(file_text(&detail)),
        AnchorJsonError::UnsupportedVersion { got } => AnchorJsonError::UnsupportedVersion {
            got: file_text(&got),
        },
        AnchorJsonError::InvalidHex { field, value } => AnchorJsonError::InvalidHex {
            field,
            value: file_text(&value),
        },
        AnchorJsonError::InvalidMode { value } => AnchorJsonError::InvalidMode {
            value: file_text(&value),
        },
    };
    RecordError::Malformed {
        detail: format!("{e:?}"),
    }
}

/// `serde_json` quotes what it refused inside its own sentence: a key or a tag
/// between backticks, a value between double quotes, and either may hold those
/// characters too. The sentence is `<fixed> <quoted> <fixed>`, and the second fixed
/// part starts at the LAST `, expected ` or, without one, at the last ` at line `:
/// no later text comes from the file, because what follows is the list of names of
/// this format and the position. The quoted part gets [`file_text`], delimiters
/// included in what it replaces. `Debug` over the whole sentence stays as the
/// second layer.
fn malformed_json(e: serde_json::Error) -> RecordError {
    let message = e.to_string();
    let detail = match message.find(['`', '"']) {
        None => message,
        Some(open) => {
            let close = message
                .rfind(", expected ")
                .or_else(|| message.rfind(" at line "))
                .filter(|close| *close > open)
                .unwrap_or(message.len());
            let quoted = &message[open + 1..close];
            let quoted = quoted.strip_suffix(['`', '"']).unwrap_or(quoted);
            format!("{}{}{}", &message[..open], file_text(quoted), &message[close..])
        }
    };
    RecordError::Malformed {
        detail: format!("{detail:?}"),
    }
}

/// [`ChainPackageError`] is the type of `verify-chain` too, whose messages do not
/// change, so its text of the file is replaced here and not in its `Display`.
fn chain_error(e: ChainPackageError) -> RecordError {
    RecordError::Chain(match e {
        ChainPackageError::GenesisHasPrev { declared } => ChainPackageError::GenesisHasPrev {
            declared: file_text(&declared),
        },
        ChainPackageError::LinkSevered {
            ordinal,
            declared,
            expected,
        } => ChainPackageError::LinkSevered {
            ordinal,
            declared: declared.as_deref().map(file_text),
            expected: file_text(&expected),
        },
        ChainPackageError::RowInconsistent {
            ordinal,
            persisted,
            recomputed,
        } => ChainPackageError::RowInconsistent {
            ordinal,
            persisted: file_text(&persisted),
            recomputed,
        },
        e @ (ChainPackageError::Empty | ChainPackageError::OrdinalMismatch { .. }) => e,
    })
}

/// A digest of this format is 64 lowercase hex characters.
/// [`verify_public_chain`] hashes `verdict_hash` as text and accepts anything, and
/// it stays that way for `verify-chain`; this new surface holds the field to what
/// every other digest of a record is held to.
fn check_digest(field: &'static str, value: &str) -> Result<(), RecordError> {
    hex_fixed::<32>(field, value).map(|_| ()).map_err(malformed_hex)
}

/// `owner/repo`, each side in the characters a forge allows in such a name, all of
/// it ASCII: no space, no colon, no invisible or look-alike character.
fn is_repository_name(name: &str) -> bool {
    let is_part = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    name.len() <= REPOSITORY_NAME_MAX_BYTES
        && name
            .split_once('/')
            .is_some_and(|(owner, repo)| is_part(owner) && is_part(repo))
}

/// `<hex:...>` of at most [`REPOSITORY_NAME_MAX_BYTES`] of `text`, with its length
/// when it is cut.
fn hex_of_file_text(text: &str) -> String {
    let bytes = text.as_bytes();
    let shown = &bytes[..bytes.len().min(REPOSITORY_NAME_MAX_BYTES)];
    let hex = hex::encode(shown);
    if shown.len() == bytes.len() {
        format!("<hex:{hex}>")
    } else {
        format!("<hex:{hex}> (first {} of {} bytes)", shown.len(), bytes.len())
    }
}

/// How `repository_as_told` is shown. The field is bound to nothing and written by
/// the client, so `Debug` is not enough: it leaves spaces, look-alikes and invisible
/// characters as they are, and it has no length.
///
/// A name of the right shape prints as a quoted string; anything else as
/// `<hex:...>`, at most [`REPOSITORY_NAME_MAX_BYTES`] of it. It is printed and not
/// refused because the verdict on the chain must not depend on text no hash covers:
/// hex says what the file holds and leaves the exit code alone.
pub fn repository_for_display(told: &str) -> String {
    if is_repository_name(told) {
        return format!("{told:?}");
    }
    hex_of_file_text(told)
}

/// One word of the charset of an identifier of this format: a schema name, a
/// version, a field name, a digest. No space, so it cannot push anything to a line
/// of its own, and no colon, so it cannot read as a result line.
fn is_plain_word(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= REPOSITORY_NAME_MAX_BYTES
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
}

/// How text of the file is carried by a [`RecordError`]: as it is when it is one
/// plain word, which keeps `schema "seetrex.record.v2" is not supported` readable,
/// and as `<hex:...>` otherwise, for the reason [`repository_for_display`] gives.
/// `Debug` alone let two hundred spaces and a result line print that line on a
/// screen of its own, on a run that exited 1.
fn file_text(text: &str) -> String {
    if is_plain_word(text) {
        text.to_string()
    } else {
        hex_of_file_text(text)
    }
}

/// Walk the cut in order: contiguous ordinals, every row recomputing its own
/// `chain_hash` through the single source of truth, every link pointing at the row
/// before it. Every previous link is a digest, which only this check can say of the
/// first row: no row of the cut links to what it names.
///
/// The ordinal of a row is hashed nowhere; it matters here because the fact in the
/// log names one, and it keeps a cut from being read as a longer walk than it is.
fn walk_batch_rows(rows: &[BatchRowCut]) -> Result<(), RecordError> {
    let Some(first) = rows.first() else {
        return Err(anchor_failed("the proof carries no batch row"));
    };
    if first.ordinal == 0 {
        return Err(anchor_failed("batch row ordinals start at 1, found 0"));
    }
    let mut expected = first.ordinal;
    let mut previous: Option<&BatchRowCut> = None;
    for row in rows {
        check_digest("batch_rows.verdict_hash", &row.verdict_hash)?;
        if let Some(prev) = &row.chain_prev_hash {
            check_digest("batch_rows.chain_prev_hash", prev)?;
        }
        if row.ordinal != expected {
            return Err(anchor_failed(format!(
                "batch rows are not contiguous: expected ordinal {expected}, found {}",
                row.ordinal
            )));
        }
        expected = expected
            .checked_add(1)
            .ok_or_else(|| anchor_failed("batch row ordinal overflows"))?;
        if (row.ordinal == 1) != row.chain_prev_hash.is_none() {
            return Err(anchor_failed(format!(
                "batch row {}: only the genesis (ordinal 1) has no previous link",
                row.ordinal
            )));
        }
        if let Some(prev) = previous {
            if row.chain_prev_hash.as_deref() != Some(prev.chain_hash.as_str()) {
                return Err(anchor_failed(format!(
                    "batch row {}: link severed from row {}",
                    row.ordinal, prev.ordinal
                )));
            }
        }
        if compute_chain_hash(row.chain_prev_hash.as_deref(), &row.verdict_hash) != row.chain_hash {
            return Err(anchor_failed(format!(
                "batch row {}: chain_hash does not recompute",
                row.ordinal
            )));
        }
        previous = Some(row);
    }
    Ok(())
}

/// A rotation is a `rotate` leaf with two digests, said here and not by the
/// functions of [`crate::checkpoint`], whose reasons print the lane as `Debug`: this
/// is the only place the strings of a rotation can come back from.
fn check_rotation_lane(leaf: &AnchoredLeaf) -> Result<(), RecordError> {
    let Lane::Rotate {
        key_hash_old,
        key_hash_new,
        ..
    } = &leaf.lane
    else {
        return Err(anchor_failed("a rotation of the proof is a non-rotate lane"));
    };
    for (field, value) in [("key_hash_old", key_hash_old), ("key_hash_new", key_hash_new)] {
        if hex_fixed::<32>(field, value).is_err() {
            return Err(anchor_failed(format!(
                "unexplained rotate leaf: {field} is not a digest: {}",
                file_text(value)
            )));
        }
    }
    Ok(())
}

/// The anchored fact must be the `head` of the batch chain AT the last row of the
/// cut. Without this, a real leaf of any tenant would close the walk.
fn check_fact_names_last_row(fact: &Lane, last: &BatchRowCut) -> Result<(), RecordError> {
    match fact {
        Lane::Head {
            slug,
            ordinal,
            chain_hash,
        } if slug == BATCH_CHAIN_SLUG
            && *ordinal == last.ordinal
            && *chain_hash == last.chain_hash =>
        {
            Ok(())
        }
        _ => Err(anchor_failed(format!(
            "the anchored leaf does not name the last batch row (ordinal {}) as a head of \
             {BATCH_CHAIN_SLUG:?}",
            last.ordinal
        ))),
    }
}

/// Everything from the chain row to the cosigned checkpoint. The chain has already
/// been verified, so `rows[k - 1]` is a row of a whole chain.
fn verify_proof(
    slug: &str,
    rows: &[crate::chain_export::PublicChainRow],
    proof: RecordAnchorDto,
    kit: &AuditorKit,
) -> Result<AnchorStatus, RecordError> {
    if proof.version != RECORD_PROOF_VERSION {
        return Err(RecordError::UnsupportedProofVersion {
            found: file_text(&proof.version),
        });
    }
    let audit_path = proof
        .audit_path
        .iter()
        .map(|p| hex_fixed::<32>("audit_path", p))
        .collect::<Result<Vec<_>, _>>()
        .map_err(malformed_hex)?;
    let anchored_leaf: AnchoredLeaf = proof.anchored_leaf.into_leaf().map_err(malformed_hex)?;
    let rotations: Vec<AnchoredLeaf> = proof
        .rotations
        .into_iter()
        .map(AnchoredLeafDto::into_leaf)
        .collect::<Result<_, _>>()
        .map_err(malformed_hex)?;
    let checkpoint: Checkpoint = proof.checkpoint.into_checkpoint().map_err(malformed_hex)?;

    // Before the first signature: the cost of a proof is these two numbers.
    if rotations.len() > MAX_PROOF_ROTATIONS {
        return Err(anchor_failed(format!(
            "the proof carries {} rotations, over the bound of {MAX_PROOF_ROTATIONS}",
            rotations.len()
        )));
    }
    if checkpoint.cosignatures.len() > MAX_PROOF_COSIGNATURES {
        return Err(anchor_failed(format!(
            "the proof carries {} cosignatures, over the bound of {MAX_PROOF_COSIGNATURES}",
            checkpoint.cosignatures.len()
        )));
    }
    rotations.iter().try_for_each(check_rotation_lane)?;

    // (1) The cut holds together, and its last row is what the log holds.
    walk_batch_rows(&proof.batch_rows)?;
    let member_batch = &proof.batch_rows[0];
    let anchored_batch = &proof.batch_rows[proof.batch_rows.len() - 1];
    check_fact_names_last_row(&anchored_leaf.lane, anchored_batch)?;

    // (2) The row of THIS chain is a member of the first batch of the cut. The hash
    // and the slug come from the verified chain and the record, never from the cut.
    let k = proof.proved_ordinal;
    let row = usize::try_from(k)
        .ok()
        .and_then(|k| k.checked_sub(1))
        .and_then(|i| rows.get(i))
        .ok_or_else(|| {
            anchor_failed(format!("proved_ordinal {k} is not a row of this chain"))
        })?;
    let leaf = batch_leaf_hash(slug, k, &row.chain_hash);
    let root = hex_fixed::<32>("batch_rows.verdict_hash", &member_batch.verdict_hash)
        .map_err(malformed_hex)?;
    if !verify_inclusion(proof.leaf_index, proof.batch_size, leaf, &audit_path, root) {
        return Err(anchor_failed(format!(
            "row {k} of {slug:?} is not in the batch of row {}",
            member_batch.ordinal
        )));
    }

    // (3) The checkpoint, under the pinned quorum, once: everything below is a path
    // to this root.
    let log_root = verify_checkpoint(&kit.policy, &checkpoint).map_err(|e| {
        anchor_failed(format!("checkpoint not authenticated by pinned quorum: {e:?}"))
    })?;

    // (4) The identity, from the pinned genesis, over rotations whose inclusion was
    // verified first: `submitter_key_hash` means nothing before that.
    let records = rotations
        .iter()
        .map(|leaf| verify_rotate_inclusion_under_root(checkpoint.size, log_root, leaf))
        .collect::<Result<Vec<_>, Verdict>>()
        .map_err(|v| anchor_failed(verdict_reason(v)))?;
    let identity = derive_producer_identity_set(kit.genesis_key_hash, &records)
        .map_err(|e| anchor_failed(format!("producer identity derivation failed: {e:?}")))?;

    // (5) The leaf, under that identity.
    let inclusion = verify_anchored_inclusion_under_root(
        BATCH_CHAIN_SLUG,
        &identity.keys,
        checkpoint.size,
        log_root,
        &anchored_leaf,
    );
    if !matches!(inclusion, Verdict::Verified) {
        return Err(anchor_failed(verdict_reason(inclusion)));
    }

    // (6) The signatures, last: until here a submitter is a claim of the file, and a
    // key the kit lacks says nothing about the leaf of a stranger.
    check_submitter_signatures(
        &kit.identity_pubkeys,
        &identity.keys,
        &rotations,
        std::slice::from_ref(&anchored_leaf),
    )
    .map_err(|failure| match failure {
        SignatureFailure::Invalid { reason } => anchor_failed(reason),
        SignatureFailure::KitGap { key_hash } => RecordError::KitMissingIdentityKey {
            key_hash: hex::encode(key_hash),
        },
    })?;

    Ok(AnchorStatus::Confirmed {
        proved_ordinal: k,
        member_batch_ordinal: member_batch.ordinal,
        anchored_batch_ordinal: anchored_batch.ordinal,
        log_leaf_index: anchored_leaf.index,
        checkpoint_size: checkpoint.size,
        anomalous_rotations: identity.anomalous_rotations.len(),
    })
}

fn verdict_reason(verdict: Verdict) -> String {
    match verdict {
        Verdict::Failed { reason } | Verdict::Inconclusive { reason } => reason,
        Verdict::Verified => "verified".to_string(),
    }
}

/// Verify a `seetrex.record.v1` document OFFLINE. No DB, no network.
///
/// The chain is verified whole, always, with [`verify_public_chain`]; `anchor` then
/// decides. With a proof, `kit` is required and supplies everything the proof is
/// checked against, and it has to be a v2 kit: a proof is not confirmed with its
/// signatures unread. With `anchor: null` the kit is not needed, and the report says
/// [`AnchorStatus::NotYetAnchored`]. A kit that is supplied is checked either way, so
/// a wrong one is reported on the day there is nothing to prove too.
pub fn verify_record(raw: &str, kit: Option<&AuditorKit>) -> Result<RecordReport, RecordError> {
    if let Some(kit) = kit {
        if kit.tenant_slug != BATCH_CHAIN_SLUG {
            return Err(RecordError::KitNotForBatches {
                tenant: kit.tenant_slug.clone(),
            });
        }
    }
    let probe: SchemaProbe = serde_json::from_str(raw).map_err(malformed_json)?;
    if probe.schema != RECORD_SCHEMA {
        return Err(RecordError::UnsupportedSchema {
            found: file_text(&probe.schema),
        });
    }
    let record: RecordDto = serde_json::from_str(raw).map_err(malformed_json)?;
    if !is_valid_slug(&record.slug) {
        return Err(RecordError::InvalidSlug {
            slug: file_text(&record.slug),
        });
    }
    if record.chain.schema_version != PUBLIC_CHAIN_SCHEMA_VERSION {
        return Err(RecordError::UnsupportedChainSchema {
            found: file_text(&record.chain.schema_version),
        });
    }
    let head = verify_public_chain(&record.chain.chain).map_err(chain_error)?;
    for row in &record.chain.chain {
        check_digest("chain.verdict_hash", &row.verdict_hash)?;
    }

    let anchor = match record.anchor {
        None => AnchorStatus::NotYetAnchored,
        Some(proof) => {
            let kit = kit.ok_or(RecordError::KitRequired)?;
            if kit.identity_pubkeys.is_empty() {
                return Err(RecordError::KitLacksIdentityKeys);
            }
            verify_proof(&record.slug, &record.chain.chain, proof, kit)?
        }
    };
    Ok(RecordReport {
        slug: record.slug,
        repository_as_told: repository_for_display(&record.repository_as_told),
        head,
        anchor,
    })
}
