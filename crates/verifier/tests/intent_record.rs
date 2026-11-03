// SPDX-License-Identifier: Apache-2.0
//! `verify-record`, driven from the outside: every test here writes a
//! `seetrex.record.v1` file to disk and spawns the executable, so what is
//! pinned is what an auditor runs, exit code included.
//!
//! The Sigsum side is a SYNTHETIC log: its keys are fixed test seeds and its
//! tree is built below. No real vector can exercise this path yet, because
//! `verify_record` accepts only a `head` leaf of the `oss-batches` slug and the
//! log holds none. The real-crypto coverage of the primitives it composes
//! (`verify_checkpoint`, `verify_anchored_inclusion`) is in `checkpoint.rs` and
//! `anchor_package.rs`, against real `test.sigsum.org` captures. Everything
//! built here is written from the formats (RFC 6962, the Sigsum tree head, the
//! c2sp cosignature, the Sigsum leaf signature, the `seetrex/oss-batch/v1` leaf),
//! not by calling the code under test: the builders below use `sha2` and
//! `ed25519-dalek` directly.

use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicU32, Ordering};

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const BIN: &str = env!("CARGO_BIN_EXE_seetrex-verifier");
const SLUG: &str = "gh-123456789";
const BATCH_SLUG: &str = "oss-batches";
const CHECKPOINT_TS: u64 = 1_790_000_000;

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

// ---- RFC 6962, written from the RFC ---------------------------------------

fn node(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    sha(&[&[0x01], l, r])
}

fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split(leaves.len());
    node(&mth(&leaves[..k]), &mth(&leaves[k..]))
}

fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }
    let k = split(leaves.len());
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

// ---- the leaf of a head and the anchored batch fact ------------------------

fn member_leaf(slug: &str, ordinal: u32, chain_hash: &str) -> [u8; 32] {
    let data = format!("seetrex/oss-batch/v1\0{slug}\0{ordinal}\0{chain_hash}");
    sha(&[&[0x00], data.as_bytes()])
}

fn link(prev: Option<&str>, h: &str) -> String {
    hex::encode(sha(&[prev.unwrap_or("").as_bytes(), h.as_bytes()]))
}

fn base64(input: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in input.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

// ---- a synthetic log --------------------------------------------------------

struct Keys {
    log: SigningKey,
    witnesses: [SigningKey; 3],
    genesis_submitter: [u8; 32],
}

/// The submitter keys of these tests, by seed. A real key, because a leaf now has
/// to carry a signature that verifies.
const GENESIS_SEED: u8 = 0x77;
const NEW_KEY_SEED: u8 = 0x88;

fn submitter_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn key_hash(seed: u8) -> [u8; 32] {
    sha(&[submitter_key(seed).verifying_key().as_bytes()])
}

fn pubkey(seed: u8) -> String {
    hex::encode(submitter_key(seed).verifying_key().as_bytes())
}

fn keys() -> Keys {
    Keys {
        log: SigningKey::from_bytes(&[1; 32]),
        witnesses: [
            SigningKey::from_bytes(&[2; 32]),
            SigningKey::from_bytes(&[3; 32]),
            SigningKey::from_bytes(&[4; 32]),
        ],
        genesis_submitter: key_hash(GENESIS_SEED),
    }
}

/// A kit v2 that pins the genesis key and the key rotated to.
fn kit(tenant: &str) -> Value {
    kit_v2(tenant, &[GENESIS_SEED, NEW_KEY_SEED])
}

fn kit_v2(tenant: &str, seeds: &[u8]) -> Value {
    let k = keys();
    json!({
        "version": "seetrex/anchor-kit/v2",
        "tenant_slug": tenant,
        "genesis_key_hash": hex::encode(k.genesis_submitter),
        "identity_pubkeys": seeds.iter().map(|s| pubkey(*s)).collect::<Vec<_>>(),
        "policy": {
            "log_pubkey": hex::encode(k.log.verifying_key().as_bytes()),
            "witnesses": k.witnesses.iter()
                .map(|w| hex::encode(w.verifying_key().as_bytes()))
                .collect::<Vec<_>>(),
            "quorum_k": 2,
        },
    })
}

fn kit_v1(tenant: &str) -> Value {
    let mut kit = kit_v2(tenant, &[]);
    kit["version"] = json!("seetrex/anchor-kit/v1");
    kit.as_object_mut().unwrap().remove("identity_pubkeys");
    kit
}

/// A `rotate` fact to place in the synthetic log, and the seed of who submitted it.
#[derive(Clone, Copy)]
struct Rotation {
    submitter: u8,
    new_key: u8,
}

fn checksum_of(preimage: &str) -> [u8; 32] {
    sha(&[&sha(&[preimage.as_bytes()])])
}

/// The Sigsum leaf signature, from the format: 56 bytes under its domain, by `seed`.
fn leaf_signature(preimage: &str, seed: u8) -> [u8; 64] {
    let mut message = b"sigsum.org/v1/tree-leaf\0".to_vec();
    message.extend_from_slice(&checksum_of(preimage));
    submitter_key(seed).sign(&message).to_bytes()
}

fn sigsum_leaf(preimage: &str, signature: &[u8; 64], submitter: &[u8; 32]) -> [u8; 32] {
    sha(&[&[0x00], &checksum_of(preimage), signature, submitter])
}

/// The anchored leaf, the rotation leaves and the checkpoint over a log holding
/// foreign leaves, then `rotation` if any, then the `head` fact for the batch row
/// `(ordinal, chain_hash)`, submitted by the key of `submitter`.
fn anchored_by(
    ordinal: u64,
    chain_hash: &str,
    submitter: u8,
    rotation: Option<Rotation>,
) -> (Value, Vec<Value>, Value) {
    anchored_forged(ordinal, chain_hash, submitter, rotation, Forged::default())
}

/// Signatures to place in the log instead of the ones the format requires. The
/// operator of a log can hold such a leaf, with a real inclusion proof under a
/// real checkpoint: nothing but the signature gives it away.
#[derive(Clone, Copy, Default)]
struct Forged {
    leaf: Option<[u8; 64]>,
    rotation: Option<[u8; 64]>,
}

/// [`anchored_by`] with the signatures of `forged` in place of the honest ones.
fn anchored_forged(
    ordinal: u64,
    chain_hash: &str,
    submitter: u8,
    rotation: Option<Rotation>,
    forged: Forged,
) -> (Value, Vec<Value>, Value) {
    let k = keys();
    let preimage = format!("seetrex/anchor/v1/head\0{BATCH_SLUG}\0{ordinal}\0{chain_hash}");
    let signature = forged.leaf.unwrap_or_else(|| leaf_signature(&preimage, submitter));
    let submitter = key_hash(submitter);
    let mut tree: Vec<[u8; 32]> = (0..6u8).map(|i| sha(&[&[i]])).collect();
    let old = hex::encode(k.genesis_submitter);
    let rotate_at = tree.len();
    let mut rotation_signature = [0u8; 64];
    if let Some(r) = rotation {
        let new = hex::encode(key_hash(r.new_key));
        let fact = format!("seetrex/anchor/v1/rotate\x001\0{old}\0{new}");
        rotation_signature = forged.rotation.unwrap_or_else(|| leaf_signature(&fact, r.submitter));
        tree.push(sigsum_leaf(&fact, &rotation_signature, &key_hash(r.submitter)));
    }
    let filler = tree.len();
    tree.push(sigsum_leaf(&preimage, &signature, &submitter));
    let leaf = json!({
        "lane": {"kind": "head", "slug": BATCH_SLUG, "ordinal": ordinal, "chain_hash": chain_hash},
        "submitter_signature": hex::encode(signature),
        "submitter_key_hash": hex::encode(submitter),
        "index": filler,
        "inclusion_proof": path(filler, &tree).iter().map(hex::encode).collect::<Vec<_>>(),
    });
    let rotations: Vec<Value> = rotation
        .iter()
        .map(|r| {
            json!({
                "lane": {
                    "kind": "rotate",
                    "rot_ordinal": 1,
                    "key_hash_old": old,
                    "key_hash_new": hex::encode(key_hash(r.new_key)),
                },
                "submitter_signature": hex::encode(rotation_signature),
                "submitter_key_hash": hex::encode(key_hash(r.submitter)),
                "index": rotate_at,
                "inclusion_proof": path(rotate_at, &tree).iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();
    (leaf, rotations, checkpoint_over(&tree))
}

/// The cosigned checkpoint of the tree `leaves`.
fn checkpoint_over(leaves: &[[u8; 32]]) -> Value {
    let k = keys();
    let root = mth(leaves);
    let size = leaves.len();
    let log_kh = hex::encode(sha(&[k.log.verifying_key().as_bytes()]));
    let head = format!("sigsum.org/v1/tree/{log_kh}\n{size}\n{}\n", base64(&root));
    let cosigned = format!("cosignature/v1\ntime {CHECKPOINT_TS}\n{head}");
    let cosignatures: Vec<Value> = k
        .witnesses
        .iter()
        .take(2)
        .map(|w| {
            json!({
                "key_hash": hex::encode(sha(&[w.verifying_key().as_bytes()])),
                "timestamp": CHECKPOINT_TS,
                "signature": hex::encode(w.sign(cosigned.as_bytes()).to_bytes()),
            })
        })
        .collect();
    json!({
        "size": size,
        "root": hex::encode(root),
        "log_signature": hex::encode(k.log.sign(head.as_bytes()).to_bytes()),
        "cosignatures": cosignatures,
    })
}

// ---- a record ---------------------------------------------------------------

fn tenant_rows(n: u32) -> Vec<Value> {
    let mut rows = Vec::new();
    let mut prev: Option<String> = None;
    for ordinal in 1..=n {
        let verdict_hash = format!("{ordinal:064x}");
        let chain_hash = link(prev.as_deref(), &verdict_hash);
        rows.push(json!({
            "ordinal": ordinal,
            "verdict_id": "00000000-0000-0000-0000-000000000000",
            "verdict_hash": verdict_hash,
            "chain_prev_hash": prev,
            "chain_hash": chain_hash,
            "appended_at": "2026-11-01T10:00:00Z",
            "ruleset_id": "cra-art13-vulnerability-handling",
            "verdict_outcome": "AT_RISK",
        }));
        prev = Some(chain_hash);
    }
    rows
}

fn record_without_anchor(n: u32) -> Value {
    json!({
        "schema": "seetrex.record.v1",
        "repository_as_told": "acme/widget",
        "slug": SLUG,
        "generated_at": "2026-11-01T12:00:00Z",
        "chain": {"schema_version": "1.0", "chain": tenant_rows(n)},
        "anchor": null,
        "results": [],
    })
}

/// A record of `n` rows whose row `proved` is a member of batch 2 (three
/// leaves, member at index 1). `lost` further batches follow with no leaf in
/// the log; the row that IS anchored is the last one.
fn record(n: u32, proved: u32, lost: u32) -> Value {
    let mut rec = record_without_anchor(n);
    let row = rec["chain"]["chain"][(proved - 1) as usize].clone();
    let member = member_leaf(SLUG, proved, row["chain_hash"].as_str().unwrap());
    let leaves = [sha(&[b"sibling-a"]), member, sha(&[b"sibling-b"])];

    // Batch 1 exists only so that the cut does not start at the genesis.
    let first_root = hex::encode(sha(&[b"batch-1"]));
    let mut prev = link(None, &first_root);
    let mut cut = Vec::new();
    for seq in 2..=(2 + lost) {
        let root = if seq == 2 {
            hex::encode(mth(&leaves))
        } else {
            hex::encode(sha(&[format!("batch-{seq}").as_bytes()]))
        };
        let chain_hash = link(Some(&prev), &root);
        cut.push(json!({
            "ordinal": seq,
            "verdict_hash": root,
            "chain_prev_hash": prev,
            "chain_hash": chain_hash,
            "appended_at": "2026-11-01T11:00:00Z",
        }));
        prev = chain_hash;
    }
    let (leaf, rotations, checkpoint) =
        anchored_by(u64::from(2 + lost), &prev, GENESIS_SEED, None);
    rec["anchor"] = json!({
        "version": "seetrex/oss-batch-proof/v1",
        "proved_ordinal": proved,
        "leaf_index": 1,
        "batch_size": leaves.len(),
        "audit_path": path(1, &leaves).iter().map(hex::encode).collect::<Vec<_>>(),
        "batch_rows": cut,
        "anchored_leaf": leaf,
        "rotations": rotations,
        "checkpoint": checkpoint,
    });
    rec
}

/// A record whose row `proved` is the only member of batch 1: the cut starts at
/// the genesis of the batch chain, with no previous link and an empty audit path.
fn genesis_record(n: u32, proved: u32) -> Value {
    let mut rec = record_without_anchor(n);
    let row = rec["chain"]["chain"][(proved - 1) as usize].clone();
    let root = hex::encode(member_leaf(SLUG, proved, row["chain_hash"].as_str().unwrap()));
    let chain_hash = link(None, &root);
    let (leaf, rotations, checkpoint) = anchored_by(1, &chain_hash, GENESIS_SEED, None);
    rec["anchor"] = json!({
        "version": "seetrex/oss-batch-proof/v1",
        "proved_ordinal": proved,
        "leaf_index": 0,
        "batch_size": 1,
        "audit_path": [],
        "batch_rows": [{
            "ordinal": 1,
            "verdict_hash": root,
            "chain_prev_hash": null,
            "chain_hash": chain_hash,
            "appended_at": "2026-11-01T11:00:00Z",
        }],
        "anchored_leaf": leaf,
        "rotations": rotations,
        "checkpoint": checkpoint,
    });
    rec
}

/// Put the log side back on the LAST row of the cut, after a test rewrote that
/// row: the leaf, the rotations and the checkpoint are genuine for what it says.
fn anchor_last_row(rec: &mut Value, submitter: u8, rotation: Option<Rotation>) {
    forge_last_row(rec, submitter, rotation, Forged::default());
}

/// [`anchor_last_row`] with the signatures of `forged` in the log.
fn forge_last_row(rec: &mut Value, submitter: u8, rotation: Option<Rotation>, forged: Forged) {
    let rows = rec["anchor"]["batch_rows"].as_array().unwrap();
    let last = rows.last().unwrap();
    let (leaf, rotations, checkpoint) = anchored_forged(
        last["ordinal"].as_u64().unwrap(),
        last["chain_hash"].as_str().unwrap(),
        submitter,
        rotation,
        forged,
    );
    rec["anchor"]["anchored_leaf"] = leaf;
    rec["anchor"]["rotations"] = json!(rotations);
    rec["anchor"]["checkpoint"] = checkpoint;
}

/// Rewrite the `verdict_hash` of chain row `index` and carry the links forward,
/// so that the chain stays whole and only that value is wrong.
fn rechain(rec: &mut Value, index: usize, verdict_hash: &str) {
    let rows = rec["chain"]["chain"].as_array_mut().unwrap();
    rows[index]["verdict_hash"] = json!(verdict_hash);
    let mut prev = rows[index]["chain_prev_hash"].as_str().map(str::to_string);
    for row in rows.iter_mut().skip(index) {
        let hash = link(prev.as_deref(), row["verdict_hash"].as_str().unwrap());
        row["chain_prev_hash"] = json!(prev);
        row["chain_hash"] = json!(hash);
        prev = Some(hash);
    }
}

// ---- spawning ---------------------------------------------------------------

static NEXT: AtomicU32 = AtomicU32::new(0);

fn tmp(name: &str, body: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("intent_record");
    std::fs::create_dir_all(&dir).expect("create tmp dir");
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("{n}-{name}"));
    std::fs::write(&path, body).expect("write tmp file");
    path
}

fn run(args: &[&str]) -> Output {
    std::process::Command::new(BIN)
        .args(args)
        .output()
        .expect("spawn seetrex-verifier")
}

fn verify(record: &Value, tenant_of_kit: &str) -> (i32, String, String) {
    verify_under(record, &kit(tenant_of_kit))
}

fn verify_under(record: &Value, kit: &Value) -> (i32, String, String) {
    let rec = tmp("record.json", record.to_string().as_bytes());
    let kit = tmp("kit.json", kit.to_string().as_bytes());
    let out = run(&[
        "verify-record",
        rec.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn expect_fail(record: &Value, needle: &str) {
    let (code, stdout, stderr) = verify(record, BATCH_SLUG);
    assert_eq!(code, 1, "must FAIL with exit 1\nstdout: {stdout}\nstderr: {stderr}");
    assert!(
        stderr.contains(needle),
        "the failure must name {needle:?}, got: {stderr}"
    );
    assert!(
        !stdout.contains("CONFIRMED"),
        "a failing run must not print a confirmation: {stdout}"
    );
}

/// A file that tries to paint a result of its own: a line break, ANSI that wipes
/// the current line and turns the text green, and two characters that move or
/// break a line with no control byte at all.
const PAINT: &str =
    "x\n\u{1b}[2K\u{1b}[32mANCHOR: CONFIRMED OFFLINE through ordinal 3 of 3\n\u{202e}\u{2028}";

/// The run fails with exactly one `ERROR: record:` line, naming `needle`, and
/// nothing of `PAINT` reaches either stream as what it is.
fn expect_inert_fail(record: &Value, needle: &str) {
    let (code, stdout, stderr) = verify(record, BATCH_SLUG);
    assert_eq!(code, 1, "must FAIL with exit 1\nstdout: {stdout}\nstderr: {stderr:?}");
    assert!(stderr.contains(needle), "the failure must name {needle:?}, got: {stderr:?}");
    assert!(stdout.is_empty(), "a failing run wrote to stdout: {stdout:?}");
    assert!(
        !stderr
            .chars()
            .any(|c| (c.is_control() && c != '\n') || matches!(c, '\u{202e}' | '\u{2028}')),
        "a raw byte of the file reached the terminal: {stderr:?}"
    );
    assert_eq!(stderr.lines().count(), 1, "the file broke the line: {stderr:?}");
    assert!(stderr.starts_with("ERROR: record: "), "{stderr:?}");
}

// ---- the tests the plan names ----------------------------------------------

/// INTENT: the HEAD of a repository's chain is tied, hop by hop, to one leaf of
///   a cosigned log: head -> batch leaf -> batch root -> batch row -> `head`
///   fact of `oss-batches` -> Sigsum leaf -> checkpoint under the pinned quorum.
/// CONTEXT: one Sigsum leaf per repository does not fit the budget of a shared
///   log, so third-party chains are anchored through a batch chain, and the open
///   verifier has to walk that whole path offline or the anchor is a claim.
/// EXPIRES IF: the batch chain is replaced by a lane of its own in the log.
#[test]
fn test_intent_record_links_head_to_sigsum_leaf() {
    let (code, stdout, stderr) = verify(&record(3, 3, 0), BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE through ordinal 3 of 3"), "{stdout}");
    assert!(stdout.contains("rows not yet anchored:   0"), "{stdout}");

    // The slug is unsigned text in the file; the leaf is what binds it, so a
    // record relabelled for another repository cannot keep its anchor.
    let mut relabelled = record(3, 3, 0);
    relabelled["slug"] = json!("gh-987654321");
    expect_fail(&relabelled, "is not in the batch");

    // The same for the row the proof names: the leaf commits to the ordinal.
    let mut moved = record(3, 3, 0);
    moved["anchor"]["proved_ordinal"] = json!(2);
    expect_fail(&moved, "is not in the batch");
}

/// INTENT: a proof on an EARLIER row is enough: the verifier checks that row
///   against the log and walks to the head with `compute_chain_hash`, and it
///   says how many rows after the proof are not anchored yet. A row before the
///   proof that was rewritten fails, and so does one after it.
/// CONTEXT: the anchor reaches the log with roughly a day of delay, so the head
///   of a live repository almost never carries a proof of its own; asking for
///   one would give `anchor: null` nearly always.
/// EXPIRES IF: heads are anchored synchronously with the push.
#[test]
fn test_intent_record_walks_from_last_proved_row_to_head() {
    let (code, stdout, stderr) = verify(&record(5, 3, 0), BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE through ordinal 3 of 5"), "{stdout}");
    assert!(stdout.contains("rows not yet anchored:   2"), "{stdout}");

    for tampered_row in [1usize, 3] {
        let mut rec = record(5, 3, 0);
        rec["chain"]["chain"][tampered_row]["verdict_hash"] = json!("f".repeat(64));
        expect_fail(&rec, "CHAIN BROKEN");
    }
}

/// INTENT: a batch whose own leaf never reached the log is still proved, by the
///   `chain_prev_hash` links up to the next batch that was anchored.
/// CONTEXT: the anchorer signs only the last head of each export, so a batch
///   whose tick failed would otherwise stay without an anchor forever.
/// EXPIRES IF: every batch gets a leaf of its own, with retries that cannot lose
///   one.
#[test]
fn test_intent_batch_without_leaf_is_proved_through_next_anchored_batch() {
    let (code, stdout, stderr) = verify(&record(2, 2, 2), BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE through ordinal 2 of 2"), "{stdout}");
    assert!(stdout.contains("batch rows walked:       2..=4"), "{stdout}");
}

/// INTENT: the walk across batches holds only over real links: a severed
///   `chain_prev_hash`, a row taken out of the cut, a swapped root, and a row
///   whose own `chain_hash` does not recompute all FAIL.
/// CONTEXT: the negative of the previous test. Without it, a cut that merely
///   ENDS at an anchored row would prove any member.
/// EXPIRES IF: same as the previous test.
#[test]
fn test_intent_batch_walk_with_a_broken_link_fails() {
    let mut severed = record(2, 2, 2);
    severed["anchor"]["batch_rows"][1]["chain_prev_hash"] = json!("e".repeat(64));
    expect_fail(&severed, "link severed");

    let mut dropped = record(2, 2, 2);
    dropped["anchor"]["batch_rows"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    expect_fail(&dropped, "not contiguous");

    let mut skipped_link = record(2, 2, 2);
    skipped_link["anchor"]["batch_rows"][1]["ordinal"] = json!(9);
    expect_fail(&skipped_link, "not contiguous");

    let mut swapped_root = record(2, 2, 2);
    swapped_root["anchor"]["batch_rows"][1]["verdict_hash"] = json!("d".repeat(64));
    expect_fail(&swapped_root, "does not recompute");

    // Last row: the hash that the log signed is re-derived, so even a first
    // row that recomputes on its own cannot be grafted onto the anchored tail.
    let mut grafted = record(2, 2, 2);
    let root = grafted["anchor"]["batch_rows"][0]["verdict_hash"].clone();
    grafted["anchor"]["batch_rows"][0]["chain_prev_hash"] = json!("c".repeat(64));
    grafted["anchor"]["batch_rows"][0]["chain_hash"] =
        json!(link(Some(&"c".repeat(64)), root.as_str().unwrap()));
    expect_fail(&grafted, "link severed");

    // A genesis link on a row that does not say it is the genesis.
    let mut false_genesis = record(2, 2, 0);
    let root = false_genesis["anchor"]["batch_rows"][0]["verdict_hash"].clone();
    false_genesis["anchor"]["batch_rows"][0]["chain_prev_hash"] = Value::Null;
    false_genesis["anchor"]["batch_rows"][0]["chain_hash"] =
        json!(link(None, root.as_str().unwrap()));
    expect_fail(&false_genesis, "genesis");
}

/// INTENT: the batch rows inside a record carry neither `ruleset_id` nor
///   `verdict_outcome`; a cut that does is refused, not tolerated.
/// CONTEXT: those two fields of a batch row are metadata the export format
///   imposes, and the outcome is a filler no engine evaluated. Inside a record
///   that a customer holds, a `SATISFIED` nobody derived would read as a result.
/// EXPIRES IF: a chain export schema with a batch row class of its own replaces
///   the filler.
#[test]
fn test_intent_proof_cut_carries_no_outcome_nor_ruleset() {
    for (field, value) in [("verdict_outcome", "SATISFIED"), ("ruleset_id", "seetrex-oss-batch-v1")] {
        let mut rec = record(3, 3, 0);
        rec["anchor"]["batch_rows"][0][field] = json!(value);
        let (code, stdout, stderr) = verify(&rec, BATCH_SLUG);
        assert_eq!(code, 1, "a cut carrying {field} must be refused: {stdout} {stderr}");
        assert!(stderr.contains(field), "the refusal must name {field}: {stderr}");
    }
    let rows = record(3, 3, 0)["anchor"]["batch_rows"].clone();
    let fields: Vec<&str> = rows[0].as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(
        fields,
        ["appended_at", "chain_hash", "chain_prev_hash", "ordinal", "verdict_hash"],
        "this test's own positive cut must be the closed five-field list"
    );
}

/// INTENT: both Merkle paths are checked: the batch path from the member to the
///   root and the log path from the leaf to the checkpoint. A flipped node, or an
///   index or a size that does not fit the path, fails.
/// CONTEXT: an unchecked path is the whole forgery: anyone can state a batch root.
/// EXPIRES IF: never, while inclusion is proved by a Merkle path.
#[test]
fn test_intent_tampered_merkle_path_fails() {
    let mut node_flip = record(3, 3, 0);
    node_flip["anchor"]["audit_path"][0] = json!("a".repeat(64));
    expect_fail(&node_flip, "is not in the batch");

    let mut index = record(3, 3, 0);
    index["anchor"]["leaf_index"] = json!(0);
    expect_fail(&index, "is not in the batch");

    let mut size = record(3, 3, 0);
    size["anchor"]["batch_size"] = json!(9);
    expect_fail(&size, "is not in the batch");

    let mut log_path = record(3, 3, 0);
    log_path["anchor"]["anchored_leaf"]["inclusion_proof"][0] = json!("a".repeat(64));
    expect_fail(&log_path, "not included in the authenticated tree");

    let mut bad_hex = record(3, 3, 0);
    bad_hex["anchor"]["audit_path"][0] = json!("A".repeat(64));
    expect_fail(&bad_hex, "audit_path");
}

/// INTENT: a record with no anchor says so in those words, under an exit code of
///   its own, 4, the code this tool already gives a pass nothing outside the
///   file attested. It never reads as an anchored pass, and `anchor` has to be
///   present: dropping the key is not how a record says "no anchor".
/// CONTEXT: the rows of the last ~25 hours have no anchor yet by construction,
///   and a tool that exited 0 for them would teach scripts that exit 0 means
///   anchored.
/// EXPIRES IF: the verify-package outcome vocabulary stops reserving 4.
#[test]
fn test_intent_record_without_anchor_says_not_yet_anchored() {
    let rec = tmp("no-anchor.json", record_without_anchor(2).to_string().as_bytes());
    let out = run(&["verify-record", rec.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(4), "{stdout}");
    assert!(stdout.contains("ANCHOR: NOT YET ANCHORED"), "{stdout}");
    assert!(!stdout.contains("CONFIRMED"), "{stdout}");
    assert!(stdout.contains("verdict_count:           2"), "{stdout}");

    let mut no_key = record_without_anchor(2);
    no_key.as_object_mut().unwrap().remove("anchor");
    expect_fail(&no_key, "anchor");

    let mut empty = record_without_anchor(1);
    empty["chain"]["chain"] = json!([]);
    expect_fail(&empty, "ZERO");
}

/// INTENT: adding `verify-record` does not move one byte of what `verify-chain`
///   prints, nor its exit code. The golden was captured from the binary BEFORE
///   the subcommand existed.
/// CONTEXT: the batch design was chosen because the open format and the existing
///   commands do not change: only a subcommand is ADDED.
/// EXPIRES IF: `verify-chain`'s wording is deliberately revised; the golden moves
///   in that same change.
#[test]
fn test_intent_existing_verify_chain_output_unchanged() {
    let export = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/record/verify_chain_golden_export.json"
    );
    let golden = include_str!("fixtures/record/verify_chain_golden_stdout.txt");
    let out = run(&["verify-chain", export]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), golden);
    assert!(out.stderr.is_empty(), "verify-chain wrote to stderr on success");
}

// ---- what the plan does not name and the design depends on -----------------

/// INTENT: the batch leaf is byte for byte the layout the producer writes:
///   `SHA256(0x00 || "seetrex/oss-batch/v1\0" || slug \0 ordinal \0 chain_hash)`,
///   with the ordinal in decimal and the hash in hex.
/// CONTEXT: producer and verifier spell this twice, in a closed crate and in this
///   open one, so a change on one side alone has to go red here.
/// EXPIRES IF: the leaf gets a new domain tag.
#[test]
fn test_intent_batch_leaf_layout_is_frozen() {
    let hash = "a".repeat(64);
    assert_eq!(
        seetrex_verifier::record::batch_leaf_hash("gh-7", 3, &hash),
        sha(&[b"\x00seetrex/oss-batch/v1\x00gh-7\x003\x00", hash.as_bytes()]),
    );
}

/// INTENT: the anchored fact has to be the `head` of `oss-batches` at the LAST row
///   of the cut, under a key the pinned genesis reaches and a quorum of the pinned
///   witnesses. A leaf of another slug, at another ordinal, by a stranger, or under
///   a checkpoint missing the quorum fails.
/// CONTEXT: the log is shared: a real inclusion proves nothing about who wrote the
///   leaf, and the cut is untrusted input.
/// EXPIRES IF: the identity model of the anchor changes.
#[test]
fn test_intent_anchored_leaf_is_ours_and_of_the_last_row() {
    // The attack the check exists for: a real leaf for row 2 and a forged row 3
    // appended after it, carrying a root of the forger's choosing. The links
    // hold and the leaf is genuinely in the log; what gives it away here is the
    // fact not naming the LAST row of the cut. Rewriting the fact to name it is
    // the `renamed` case below: then it is the log that does not hold the leaf.
    let mut extended = record(3, 3, 0);
    let last = extended["anchor"]["batch_rows"][0].clone();
    let forged_root = "b".repeat(64);
    let tail = last["chain_hash"].as_str().unwrap().to_string();
    extended["anchor"]["batch_rows"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "ordinal": 3,
            "verdict_hash": forged_root,
            "chain_prev_hash": tail,
            "chain_hash": link(Some(&tail), &forged_root),
            "appended_at": "2026-11-01T11:00:00Z",
        }));
    expect_fail(&extended, "does not name the last batch row");

    let mut renamed = extended.clone();
    let forged = renamed["anchor"]["batch_rows"][1]["chain_hash"].clone();
    renamed["anchor"]["anchored_leaf"]["lane"]["ordinal"] = json!(3);
    renamed["anchor"]["anchored_leaf"]["lane"]["chain_hash"] = forged;
    expect_fail(&renamed, "not included in the authenticated tree");

    // The anchored row replaced in place: same ordinal as the fact, the links
    // hold, and the fact is untouched and genuinely in the log. Only the hash the
    // fact names differs from the row of the cut.
    let mut substituted = record(3, 3, 1);
    let prev = substituted["anchor"]["batch_rows"][1]["chain_prev_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let forged_root = "b".repeat(64);
    substituted["anchor"]["batch_rows"][1]["verdict_hash"] = json!(forged_root);
    substituted["anchor"]["batch_rows"][1]["chain_hash"] = json!(link(Some(&prev), &forged_root));
    expect_fail(&substituted, "does not name the last batch row");

    let mut other_slug = record(3, 3, 0);
    other_slug["anchor"]["anchored_leaf"]["lane"]["slug"] = json!("seetrex-compliance");
    expect_fail(&other_slug, "does not name the last batch row");

    let mut other_ordinal = record(3, 3, 0);
    other_ordinal["anchor"]["anchored_leaf"]["lane"]["ordinal"] = json!(99);
    expect_fail(&other_ordinal, "does not name the last batch row");

    let mut other_lane = record(3, 3, 0);
    let hash = other_lane["anchor"]["anchored_leaf"]["lane"]["chain_hash"].clone();
    other_lane["anchor"]["anchored_leaf"]["lane"] = json!({
        "kind": "retired", "slug": BATCH_SLUG, "ordinal_final": 2, "chain_hash_final": hash,
    });
    expect_fail(&other_lane, "does not name the last batch row");

    let mut stranger = record(3, 3, 0);
    stranger["anchor"]["anchored_leaf"]["submitter_key_hash"] = json!("9".repeat(64));
    expect_fail(&stranger, "pinned producer identity set");

    let mut below_quorum = record(3, 3, 0);
    below_quorum["anchor"]["checkpoint"]["cosignatures"]
        .as_array_mut()
        .unwrap()
        .pop();
    expect_fail(&below_quorum, "QuorumNotMet");

    let mut unsigned = record(3, 3, 0);
    unsigned["anchor"]["checkpoint"]["log_signature"] = json!("0".repeat(128));
    expect_fail(&unsigned, "LogSignature");
}

/// INTENT: a leaf under a ROTATED key is accepted only through a `rotate` leaf the
///   log really holds and the old key really submitted, followed from the genesis
///   pinned in the kit. An unauthorized rotation does not extend the identity.
/// CONTEXT: the submitter key of the batch chain will rotate one day, and a record
///   issued after that has to go on verifying with the same kit.
/// EXPIRES IF: the identity model of the anchor changes.
#[test]
fn test_intent_rotated_submitter_is_followed_from_the_pinned_genesis() {
    let genesis = GENESIS_SEED;
    let new_key = NEW_KEY_SEED;
    let with_rotation = |rotation: Rotation| {
        let mut rec = record(3, 3, 0);
        anchor_last_row(&mut rec, new_key, Some(rotation));
        rec
    };

    let authorized = with_rotation(Rotation { submitter: genesis, new_key });
    let (code, stdout, stderr) = verify(&authorized, BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE"), "{stdout}");
    assert!(!stdout.contains("anomalous rotations"), "{stdout}");

    let unauthorized = with_rotation(Rotation { submitter: new_key, new_key });
    expect_fail(&unauthorized, "pinned producer identity set");

    // The same rotation beside a leaf of the genesis key: the anchor holds and the
    // rotation is surfaced, because it does not decide this leaf but somebody
    // tried it.
    let mut surfaced = record(3, 3, 0);
    anchor_last_row(&mut surfaced, genesis, Some(Rotation { submitter: new_key, new_key }));
    let (code, stdout, stderr) = verify(&surfaced, BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE"), "{stdout}");
    assert!(
        stdout.contains("anomalous rotations:     1 surfaced (unaccounted - investigate)"),
        "{stdout}"
    );

    let mut not_in_log = authorized.clone();
    not_in_log["anchor"]["rotations"][0]["inclusion_proof"][0] = json!("a".repeat(64));
    expect_fail(&not_in_log, "rotate leaf is not included");
}

/// INTENT: an anchor proof cannot be skipped by leaving the kit out, and a kit
///   pinned for another tenant is refused: both are the auditor's own input, exit
///   2. The proof's trust comes from the kit and the record never names a witness.
/// CONTEXT: same split as `verify-anchor`: the package is untrusted, the kit is not.
/// EXPIRES IF: the kit stops being a separate artifact.
#[test]
fn test_intent_anchor_needs_the_batch_kit() {
    let rec = tmp("anchored.json", record(3, 3, 0).to_string().as_bytes());
    let out = run(&["verify-record", rec.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--kit"), "{stderr}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("CONFIRMED"));

    let (code, _, stderr) = verify(&record(3, 3, 0), "seetrex-compliance");
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("oss-batches"), "{stderr}");

    // A kit that is supplied is checked on the day there is nothing to prove too.
    let (code, stdout, stderr) = verify(&record_without_anchor(2), "seetrex-compliance");
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("oss-batches"), "{stderr}");
    assert!(!stdout.contains("ANCHOR"), "{stdout}");
}

/// INTENT: the envelope is closed and versioned; a future schema is refused by
///   name, and a field the format does not have is refused rather than read past.
/// CONTEXT: the same fail-loud posture as the chain export and `anchor.json`.
/// EXPIRES IF: `seetrex.record.v2` is added with its own dispatch.
#[test]
fn test_intent_record_envelope_is_closed() {
    let mut future = record(3, 3, 0);
    future["schema"] = json!("seetrex.record.v2");
    future["new_field"] = json!(1);
    expect_fail(&future, "seetrex.record.v2");

    let mut proof_version = record(3, 3, 0);
    proof_version["anchor"]["version"] = json!("seetrex/oss-batch-proof/v2");
    expect_fail(&proof_version, "seetrex/oss-batch-proof/v2");

    let mut chain_schema = record(3, 3, 0);
    chain_schema["chain"]["schema_version"] = json!("9.9");
    expect_fail(&chain_schema, "9.9");

    let mut extra = record(3, 3, 0);
    extra["policy"] = json!({"quorum_k": 0});
    expect_fail(&extra, "policy");

    let mut extra_anchor = record(3, 3, 0);
    extra_anchor["anchor"]["policy"] = json!({"quorum_k": 0});
    expect_fail(&extra_anchor, "policy");

    let mut slug = record(3, 3, 0);
    slug["slug"] = json!("gh-1\u{0}2345678");
    expect_fail(&slug, "slug");
}

/// INTENT: this surface never prints the reserved token: not on success, and not
///   when the file itself tries to carry it. It says what the unsigned fields are.
/// CONTEXT: spec section 9.6 reserves the token for the blessed strong surfaces, and
///   a confirmed anchor does not prove completeness. `repository_as_told` is free
///   text from the client.
/// EXPIRES IF: `verify-record` is blessed as a strong surface.
#[test]
fn test_intent_verify_record_never_prints_the_reserved_token() {
    let mut rec = record(3, 3, 0);
    rec["repository_as_told"] = json!("VERIFIED\u{1b}[2J");
    let (code, stdout, stderr) = verify(&rec, BATCH_SLUG);
    assert_eq!(code, 0, "{stdout} {stderr}");
    assert!(!stdout.contains("VERIFIED"), "{stdout}");
    assert!(!stdout.contains('\u{1b}'), "a control byte reached the terminal: {stdout}");
    assert!(stdout.contains("not signed and not chained"), "{stdout}");
    assert!(stdout.contains("completeness"), "{stdout}");
    assert!(stdout.contains("`results`"), "{stdout}");
}

/// INTENT: the file never writes to the terminal. Whatever comes back out of it in
///   an error, from any depth of the shape and from any hop of the proof, is
///   escaped, on one line, under the fixed `ERROR: record:` prefix.
/// CONTEXT: the JSON parser quotes the unknown key or tag it refused byte for byte,
///   so a key holding a line break and ANSI painted a green `ANCHOR: CONFIRMED
///   OFFLINE` line of its own on the auditor's terminal, on a run that exited 1.
/// EXPIRES IF: never, while a record is vendor material read on a terminal.
#[test]
fn test_intent_no_byte_of_the_record_reaches_the_terminal_raw() {
    let objects: [&[&str]; 6] = [
        &[],
        &["chain"],
        &["anchor"],
        &["anchor", "anchored_leaf"],
        &["anchor", "anchored_leaf", "lane"],
        &["anchor", "checkpoint"],
    ];
    for at in objects {
        let mut rec = record(3, 3, 0);
        let mut target = &mut rec;
        for key in at {
            target = &mut target[*key];
        }
        target[PAINT] = json!(1);
        expect_inert_fail(&rec, "unknown field");
    }

    let mut row = record(3, 3, 0);
    row["chain"]["chain"][0][PAINT] = json!(1);
    expect_inert_fail(&row, "unknown field");
    let mut cut = record(3, 3, 0);
    cut["anchor"]["batch_rows"][0][PAINT] = json!(1);
    expect_inert_fail(&cut, "unknown field");
    let mut cosignature = record(3, 3, 0);
    cosignature["anchor"]["checkpoint"]["cosignatures"][0][PAINT] = json!(1);
    expect_inert_fail(&cosignature, "unknown field");
    let mut rotation = record(3, 3, 0);
    rotation["anchor"]["rotations"] = json!([{ PAINT: 1 }]);
    expect_inert_fail(&rotation, "unknown field");

    let mut kind = record(3, 3, 0);
    kind["anchor"]["anchored_leaf"]["lane"]["kind"] = json!(PAINT);
    expect_inert_fail(&kind, "unknown variant");

    // Values, not keys: each of these is quoted back by a different layer.
    let values: [(&[&str], &str); 7] = [
        (&["schema"], "not supported"),
        (&["slug"], "invalid record slug"),
        (&["anchor", "version"], "not supported"),
        (&["chain", "schema_version"], "not supported"),
        (&["anchor", "anchored_leaf", "submitter_key_hash"], "submitter_key_hash"),
        (&["anchor", "checkpoint", "root"], "checkpoint.root"),
        (&["anchor", "checkpoint", "size"], "invalid type"),
    ];
    for (place, needle) in values {
        let mut rec = record(3, 3, 0);
        let mut target = &mut rec;
        for key in place {
            target = &mut target[*key];
        }
        *target = json!(PAINT);
        expect_inert_fail(&rec, needle);
    }
    for field in ["verdict_id", "appended_at", "ordinal", "chain_prev_hash", "chain_hash"] {
        let mut rec = record(3, 3, 0);
        rec["chain"]["chain"][1][field] = json!(PAINT);
        expect_inert_fail(&rec, "ERROR");
    }

    // Past the parser: the reasons the checks themselves compose.
    let mut head_as_rotation = record(3, 3, 0);
    let mut leaf = head_as_rotation["anchor"]["anchored_leaf"].clone();
    leaf["lane"]["slug"] = json!(PAINT);
    head_as_rotation["anchor"]["rotations"] = json!([leaf]);
    expect_inert_fail(&head_as_rotation, "non-rotate lane");

    let mut bad_rotate = record(3, 3, 0);
    let mut leaf = bad_rotate["anchor"]["anchored_leaf"].clone();
    leaf["lane"] = json!({
        "kind": "rotate", "rot_ordinal": 1, "key_hash_old": PAINT, "key_hash_new": PAINT,
    });
    bad_rotate["anchor"]["rotations"] = json!([leaf]);
    expect_inert_fail(&bad_rotate, "unexplained rotate leaf");
}

/// INTENT: the row of the very first batch is proved like any other: no previous
///   link, a batch of one member whose root is the leaf itself, an empty audit
///   path. A genesis row that carries a previous link fails.
/// CONTEXT: the first head ever batched sits on exactly this row, and every other
///   test cut starts later, so the genesis branch of the walk went unrun.
/// EXPIRES IF: the batch chain stops having a genesis of its own.
#[test]
fn test_intent_genesis_batch_of_one_member_is_proved() {
    let (code, stdout, stderr) = verify(&genesis_record(2, 2), BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE through ordinal 2 of 2"), "{stdout}");
    assert!(stdout.contains("batch rows walked:       1..=1"), "{stdout}");

    let mut linked = genesis_record(2, 2);
    let root = linked["anchor"]["batch_rows"][0]["verdict_hash"].clone();
    let prev = "c".repeat(64);
    linked["anchor"]["batch_rows"][0]["chain_prev_hash"] = json!(prev);
    linked["anchor"]["batch_rows"][0]["chain_hash"] =
        json!(link(Some(&prev), root.as_str().unwrap()));
    anchor_last_row(&mut linked, GENESIS_SEED, None);
    expect_fail(&linked, "genesis");
}

/// INTENT: `verify-chain` reads the chain block, not the record: the whole record
///   is exit 1 there, and the block taken out of it gives the head `verify-record`
///   prints.
/// CONTEXT: the demonstration runs both on the same artifact, and `verify-chain`
///   was not changed for records: the export envelope stays closed.
/// EXPIRES IF: `verify-chain` learns to read a record, which the batch design
///   exists to avoid.
#[test]
fn test_intent_verify_chain_takes_the_chain_block_not_the_record() {
    let rec = record(3, 3, 0);
    let whole = tmp("whole.json", rec.to_string().as_bytes());
    assert_eq!(run(&["verify-chain", whole.to_str().unwrap()]).status.code(), Some(1));

    let block = tmp("block.json", rec["chain"].to_string().as_bytes());
    let out = run(&["verify-chain", block.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}");
    let head = rec["chain"]["chain"][2]["chain_hash"].as_str().unwrap();
    assert!(stdout.contains(head), "{stdout}");
}

/// INTENT: what the kit and the scope block say this command does not see is
///   measured: a chain cut back to the proved row still exits 0 and reports the
///   shorter count, and `verdict_outcome`, `ruleset_id` and `appended_at` change
///   under the same exit 0 and the same head.
/// CONTEXT: a limit stated in prose and never run is a claim. The record is one
///   file from one vendor: nothing in it pins how long the chain was.
/// EXPIRES IF: a record starts carrying something that pins its length, or the
///   command starts recomputing a verdict package.
#[test]
fn test_intent_declared_limits_are_what_the_tool_does() {
    let (code, full, _) = verify(&record(5, 3, 0), BATCH_SLUG);
    assert_eq!(code, 0, "{full}");
    assert!(full.contains("truncation from the end"), "{full}");
    assert!(full.contains("verdict_id"), "{full}");

    let mut truncated = record(5, 3, 0);
    truncated["chain"]["chain"].as_array_mut().unwrap().truncate(3);
    let (code, stdout, stderr) = verify(&truncated, BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE through ordinal 3 of 3"), "{stdout}");

    let mut relabelled = record(5, 3, 0);
    for (field, value) in [
        ("verdict_outcome", "SATISFIED"),
        ("ruleset_id", "another-ruleset"),
        ("appended_at", "2001-01-01T00:00:00Z"),
        ("verdict_id", "11111111-1111-1111-1111-111111111111"),
    ] {
        relabelled["chain"]["chain"][2][field] = json!(value);
    }
    let (code, stdout, stderr) = verify(&relabelled, BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert_eq!(stdout, full, "the run must not be able to tell the two files apart");
}

/// INTENT: the `chain` block is the export row of section 8.1, read by the same
///   type: a genesis row with no `chain_prev_hash` key means what `null` means, and
///   keeps its head; the same key missing from any later row is a severed link.
/// CONTEXT: the proof's own cut is a format of its own and requires the key
///   (`present`). The chain block is not: a stricter copy of the row here would
///   make one chain pass `verify-chain` and fail `verify-record`. The missing key
///   changes no byte of any hash.
/// EXPIRES IF: the export row itself starts requiring the key.
#[test]
fn test_intent_chain_block_keeps_the_export_row_shape() {
    let (code, with_key, _) = verify(&record_without_anchor(2), BATCH_SLUG);
    assert_eq!(code, 4, "{with_key}");

    let mut genesis = record_without_anchor(2);
    genesis["chain"]["chain"][0].as_object_mut().unwrap().remove("chain_prev_hash");
    let (code, without_key, stderr) = verify(&genesis, BATCH_SLUG);
    assert_eq!(code, 4, "stdout: {without_key}\nstderr: {stderr}");
    assert_eq!(without_key, with_key);

    let mut interior = record_without_anchor(2);
    interior["chain"]["chain"][1].as_object_mut().unwrap().remove("chain_prev_hash");
    expect_fail(&interior, "CHAIN BROKEN");
}

/// INTENT: `verify-record` refuses a `verdict_hash` that is not 64 lowercase hex
///   characters, on the rows of the chain and on every row of the cut, even when
///   the links recompute. `verify-chain` keeps accepting that file: this strictness
///   belongs to the new command only.
/// CONTEXT: `verify_public_chain` hashes the field as text, so any string links.
///   A record is a new surface with no installed base, and everything else in it
///   that is a digest is held to `hex_fixed`; a digest that cannot be one is not
///   ours, and fails closed.
/// EXPIRES IF: the chain export gains a check of its own, or a digest of another
///   length.
#[test]
fn test_intent_non_hex_verdict_hash_is_refused() {
    for bad in ["not a digest", "A".repeat(64).as_str(), PAINT] {
        let mut rec = record_without_anchor(2);
        rechain(&mut rec, 0, bad);
        let (code, stdout, stderr) = verify(&rec, BATCH_SLUG);
        assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
        assert!(stderr.contains("chain.verdict_hash"), "{stderr}");
        assert!(!stderr.chars().any(|c| c.is_control() && c != '\n'), "{stderr:?}");

        let block = tmp("non-hex.json", rec["chain"].to_string().as_bytes());
        let out = run(&["verify-chain", block.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(0), "verify-chain does not change");
    }

    let mut anchored = record(3, 3, 0);
    rechain(&mut anchored, 1, "not a digest");
    expect_fail(&anchored, "chain.verdict_hash");

    // A row between the member and the anchored one: its root is read by nothing,
    // so only this check sees it.
    let mut cut = record(2, 2, 1);
    let prev = cut["anchor"]["batch_rows"][1]["chain_prev_hash"]
        .as_str()
        .unwrap()
        .to_string();
    cut["anchor"]["batch_rows"][1]["verdict_hash"] = json!("not a digest");
    cut["anchor"]["batch_rows"][1]["chain_hash"] = json!(link(Some(&prev), "not a digest"));
    anchor_last_row(&mut cut, GENESIS_SEED, None);
    expect_fail(&cut, "batch_rows.verdict_hash");
}

/// INTENT: `chain_prev_hash` of the FIRST row of the cut is a digest like every
///   other: nothing links it to a row of the cut, so only this check sees it.
/// CONTEXT: the links reach every later row, and `chain_hash` is recomputed, but
///   the previous link of the first row is hashed as text: any string recomputed
///   and the walk accepted it.
/// EXPIRES IF: the cut starts carrying the row before its first one.
#[test]
fn test_intent_first_row_previous_link_is_a_digest() {
    for bad in ["not a digest", "A".repeat(64).as_str(), PAINT] {
        let mut rec = record(3, 3, 0);
        let root = rec["anchor"]["batch_rows"][0]["verdict_hash"].clone();
        rec["anchor"]["batch_rows"][0]["chain_prev_hash"] = json!(bad);
        rec["anchor"]["batch_rows"][0]["chain_hash"] =
            json!(link(Some(bad), root.as_str().unwrap()));
        anchor_last_row(&mut rec, GENESIS_SEED, None);
        expect_inert_fail(&rec, "batch_rows.chain_prev_hash");
    }
}

/// INTENT: an ordinal 0 in the cut is refused by saying what is wrong, not with a
///   message that contradicts itself.
/// CONTEXT: the walk started from the first row's own ordinal, so it answered
///   «expected ordinal 0, found 0».
/// EXPIRES IF: the batch chain stops starting at ordinal 1.
#[test]
fn test_intent_batch_ordinal_zero_is_named() {
    let mut rec = record(3, 3, 0);
    rec["anchor"]["batch_rows"][0]["ordinal"] = json!(0);
    expect_fail(&rec, "batch row ordinals start at 1, found 0");
}

/// One real rotation repeated `rotations` times, and `cosignatures` entries in the
/// checkpoint: all but the two real ones are well-formed signatures of a policy
/// witness over something else, placed first, so each is worth a full check.
fn costly(rotations: usize, cosignatures: usize) -> Value {
    let (genesis, new_key) = (GENESIS_SEED, NEW_KEY_SEED);
    let mut rec = record(3, 3, 0);
    anchor_last_row(&mut rec, new_key, Some(Rotation { submitter: genesis, new_key }));
    let rotation = rec["anchor"]["rotations"][0].clone();
    rec["anchor"]["rotations"] = json!(vec![rotation; rotations]);

    let k = keys();
    let real = rec["anchor"]["checkpoint"]["cosignatures"].as_array().unwrap().clone();
    let mut all: Vec<Value> = (0..cosignatures - real.len())
        .map(|i| {
            let witness = &k.witnesses[i % 2];
            json!({
                "key_hash": hex::encode(sha(&[witness.verifying_key().as_bytes()])),
                "timestamp": CHECKPOINT_TS,
                "signature": hex::encode(witness.sign(format!("{i}").as_bytes()).to_bytes()),
            })
        })
        .collect();
    all.extend(real);
    rec["anchor"]["checkpoint"]["cosignatures"] = json!(all);
    rec
}

/// INTENT: the cost of a proof is linear in the file. The checkpoint is verified
///   once, not once per rotation, and a proof above the bounds on rotations and
///   cosignatures is refused before any signature is checked, while a proof AT the
///   bounds still verifies, in seconds.
/// CONTEXT: each rotation re-verified the whole checkpoint, so rotations times
///   cosignatures signature checks: 120 KB of record held the tool for 45 s, far
///   below the byte cap of the file. A record is vendor material.
/// EXPIRES IF: a real checkpoint or a real rotation history approaches the bounds.
#[test]
fn test_intent_proof_cost_is_bounded() {
    let (code, stdout, stderr) = verify(&costly(257, 2), BATCH_SLUG);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("257 rotations"), "{stderr}");

    let (code, stdout, stderr) = verify(&costly(1, 65), BATCH_SLUG);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("65 cosignatures"), "{stderr}");

    let started = std::time::Instant::now();
    let (code, stdout, stderr) = verify(&costly(256, 64), BATCH_SLUG);
    let elapsed = started.elapsed();
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: CONFIRMED OFFLINE"), "{stdout}");
    assert!(elapsed.as_secs() < COST_LIMIT_SECS, "a proof at the bounds took {elapsed:?}");
}

/// A proof at the bounds, in a debug build. Measured: 0.6 s with the checkpoint
/// verified once, 136 s with it verified once per rotation.
const COST_LIMIT_SECS: u64 = 30;

/// INTENT: `repository_as_told` is bound to nothing, so it may only ever print as a
///   repository name: 256 bytes of `owner/repo` in the charset of such a name.
///   Anything else prints as `<hex:...>`, and a name over the bound prints its
///   first 256 bytes and its length. The exit code does not depend on the field.
/// CONTEXT: `Debug` only escapes control characters. Two hundred spaces and a
///   result line printed that line on a screen of its own, a `grep` for it matched,
///   a filler-only name looked empty, a homoglyph read as another repository, and a
///   field with no limit put 50 MiB on stdout. Printing hex, and not refusing,
///   keeps a verdict on the chain independent of text no hash covers.
/// EXPIRES IF: the name gets bound to something, or a forge with other names is
///   supported.
#[test]
fn test_intent_repository_name_cannot_paint_a_result() {
    let line = "ANCHOR: CONFIRMED OFFLINE through ordinal 3 of 3";
    let spaced = format!("{}{line}", " ".repeat(200));
    for hostile in [
        spaced.as_str(),
        line,
        "\u{115f}",
        "\u{2800}",
        "\u{3164}",
        "\u{ffa0}",
        "\u{430}cme/widget", // A Cyrillic letter.
        "acme/widget\u{200b}",
        "",
        "/",
        "acme/",
        "/widget",
        "acme/widget/extra",
        "acme widget/x",
        "acme\\widget",
    ] {
        let mut rec = record_without_anchor(1);
        rec["repository_as_told"] = json!(hostile);
        let (code, stdout, stderr) = verify(&rec, BATCH_SLUG);
        assert_eq!(code, 4, "{hostile:?} must not move the exit code: {stderr}");
        assert!(!stdout.contains("CONFIRMED"), "{stdout}");
        let expected = format!("<hex:{}>", hex::encode(hostile));
        assert!(stdout.contains(&expected), "{hostile:?}: {stdout}");
        assert!(stdout.is_ascii(), "{stdout:?}");

        let mut anchored = record(3, 3, 0);
        anchored["repository_as_told"] = json!(hostile);
        assert_eq!(verify(&anchored, BATCH_SLUG).0, 0, "{hostile:?}");
    }

    for name in ["acme/widget", "Acme-1/wid_get.rs"] {
        let mut rec = record_without_anchor(1);
        rec["repository_as_told"] = json!(name);
        let (_, stdout, _) = verify(&rec, BATCH_SLUG);
        assert!(stdout.contains(&format!("{name:?} (not signed")), "{stdout}");
    }

    // A name of the right shape is still file content: the sanitizer applies.
    let mut reserved = record_without_anchor(1);
    reserved["repository_as_told"] = json!("VERIFIED/x");
    let (_, stdout, _) = verify(&reserved, BATCH_SLUG);
    assert!(!stdout.contains("VERIFIED"), "{stdout}");

    let mut at_bound = record_without_anchor(1);
    let name = format!("{}/{}", "a".repeat(100), "b".repeat(155));
    at_bound["repository_as_told"] = json!(name);
    assert!(verify(&at_bound, BATCH_SLUG).1.contains(&format!("{name:?}")));

    // The first 256 bytes and the length; never the rest of the file.
    let mut over = record_without_anchor(1);
    let long = "a/".to_string() + &"b".repeat(300_000);
    over["repository_as_told"] = json!(long);
    let (code, stdout, _) = verify(&over, BATCH_SLUG);
    assert_eq!(code, 4);
    let expected = format!("<hex:{}> (first 256 of 300002 bytes)", hex::encode(&long[..256]));
    assert!(stdout.contains(&expected), "{stdout}");
    assert!(stdout.len() < 8192, "{} bytes reached stdout", stdout.len());

    // A character cut in two at the bound must not panic nor leak.
    let mut split = record_without_anchor(1);
    split["repository_as_told"] = json!("\u{3164}".repeat(100));
    let (code, stdout, stderr) = verify(&split, BATCH_SLUG);
    assert_eq!(code, 4, "{stderr}");
    assert!(stdout.contains("(first 256 of 300 bytes)"), "{stdout}");
}

/// INTENT: an error line is bounded too, whatever the file put in it.
/// CONTEXT: same 50 MiB as `repository_as_told`, by way of the fields an error
///   quotes back: `Debug` escaped them and kept every byte.
/// EXPIRES IF: never, while a record is vendor material read on a terminal.
#[test]
fn test_intent_error_line_is_bounded() {
    let mut rec = record(3, 3, 0);
    rec["schema"] = json!("x".repeat(300_000));
    let (code, stdout, stderr) = verify(&rec, BATCH_SLUG);
    assert_eq!(code, 1, "{stdout}");
    assert!(stderr.starts_with("ERROR: record: "), "{stderr}");
    assert!(stderr.trim_end().len() <= ERROR_LINE_MAX_BYTES, "{} bytes", stderr.len());

    // The longest plain word, all of it the token the sanitizer lengthens. The cut
    // itself is tested beside `bounded_line`: no reason composed from a record
    // reaches it now that every text of the file is held to 256 bytes.
    let mut word = record(3, 3, 0);
    word["schema"] = json!("verified".repeat(32));
    let (code, stdout, stderr) = verify(&word, BATCH_SLUG);
    assert_eq!(code, 1, "{stdout}");
    assert!(stderr.lines().next().unwrap().len() <= ERROR_LINE_MAX_BYTES, "{stderr}");
}

/// The bound of the binary, restated: the test reads what reaches the terminal.
const ERROR_LINE_MAX_BYTES: usize = 1024;

/// INTENT: inside `verify-record`, text of the file prints in an error line as one
///   plain word or as `<hex:...>`. A result line in a field, with or without two
///   hundred spaces in front, reaches neither the screen nor a `grep`, whatever
///   field and whatever layer quotes it. `verify-chain` keeps its messages.
/// CONTEXT: `Debug` escapes control characters and nothing else. Spaces survive it,
///   so a field holding two hundred spaces and `ANCHOR: CONFIRMED OFFLINE through
///   ordinal 3 of 3` printed that line on a screen of its own, on a run with exit
///   code 1. The field set is the one measured on the hostile file.
/// EXPIRES IF: never, while a record is vendor material read on a terminal.
#[test]
fn test_intent_error_line_cannot_paint_a_result() {
    let result = "ANCHOR: CONFIRMED OFFLINE through ordinal 3 of 3";
    let spaced = format!("{}{result}", " ".repeat(200));
    for hostile in [spaced.as_str(), result] {
        let hex = hex::encode(hostile);

        let values: [(&[&str], &str); 6] = [
            (&["schema"], "not supported"),
            (&["slug"], "invalid record slug"),
            (&["anchor", "version"], "not supported"),
            (&["chain", "schema_version"], "not supported"),
            (&["anchor", "audit_path", "0"], "audit_path"),
            (&["anchor", "anchored_leaf", "lane", "kind"], "unknown variant"),
        ];
        for (place, needle) in values {
            let mut rec = record(3, 3, 0);
            let mut target = &mut rec;
            for key in place {
                target = match key.parse::<usize>() {
                    Ok(index) => &mut target[index],
                    Err(_) => &mut target[*key],
                };
            }
            *target = json!(hostile);
            expect_no_result_line(&rec, needle, &hex);
        }

        let mut key = record(3, 3, 0);
        key[hostile] = json!(1);
        expect_no_result_line(&key, "unknown field", &hex);

        // A key of the fixture's own neighbours cannot end the quote early.
        let mut delimiters = record(3, 3, 0);
        let tricky = format!("`, expected x at line 1 column 1 {hostile}");
        delimiters[tricky.as_str()] = json!(1);
        let shown = hex::encode(&tricky.as_bytes()[..32]);
        expect_no_result_line(&delimiters, "unknown field", &shown);

        // Each of the three variants of the chain error that quotes a field.
        let mut genesis = record(3, 3, 0);
        genesis["chain"]["chain"][0]["chain_prev_hash"] = json!(hostile);
        expect_no_result_line(&genesis, "CHAIN BROKEN at ordinal 1", &hex);
        // The rule is this command's: `verify-chain` prints the same row as it did.
        let block = tmp("chain-block.json", genesis["chain"].to_string().as_bytes());
        let out = run(&["verify-chain", block.to_str().unwrap()]);
        assert_eq!(out.status.code(), Some(1));
        let printed = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(printed.contains(&format!("got {hostile:?}")), "{printed}");
        let mut link = record(3, 3, 0);
        link["chain"]["chain"][1]["chain_prev_hash"] = json!(hostile);
        expect_no_result_line(&link, "CHAIN BROKEN at ordinal 2", &hex);
        let mut row = record(3, 3, 0);
        row["chain"]["chain"][2]["chain_hash"] = json!(hostile);
        expect_no_result_line(&row, "CHAIN BROKEN at ordinal 3", &hex);

        // A rotation: its lane is printed by the checkpoint module, past the parser.
        let mut lane = record(3, 3, 0);
        let mut leaf = lane["anchor"]["anchored_leaf"].clone();
        leaf["lane"]["slug"] = json!(hostile);
        lane["anchor"]["rotations"] = json!([leaf]);
        expect_no_result_line(&lane, "non-rotate lane", "non-rotate lane");
        let mut rotate = record(3, 3, 0);
        let mut leaf = rotate["anchor"]["anchored_leaf"].clone();
        leaf["lane"] = json!({
            "kind": "rotate", "rot_ordinal": 1, "key_hash_old": hostile, "key_hash_new": hostile,
        });
        rotate["anchor"]["rotations"] = json!([leaf]);
        expect_no_result_line(&rotate, "unexplained rotate leaf", &hex);
    }

    // An identifier stays readable: the rule is about what is not one.
    let mut future = record(3, 3, 0);
    future["schema"] = json!("seetrex.record.v2");
    let (_, _, stderr) = verify(&future, BATCH_SLUG);
    assert!(stderr.contains("record schema \"seetrex.record.v2\" is not supported"), "{stderr}");
}

fn expect_no_result_line(record: &Value, needle: &str, shown: &str) {
    let (code, stdout, stderr) = verify(record, BATCH_SLUG);
    assert_eq!(code, 1, "must FAIL with exit 1\nstdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.is_empty(), "{stdout:?}");
    assert!(stderr.contains(needle), "the failure must name {needle:?}, got: {stderr}");
    assert!(stderr.contains(shown), "the failure must show {shown:?}, got: {stderr}");
    assert!(!stderr.contains("ANCHOR:"), "the file printed a result: {stderr}");
    assert!(!stderr.contains("CONFIRMED"), "the file printed a result: {stderr}");
    assert!(!stderr.contains("   "), "the file's spaces reached the terminal: {stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
    assert!(stderr.starts_with("ERROR: record: "), "{stderr:?}");
    assert!(stderr.trim_end().len() <= ERROR_LINE_MAX_BYTES, "{stderr}");
}

/// INTENT: a path from argv is escaped like everything else this command prints,
///   on the read of the record, of the kit, and on a refused argument.
/// CONTEXT: argv comes from a script that may take the name from the file's
///   publisher, and a name with a line break printed a result line of its own.
/// EXPIRES IF: never.
#[test]
fn test_intent_argv_reaches_the_terminal_escaped() {
    let kit = tmp("kit.json", kit(BATCH_SLUG).to_string().as_bytes());
    let rec = tmp("anchored.json", record(3, 3, 0).to_string().as_bytes());
    let hostile = format!("--{PAINT}");
    let cases: [(Vec<&str>, i32); 3] = [
        (vec!["verify-record", PAINT], 1),
        (vec!["verify-record", rec.to_str().unwrap(), "--kit", PAINT], 2),
        (vec!["verify-record", rec.to_str().unwrap(), &hostile], 2),
    ];
    for (args, exit) in cases {
        let out = run(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(exit), "{stderr:?}");
        assert!(out.stdout.is_empty(), "{:?}", out.stdout);
        assert!(
            !stderr
                .chars()
                .any(|c| (c.is_control() && c != '\n') || matches!(c, '\u{202e}' | '\u{2028}')),
            "a raw byte of argv reached the terminal: {stderr:?}"
        );
        assert_eq!(stderr.lines().count(), 1, "argv broke the line: {stderr:?}");
    }
    assert_eq!(run(&["verify-record", rec.to_str().unwrap(), "--kit", kit.to_str().unwrap()]).status.code(), Some(0));
}

/// INTENT: `-h` is what `--help` is on this subcommand, exit 2, and not a file name
///   that fails to open with exit 1. A file that really starts with a dash is
///   still reachable as `./-x`.
/// CONTEXT: the help table fixes `verify-record --help` at 2: usage errors are the
///   auditor's own input, and a script filtering for a vendor failure must not see
///   a typo as one.
/// EXPIRES IF: `help_exit_codes.tsv` moves the row.
#[test]
fn test_intent_short_help_follows_the_help_table() {
    for flag in ["-h", "--help"] {
        let out = run(&["verify-record", flag]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flag}: {stderr}");
        assert!(stderr.contains("unexpected argument"), "{flag}: {stderr}");
    }
    let out = run(&["verify-record", "./-x-does-not-exist"]);
    assert_eq!(out.status.code(), Some(1));
}

/// INTENT: what the kit and the scope block say about `anchor` and `rotations` is
///   measured. Setting `anchor` to null turns a record whose proof fails into exit
///   4; the rotations are whatever the presenter chose to include, and a key that
///   was rotated away still signs; an anomalous rotation does not move the exit.
/// CONTEXT: `verify-record` has no monitor, and exit 4 is not evidence that a proof
///   is on its way. A limit stated in prose and never run is a claim.
/// EXPIRES IF: the record gains a monitor input, or rotation starts revoking.
#[test]
fn test_intent_stripped_anchor_and_presented_rotations_are_declared_limits() {
    let mut broken = record(3, 3, 0);
    broken["anchor"]["audit_path"][0] = json!("a".repeat(64));
    expect_fail(&broken, "is not in the batch");
    broken["anchor"] = Value::Null;
    let (code, stdout, stderr) = verify(&broken, BATCH_SLUG);
    assert_eq!(code, 4, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: NOT YET ANCHORED"), "{stdout}");
    assert!(stdout.contains("not that a proof will follow"), "{stdout}");
    assert!(stdout.contains("a record whose proof was removed"), "{stdout}");

    // A leaf of the old key after a rotation away from it, and the same record with
    // the rotation left out: both pass, so neither revocation nor omission shows.
    let genesis = GENESIS_SEED;
    let new_key = NEW_KEY_SEED;
    let mut old_key = record(3, 3, 0);
    anchor_last_row(&mut old_key, genesis, Some(Rotation { submitter: genesis, new_key }));
    let (code, stdout, _) = verify(&old_key, BATCH_SLUG);
    assert_eq!(code, 0, "{stdout}");
    assert!(!stdout.contains("anomalous rotations:"), "{stdout}");
    old_key["anchor"]["rotations"] = json!([]);
    let (code, without_rotation, _) = verify(&old_key, BATCH_SLUG);
    assert_eq!(code, 0);
    assert_eq!(stdout, without_rotation, "the run cannot tell a rotation was omitted");

    let mut anomalous = record(3, 3, 0);
    anchor_last_row(&mut anomalous, genesis, Some(Rotation { submitter: new_key, new_key }));
    let (code, stdout, _) = verify(&anomalous, BATCH_SLUG);
    assert_eq!(code, 0, "{stdout}");
    for declared in [
        "a fork that was left out",
        "does not revoke",
        "no monitor",
        "does not change the exit code",
        "submitter signature",
        "operator of the log",
    ] {
        assert!(stdout.contains(declared), "the scope block must say {declared:?}: {stdout}");
    }
}

// ---- the submitter signature --------------------------------------------------

/// A seed that no kit of these tests pins.
const STRANGER_SEED: u8 = 0x99;

/// A signature of the same key over the wrong fact: a valid Ed25519 signature that
/// proves nothing about this leaf.
fn signature_of_another_fact(seed: u8) -> [u8; 64] {
    leaf_signature("seetrex/anchor/v1/head\0oss-batches\x001\0another", seed)
}

/// INTENT: a leaf that names the pinned identity and carries no signature of it
///   does not confirm a record. Inclusion, quorum and the hash all hold: this is the
///   leaf only the operator of the log could have placed.
/// CONTEXT: the log verifies a submitter's signature when it takes a leaf, and no
///   witness does; until 0.3.8 the verifier took `submitter_key_hash` at its word.
/// EXPIRES IF: a verifier stops being able to hold the public keys.
#[test]
fn test_intent_leaf_with_producer_key_hash_without_signature_fails() {
    let mut garbage = record(3, 3, 0);
    let forged = Forged { leaf: Some([0x55; 64]), ..Forged::default() };
    forge_last_row(&mut garbage, GENESIS_SEED, None, forged);
    expect_fail(&garbage, "submitter signature");
}

/// INTENT: a signature is of ONE fact. A real signature of the pinned key over
///   another fact, placed in a leaf of this one, fails.
/// CONTEXT: every signature of the producer is public; a log operator has them all.
/// EXPIRES IF: the checksum stops being computed from the fact.
#[test]
fn test_intent_signature_from_other_fact_fails() {
    let mut replayed = record(3, 3, 0);
    let forged = Forged { leaf: Some(signature_of_another_fact(GENESIS_SEED)), ..Forged::default() };
    forge_last_row(&mut replayed, GENESIS_SEED, None, forged);
    expect_fail(&replayed, "submitter signature");
}

/// INTENT: a rotation is followed on the signature of the OLD key. A rotation that
///   names the genesis as its submitter and is signed by anyone else fails, however
///   real its inclusion, and the failure outranks the kit having no key for the new
///   one: it reads as forged, not as a kit to complete.
/// CONTEXT: `submitter == old` was a claim of the log, and a forged rotation is the
///   cheapest way to take over an identity: every later leaf would follow it.
/// EXPIRES IF: rotations stop being authorized by the old key.
#[test]
fn test_intent_followed_rotation_requires_old_key_signature() {
    let rotation = Rotation { submitter: GENESIS_SEED, new_key: NEW_KEY_SEED };
    let forged = Forged {
        rotation: Some(signature_of_another_fact(NEW_KEY_SEED)),
        ..Forged::default()
    };
    let mut rec = record(3, 3, 0);
    forge_last_row(&mut rec, NEW_KEY_SEED, Some(rotation), forged);
    expect_fail(&rec, "submitter signature");

    let (code, stdout, stderr) = verify_under(&rec, &kit_v2(BATCH_SLUG, &[GENESIS_SEED]));
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("submitter signature"), "{stderr}");
}

/// INTENT: an anomalous rotation is not followed, so its key is not needed and its
///   signature decides nothing: it is surfaced, as it always was. Its signature here
///   is garbage under a key no kit pins.
/// CONTEXT: anyone can publish a rotation that names our genesis under their own key.
///   Requiring that key would let a stranger make our kit look incomplete.
/// EXPIRES IF: anomalous rotations start deciding the exit code.
#[test]
fn test_intent_anomalous_rotation_needs_no_key() {
    let rotation = Rotation { submitter: STRANGER_SEED, new_key: STRANGER_SEED };
    let forged = Forged { rotation: Some([0x55; 64]), ..Forged::default() };
    let mut rec = record(3, 3, 0);
    forge_last_row(&mut rec, GENESIS_SEED, Some(rotation), forged);
    let (code, stdout, stderr) = verify_under(&rec, &kit_v2(BATCH_SLUG, &[GENESIS_SEED]));
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("anomalous rotations:     1 surfaced"), "{stdout}");

    // Not even when the kit HAS the key: this rotation names the genesis as old and
    // was submitted by a key the kit pins and the identity does not reach, so it was
    // not followed. The two tests below take away each half of what followed means.
    let rotation = Rotation { submitter: NEW_KEY_SEED, new_key: NEW_KEY_SEED };
    let mut rec = record(3, 3, 0);
    forge_last_row(&mut rec, GENESIS_SEED, Some(rotation), forged);
    let (code, stdout, stderr) = verify(&rec, BATCH_SLUG);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("anomalous rotations:     1 surfaced"), "{stdout}");
}

/// INTENT: a key the proof derives and the kit does not pin is the auditor's gap,
///   exit 2, with the key named; it is neither a confirmation nor a failure of the
///   vendor. It holds with a leaf under that key and with no leaf under it: the kit
///   is what pins the identity.
/// CONTEXT: the signature of the rotation is good here, so the only thing missing is
///   the auditor's own input.
/// EXPIRES IF: a derived key absent from the kit stops being the auditor's error.
#[test]
fn test_intent_rotated_key_absent_from_kit_is_exit_2() {
    let rotation = Rotation { submitter: GENESIS_SEED, new_key: NEW_KEY_SEED };
    let only_genesis = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    for leaf_key in [NEW_KEY_SEED, GENESIS_SEED] {
        let mut rec = record(3, 3, 0);
        anchor_last_row(&mut rec, leaf_key, Some(rotation));
        let (code, stdout, stderr) = verify_under(&rec, &only_genesis);
        assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
        assert!(stderr.contains(&hex::encode(key_hash(NEW_KEY_SEED))), "{stderr}");
        assert!(stderr.starts_with("error: "), "{stderr}");
        assert!(!stdout.contains("CONFIRMED"), "{stdout}");
    }
}

/// INTENT: a v1 kit cannot confirm a proof: it has no public key, and a confirmation
///   whose signature nobody read is the overclaim this release removes. Exit 2.
/// CONTEXT: `verify-record` is new in the same release, so no auditor loses a run
///   that used to pass, unlike `verify-anchor`.
/// EXPIRES IF: v1 kits are retired from the parser.
#[test]
fn test_intent_record_refuses_v1_kit_with_proof() {
    let (code, stdout, stderr) = verify_under(&record(3, 3, 0), &kit_v1(BATCH_SLUG));
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("seetrex/anchor-kit/v2"), "{stderr}");
    assert!(!stdout.contains("CONFIRMED"), "{stdout}");
}

/// INTENT: with `anchor: null` there is no signature to check, so a v1 kit is fine
///   and the run says what it said.
/// CONTEXT: a fresh repository has no proof yet, and its auditor may hold either kit.
/// EXPIRES IF: v1 kits are retired from the parser.
#[test]
fn test_intent_record_null_anchor_accepts_v1_kit() {
    let (code, stdout, stderr) = verify_under(&record_without_anchor(2), &kit_v1(BATCH_SLUG));
    assert_eq!(code, 4, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("ANCHOR: NOT YET ANCHORED"), "{stdout}");
}

// ---- the same signature through `verify-anchor` ---------------------------------

/// An `anchor.json` of the batch tenant over the same synthetic log: two rows, a
/// `head` at row 2 submitted by `submitter`, and `rotation` if any.
fn package(submitter: u8, rotation: Option<Rotation>, forged: Forged) -> Value {
    let rows = tenant_rows(2);
    let head = rows[1]["chain_hash"].as_str().unwrap().to_string();
    let (leaf, rotations, checkpoint) = anchored_forged(2, &head, submitter, rotation, forged);
    json!({
        "version": "seetrex/anchor/v1",
        "tenant_slug": BATCH_SLUG,
        "rows": rows,
        "checkpoint": checkpoint,
        "anchored_leaves": [leaf],
        "rotations": rotations,
    })
}

fn verify_anchor(package: &Value, kit: &Value) -> (i32, String, String) {
    let anchor = tmp("anchor.json", package.to_string().as_bytes());
    let kit = tmp("kit.json", kit.to_string().as_bytes());
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
    ]);
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// INTENT: `verify-anchor` under a v2 kit checks what `verify-record` checks, and the
///   run says how many signatures it read: the leaf and the followed rotation, not
///   the anomalous one.
/// CONTEXT: both surfaces take the same leaf from the same log; a check on one of
///   them only would make the weaker one the one to present.
/// EXPIRES IF: the two surfaces stop sharing the signature check.
#[test]
fn test_intent_anchor_counts_the_signatures_it_read() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]);
    let plain = package(GENESIS_SEED, None, Forged::default());
    let (code, stdout, stderr) = verify_anchor(&plain, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("submitter signatures:    1 checked"), "{stdout}");

    let rotated = Rotation { submitter: GENESIS_SEED, new_key: NEW_KEY_SEED };
    let followed = package(NEW_KEY_SEED, Some(rotated), Forged::default());
    let (code, stdout, stderr) = verify_anchor(&followed, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("submitter signatures:    2 checked"), "{stdout}");

    let stranger = Rotation { submitter: STRANGER_SEED, new_key: STRANGER_SEED };
    let garbage = Forged { rotation: Some([0x55; 64]), ..Forged::default() };
    let anomalous = package(GENESIS_SEED, Some(stranger), garbage);
    let (code, stdout, stderr) = verify_anchor(&anomalous, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("submitter signatures:    1 checked"), "{stdout}");
    assert!(stdout.contains("anomalous rotations:     1 surfaced"), "{stdout}");
}

/// INTENT: the leaf only the operator of the log could place fails `verify-anchor`
///   under a v2 kit, exit 1, whichever signature it is that does not hold.
/// CONTEXT: see `test_intent_leaf_with_producer_key_hash_without_signature_fails`.
/// EXPIRES IF: a verifier stops being able to hold the public keys.
#[test]
fn test_intent_anchor_leaf_with_producer_key_hash_without_signature_fails() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]);
    let rotated = Rotation { submitter: GENESIS_SEED, new_key: NEW_KEY_SEED };
    let another_fact = signature_of_another_fact(GENESIS_SEED);
    for bad in [
        package(GENESIS_SEED, None, Forged { leaf: Some([0x55; 64]), rotation: None }),
        package(GENESIS_SEED, None, Forged { leaf: Some(another_fact), rotation: None }),
        package(NEW_KEY_SEED, Some(rotated), Forged { leaf: None, rotation: Some(another_fact) }),
    ] {
        let (code, stdout, stderr) = verify_anchor(&bad, &kit);
        assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
        assert!(stderr.contains("CONSISTENCIA FAILED"), "{stderr}");
        assert!(stderr.contains("submitter signature"), "{stderr}");
        assert!(!stdout.contains("CONFIRMED"), "{stdout}");
    }
}

/// INTENT: a derived key the kit does not pin is exit 2 here too, with the key named,
///   and a forged rotation to that key still reads as forged, exit 1.
/// CONTEXT: an accusation must not turn into a kit to complete.
/// EXPIRES IF: a derived key absent from the kit stops being the auditor's error.
#[test]
fn test_intent_anchor_rotated_key_absent_from_kit_is_exit_2() {
    let only_genesis = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let rotated = Rotation { submitter: GENESIS_SEED, new_key: NEW_KEY_SEED };
    let (code, stdout, stderr) =
        verify_anchor(&package(NEW_KEY_SEED, Some(rotated), Forged::default()), &only_genesis);
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains(&hex::encode(key_hash(NEW_KEY_SEED))), "{stderr}");
    assert!(stderr.contains("identity_pubkeys"), "{stderr}");
    assert!(!stdout.contains("CONFIRMED"), "{stdout}");

    let forged = Forged { leaf: None, rotation: Some([0x55; 64]) };
    let (code, _, stderr) =
        verify_anchor(&package(NEW_KEY_SEED, Some(rotated), forged), &only_genesis);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("submitter signature"), "{stderr}");
}

/// INTENT: with a v1 kit the verdict and the exit code of `verify-anchor` are what
///   they were, even over a leaf that a v2 kit refuses, and the run says that no
///   signature was read, next to the verdict.
/// CONTEXT: a v1 kit in an auditor's hands keeps working on the day 0.3.8 ships, and
///   the silent reading of its pass is what the line removes.
/// EXPIRES IF: v1 kits are retired from the parser, or a v1 kit starts refusing.
#[test]
fn test_intent_v1_kit_verdict_unchanged_and_declared() {
    let unsigned = package(GENESIS_SEED, None, Forged { leaf: Some([0x55; 64]), rotation: None });
    let (code, stdout, stderr) = verify_anchor(&unsigned, &kit_v1(BATCH_SLUG));
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("CONSISTENCIA CONFIRMED OFFLINE"), "{stdout}");
    assert!(stdout.contains("submitter signatures:    NOT CHECKED"), "{stdout}");
    assert!(!stdout.contains("VERIFIED"), "{stdout}");
}

// ---- a log of several facts, and a monitor over it ---------------------------------

/// A seed that some kits pin and that the identity of these tests never reaches.
const OFF_CHAIN_SEED: u8 = 0xAA;

const GARBAGE: [u8; 64] = [0x55; 64];

/// One fact in a synthetic log: its lane as `anchor.json` spells it, the key the
/// leaf names, and the signature the leaf carries.
struct Entry {
    lane: Value,
    submitter: u8,
    signature: [u8; 64],
}

/// The preimage of a lane, from the format.
fn preimage_of(lane: &Value) -> String {
    let text = |key: &str| lane[key].as_str().unwrap();
    let number = |key: &str| lane[key].as_u64().unwrap();
    match text("kind") {
        "head" => format!(
            "seetrex/anchor/v1/head\0{}\0{}\0{}",
            text("slug"),
            number("ordinal"),
            text("chain_hash")
        ),
        "enroll" => format!("seetrex/anchor/v1/enroll\0{}\0{}", text("slug"), text("mode")),
        "retired" => format!(
            "seetrex/anchor/v1/retired\0{}\0{}\0{}",
            text("slug"),
            number("ordinal_final"),
            text("chain_hash_final")
        ),
        "rotate" => format!(
            "seetrex/anchor/v1/rotate\0{}\0{}\0{}",
            number("rot_ordinal"),
            text("key_hash_old"),
            text("key_hash_new")
        ),
        other => panic!("not a lane: {other}"),
    }
}

/// `lane` as the key of `seed` submits it.
fn signed(lane: Value, seed: u8) -> Entry {
    let signature = leaf_signature(&preimage_of(&lane), seed);
    Entry { lane, submitter: seed, signature }
}

/// `lane` naming the key of `seed`, with a signature nobody made. The operator of a
/// log can hold it, under a real proof and a real checkpoint.
fn unsigned(lane: Value, seed: u8) -> Entry {
    Entry { lane, submitter: seed, signature: GARBAGE }
}

fn head_at(ordinal: usize) -> Value {
    let chain_hash = tenant_rows(2)[ordinal - 1]["chain_hash"].clone();
    json!({"kind": "head", "slug": BATCH_SLUG, "ordinal": ordinal, "chain_hash": chain_hash})
}

fn enroll(mode: &str) -> Value {
    json!({"kind": "enroll", "slug": BATCH_SLUG, "mode": mode})
}

/// The retirement of the tenant at its last row.
fn retired() -> Value {
    let chain_hash = tenant_rows(2)[1]["chain_hash"].clone();
    json!({"kind": "retired", "slug": BATCH_SLUG, "ordinal_final": 2, "chain_hash_final": chain_hash})
}

fn rotate(rot_ordinal: u64, old: u8, new: u8) -> Value {
    json!({
        "kind": "rotate",
        "rot_ordinal": rot_ordinal,
        "key_hash_old": hex::encode(key_hash(old)),
        "key_hash_new": hex::encode(key_hash(new)),
    })
}

/// The leaves of `entries` in one log, in order, and its checkpoint.
fn log_of(entries: &[Entry]) -> (Vec<Value>, Value) {
    let mut tree: Vec<[u8; 32]> = (0..6u8).map(|i| sha(&[&[i]])).collect();
    let first = tree.len();
    for e in entries {
        tree.push(sigsum_leaf(&preimage_of(&e.lane), &e.signature, &key_hash(e.submitter)));
    }
    let leaves = entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            json!({
                "lane": e.lane,
                "submitter_signature": hex::encode(e.signature),
                "submitter_key_hash": hex::encode(key_hash(e.submitter)),
                "index": first + i,
                "inclusion_proof": path(first + i, &tree).iter().map(hex::encode).collect::<Vec<_>>(),
            })
        })
        .collect();
    (leaves, checkpoint_over(&tree))
}

/// A package of the two rows, of `rotations` first and `anchored` after them.
fn package_of(rotations: Vec<Entry>, anchored: Vec<Entry>) -> Value {
    let split_at = rotations.len();
    let entries: Vec<Entry> = rotations.into_iter().chain(anchored).collect();
    let (leaves, checkpoint) = log_of(&entries);
    json!({
        "version": "seetrex/anchor/v1",
        "tenant_slug": BATCH_SLUG,
        "rows": tenant_rows(2),
        "checkpoint": checkpoint,
        "anchored_leaves": leaves[split_at..],
        "rotations": leaves[..split_at],
    })
}

/// The package that anchors head@2 under the genesis, read with a monitor of the
/// same log that also saw `seen`, the export of the tenant being `served` or not.
fn verify_monitored(seen: Vec<Entry>, served: bool, kit: &Value) -> (i32, String, String) {
    verify_monitored_rotated(vec![], seen, served, kit)
}

/// [`verify_monitored`] of a package that also publishes `rotations`, which the
/// monitor sees as well.
fn verify_monitored_rotated(
    rotations: Vec<Entry>,
    seen: Vec<Entry>,
    served: bool,
    kit: &Value,
) -> (i32, String, String) {
    verify_monitored_edited(rotations, seen, served, kit, |_, _| {})
}

/// [`verify_monitored_rotated`] with the bundle edited after the log was built, so a
/// leaf can stop being the one the log holds. `edit` gets the leaves of the bundle
/// and the position of the first of `seen`.
fn verify_monitored_edited(
    rotations: Vec<Entry>,
    seen: Vec<Entry>,
    served: bool,
    kit: &Value,
    edit: impl Fn(&mut Vec<Value>, usize),
) -> (i32, String, String) {
    let head_at_index = rotations.len();
    let mut entries = rotations;
    entries.push(signed(head_at(2), GENESIS_SEED));
    entries.extend(seen);
    let (leaves, checkpoint) = log_of(&entries);
    let package = json!({
        "version": "seetrex/anchor/v1",
        "tenant_slug": BATCH_SLUG,
        "rows": tenant_rows(2),
        "checkpoint": checkpoint,
        "anchored_leaves": [leaves[head_at_index]],
        "rotations": leaves[..head_at_index],
    });
    let mut bundle_leaves = leaves.clone();
    edit(&mut bundle_leaves, head_at_index + 1);
    let bundle = json!({
        "version": "seetrex/anchor-monitor/v1",
        "c_audit": checkpoint,
        "leaves": bundle_leaves,
        "consistency_proof": [],
        "observations": [{"slug": BATCH_SLUG, "served": served}],
    });
    let anchor = tmp("anchor.json", package.to_string().as_bytes());
    let kit = tmp("kit.json", kit.to_string().as_bytes());
    let monitor = tmp("monitor.json", bundle.to_string().as_bytes());
    let out = run(&[
        "verify-anchor",
        anchor.to_str().unwrap(),
        "--kit",
        kit.to_str().unwrap(),
        "--monitor",
        monitor.to_str().unwrap(),
    ]);
    (
        out.status.code().expect("exit code"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A followed rotation to `new`, signed by the genesis, under a monitor-free package
/// whose head is signed by the genesis, for the tests of what is followed.
fn followed(new: u8) -> Entry {
    signed(rotate(1, GENESIS_SEED, new), GENESIS_SEED)
}

/// INTENT: a rotation that names the genesis as old and was submitted by ANOTHER key
///   of the identity is not followed, so its signature is not read, even though its
///   submitter is a derived key the kit pins.
/// CONTEXT: half of `is_followed_rotation`: `submitter == old`. Nothing pinned it: the
///   only such case on file had a submitter out of the identity.
/// EXPIRES IF: a rotation stops needing the old key to submit it.
#[test]
fn test_intent_rotation_not_submitted_by_its_old_key_is_not_read() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]);
    let anomalous = unsigned(rotate(2, GENESIS_SEED, STRANGER_SEED), NEW_KEY_SEED);
    let package = package_of(
        vec![followed(NEW_KEY_SEED), anomalous],
        vec![signed(head_at(2), GENESIS_SEED)],
    );
    let (code, stdout, stderr) = verify_anchor(&package, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("submitter signatures:    2 checked"), "{stdout}");
    assert!(stdout.contains("anomalous rotations:     1 surfaced"), "{stdout}");
}

/// INTENT: a rotation off the chain from the pinned genesis is not followed, so its
///   signature is not read, even though its submitter is its old key and the kit pins
///   that key.
/// CONTEXT: the other half of `is_followed_rotation`: the old key is in the derived
///   set. An auditor may well pin a key the package never reaches.
/// EXPIRES IF: the kit stops being a superset of the derived identity.
#[test]
fn test_intent_off_chain_rotation_is_not_read() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED, OFF_CHAIN_SEED]);
    let off_chain = unsigned(rotate(1, OFF_CHAIN_SEED, NEW_KEY_SEED), OFF_CHAIN_SEED);
    let package = package_of(vec![off_chain], vec![signed(head_at(2), GENESIS_SEED)]);
    let (code, stdout, stderr) = verify_anchor(&package, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("submitter signatures:    1 checked"), "{stdout}");
    assert!(stdout.contains("anomalous rotations:     1 surfaced"), "{stdout}");
}

/// INTENT: an `enroll` and a `retired` are signed facts like a `head`: signed, they
///   count; unsigned, they fail, each one.
/// CONTEXT: every signature test on file went through a `head` or a `rotate`, and
///   those two lanes serialize otherwise.
/// EXPIRES IF: those lanes leave the anchored leaves.
#[test]
fn test_intent_signed_enroll_and_retired_are_read() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let leaves = |enroll_leaf, retired_leaf| {
        package_of(vec![], vec![signed(head_at(2), GENESIS_SEED), enroll_leaf, retired_leaf])
    };
    let good = leaves(signed(enroll("attested"), GENESIS_SEED), signed(retired(), GENESIS_SEED));
    let (code, stdout, stderr) = verify_anchor(&good, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("submitter signatures:    3 checked"), "{stdout}");

    for bad in [
        leaves(unsigned(enroll("attested"), GENESIS_SEED), signed(retired(), GENESIS_SEED)),
        leaves(signed(enroll("attested"), GENESIS_SEED), unsigned(retired(), GENESIS_SEED)),
    ] {
        let (code, stdout, stderr) = verify_anchor(&bad, &kit);
        assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
        assert!(stderr.contains("submitter signature"), "{stderr}");
    }
}

/// INTENT: under a v2 kit, a leaf of a monitor that names a key of the kit and does
///   not carry its signature does not count for COMPLETITUD, in either direction, and
///   the run says how many there were: it cannot absolve a FAILED, whether by a
///   RETIRED, by a rotation or by a revocable ENROLL, and it cannot accuse.
/// CONTEXT: the rules read the lanes of the bundle and nobody read their signatures:
///   a made-up RETIRED turned exit 1 into exit 0; a made-up rotation from the genesis
///   to the key of an alien leaf turned exit 1 into exit 0 with no anomaly on screen;
///   a made-up revocable ENROLL turned FAILED into INCONCLUSIVE. Dropping such a leaf
///   gives nobody a new power: the completeness of a bundle is a trusted input, so
///   whoever writes it can already leave a leaf out.
/// EXPIRES IF: the rules stop reading the lanes of the bundle.
#[test]
fn test_intent_monitor_leaf_with_bad_signature_does_not_count() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let discarded = |n: usize| format!("monitor leaves:          {n} discarded");

    // The honest control: the same bundle shapes, signed, count for what they say.
    let (code, stdout, stderr) = verify_monitored(vec![], true, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![signed(retired(), GENESIS_SEED)], false, &kit);
    assert_eq!(code, 0, "a real RETIRED absolves a 404: {stdout}\n{stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![signed(enroll("revocable"), GENESIS_SEED)], false, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             INCONCLUSIVE"), "{stdout}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    let alien = || signed(head_at(1), STRANGER_SEED);
    let with_rotated = kit_v2(BATCH_SLUG, &[GENESIS_SEED, STRANGER_SEED]);
    let (code, stdout, stderr) = verify_monitored(
        vec![signed(rotate(1, GENESIS_SEED, STRANGER_SEED), GENESIS_SEED), alien()],
        true,
        &with_rotated,
    );
    assert_eq!(code, 0, "a real rotation explains its key: {stdout}\n{stderr}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    // The three absolutions, FAILED and exit 1 as without the leaf.
    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(retired(), GENESIS_SEED)], false, &kit);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             FAILED"), "{stdout}");
    assert!(stdout.contains("G-v6-4bis"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    let (code, stdout, stderr) = verify_monitored(
        vec![unsigned(rotate(1, GENESIS_SEED, STRANGER_SEED), GENESIS_SEED), alien()],
        true,
        &kit,
    );
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("G-v6-7"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(enroll("revocable"), GENESIS_SEED)], false, &kit);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             FAILED"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    // The accusation: a head of the producer that contradicts row 2, made up.
    let contradicting = || {
        let mut lane = head_at(2);
        lane["chain_hash"] = json!("ab".repeat(32));
        lane
    };
    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(contradicting(), GENESIS_SEED)], true, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    // The same accusation with the signature of the producer stands.
    let (code, stdout, stderr) =
        verify_monitored(vec![signed(contradicting(), GENESIS_SEED)], true, &kit);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("G-v6-3"), "{stdout}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    // A key of the kit outside the genesis is a key of the kit.
    let both = kit_v2(BATCH_SLUG, &[GENESIS_SEED, OFF_CHAIN_SEED]);
    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(head_at(1), OFF_CHAIN_SEED)], true, &both);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");
}

/// INTENT: a leaf under a key the kit does not hold stays what it was: there is
///   nothing to check it against, and it is still an alien leaf, FAILED. Its bad
///   signature is not a way out.
/// CONTEXT: dropping every leaf that cannot be shown good would let anyone silence
///   the alien-leaf rule by writing garbage in the signature.
/// EXPIRES IF: the rules stop reading alien leaves.
#[test]
fn test_intent_monitor_leaf_under_a_foreign_key_stays_counted() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(head_at(1), STRANGER_SEED)], true, &kit);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("G-v6-7"), "{stdout}");
    assert!(stdout.contains("monitor leaves:          0 discarded"), "{stdout}");
}

/// INTENT: under a v1 kit the leaves of a monitor are what they were, and the run
///   says that nobody read them: a made-up leaf can absolve and can accuse.
/// CONTEXT: the same three absolutions and the accusation, measured under a v1 kit
///   before the v2 path existed.
/// EXPIRES IF: v1 kits are retired from the parser.
#[test]
fn test_intent_v1_kit_monitor_leaves_are_declared_not_checked() {
    let kit = kit_v1(BATCH_SLUG);
    let declared = "monitor leaves:          NOT CHECKED";

    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(retired(), GENESIS_SEED)], false, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains(declared), "{stdout}");

    let (code, stdout, stderr) = verify_monitored(
        vec![
            unsigned(rotate(1, GENESIS_SEED, STRANGER_SEED), GENESIS_SEED),
            signed(head_at(1), STRANGER_SEED),
        ],
        true,
        &kit,
    );
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(!stdout.contains("anomalous rotations:"), "{stdout}");
    assert!(stdout.contains(declared), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![unsigned(enroll("revocable"), GENESIS_SEED)], false, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("COMPLETITUD:             INCONCLUSIVE"), "{stdout}");
    assert!(stdout.contains(declared), "{stdout}");

    let mut lane = head_at(2);
    lane["chain_hash"] = json!("ab".repeat(32));
    let (code, stdout, stderr) = verify_monitored(vec![unsigned(lane, GENESIS_SEED)], true, &kit);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stdout.contains("G-v6-3"), "{stdout}");
    assert!(stdout.contains(declared), "{stdout}");
}

/// INTENT: the arm of a CONSISTENCIA FAILED keeps the count of the bundle, and a bad
///   signature in the package can sit beside a CONFIRMED COMPLETITUD: the two verdicts
///   do not collapse, and the exit code follows CONSISTENCIA.
/// CONTEXT: the same forged rotation is in the package, where it fails CONSISTENCIA,
///   and in the bundle, where it is dropped, so the rules see an honest enumeration.
/// EXPIRES IF: the two verdicts collapse into one.
#[test]
fn test_intent_failed_arm_keeps_the_monitor_count() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]);
    let forged = unsigned(rotate(1, GENESIS_SEED, NEW_KEY_SEED), GENESIS_SEED);
    let (code, stdout, stderr) = verify_monitored_rotated(vec![forged], vec![], true, &kit);
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("CONSISTENCIA FAILED"), "{stderr}");
    assert!(stderr.contains("COMPLETITUD: CONFIRMED"), "{stderr}");
    assert!(stderr.contains("monitor leaves: 1 discarded"), "{stderr}");
}

/// INTENT: no monitor, no line about its leaves.
/// CONTEXT: the line speaks of an input the run did not have.
/// EXPIRES IF: never, while `--monitor` is optional.
#[test]
fn test_intent_no_monitor_no_monitor_line() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let plain = package_of(vec![], vec![signed(head_at(2), GENESIS_SEED)]);
    let (code, stdout, stderr) = verify_anchor(&plain, &kit);
    assert_eq!(code, 0, "stdout: {stdout}\nstderr: {stderr}");
    assert!(!stdout.contains("monitor leaves:"), "{stdout}");
}

/// INTENT: the arm of a kit gap prints what the other arms print: the truncation
///   reference and the anomalous rotations, on stderr with the error. Exit 2 wins over
///   a COMPLETITUD FAILED, which is printed there too.
/// CONTEXT: a kit to complete must not hide what the same run found. The help says
///   which of the two the exit code follows, and a script reads only the code.
/// EXPIRES IF: the exit codes of `verify-anchor` change.
#[test]
fn test_intent_kit_gap_arm_prints_what_the_run_found() {
    let only_genesis = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let anomalous = unsigned(rotate(2, STRANGER_SEED, STRANGER_SEED), STRANGER_SEED);
    let gap = package_of(
        vec![followed(NEW_KEY_SEED), anomalous],
        vec![signed(head_at(2), GENESIS_SEED)],
    );
    let (code, stdout, stderr) = verify_anchor(&gap, &only_genesis);
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("truncation reference: "), "{stderr}");
    assert!(stderr.contains("anomalous rotations: 1 surfaced"), "{stderr}");

    let (code, stdout, stderr) =
        verify_monitored_rotated(vec![followed(NEW_KEY_SEED)], vec![], false, &only_genesis);
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("COMPLETITUD: FAILED"), "{stderr}");
    assert!(stderr.contains("monitor leaves: 0 discarded"), "{stderr}");
}

/// Turn the first hex digit of the signature of `leaf` into another one: the leaf
/// the log holds is no longer the one presented.
fn flip_signature(leaf: &mut Value) {
    let text = leaf["submitter_signature"].as_str().unwrap().to_string();
    let first = if text.starts_with('0') { "1" } else { "0" };
    leaf["submitter_signature"] = json!(format!("{first}{}", &text[1..]));
}

/// A head of the producer that contradicts row 2.
fn contradicting_head() -> Value {
    let mut lane = head_at(2);
    lane["chain_hash"] = json!("ab".repeat(32));
    lane
}

/// INTENT: a leaf of a bundle is only discarded if it is in the log and its signature
///   is refuted. One that does not include under `C_audit`, or does not serialize, is
///   a corrupt bundle and stays FAILED, exit 1, under a v2 kit as under a v1 kit, even
///   when it names a key of the kit and its signature does not hold.
/// CONTEXT: the discard ran on the raw bundle, ahead of `authenticate_leaf_inclusion`,
///   and read a lane that does not serialize as a refuted signature: a corrupt bundle
///   went from exit 1 to exit 0 CONFIRMED, and a real accusation could be silenced by
///   changing one nibble of its signature.
/// EXPIRES IF: a bundle stops being checked against `C_audit`.
#[test]
fn test_intent_corrupt_bundle_leaf_stays_failed_under_a_v2_kit() {
    let v2 = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let v1 = kit_v1(BATCH_SLUG);
    let attested = || vec![signed(enroll("attested"), GENESIS_SEED)];
    let accusing = || vec![signed(contradicting_head(), GENESIS_SEED)];
    let rotation = || vec![followed(STRANGER_SEED)];
    type Edit = fn(&mut Vec<Value>, usize);
    let cases: Vec<(&str, Vec<Entry>, &str, Edit)> = vec![
        ("signature", attested(), "does not include under C_audit root", |l, i| {
            flip_signature(&mut l[i]);
        }),
        ("signature and proof", attested(), "does not include under C_audit root", |l, i| {
            flip_signature(&mut l[i]);
            l[i]["inclusion_proof"] = json!(["00".repeat(32)]);
        }),
        ("index past the tree", attested(), "at index 999999 does not include", |l, i| {
            flip_signature(&mut l[i]);
            l[i]["index"] = json!(999_999);
        }),
        ("uppercase chain_hash", accusing(), "does not serialize to v1", |l, i| {
            l[i]["lane"]["chain_hash"] = json!("AB".repeat(32));
        }),
        ("ordinal 0", accusing(), "does not serialize to v1", |l, i| {
            l[i]["lane"]["ordinal"] = json!(0);
        }),
        ("invalid slug", attested(), "does not serialize to v1", |l, i| {
            l[i]["lane"]["slug"] = json!("X");
        }),
        ("key_hash_new zz", rotation(), "does not serialize to v1", |l, i| {
            l[i]["lane"]["key_hash_new"] = json!("zz");
        }),
        ("real accusation, signature edited", accusing(), "does not include", |l, i| {
            flip_signature(&mut l[i]);
        }),
        ("real accusation, lane rewritten", accusing(), "does not include", |l, i| {
            l[i]["lane"] = head_at(2);
        }),
    ];
    for (name, seen, reason, edit) in cases {
        let copy: Vec<Entry> = seen
            .iter()
            .map(|e| Entry { lane: e.lane.clone(), submitter: e.submitter, signature: e.signature })
            .collect();
        for (kit, entries) in [(&v2, seen), (&v1, copy)] {
            let (code, stdout, stderr) =
                verify_monitored_edited(vec![], entries, true, kit, edit);
            assert_eq!(code, 1, "{name}: {stdout}\n{stderr}");
            assert!(stdout.contains("COMPLETITUD:             FAILED"), "{name}: {stdout}");
            assert!(stdout.contains(reason), "{name}: {stdout}");
        }
    }
}

/// INTENT: the line about the leaves of a bundle is printed when the rules ran, and
///   only then, under either kit: it says what happened to their input, and a run that
///   stopped above them discarded nothing and read nothing.
/// CONTEXT: the count was taken ahead of everything, so a package that failed early
///   printed `1 discarded` beside a COMPLETITUD that was never evaluated.
/// EXPIRES IF: `--monitor` goes away.
#[test]
fn test_intent_monitor_line_only_when_the_rules_ran() {
    let v2 = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let v1 = kit_v1(BATCH_SLUG);
    // A package whose leaf does not include: refused above the rules.
    let entries = vec![signed(head_at(2), GENESIS_SEED), unsigned(retired(), GENESIS_SEED)];
    let (leaves, checkpoint) = log_of(&entries);
    let mut broken = leaves[0].clone();
    broken["inclusion_proof"] = json!(["00".repeat(32)]);
    let package = json!({
        "version": "seetrex/anchor/v1",
        "tenant_slug": BATCH_SLUG,
        "rows": tenant_rows(2),
        "checkpoint": checkpoint,
        "anchored_leaves": [broken],
        "rotations": [],
    });
    let bundle = json!({
        "version": "seetrex/anchor-monitor/v1",
        "c_audit": checkpoint,
        "leaves": leaves,
        "consistency_proof": [],
        "observations": [{"slug": BATCH_SLUG, "served": true}],
    });
    let anchor = tmp("anchor.json", package.to_string().as_bytes());
    let monitor = tmp("monitor.json", bundle.to_string().as_bytes());
    for kit in [&v2, &v1] {
        let kit = tmp("kit.json", kit.to_string().as_bytes());
        let out = run(&[
            "verify-anchor",
            anchor.to_str().unwrap(),
            "--kit",
            kit.to_str().unwrap(),
            "--monitor",
            monitor.to_str().unwrap(),
        ]);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("CONSISTENCIA FAILED"), "{stderr}");
        assert!(!stderr.contains("monitor leaves:"), "{stderr}");
    }

    // A bundle refused above the rules, on the arm that prints to stdout.
    for kit in [&v2, &v1] {
        let (code, stdout, stderr) = verify_monitored_edited(
            vec![],
            vec![signed(enroll("attested"), GENESIS_SEED)],
            true,
            kit,
            |l, i| flip_signature(&mut l[i]),
        );
        assert_eq!(code, 1, "{stdout}\n{stderr}");
        assert!(stdout.contains("does not include under C_audit root"), "{stdout}");
        assert!(!stdout.contains("monitor leaves:"), "{stdout}");
    }
}

/// INTENT: the identity COMPLETITUD works with counts for the kit as well: a rotation
///   of the log that only the bundle shows, to a key the kit lacks, is exit 2, naming
///   the key, whatever the leaves under that key would decide, and also when they
///   would make a fork. With the key in the kit the same leaves are read and do not
///   count. Exit 2 also wins over the FAILED one of them would cause, and an invalid
///   signature of the package still wins over the gap.
/// CONTEXT: `kit_gap` looked at the identity of the package while COMPLETITUD derived
///   its own: with a kit `[G]` and a real G→K2 in log and bundle only, the leaves
///   under K2 could not be checked and decided: a made-up RETIRED and a made-up
///   rotation K2→S were exit 0, a revocable ENROLL INCONCLUSIVE, and a made-up HEAD
///   accused.
/// EXPIRES IF: COMPLETITUD stops deriving an identity from the bundle.
#[test]
fn test_intent_bundle_rotated_key_absent_from_kit_is_exit_2() {
    let genesis_only = kit_v2(BATCH_SLUG, &[GENESIS_SEED]);
    let up_to_date = kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]);
    let k2 = NEW_KEY_SEED;
    let k2_hash = hex::encode(key_hash(k2));
    let rotation = || followed(k2);
    let forged_fork = || {
        vec![
            rotation(),
            unsigned(rotate(2, k2, STRANGER_SEED), k2),
            unsigned(rotate(2, k2, OFF_CHAIN_SEED), k2),
        ]
    };
    let scenarios: Vec<(&str, Vec<Entry>, bool)> = vec![
        ("RETIRED", vec![rotation(), unsigned(retired(), k2)], false),
        ("revocable ENROLL", vec![rotation(), unsigned(enroll("revocable"), k2)], false),
        (
            "rotation K2 to S",
            vec![
                rotation(),
                unsigned(rotate(2, k2, STRANGER_SEED), k2),
                signed(head_at(1), STRANGER_SEED),
            ],
            true,
        ),
        ("HEAD", vec![rotation(), unsigned(contradicting_head(), k2)], true),
        ("fork at K2", forged_fork(), true),
    ];
    for (name, seen, served) in scenarios {
        let (code, stdout, stderr) = verify_monitored(seen, served, &genesis_only);
        assert_eq!(code, 2, "{name}: {stdout}\n{stderr}");
        assert!(stderr.contains(&k2_hash), "{name}: {stderr}");
        assert!(stderr.contains("identity_pubkeys"), "{name}: {stderr}");
        assert!(stderr.contains("monitor bundle"), "{name}: {stderr}");
        assert!(!stdout.contains("CONFIRMED"), "{name}: {stdout}");
    }

    // With K2 in the kit the leaves are read, and made-up ones do not count.
    let discarded = |n: usize| format!("monitor leaves:          {n} discarded");
    let (code, stdout, stderr) =
        verify_monitored(vec![rotation(), unsigned(retired(), k2)], false, &up_to_date);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("G-v6-4bis"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![rotation(), unsigned(enroll("revocable"), k2)], false, &up_to_date);
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("COMPLETITUD:             FAILED"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    let (code, stdout, stderr) = verify_monitored(
        vec![
            rotation(),
            unsigned(rotate(2, k2, STRANGER_SEED), k2),
            signed(head_at(1), STRANGER_SEED),
        ],
        true,
        &up_to_date,
    );
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("G-v6-7"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![rotation(), unsigned(contradicting_head(), k2)], true, &up_to_date);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains(&discarded(1)), "{stdout}");

    let (code, stdout, stderr) = verify_monitored(forged_fork(), true, &up_to_date);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains(&discarded(2)), "{stdout}");

    // An invalid signature of the package outranks a gap of the bundle.
    let (code, stdout, stderr) = verify_monitored_rotated(
        vec![unsigned(rotate(1, GENESIS_SEED, NEW_KEY_SEED), GENESIS_SEED)],
        vec![signed(rotate(2, GENESIS_SEED, OFF_CHAIN_SEED), GENESIS_SEED)],
        true,
        &up_to_date,
    );
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stderr.contains("submitter signature"), "{stderr}");

    // A rotation of the bundle that its old key did not submit reaches nobody, so the
    // kit owes no key for it.
    let (code, stdout, stderr) = verify_monitored(
        vec![unsigned(rotate(1, GENESIS_SEED, k2), STRANGER_SEED)],
        true,
        &genesis_only,
    );
    assert_ne!(code, 2, "{stdout}\n{stderr}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    // Nor does a rotation that its submitter does not name as the old key.
    let (code, stdout, stderr) = verify_monitored(
        vec![signed(rotate(1, OFF_CHAIN_SEED, k2), GENESIS_SEED)],
        true,
        &genesis_only,
    );
    assert_ne!(code, 2, "{stdout}\n{stderr}");
    assert!(stdout.contains(&discarded(0)), "{stdout}");

    // A real fork at a key of the kit is a finding, not a kit to complete: both of
    // its rotations were read, and its branches are nobody's identity.
    let (code, stdout, stderr) = verify_monitored(
        vec![rotation(), signed(rotate(1, GENESIS_SEED, STRANGER_SEED), GENESIS_SEED)],
        true,
        &genesis_only,
    );
    assert_eq!(code, 1, "{stdout}\n{stderr}");
    assert!(stdout.contains("G-v6-8"), "{stdout}");

    // The walk goes on past the first hop: the third key is owed as well.
    let third_key = signed(rotate(2, k2, STRANGER_SEED), k2);
    let (code, stdout, stderr) = verify_monitored(vec![rotation(), third_key], true, &up_to_date);
    assert_eq!(code, 2, "{stdout}\n{stderr}");
    assert!(stderr.contains(&hex::encode(key_hash(STRANGER_SEED))), "{stderr}");

    // A v1 kit reads no key: what it did, it still does.
    let (code, stdout, stderr) =
        verify_monitored(vec![rotation(), unsigned(retired(), k2)], false, &kit_v1(BATCH_SLUG));
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("monitor leaves:          NOT CHECKED"), "{stdout}");
}

/// INTENT: a kit that is up to date passes an honest run, with the rotation in the
///   package or only in the bundle, and leaves under the rotated key are read and
///   count: nothing here turns a current kit into a gap.
/// CONTEXT: the control of the kit gap of the bundle: exit 2 has to mean a kit to
///   complete, never an honest log.
/// EXPIRES IF: a kit stops being a superset of the derived identity.
#[test]
fn test_intent_up_to_date_kit_passes_an_honest_rotated_log() {
    let kit = kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]);
    let under_new_key = || signed(head_at(2), NEW_KEY_SEED);

    let (code, stdout, stderr) =
        verify_monitored_rotated(vec![followed(NEW_KEY_SEED)], vec![under_new_key()], true, &kit);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains("monitor leaves:          0 discarded"), "{stdout}");
    assert!(stdout.contains("submitter signatures:    2 checked"), "{stdout}");

    let (code, stdout, stderr) =
        verify_monitored(vec![followed(NEW_KEY_SEED), under_new_key()], true, &kit);
    assert_eq!(code, 0, "{stdout}\n{stderr}");
    assert!(stdout.contains("COMPLETITUD:             CONFIRMED"), "{stdout}");
    assert!(stdout.contains("monitor leaves:          0 discarded"), "{stdout}");
}

/// INTENT: the same leaf presented twice in a bundle is one rotation, not a fork, so
///   the walk of the keys goes past it and a stale kit still owes the key it reaches.
/// CONTEXT: a bundle is free to repeat a leaf, and `keys_reached_from` drops repeats.
///   Without that, the copy reads as two successors, the walk stops at the genesis, and
///   a forged RETIRED under a key the kit lacks absolves with exit 0.
/// EXPIRES IF: a bundle stops being read as a list a monitor can repeat leaves in.
#[test]
fn test_intent_repeated_rotation_leaf_in_a_bundle_does_not_stop_the_walk() {
    let k2 = NEW_KEY_SEED;
    let repeat_the_rotation = |leaves: &mut Vec<Value>, first_seen: usize| {
        let copy = leaves[first_seen].clone();
        leaves.push(copy);
    };
    let read = |kit: &Value| {
        verify_monitored_edited(
            vec![],
            vec![followed(k2), unsigned(retired(), k2)],
            false,
            kit,
            repeat_the_rotation,
        )
    };

    let (code, stdout, stderr) = read(&kit_v2(BATCH_SLUG, &[GENESIS_SEED]));
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains(&hex::encode(key_hash(k2))), "{stderr}");

    // With the key in the kit the forged RETIRED is read and absolves nothing.
    let (code, stdout, stderr) = read(&kit_v2(BATCH_SLUG, &[GENESIS_SEED, k2]));
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("1 discarded") || stdout.contains("1 discarded"), "{stdout}\n{stderr}");
}

/// INTENT: a real fork with one branch published in the package and a kit that lacks
///   that key is exit 2, printing the COMPLETITUD FAILED; with the key it is exit 1.
/// CONTEXT: the key of a rotation of the package is owed by the kit before the bundle
///   is looked at, so the fork that is exit 1 with both branches in the bundle is not
///   exit 1 here. The kit and the plan say which of the two a script reads.
/// EXPIRES IF: the exit codes of `verify-anchor` change.
#[test]
fn test_intent_real_fork_with_a_branch_in_the_package_owes_the_key_first() {
    let read = |kit: &Value| {
        verify_monitored_rotated(
            vec![followed(NEW_KEY_SEED)],
            vec![signed(rotate(1, GENESIS_SEED, STRANGER_SEED), GENESIS_SEED)],
            true,
            kit,
        )
    };

    let (code, stdout, stderr) = read(&kit_v2(BATCH_SLUG, &[GENESIS_SEED]));
    assert_eq!(code, 2, "stdout: {stdout}\nstderr: {stderr}");
    assert!(stderr.contains("COMPLETITUD: FAILED"), "{stderr}");
    assert!(stderr.contains("G-v6-8"), "{stderr}");

    let (code, stdout, stderr) = read(&kit_v2(BATCH_SLUG, &[GENESIS_SEED, NEW_KEY_SEED]));
    assert_eq!(code, 1, "stdout: {stdout}\nstderr: {stderr}");
}
