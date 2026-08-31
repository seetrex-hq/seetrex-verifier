# Alignment of `seetrex_verifier.py` to the revised SPEC_VERDICT_PACKAGE_V1

The Python reference verifier was written from a pre-T10 revision of the spec.
Below, one entry per behaviour changed: the spec sentence that mandates it, what
the code now does, and the corpus case that exercises it.

Result of this alignment: no corpus case left red. Later spec revisions add
their own entries below; the runner's own count is the live number.

---

## 1. §4 (DIV-01) — `working_memory_canonical` values are recovered and re-serialized

> "a verifier MUST recover every `working_memory_canonical` value through the
> §4.1 type inference and re-serialize it in its §4 canonical form before JCS
> (§7.1) — exactly as the emitter would have serialized it. […] A verifier that
> canonicalizes the stored JSON values verbatim (JCS only, no §4 recovery)
> produces a different hash for such a package and is NOT conformant."

**Changed:** new `canonical_fact_value()` implementing the §4.1 precedence
(Boolean → Number → Money → DateTime → Date → Duration → String → List) plus the
§4 canonical forms: money trimming (`"100.50"` → `"100.5"`, trailing `.` dropped),
duration unit-chain (`"90m"` → `"1h30m"`), date-time offset → `Z` with the
fractional digits in groups of three (0/3/6/9, shortest exact). `build_preimage`
maps every working-memory value through it instead of carrying the object verbatim.

**Cases:** `wm-money-noncanonical-stored` (stored `"100.50"`, hash over `"100.5"`
⇒ PASS_UNANCHORED) and `wm-money-string` (same stored value, hash over the
verbatim `"100.50"` ⇒ must FAIL). Regression-guarded by `wm-bool-and-list`,
`wm-number-24-0`, `wm-nan-rejected`.

## 2. §6.1 (Q8) — ruleset *fact values* are canonicalized; plain string fields are not

> "a verifier that does not take that option MUST recover a non-canonical **fact
> value** through the §4.1 type inference and re-serialize it in its §4 canonical
> form before canonicalizing the completed document […] This applies to fact
> values only; the ruleset's plain string fields (`ruleset_id`, `framework`,
> `article`, `control`, `doc`, `facts_consumed`, `verdicts_emitted`, and a rule's
> `id`, `name` and `consequent`) are not fact values and are carried verbatim."

**Changed:** the completion path now sends exactly the two fact-value slots —
a condition's `value` and a rule's `consequent_value` — through
`canonical_fact_value()`. Every other ruleset field stays byte-verbatim.

**Case:** `rs-noncanonical-duration-normalised` (condition `value: "90m"`; the
anchor only reproduces when the completed document carries `"1h30m"`).
Guarded against over-reach by `rs-completion-trap`, `rs-scalar-type-string-rejected`,
`rs-unknown-key`, `rs-duplicate-key` and the Appendix-A packages.

## 3. §7.3 (Q10, Q11) — wire grammar: space separator, second 60, never a grammar rejection

> "a verifier MUST accept every RFC 3339 spelling its date-time library accepts —
> at minimum `T`/`t`, `Z`/`z`, a numeric `±HH:MM` offset (normalised to UTC), a
> space in place of `T` (RFC 3339 §5.6), and second `60` — and MUST NOT reject a
> value on the grammar alone; a value that denotes a different instant than the
> emitter's will fail at the preimage instead."

**Changed:** `TS_RE` accepts a space separator; parsing moved into
`parse_rfc3339()`, which maps second `60` to the instant after `:59` instead of
raising. Truncation of >6 fractional digits toward zero (Q11) is unchanged.

**Cases:** `derived-at-space-separator-ok` (now PASS_UNANCHORED) and
`derived-at-second-60-fails`, which still exits 1 but now fails **at step 6, the
preimage** (recomputed hash ≠ packaged hash) rather than on the grammar — the
behaviour the sentence prescribes. Also `derived-at-legacy-short`,
`derived-at-six-digits`, `derived-at-nine-digits-truncated-ok`.

## 4. §3.3 (Q5) — the evidence record's identity is its `id` field, not its filename

> "The `id` field, not the filename, establishes an evidence record's identity; a
> verifier MUST NOT fail a package because `evidence/<A>.json` carries `id: <B>`,
> provided the multiset check of §9.6 step 3 holds."

**Changed:** dropped the filename-equals-`id` check in step 3. The multiset
equality against `evidence_refs` is unchanged and remains the only identity gate.

**Case:** `ev-filename-not-id-ok`. Still caught by `ev-orphan-file`,
`ev-dangling-ref`, `ev-hash-mismatch`, `ev-null-inline-fails`.

## 5. §2 (Q3) — uppercase hex is tolerated in *comparisons*, never in a *preimage*

> "A verifier MUST also accept uppercase hex in package-internal hash
> **comparisons** (it compares them case-insensitively); this tolerance does not
> extend to any hex string that is itself a hash **preimage** —
> `manifest.verdict_hash` feeds the §8 chain link over its ASCII bytes, so a
> non-lowercase spelling there changes the link and fails step 4 of §9.6."

**Changed:** `need_hex` now validates 64 hex characters in any case and returns
the bytes **verbatim**; a new `same_hex()` performs every package-internal
comparison case-insensitively (manifest vs verdict hash, evidence content hashes,
`files_sha256` entries, the ruleset anchor, step 6, step 7, and the chain-export
links). The step-4 chain link is now computed over `manifest.verdict_hash`'s own
ASCII bytes (previously it used `verdict.json`'s copy). The §7.1.1 sort key uses
the lowercase forms while the element keeps the bytes as written (preimage material).

**Cases:** `hex-upper-internal-ok` (uppercase in `verdict.json`'s `verdict_hash`
and in an evidence file's `content_hash` ⇒ passes) and
`hex-upper-manifest-verdict-hash-fails` (uppercase in the manifest ⇒ the link no
longer reproduces `chain_hash`, step 4 fails).

## 6. §9.6 (Q15) — the reserved-token sanitizer matches case-insensitively, plus a legend

> "The match is case-INSENSITIVE (`Verified`, `verified` and `VeRiFiEd` are all
> rewritten to `VERIF[REDACTED]`), it covers every line of a `verify-package`
> surface including error text, and an implementation SHOULD print, once, a
> legend explaining the mask when it actually reached the output."

**Changed:** the output boundary substitutes with a case-insensitive regex and
records whether it fired; a one-line legend is printed once, at the end, only when
the mask actually reached the output.

**Case:** `reserved-token-lowercase-filename` (a planted `verified_extra.txt`
interpolated into the step-1 error). `reserved-token-filename` covers the
uppercase spelling.

## 7. §9.6 (Q2) — terminal token between the warning block and the scope statement

> "The terminal outcome token is printed after the warning block and **before**
> the honest-scope statement; a script that reads the token MUST match it as a
> line, not as the last line of the output."

**Changed:** `print_tail` split into `print_warnings()` and `print_scope()`; the
order is now step lines → warning block → terminal token → SCOPE (→ mask legend).
A failing run prints ERROR → warnings → SCOPE with no success token.

**Case:** none asserts the order (the runner matches the token as a line, which
holds either way); every PASS/FAIL case exercises the new sequence.

## 8. §9.6 step 5 (Q9) — an absent ruleset anchor is not a WARNING

> "This case is NOT a WARNING condition: the §9.6 warning set is exhaustive
> (absent `files_sha256`, non-canonical wire `inferred_at`), and an absent anchor
> is reported on the step line."

**Changed:** removed the "verdict declares no ruleset_content_hash" warning; the
computed hash is still noted on the step-5 line.

**Case:** none asserts warning content; exercised by `pv-absent-is-v1`,
`pv-null-is-v1`, `unanchored-pass`, `ev-filename-not-id-ok`.

## 9. §3.1 (Q4) — only four manifest fields are load-bearing

> "Only `verdict_id`, `verdict_hash`, `chain_hash` and `files` are load-bearing
> for §9.6; a manifest missing any other field […] verifies, and unknown manifest
> keys are ignored."

**Changed:** `chain_prev_hash` is no longer a required manifest field — absent is
read as `null`, i.e. the genesis branch of §8. (Self-listing in `files` and
unknown keys were already tolerated; `package_format_version` absent already
defaulted to 2.)

**Case:** none in the corpus for the absent `chain_prev_hash`; `pfv-absent-defaults-2`
covers the sibling default, `chain-genesis`/`chain-nongenesis` the two branches.

## 10. §8.1 (Q16) — the chain export's own 50 MiB cap

> "the reference implementation caps it at **50 MiB** — its own cap, larger than
> the 10 MiB per-file cap of §9.6".

**Changed:** `MAX_EXPORT_BYTES` 256 MiB → 50 MiB.

**Case:** none (no oversized fixture).

---

## Deliberately NOT changed

- **`evidence_refs` element key set stays exact.** §3.2's Q6 clarification opens
  the key sets "of `verdict.json` and of `evidence/<uuid>.json`" — the documents.
  The same section still says each `evidence_refs` element has "exactly"
  `evidence_id` and `content_hash`, and those two members are preimage material,
  so an unknown member there is rejected as before. Unknown *top-level* keys of
  `verdict.json` and of evidence files were already ignored, as Q6 requires.
- **Non-ASCII fact identifiers / string facts.** §4 says they MUST be ASCII, but
  that requirement is normative for emitters and re-derivation; §9.6's step list
  gives a verifier no rejection duty, so no new gate was added.

## Cases left red

None.
