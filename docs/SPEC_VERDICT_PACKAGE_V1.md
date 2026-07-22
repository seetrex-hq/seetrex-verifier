# Seetrex Compliance — Verdict Audit Package Format Specification

> **Status: v1.0-draft — format as implemented at commit 6123df1; pending adversarial review.**

**Spec version:** 1 (draft) · **Describes:** `package_format_version: 2` packages ·
**Preimage versions covered:** 1 and 2

---

## 1. Purpose and audience

This document specifies, at byte level, the audit package format produced by
`compliance-cli export-package` and the cryptographic quantities an independent
auditor can recompute from it **without the vendor binary**:

- the content hash of each evidence file (§5);
- the content hash of the evaluated ruleset (§6);
- the verdict hash, for both preimage versions in circulation (§7);
- the audit chain link (§8).

**Scope of independent verification (the two legs).** What this format makes
verifiable from public material alone — with no vendor involvement at all — is
the **integrity of the record**: the per-file hashes, the evidence-to-reference
binding, the ruleset content hash, the verdict hash, the audit chain link and
its external anchor. **Re-derivation of the verdict outcome** (re-executing the
inference over the evidence) is deliberately outside this leg: it requires the
inference engine, which is closed source; it is provided as a signed,
reproducibly built binary (black box), or as a source rebuild under NDA for
regulators. This specification never claims that outcome re-derivation is
possible without the engine — it proves integrity of the record, not
re-execution of the engine.

Any implementation language with SHA-256 and an RFC 8785 (JSON Canonicalization
Scheme, "JCS") library is sufficient. No Seetrex software is required to verify
the hashes defined here.

This document also defines, normatively, **what each verification mode proves
and what it does not prove** (§9). A verifier that reports more than the mode
it ran can prove is misrepresenting this specification.

### 1.1 Requirements language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted
as described in RFC 2119 and RFC 8174 when, and only when, they appear in all
capitals.

### 1.2 Version axes (read this first)

Three independent version numbers appear in this document. They are not the
same thing:

| Axis | Where it lives | Values | Meaning |
|---|---|---|---|
| Spec version | this document's title | 1 | revision of this specification |
| `package_format_version` | `manifest.json` | 2 | shape of the package (file layout and JSON fields) |
| `preimage_version` | `verdict.json` / verdict record | absent/`null`/1, or 2 | which preimage (§7) the verdict's `verdict_hash` was computed over |

A single `package_format_version: 2` package may carry a verdict of either
preimage version. The preimage version is decided per verdict at emission time
and never changes afterwards (§7.4).

---

## 2. Conventions and primitives

- **Hash function.** SHA-256 (FIPS 180-4) everywhere. No other hash is used.
- **Hex encoding.** All hashes are encoded as 64 lowercase hexadecimal
  characters (`[0-9a-f]{64}`). Verifiers SHOULD accept uppercase input for
  externally supplied expected values and compare case-insensitively, but MUST
  emit lowercase.
- **JSON canonicalization.** "JCS" means RFC 8785: object members sorted by
  the UTF-16 code units of their names, no insignificant whitespace, minimal
  string escaping, numbers serialized in the ECMAScript shortest round-trip
  form, output encoded as UTF-8. `NaN` and `Infinity` are not representable
  and MUST be rejected.
- **Duplicate keys.** A verifier MUST reject any JSON document in the
  package that contains a duplicate object key at any nesting level, as
  **malformed** — the same treatment, and the same class of condition, as
  unknown ruleset keys (§6.1); distinct from tampering. Rationale: JCS
  presupposes unique keys, and JSON parsers diverge on how they collapse
  duplicates (most keep the last occurrence, others keep the first or
  reject), so two otherwise-correct verifiers could reach different results
  over the same bytes. The reference implementation rejects duplicates when
  parsing the ruleset ("duplicate field").
- **UUIDs.** Serialized as lowercase hyphenated strings
  (`8-4-4-4-12` hex digits, e.g. `908519d1-3970-4609-aa97-e1e2902f1e3f`).
- **Hashing hex strings.** Where this document says a hex-encoded hash is
  hashed again (§8), the input to SHA-256 is the **ASCII bytes of the 64-char
  lowercase hex string itself**, NOT the decoded 32 raw bytes. This is
  deliberate: it lets a verifier reproduce the chain without a hex decoder.
- **Timestamps.** RFC 3339. Two distinct precision rules apply; see §7.3.

---

## 3. Package layout

A package is a gzip-compressed tar archive (GNU tar format) containing, at
the archive root:

```
verdict.json               the verdict record (one per package)
ruleset.json               the exact ruleset document the verdict was evaluated against
evidence/<uuid>.json       one file per evidence row referenced by the verdict
manifest.json              package metadata and file inventory
```

### 3.1 `manifest.json`

Plain (non-canonicalized) JSON with the fields:

| Field | Type | Meaning |
|---|---|---|
| `package_format_version` | integer | `2` for packages described here |
| `tenant_id` | UUID string | owning tenant |
| `verdict_id` | UUID string | verdict row identifier |
| `verdict_hash` | hex string | copy of the verdict's hash (§7) |
| `chain_prev_hash` | hex string or `null` | copy of the chain link input (§8); `null` for the genesis verdict |
| `chain_hash` | hex string | copy of the chain link (§8) |
| `replay_token` | string | opaque correlation token |
| `appended_at` | RFC 3339 string | when the chain row was appended |
| `files` | array of strings | inventory of archive members |
| `files_sha256` | object (string → hex string), OPTIONAL | per-file integrity index (§3.1.1); present in packages emitted by CLI ≥ 0.1.11 |

**The manifest is not cryptographically covered by anything.** No hash defined
in this specification commits to the manifest's bytes, and `verdict_id` is not
part of any preimage. The manifest is a convenience index: a verifier MUST
treat its contents as claims to be cross-checked against `verdict.json` (the
`verdict_hash` fields MUST agree, and `manifest.json`'s `verdict_id` MUST
equal `verdict.json`'s `id`), never as an independent source of truth.
Consequently, per-file integrity of the archive as a container is **not**
provable from the package alone; what is provable is the integrity of the
individual quantities defined in §5–§8. The OPTIONAL `files_sha256` index
(§3.1.1) does not change this: it lives inside the uncovered manifest, so a
party that re-forges the whole package re-forges the index too. Its value is
internal cross-file consistency, not an external trust root.

#### 3.1.1 `files_sha256` — per-file integrity index (OPTIONAL)

When present, `files_sha256` is a JSON object mapping each archive member's
relative path (forward-slash form, as it appears in `files`) to the SHA-256 of
that file's bytes **exactly as stored in the archive**, encoded as 64
lowercase hexadecimal characters (the raw-bytes primitive of §2, applied
verbatim — no canonicalization). The covered set is every entry in `files`
**except `manifest.json`**, which is excluded because the index lives inside
the manifest and cannot commit to its own bytes.

- Emitters that write this field MUST cover exactly that set — every listed
  file except `manifest.json`, and no other key — and MUST hash the same
  bytes they write into the archive.
- The field is additive: `package_format_version` stays `2`. Packages that
  omit it (emitted before CLI 0.1.11) remain valid, and readers MUST accept
  their absence. A verifier SHOULD emit a WARNING when it is absent.
- A verifier that encounters `files_sha256` MUST enforce it: the map's key set
  MUST equal the covered set exactly (a key for an unlisted file, a key for
  `manifest.json`, or a listed file missing from the map is a failure), and
  every entry's recomputed hash MUST match. Any mismatch MUST fail
  verification.
- Its **absence** downgrades nothing that §5–§8 already prove: the verdict
  hash, evidence content hashes, ruleset anchor, and chain link are still
  checked. What its absence leaves unpinned are the evidence-file fields OTHER
  than `canonical_inline` (e.g. `category`, `ingested_at`) — bytes no §5–§8
  hash covers — which could be altered without tripping any other check. When
  present, `files_sha256` pins those bytes to the (uncovered) manifest, giving
  internal consistency; it is not, and does not claim to be, an external trust
  anchor (§9.3).

### 3.2 `verdict.json`

Plain JSON with the fields:

| Field | Type | In v1 preimage | In v2 preimage |
|---|---|---|---|
| `id` | UUID string | no | no |
| `tenant_id` | UUID string | yes | yes |
| `ruleset_id` | string | yes | yes |
| `ruleset_version` | integer | yes | yes |
| `control_id` | string | yes | yes |
| `verdict_outcome` | string | yes | yes |
| `evidence_refs` | array | yes | yes |
| `working_memory_canonical` | object | yes | yes |
| `verdict_hash` | hex string | — (output) | — (output) |
| `engine_semantic_version` | integer | yes | yes |
| `inferred_at` | RFC 3339 string | no | yes, as `derived_at` (§7.3) |
| `ruleset_content_hash` | hex string or `null` | no | yes |
| `preimage_version` | integer, absent or `null` allowed | discriminator (§7.4) | discriminator (§7.4) |

`verdict_outcome` is one of the exact strings `"SATISFIED"`, `"AT_RISK"`,
`"VIOLATED"`. Any other value MUST be rejected.

`evidence_refs` is an array of objects, each with exactly:

```json
{ "evidence_id": "<uuid>", "content_hash": "<64-char lowercase hex>" }
```

### 3.3 `evidence/<uuid>.json`

One plain-JSON file per referenced evidence row. Fields relevant to
verification:

| Field | Type | Role |
|---|---|---|
| `id` | UUID string | matches the filename and the `evidence_id` in `evidence_refs` |
| `category` | string | evidence category (used by re-derivation) |
| `content_hash` | hex string | commitment to the canonical payload (§5) |
| `canonical_inline` | string or `null` | the canonical evidence payload, inline; `null` when the payload is stored out-of-band ("blob reference") |

Remaining fields (`tenant_id`, `source_id`, `canonical_kind`,
`canonical_blob_key`, `canonical_blob_size_bytes`, `derived_facts`,
`contains_pii_flag`, `ingested_at`) are informational for this
specification.

### 3.4 `ruleset.json`

The exact ruleset document (verbatim bytes of the emitter's embedded ruleset
file) that the verdict was evaluated against. Its content hash is defined in
§6.

---

## 4. Canonical value forms

The verdict's `working_memory_canonical` is a JSON object mapping **fact
identifiers** to **fact values**. These forms are normative for emitters and
for anyone independently re-deriving facts from evidence. For plain hash
recomputation from a package they are informative: the auditor takes the JSON
values exactly as they appear in `verdict.json` and canonicalizes them with
JCS (§7.1) — no value transformation is performed at verification time.

- **Fact identifiers** (object keys) MUST be ASCII.
- **Boolean** facts: JSON `true` / `false`.
- **Numeric** facts: JSON numbers. `NaN` and `±Infinity` MUST be rejected
  (recursively, including inside lists). Serialization follows JCS number
  formatting.
- **Monetary** facts: JSON **strings** (arbitrary-precision decimals are never
  JSON numbers). Canonical form: the decimal string with trailing fractional
  zeros removed, and a resulting trailing `.` removed. Sign is preserved.
  Examples: `1.00` → `"1"`, `1.10` → `"1.1"`, `-1.00` → `"-1"`, `0.0` → `"0"`,
  `100` → `"100"`.
- **Date-time** facts: JSON strings, RFC 3339 UTC with `Z` suffix. The
  fractional-second width of date-time *fact values* is deliberately NOT
  pinned to a fixed number of digits (unlike `derived_at`, §7.3): the
  reference serializer emits the shortest exact representation with
  fractional digits in groups of three (0, 3, 6 or 9 digits), and an input
  carrying a numeric UTC offset (`+00:00`) is normalized to `Z` on
  re-serialization. For hash recomputation from a package this is moot —
  the stored string is used verbatim.
- **Date** facts: JSON strings, ISO 8601 `YYYY-MM-DD`.
- **Duration** facts: JSON strings in canonical unit-chain form
  `[-]<D>d<H>h<M>m<S>s` with zero-valued components omitted and the value
  `0s` for a zero duration (e.g. `5400` seconds → `"1h30m"`, never `"90m"`).
- **String** facts: JSON strings; MUST be ASCII (recursively, including
  inside lists).
- **List** facts: JSON arrays; element order is significant and MUST be
  preserved exactly. Elements recursively follow these forms.

Because fact values are strings, numbers, booleans and arrays of the same, any
correct JCS implementation reproduces the emitter's canonical bytes from the
JSON in the package.

### 4.1 Type inference precedence

Fact values are *untagged*: their JSON form does not name their kind. Where
an implementation must recover the kind of a JSON value (independent
re-derivation, or a strict verifier applying §6.1's option to reject
non-canonical scalars), it MUST use the reference precedence — candidates
are tried in order and the first match wins:

```
Boolean → Number → Money → DateTime → Date → Duration → String → List
```

Monetary (a decimal-looking string such as `"100.50"`) is tried before the
temporal kinds; this is unambiguous because the temporal string forms all
require non-numeric separators (`-`, `T`, `Z`) or duration unit suffixes
(`s`, `m`, `h`, `d`), which a decimal string cannot contain. A string
matching none of the specific kinds is a plain string.

The reference implementation normalizes recovered values to the §4 canonical
forms on re-serialization: a duration parsed from `"90m"` re-serializes as
`"1h30m"`, a date-time carrying a `+00:00` offset re-serializes with `Z`,
and a monetary string re-serializes with trailing fractional zeros trimmed.

---

## 5. Evidence content hash

For every evidence file with an inline payload:

```
content_hash = lowercase_hex( SHA-256( UTF-8 bytes of canonical_inline ) )
```

The hash covers **exactly the string value** of `canonical_inline` — the bytes
of the string content itself, not the JSON-escaped representation and not the
whole evidence file.

The obligations in this paragraph apply to any verification mode that
processes the `evidence/` directory (full re-derivation, §9.2, and any
package-level check); the weak mode (§9.1) operates on a request and a
ruleset only and does not execute them. Such a verifier MUST recompute this
hash for every evidence file and reject the package on any mismatch. It MUST
also check that the multiset of `(evidence_id, content_hash)` pairs
reconstructed from the `evidence/` directory equals the multiset declared in
`verdict.json`'s `evidence_refs` — extra files, missing files, and diverging
pairs are all rejections.

Evidence with `canonical_inline: null` (blob reference) cannot be verified
offline from the package alone; full re-derivation (§9.2) rejects such
packages explicitly.

---

## 6. Ruleset content hash

```
ruleset_content_hash = lowercase_hex( SHA-256( JCS(completed ruleset document) ) )
```

The *completed* document is `ruleset.json` after the normalization defined in
§6.1. The reference implementation obtains it by parsing the file into its
typed model and re-serializing it; an independent implementation MUST perform
the equivalent normalization directly on the JSON before canonicalizing.

**JCS over the raw file bytes is NOT sufficient in general.** The on-disk
document may omit optional fields whose defaults the completed document
carries explicitly; a canonicalization that skips §6.1 produces a different
digest on any such file. Appendix A demonstrates this with the published
synthetic fixture: the completed-document hash reproduces the emitter's
anchor, while plain JCS over the raw bytes does not.

### 6.1 Document completion rules

The ruleset document has a **closed key set**: the tables below are
exhaustive, and conforming emitters reject unknown keys at every nesting
level. Verifiers MUST reject a ruleset containing any key not listed in
these tables, at any nesting level, as **malformed** (a distinct condition
from a hash mismatch — a malformed document is outside this specification;
a hash mismatch on a well-formed document indicates tampering or drift).

**Top-level object** (all fields required except `regulatory_source`):

| Key | Type |
|---|---|
| `ruleset_id` | string |
| `framework` | string |
| `article` | string |
| `control` | string |
| `version` | integer |
| `engine_semantic_version_floor` | integer |
| `doc` | string |
| `facts_consumed` | array of strings |
| `verdicts_emitted` | array of strings |
| `rules` | array of rule objects |
| `regulatory_source` | object, OPTIONAL — when absent it stays absent (it is never materialized and never `null`) |

**Rule object** — absent optional fields MUST be materialized with their
defaults in the completed document:

| Key | Type | If absent |
|---|---|---|
| `id` | string | required |
| `name` | string | required |
| `conditions` | array of condition objects | materialize `[]` |
| `antecedents` | array of strings | materialize `[]` |
| `consequent` | string | required |
| `consequent_value` | fact value (§4) or `null` | materialize `null` |
| `priority` | integer | required |
| `condition_groups` | array of arrays of condition objects | materialize `[]` |

**Condition object** (in `conditions` and inside `condition_groups`):

| Key | Type | If absent |
|---|---|---|
| `fact_id` | string | required |
| `operator` | string, one of `Eq` `Ne` `Lt` `Le` `Gt` `Ge` `In` `Range` `Exists` `Matches` `Contains` `StartsWith` `EndsWith` | required |
| `value` | fact value (§4) | required |
| `negated` | boolean | materialize `false` |

**`regulatory_source` object** (when present, all fields required):
`regulation`, `article`, `paragraph`, `url_official` (strings);
`guidance_refs`, `interpretation_caveats` (arrays of strings).

**Scalar values.** JCS itself canonicalizes numbers (a file scalar written
`24.0` hashes as `24` — any correct RFC 8785 implementation does this
without extra work). String-typed fact values inside rules follow the §4
canonical forms; the emitter guarantees published rulesets carry them in
canonical text already (a non-canonical duration such as `"90m"` would be
normalized to `"1h30m"` by the reference parse-and-re-serialize path, which
plain JCS would not fix). A strict verifier MAY reject non-canonical string
scalars outright.

### 6.2 What the anchor means, per preimage version

The semantics of `ruleset_content_hash` differ materially between the two
verdict populations:

- **Verdicts with preimage v2** (§7.2): the anchor is **inside the verdict
  hash preimage**. Tampering with `ruleset.json`, or with the anchor field
  itself, changes the recomputed verdict hash and is caught by comparison
  against the external anchor (§9.3). The ruleset is cryptographically bound
  to the verdict at emission.
- **Verdicts with preimage v1**: the anchor field (when present) is
  **package-attested only** — it is a field of the same package it vouches
  for, outside the verdict hash. A forger who rewrites `ruleset.json` and
  recomputes the field consistently passes the anchor check. For v1 verdicts
  the anchor detects accidental drift and unsophisticated tampering, not a
  coherent re-forge; the honest statement is "the packaged ruleset is
  consistent with the hash the package itself declares", nothing stronger.

---

## 7. Verdict hash

```
verdict_hash = lowercase_hex( SHA-256( JCS(preimage object) ) )
```

The preimage is a JSON object. Its member set depends on the preimage version.

### 7.1 Preimage version 1 — 8 members

| JCS key (sorted order) | Type | Source in `verdict.json` |
|---|---|---|
| `control_id` | string | `control_id` |
| `engine_semantic_version` | integer | `engine_semantic_version` |
| `evidence_refs` | array | `evidence_refs`, sorted (§7.1.1) |
| `ruleset_id` | string | `ruleset_id` |
| `ruleset_version` | integer | `ruleset_version` |
| `tenant_id` | UUID string | `tenant_id` |
| `verdict_outcome` | string | `verdict_outcome` |
| `working_memory_canonical` | object | `working_memory_canonical`, verbatim |

Not in the preimage: `id` (`verdict_id`), `verdict_hash` itself,
`inferred_at`, `ruleset_content_hash`, `preimage_version`, and every
`manifest.json` field. For a v1 verdict, the emission timestamp is therefore
**not tamper-evident** — this is precisely the weakness preimage v2 closes.

#### 7.1.1 `evidence_refs` ordering

Before hashing, the `evidence_refs` array MUST be sorted ascending by
`content_hash`, ties broken by `evidence_id`. Both comparisons are plain
byte-wise (lexicographic) comparisons of the canonical lowercase string forms;
for UUIDs this string order coincides with the numeric byte order of the
128-bit value. Each element serializes under JCS as an object with its two
keys in the order `content_hash`, `evidence_id` (JCS sorts them so).

The emitter writes `evidence_refs` already sorted; a verifier MUST NOT rely on
that and MUST apply the sort itself.

### 7.2 Preimage version 2 — 10 members

Preimage v2 is preimage v1 plus two members. Full sorted key list:

| JCS key (sorted order) | Type | Source in `verdict.json` |
|---|---|---|
| `control_id` | string | `control_id` |
| `derived_at` | string, fixed-precision RFC 3339 (§7.3) | **parsed from** `inferred_at` |
| `engine_semantic_version` | integer | `engine_semantic_version` |
| `evidence_refs` | array | `evidence_refs`, sorted (§7.1.1) |
| `ruleset_content_hash` | 64-char lowercase hex string | `ruleset_content_hash` |
| `ruleset_id` | string | `ruleset_id` |
| `ruleset_version` | integer | `ruleset_version` |
| `tenant_id` | UUID string | `tenant_id` |
| `verdict_outcome` | string | `verdict_outcome` |
| `working_memory_canonical` | object | `working_memory_canonical`, verbatim |

The two added members make (a) the derivation timestamp and (b) the identity
of the evaluated ruleset tamper-evident: any change to either changes
`verdict_hash`.

`verdict_id` remains outside the preimage in v2.

### 7.3 `derived_at`: the name mapping and the format rule

**Name mapping.** The preimage key is `derived_at`; the wire field in
`verdict.json` (and the underlying storage column) is named `inferred_at`.
The stored name is historical; its documented semantics has always been the
**derivation clock** — the single UTC clock sample used to derive age-relative
facts during inference. The preimage names the concept correctly; the wire
keeps the historical name to avoid a second, cryptographically pointless
format break. They are the same instant.

**Format rule (normative, byte-level).** In the preimage, `derived_at` MUST
be serialized as RFC 3339 UTC with **exactly six fractional digits** and the
literal suffix `Z`:

```
YYYY-MM-DDTHH:MM:SS.ffffffZ         e.g. 2026-07-18T09:15:42.123456Z
```

- Exactly 6 fractional digits always, including trailing zeros
  (`.120000`, `.000000`) — never fewer, never more.
- Uppercase `T` and `Z`; no numeric UTC offset form.
- The emitter truncates (floor, toward zero) its clock sample to microsecond
  precision **before** using it anywhere, so the derived facts, the stored
  value, and the hashed value are the same microsecond-exact instant.

**Parse, never copy.** Emitters conforming to this specification MUST write
`inferred_at` on the wire in the fixed 6-digit format above (the reference
exporter routes the wire field through the same formatter as the preimage,
for every package it produces regardless of the verdict's preimage version).
In packages produced by conforming emitters, wire and preimage strings are
therefore byte-identical. However, packages produced by earlier emitters
remain in circulation and carry **variable** fractional precision (`.123000`
shortened to `.123`; a whole-second value with no fraction at all). A
verifier therefore MUST parse `inferred_at` to a timestamp and re-format it
under the fixed 6-digit rule; copying the wire string into the preimage is
incorrect and, on legacy-emitter packages, produces a false mismatch on
roughly any timestamp whose microseconds end in zeros.

### 7.4 The `preimage_version` discriminator

Each verdict record carries an integer discriminator, exposed in
`verdict.json` under the exact wire key `preimage_version` (legacy verdicts
export it as JSON `null`; requests and packages that omit the key entirely
are equivalent to `null`):

| Value | Meaning |
|---|---|
| absent or `null` or `1` | preimage version 1 (§7.1) |
| `2` | preimage version 2 (§7.2) |
| anything else | **unsupported — the verifier MUST reject** ("this verifier predates the preimage version"), never fall back to v1 or v2 |

Normative rules:

- The discriminator is **authoritative**. A verifier MUST NOT infer the
  preimage version from the presence or absence of `ruleset_content_hash`
  (see §10: v1 verdicts with a non-null anchor exist).
- Fail closed on unknown versions: silently verifying a future-version verdict
  against an older preimage yields a confusing mismatch at best and an
  unintended downgrade at worst.
- For a version-2 verdict, `inferred_at` and `ruleset_content_hash` are both
  REQUIRED inputs. A record or package claiming `preimage_version: 2` while
  missing either MUST be rejected as inconsistent (possible field stripping).
- `preimage_version` is itself **outside** the hash. This is safe because the
  two preimages have different JCS key sets — the preimage bytes are
  self-describing, so equating a v1 hash to a v2 hash requires a SHA-256
  collision, not a downgrade — and because every verification path compares
  against an externally obtained expected hash (§9.3), which pins the true
  version's hash.

### 7.5 Worked example: the same verdict content under both preimages

The following minimal example is the reference implementation's pinned unit
fixture (synthetic values; the hashes below are pinned in its regression
suite and were independently reproduced with a third-party JCS + SHA-256
implementation while writing this section). It shows the same 8 base members
hashed under v1, then under v2 with the two added members.

**Preimage v1 — exact JCS bytes (one line):**

```
{"control_id":"sbom_presence","engine_semantic_version":4,"evidence_refs":[{"content_hash":"aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab","evidence_id":"11111111-1111-1111-1111-111111111111"}],"ruleset_id":"sprint1-sbom-presence","ruleset_version":1,"tenant_id":"00000000-0000-0000-0000-000000000001","verdict_outcome":"SATISFIED","working_memory_canonical":{"sbom.present":true,"sprint1.verdict_SATISFIED":"SATISFIED"}}
```

```
verdict_hash (v1) = SHA-256(above) =
5fc9ad226041b5d918f6e9fe0af36ea99494fd9a0db793c51b0bedb9b7093744
```

**Preimage v2 — same content plus `derived_at` and `ruleset_content_hash`
(one line):**

```
{"control_id":"sbom_presence","derived_at":"2026-07-18T12:00:00.123456Z","engine_semantic_version":4,"evidence_refs":[{"content_hash":"aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab","evidence_id":"11111111-1111-1111-1111-111111111111"}],"ruleset_content_hash":"cafe0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab","ruleset_id":"sprint1-sbom-presence","ruleset_version":1,"tenant_id":"00000000-0000-0000-0000-000000000001","verdict_outcome":"SATISFIED","working_memory_canonical":{"sbom.present":true,"sprint1.verdict_SATISFIED":"SATISFIED"}}
```

```
verdict_hash (v2) = SHA-256(above) =
4ec1e30ae5e4460f7bfc805c747e7196e7abc2e94d16be44e75648e9dfb9abaa
```

Things to notice: the two added keys interleave with the existing ones under
JCS sorting (`derived_at` lands between `control_id` and
`engine_semantic_version`; `ruleset_content_hash` between `evidence_refs`
and `ruleset_id`); `derived_at` carries exactly six fractional digits; and
the two hashes are unrelated — the preimages are distinct byte strings with
distinct key sets (§7.4).

A complete end-to-end example over a real (synthetic) package — including
evidence hashes, the ruleset anchor, and the chain link — is Appendix A.

---

## 8. Audit chain link

Every verdict appends one row to a per-tenant, append-only hash chain. The
link formula, identical for both preimage versions (the chain hashes whatever
`verdict_hash` the row persisted, so v1 and v2 verdicts coexist on one chain):

**Genesis row** (first verdict of the tenant, `chain_prev_hash = null`):

```
chain_hash = lowercase_hex( SHA-256( ASCII(verdict_hash_hex) ) )
```

**Every subsequent row:**

```
chain_hash = lowercase_hex( SHA-256( ASCII(prev_chain_hash_hex) || ASCII(verdict_hash_hex) ) )
```

where `||` is byte concatenation, `prev_chain_hash_hex` is the previous row's
`chain_hash`, and — per §2 — the inputs are the **ASCII bytes of the 64-char
lowercase hex strings** (128 input bytes in the non-genesis case), not decoded
raw hashes. This choice is deliberate: the chain is recomputable with nothing
but SHA-256 and string concatenation.

### 8.1 The public chain export

The chain is published per tenant as a JSON document with a closed key set
(verifiers MUST reject unknown keys):

```json
{ "schema_version": "1.0", "chain": [ <row>, <row>, … ] }
```

Each row carries exactly eight fields, in three data classes —
independently checkable, reproducible offline, and self-attested:

| Field | Type | Class |
|---|---|---|
| `ordinal` | integer, 1-based contiguous (append order) | independently checkable (contiguity) |
| `verdict_hash` | hex string | reproducible offline (§7) |
| `chain_prev_hash` | hex string or `null` (genesis only) | reproducible offline (§8) |
| `chain_hash` | hex string | reproducible offline (§8) |
| `verdict_id` | UUID string | self-attested metadata |
| `appended_at` | RFC 3339 string | self-attested metadata |
| `ruleset_id` | string | self-attested metadata |
| `verdict_outcome` | string | self-attested metadata (committed inside `verdict_hash`, not independently recomputable from the export alone) |

Verifying an export means checking, for every row, that `chain_prev_hash`
equals the previous row's `chain_hash` (null exactly and only at ordinal 1),
that the recomputed link equals the row's persisted `chain_hash`, and that
ordinals are contiguous from 1. The resulting head (`verdict_count`,
`last_chain_hash`) can then be compared against the published tenant page.

The export is obtained from the vendor's public Trust Center — for example
(non-normative) the tenant's page under `https://seetrex.com/trust/` — over a
channel the auditor chooses and controls; §9.3 governs its role as the
external anchor source.

The package's `manifest.json` copies `chain_prev_hash` and `chain_hash` for
correlation, but — see §9.4 — matching them proves nothing about the
verdict's position in the *current* chain.

---

## 9. Verification modes: what each proves, and what it does not

Two full verification modes exist in the released tooling, both under
`compliance-cli replay` (§9.1, §9.2); both REQUIRE an expected verdict hash
supplied by the caller. A third, strictly weaker, package-integrity check —
`compliance-cli verify-package` (§9.6) — re-computes hashes only and treats the
external anchor as optional. This section is normative for any independent
implementation of any of the three.

### 9.1 Integrity replay ("weak" mode)

*Reference tooling: `compliance-cli replay --request … --ruleset …
--expected-verdict-hash …`.*

Pipeline: check `ruleset.json` against the request's declared `ruleset_id` and
`ruleset_version`; check the ruleset anchor (§6) when present; rebuild the
preimage from the request's **declared** canonical input (per the verdict's
preimage version, §7.4); compare the recomputed hash against the externally
supplied expected hash.

The mode's input is a `request.json` document — the declared canonical input
in portable form (an extract of `verdict.json`; every field maps 1:1):

| Field | Type | Notes |
|---|---|---|
| `tenant_id` | UUID string | |
| `ruleset_id` | string | |
| `ruleset_version` | integer | |
| `control_id` | string | |
| `verdict_outcome` | string | `SATISFIED` \| `AT_RISK` \| `VIOLATED` |
| `evidence_refs` | array of `{evidence_id, content_hash}` | as in §3.2 |
| `engine_semantic_version` | integer | |
| `working_memory_canonical` | object | fact id → fact value (§4) |
| `ruleset_content_hash` | hex string, OPTIONAL | absent/`null` = no anchor (legacy); REQUIRED when `preimage_version` is 2 — absent then = stripped, reject |
| `inferred_at` | RFC 3339 string, OPTIONAL | the derivation clock; REQUIRED when `preimage_version` is 2 (parse-and-reformat per §7.3); ignored by the v1 preimage |
| `preimage_version` | integer, OPTIONAL | absent/`null` = 1; `2` = v2; anything else = reject (§7.4) |

**Proves:** integrity of the verdict's *hashed canonical input* — that the
declared canonical input (outcome, working memory, evidence references, and
in v2 the derivation clock and ruleset anchor) hashes to the externally
anchored `verdict_hash`, i.e. the hashed canonical input was not altered
after emission. For a v1 verdict this does NOT extend to the fields outside
the preimage (§7.1): `inferred_at`, the ruleset anchor field, and the
verdict id can be altered without affecting the v1 hash.

**Does NOT prove:**

- that the decision *follows from the evidence* — the engine is not
  re-executed; the working memory is taken as declared;
- for v1 verdicts without an anchor, that the packaged ruleset content is the
  evaluated one (only id+version match; the verifier requires an explicit
  opt-in — `--allow-legacy` in the reference tooling — because an absent
  anchor is ambiguous between a genuine legacy verdict and a stripped field);
- anything in §9.4 or §9.5.

### 9.2 Full re-derivation replay ("full" mode)

*Reference tooling: `compliance-cli replay --full --package-dir …
--expected-verdict-hash …`.*

Pipeline: verify every evidence `content_hash` (§5); verify the ruleset
anchor (§6) — REQUIRED, no legacy fallback; cross-check declared vs
reconstructed evidence references (multiset equality, §5); re-derive all
facts from the evidence payloads using the persisted derivation clock
(`inferred_at`) as the *only* time source; re-execute the inference engine
against the packaged ruleset; then compare **four** things, failing loud at
the first divergence: (1) the re-derived outcome vs the packaged outcome,
(2) the re-derived working memory vs the packaged one, byte-identical under
JCS, (3) the verdict hash recomputed **from the re-derived material** vs the
packaged hash, and (4) the same recomputed hash vs the **externally
supplied** expected hash.

**Proves:** everything §9.1 proves, plus that the verdict is *re-derivable* —
the same evidence, ruleset, and derivation clock deterministically reproduce
the same working memory, outcome, and hash. In v2, tampering with the
derivation clock or the ruleset is caught by comparison (4) even when the
package is internally coherent.

**Does NOT prove:** anything in §9.4 or §9.5. Note also that full mode
requires the verifying engine build to match the verdict's
`engine_semantic_version`, and rejects blob-reference evidence (§5).

### 9.3 The external trust anchor (normative for §9.1 and §9.2, and for §9.6's anchored outcome)

**The package is never its own trust root.** Every quantity a package
contains — including `verdict_hash`, the chain fields, and the ruleset
anchor of v1 verdicts — can be rewritten consistently by whoever rewrites
the package. An internally coherent re-forge passes every self-contained
check by construction.

Therefore: a verifier MUST compare the recomputed verdict hash against an
expected value obtained **outside the package** — the tenant's public chain
export from the Trust Center, a previously recorded hash, or another channel
the auditor controls — and MUST NOT report success on the strength of
package-internal consistency alone. A verifier implementation MUST NOT
describe a check that lacked either re-derivation (§9.2) or an external
anchor as "verified"; overclaiming the mode that ran is a conformance
violation of this specification.

### 9.4 Chain position and freshness are out of scope for package verification

A *genuine but superseded* verdict — packaged with its own authentic hash and
its own historically valid chain links — passes both §9.1 and §9.2, including
the external-anchor comparison (its hash really is in the public chain).
Neither mode proves that the verdict is the **current** one for its control,
nor *where* it sits in the chain, nor that no later verdict superseded it.

Position and freshness are established only by verifying the full public
chain export (§8) against the Trust Center and locating the verdict's hash at
its ordinal there. Auditors needing "this is the latest verdict for control
X" MUST combine package verification with a chain-export check; package
verification alone can never answer that question.

### 9.5 What nothing in this specification proves

For completeness, none of the mechanisms above prove: that the ingested
evidence truthfully describes the audited system (garbage in, garbage out);
that the ruleset is an adequate interpretation of the regulation it names;
the authenticity of the verifying binary itself (obtain and verify tooling
through an independent channel); or the wall-clock truth of the derivation
timestamp beyond its integrity (v2 makes the recorded instant tamper-evident,
not externally attested).

### 9.6 Package integrity verification (`verify-package`)

*Reference tooling: `compliance-cli verify-package --package-dir …
[--expected-verdict-hash …]`.*

This mode is a **hash-integrity check over an already-extracted package
directory**. It re-computes hashes only; it does **not** re-execute the
inference engine (that is full mode, §9.2) and does **not** establish chain
position or freshness (§9.4). It is therefore **strictly weaker than §9.2**:
it proves that the package's bytes are internally consistent with the
`verdict_hash` they carry, and — when an external anchor is supplied — that
this hash matches a value obtained outside the package (§9.3). It never
re-derives the verdict. Unlike §9.1 and §9.2 the external anchor is
**OPTIONAL** here (see the outcome vocabulary below); when it is omitted the
result is explicitly NOT a verification.

**Steps.** A conforming implementation MUST run the following checks, in this
order, and MUST fail closed (halt and report failure) at the first divergence.
Each error MUST name the offending file and, where applicable, the expected and
observed values.

1. **Shape.** The verifier MUST reject a manifest whose `package_format_version`
   is a value it does not understand, failing loud and naming the version,
   mirroring the `preimage_version` unknown-version rule (§7.4); an absent field
   defaults to `2` (the current format, §1.2) and MUST NOT fail on that ground.
   Every path listed in `manifest.files` (and every `files_sha256` key) MUST be a
   plain relative path confined to the package directory — an absolute path, a
   drive prefix, or a `..` component is a failure (the verifier MUST NOT read
   outside the package). Every listed path MUST exist as a regular file in the
   package, and the package MUST contain no regular file other than
   `manifest.json` and the listed files. An undeclared extra file is a failure.
2. **`files_sha256` (§3.1.1).** If the manifest carries `files_sha256`, the
   verifier MUST enforce it: the map's key set MUST equal the covered set
   exactly (every listed file except `manifest.json`, and no other key), and
   every entry's recomputed stored-bytes hash MUST match. If the field is
   **absent**, the verifier MUST NOT fail on that ground (pre-0.1.11 packages
   are valid, §3.1.1) but SHOULD emit a WARNING that the evidence-file fields
   other than `canonical_inline` are pinned by no hash.
3. **Evidence content hashes (§5).** For each `evidence/<uuid>.json`, the
   verifier MUST recompute `SHA-256(canonical_inline)` over the STORED payload
   bytes verbatim (never re-canonicalized) and require it to equal both the
   matching `verdict.json` `evidence_refs` entry AND the evidence file's own
   `content_hash` field. Evidence whose `canonical_inline` is `null` (a blob
   reference) MUST fail — it cannot be integrity-checked offline from the
   package alone (§5). The set of evidence files present MUST equal the set of
   `evidence_refs` declared by `verdict.json`: an orphan file or a dangling
   reference is a failure (multiset equality, §5).
4. **Coherence and chain link (§8).** The `verdict_hash` MUST agree between
   `manifest.json` and `verdict.json`, and `manifest.verdict_id` MUST equal
   `verdict.json.id` (§3.1). The chain link MUST recompute to the declared
   `manifest.chain_hash`, branching on genesis exactly as §8 does: for a genesis
   row (`chain_prev_hash = null`) it is `SHA-256(ASCII(verdict_hash))` — the
   `verdict_hash` hex bytes alone, with no concatenation; for every subsequent
   row it is `SHA-256(ASCII(chain_prev_hash ‖ verdict_hash))`. Both forms are
   taken over the hex ASCII bytes per §2/§8. (The single frozen example, Appendix
   A.5, is a genesis row, so a literal implementation of this step MUST take the
   no-concatenation branch to reproduce it.)
5. **Ruleset anchor (§6).** `ruleset.json` MUST be accepted by the strict
   ruleset parser (unknown or duplicate keys are rejected as malformed, §2/§6.1;
   the rejection MUST surface loudly). Its content hash (§6, completion rules
   §6.1) MUST equal the verdict's declared `ruleset_content_hash` when present.
   When the verdict declares no anchor (pure legacy v1, §10), there is no anchor
   to check; the verifier MUST NOT invent one, and MAY note the computed hash
   for the record. (This mode has no `--allow-legacy` gate: an absent anchor is
   simply unchecked here, since the mode never claims the strength §9.1's opt-in
   guards.)
6. **Verdict-hash preimage (§7).** The verifier MUST select the preimage by the
   `preimage_version` discriminator (§7.4), never by anchor presence: absent /
   `null` / `1` ⇒ the 8-member v1 preimage (§7.1); `2` ⇒ the 10-member v2
   preimage (§7.2). Any other value MUST be rejected (fail loud, §7.4) — the
   verifier MUST NOT fall back to v1 or v2. For `preimage_version: 2`, a missing
   `inferred_at` or `ruleset_content_hash` MUST be rejected as inconsistent
   (possible field stripping, §7.4). The recomputed hash MUST reproduce the
   packaged `verdict_hash`.
7. **External anchor (§9.3).** If `--expected-verdict-hash` is supplied, the
   recomputed hash MUST equal it (compared case-insensitively, §2); a mismatch
   is a failure and MUST be reported as "internally consistent but does NOT
   reproduce the externally supplied hash — treat it as re-forged." If it is
   omitted, this step is skipped and the result is self-consistent only.

The verifier evaluates a further WARNING condition at the step 5–6 boundary: if
`verdict.json`'s wire `inferred_at` is present but not byte-identical to the
§7.3 canonical 6-digit form (a pre-F1-emitter package), the verifier SHOULD
record a WARNING and MUST NOT treat it as a failure — the preimage re-formats
the value per §7.3 (B-5). Warnings — this one and the absent-`files_sha256`
WARNING of step 2 — are collected as the checks run and printed as a block after
the step lines, not interleaved with them; their relative order within that
block is not binding. A conforming verifier SHOULD also bound its resource use
over adversarial packages (the reference implementation caps each file at 10 MiB
and the package at 8192 files, failing loud past either).

**Outcome vocabulary and exit codes.** These tokens and codes are binding:

| Outcome token | Condition | Exit |
|---|---|---|
| `INTEGRITY-OK (weak)` | all seven steps pass AND `--expected-verdict-hash` was supplied and matched (step 7) | `0` |
| `SELF-CONSISTENT (unanchored)` | steps 1–6 pass and step 7 is NOT PERFORMED (no external anchor was supplied) | `4` |
| *(error line, no success token)* | any step failed | `1` |

`SELF-CONSISTENT (unanchored)` means the package is internally coherent but
nothing outside it attested the hash. The reader MUST NOT treat it as a
verification: a coherent forgery is self-consistent by construction (§9.3). The
distinct exit code `4` exists so scripts cannot mistake an unanchored pass for
an anchored one; the reference tooling additionally prints a hint to re-run with
`--expected-verdict-hash`.

**Reserved vocabulary (`VERIFIED`).** The token `VERIFIED` is RESERVED for the
strong surfaces (`replay --full` / `verify-chain`). A package-integrity
implementation MUST NOT emit `VERIFIED` from this mode. Informative: the
surfaces that DO emit `VERIFIED` are the full-replay CLI (`replay --full`, §9.2)
and the offline chain verification (`verify-chain` against the published chain
export, §8.1); the emission of the `VERIFIED` token by those surfaces is not
specified by this document, but naming them gives the reserve its stated
counterpart. Because several failure
messages interpolate package-controlled bytes (a planted filename, a serde type
error, a rejected ruleset key), fixed wording alone cannot guarantee the token
never appears in a rendered line; an implementation SHOULD therefore sanitize
the reserved token at its output boundary before printing any line — step
confirmations, warnings, terminal tokens, and errors alike. The rationale is
concrete: downstream shell tooling pattern-matches the substring `VERIFIED` as a
strong pass, so leaking it from a weak check would misreport the result. The
reference CLI routes every line through a boundary sanitizer that rewrites
`VERIFIED` to `VERIF[REDACTED]`.

**Honest-scope statement (printed on every terminal outcome).** On success and
on failure alike, the reference tooling prints a scope statement to the effect
that this check re-computes hashes only; that it does NOT re-execute the
inference engine (that is `replay --full`); that it does NOT prove the verdict's
chain position or freshness (that is `verify-chain` against the published chain
export with an externally obtained anchor); and that **package-internal
consistency alone is never a trust root**. An implementation SHOULD surface an
equivalent statement so a reader can never mistake a package-integrity pass for
a full re-derivation or a freshness proof.

**Does NOT prove:** anything in §9.4 or §9.5; that the decision follows from the
evidence (no engine re-execution — that is §9.2); and, absent an external anchor
(§9.3), that the recomputed hash is the genuine one — an unanchored pass proves
only internal consistency.

---

## 10. Verdict populations and compatibility

Three verdict populations exist and all remain permanently verifiable
(storage is append-only; no backfill ever rewrites an emitted verdict):

| Population | `preimage_version` | `ruleset_content_hash` | Verification |
|---|---|---|---|
| Legacy | absent/`null` (⇒ 1) | `null` | §9.1 with explicit legacy opt-in (id+version ruleset check only); full mode (§9.2) unavailable — no strong derivation-clock semantics were persisted |
| Anchored v1 (transition window) | absent/`null` (⇒ 1) | non-null | §9.1 and §9.2 with the v1 preimage; the anchor is checked but is package-attested (§6.2) |
| v2 | `2` | non-null (required) | §9.1 and §9.2 with the v2 preimage; clock and anchor are inside the hash |

**The transition-window population is real, not hypothetical:** verdicts were
emitted by servers that already persisted the ruleset anchor but still
computed the 8-member v1 preimage. For these rows the implication "anchor
present ⇒ preimage v2" is **false**. This is exactly why §7.4 makes the
discriminator authoritative: classify by `preimage_version`, never by anchor
presence. An anchored-v1 verdict re-labeled as v2 fails verification (the
10-member preimage yields a different hash than its externally anchored v1
hash); the correct v1 classification verifies cleanly, anchor check included.

---

## Appendix A. Reference values: a complete synthetic package

All values in this appendix come from the reference test vector package
published alongside this specification (frozen at format commit `6123df1`).
It was produced by the real emission pipeline over **fabricated evidence** (a
fixture vulnerability scan and a fixture SBOM — nothing originates from a
real tenant), then frozen as a regression pin. Every hash
below was independently reproduced from the listed inputs with a third-party
JCS + SHA-256 implementation while writing this appendix.

### A.1 Package listing

```
verdict.json
ruleset.json
evidence/7a54f0cc-7ec2-423b-81f3-029961effc94.json     (category: vuln_scan)
evidence/a2ce0096-9fed-4e70-ba58-14bcf57e5da8.json     (category: sbom)
manifest.json
```

This frozen example predates the `files_sha256` emitter (§3.1.1): its
`manifest.json` carries no `files_sha256` field, and it remains a valid manifest
— the absent-field case §3.1.1 requires readers to accept — which a conforming
`verify-package` (§9.6, step 2) verifies without failure.

Key `verdict.json` values:

| Field | Value |
|---|---|
| `tenant_id` | `5ee70000-0000-0000-0000-000000000f1c` |
| `ruleset_id` / `ruleset_version` | `cra-art13-vulnerability-handling` / `2` |
| `control_id` | `vulnerability_handling` |
| `verdict_outcome` | `VIOLATED` |
| `engine_semantic_version` | `6` |
| `inferred_at` (wire) | `2026-07-17T22:59:29.163178Z` |
| `preimage_version` | `2` |
| `ruleset_content_hash` | `ddc5eb369b10c0bc120ec43e665f049b2b2c197fe570e7c669b81b650331d865` |
| `verdict_hash` | `066f6bcb08865beb644f5f371c58fc23b31a6e34b96c160ccceedc646fe83743` |

### A.2 Evidence content hashes (§5)

`SHA-256(canonical_inline)` of each evidence file reproduces its declared
`content_hash`:

```
7a54f0cc-7ec2-423b-81f3-029961effc94  (vuln_scan)
  b2ac67eddf17098c445832286506b5e70f29fce4f168465c9cdfc17733bbf164
a2ce0096-9fed-4e70-ba58-14bcf57e5da8  (sbom)
  f5c09386daa98920123f845a0ebd148d76d4b97e5f727a1fb433bf078f2fd110
```

### A.3 Ruleset content hash (§6) — including the negative control

The fixture's `ruleset.json` omits the defaulted fields `negated` (on every
condition) and `condition_groups` (on every rule), and writes several numeric
scalars as `24.0`, `7.0`, `0.0`, `1.0`, `3.0`.

- **Completed document (§6.1) → JCS → SHA-256** — reproduces the anchor the
  emitter recorded in `verdict.json`:

  ```
  ddc5eb369b10c0bc120ec43e665f049b2b2c197fe570e7c669b81b650331d865
  ```

- **Plain JCS over the raw file bytes, skipping §6.1** (number
  canonicalization applied, defaults NOT materialized) — a **wrong** value,
  shown as a negative control so implementers can detect the mistake
  immediately:

  ```
  3c7f3d063d02c306b866ace8eb6a98fe29c3d7456e77212ddf1712427343305c   (WRONG)
  ```

If your implementation produces the second value, it is missing the §6.1
completion step.

### A.4 Verdict hash (§7.2) — preimage v2, exact JCS bytes (one line)

```
{"control_id":"vulnerability_handling","derived_at":"2026-07-17T22:59:29.163178Z","engine_semantic_version":6,"evidence_refs":[{"content_hash":"b2ac67eddf17098c445832286506b5e70f29fce4f168465c9cdfc17733bbf164","evidence_id":"7a54f0cc-7ec2-423b-81f3-029961effc94"},{"content_hash":"f5c09386daa98920123f845a0ebd148d76d4b97e5f727a1fb433bf078f2fd110","evidence_id":"a2ce0096-9fed-4e70-ba58-14bcf57e5da8"}],"ruleset_content_hash":"ddc5eb369b10c0bc120ec43e665f049b2b2c197fe570e7c669b81b650331d865","ruleset_id":"cra-art13-vulnerability-handling","ruleset_version":2,"tenant_id":"5ee70000-0000-0000-0000-000000000f1c","verdict_outcome":"VIOLATED","working_memory_canonical":{"CRA.Art13.criticals_many":true,"CRA.Art13.freshness_basis_scan_native":true,"CRA.Art13.verdict_VIOLATED":"VIOLATED"}}
```

```
verdict_hash = SHA-256(above) =
066f6bcb08865beb644f5f371c58fc23b31a6e34b96c160ccceedc646fe83743
```

Note `derived_at` is byte-identical to the wire `inferred_at` (§7.3: this
emitter writes the fixed 6-digit format on the wire), and the two evidence
refs are already in `(content_hash, evidence_id)` order.

### A.5 Chain link (§8)

This verdict is its tenant's genesis row (`chain_prev_hash: null` in
`manifest.json`), so:

```
chain_hash = SHA-256( ASCII("066f6bcb08865beb644f5f371c58fc23b31a6e34b96c160ccceedc646fe83743") )
           = 3ce54560f4375f111433aa8a417d94bb823f6c7212756b710ccebba0a464a497
```

which matches the `chain_hash` recorded in `manifest.json`. The input is the
64 ASCII bytes of the hex string — not 32 decoded raw bytes.

### A.6 Negative test vectors

Two deliberately wrong hashes, each isolating one implementation mistake.
Both vectors are variants of the §7.5 v2 fixture; the WRONG values let an
implementer identify *which* mistake they made from the value alone.

**A.6.1 — `evidence_refs` sort key (§7.1.1).** The §7.5 fixture with a
second evidence ref chosen so that ordering by `content_hash` and ordering
by `evidence_id` disagree:

```
ref 1: content_hash aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab
       evidence_id  11111111-1111-1111-1111-111111111111
ref 2: content_hash bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab
       evidence_id  00000000-0000-0000-0000-000000000002
```

Correct order is by `content_hash` (`aaaa… < bbbb…`), i.e. ref 1 then ref 2 —
even though ref 2 has the lower `evidence_id`. Exact preimage JCS bytes (one
line):

```
{"control_id":"sbom_presence","derived_at":"2026-07-18T12:00:00.123456Z","engine_semantic_version":4,"evidence_refs":[{"content_hash":"aaaa1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab","evidence_id":"11111111-1111-1111-1111-111111111111"},{"content_hash":"bbbb1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab","evidence_id":"00000000-0000-0000-0000-000000000002"}],"ruleset_content_hash":"cafe0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab","ruleset_id":"sprint1-sbom-presence","ruleset_version":1,"tenant_id":"00000000-0000-0000-0000-000000000001","verdict_outcome":"SATISFIED","working_memory_canonical":{"sbom.present":true,"sprint1.verdict_SATISFIED":"SATISFIED"}}
```

```
correct (content_hash order):
5688f28d107231700dd3c12ce600c9741be1b91fd26e75f38b41b2abd972e0f3
WRONG  (evidence_id order — refs swapped):
2f9eeafd0f91b1ede9c9174b8b17dc5d364d6ab3149088f1c34d2b515e5d3ece
```

If your implementation produces the WRONG value, it sorts `evidence_refs` by
`evidence_id` instead of by `(content_hash, evidence_id)`.

**A.6.2 — parse, never copy (§7.3).** The §7.5 fixture (single evidence
ref) with a derivation clock whose microseconds end in zeros. A
legacy-emitter wire carries it shortened:

```
wire inferred_at (legacy emitter):  2026-07-18T12:00:00.123Z
preimage derived_at (after parse
and re-format, fixed 6 digits):     2026-07-18T12:00:00.123000Z
```

```
correct (derived_at ".123000Z"):
47b740d621afcf21b39d5e53a0819c9a4924cdee0c8d254987301b769b68dc6a
WRONG  (wire string ".123Z" copied into the preimage):
1f9869231f2b33fee150df6a4675c5c33e54b81c0228924bfe5b27f205273c63
```

The two preimages differ only in the `derived_at` bytes. If your
implementation produces the WRONG value, it copies the wire `inferred_at`
string into the preimage instead of parsing and re-formatting it.
