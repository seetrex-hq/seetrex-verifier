# SELFTEST — what this implementation reproduces from the specification

Implementation: `seetrex_verifier.py` (926 lines measured 2026-08-30, Python
3.9+, standard library only). Run on CPython 3.12, Windows.

**This file is a record of the BLIND run** and is not re-executed when the
implementation or the specification changes: what it reports is what the
reader reproduced from the document alone, before either leg had ever seen
the other. `ALIGNMENT_NOTES.md` carries everything that moved afterwards.

Method, for every vector where the specification prints exact preimage bytes:

1. **Direct check** — feed the printed bytes to SHA-256 and compare with the
   printed hash. This tests nothing but my reading of the vector.
2. **Structured check** — feed the *structured* inputs through my own JCS
   canonicalizer, `evidence_refs` sort and `derived_at` re-formatter, and assert
   the bytes come out **byte-identical to the printed preimage**, then hash them.
   Where the spec printed a WRONG negative control, I also reproduced the wrong
   value by deliberately making the mistake it isolates.

Structured inputs were fed in deliberately adverse order — `evidence_refs`
reversed, `working_memory_canonical` keys shuffled — so that a canonicalizer
that merely echoed insertion order could not pass.

---

## 1. Reproduced — every printed hash whose inputs the spec supplies

| Spec value | Printed | Reproduced | How |
|---|---|---|---|
| §7.5 v1 preimage bytes | one line, §7.5 | yes | canonicalizer output byte-identical |
| §7.5 `verdict_hash` (v1) | `5fc9ad226041b5d918f6e9fe0af36ea99494fd9a0db793c51b0bedb9b7093744` | yes | direct + structured (8 members) |
| §7.5 v2 preimage bytes | one line, §7.5 | yes | canonicalizer output byte-identical |
| §7.5 `verdict_hash` (v2) | `4ec1e30ae5e4460f7bfc805c747e7196e7abc2e94d16be44e75648e9dfb9abaa` | yes | direct + structured (10 members) |
| A.4 preimage bytes | one line, A.4 | yes | canonicalizer output byte-identical, from refs supplied in reverse order |
| A.4 `verdict_hash` | `066f6bcb08865beb644f5f371c58fc23b31a6e34b96c160ccceedc646fe83743` | yes | direct + structured |
| A.5 genesis `chain_hash` | `3ce54560f4375f111433aa8a417d94bb823f6c7212756b710ccebba0a464a497` | yes | `SHA-256(ASCII(verdict_hash))`, no concatenation |
| A.6.1 preimage bytes | one line, A.6.1 | yes | canonicalizer output byte-identical |
| A.6.1 **correct** | `5688f28d107231700dd3c12ce600c9741be1b91fd26e75f38b41b2abd972e0f3` | yes | direct + structured; refs fed in `evidence_id` order, my §7.1.1 sort re-orders them |
| A.6.1 **WRONG** | `2f9eeafd0f91b1ede9c9174b8b17dc5d364d6ab3149088f1c34d2b515e5d3ece` | yes | negative control: re-sorted by `evidence_id` only |
| A.6.2 **correct** | `47b740d621afcf21b39d5e53a0819c9a4924cdee0c8d254987301b769b68dc6a` | yes | wire `…123Z` parsed and re-formatted to `…123000Z` |
| A.6.2 **WRONG** | `1f9869231f2b33fee150df6a4675c5c33e54b81c0228924bfe5b27f205273c63` | yes | negative control: wire string copied verbatim into the preimage |

**21/21 assertions passed**, counting the byte-identity assertions separately
from the hash assertions.

Both negative controls reproducing exactly is the load-bearing result: it means
the two mistakes the spec warns about (sorting by `evidence_id`, copying the
wire timestamp) are mistakes this implementation *would* make if the
corresponding line were removed — i.e. those lines are doing the work.

Quick independent re-check of the two headline values, no code of mine involved:

```sh
python -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read().rstrip(b'\n')).hexdigest())" < preimage.txt
```

## 2. Also reproduced — derived rules the spec states but does not tabulate

| §7.3 input (wire `inferred_at`) | my `derived_at` |
|---|---|
| `2026-07-18T12:00:00.123Z` | `2026-07-18T12:00:00.123000Z` |
| `2026-07-18T12:00:00Z` | `2026-07-18T12:00:00.000000Z` |
| `2026-07-18T12:00:00.123456789Z` | `2026-07-18T12:00:00.123456Z` (truncated toward zero) |
| `2026-07-18T12:00:00.123456+00:00` | `2026-07-18T12:00:00.123456Z` |
| `2026-07-18T14:00:00.5+02:00` | `2026-07-18T12:00:00.500000Z` |

**ECMAScript number serialization** (RFC 8785 §3.2.2.3). The instruction to
check these before trusting Python was well placed: `repr()` disagrees with
ECMAScript on four of the eight values below, so `json.dumps` would have
produced wrong canonical bytes for any ruleset carrying such a scalar.

| value | Python `repr` | ECMAScript / mine | agree? |
|---|---|---|---|
| `1.0` | `1.0` | `1` | no |
| `-0.0` | `-0.0` | `0` | no |
| `1e20` | `1e+20` | `100000000000000000000` | no |
| `1e21` | `1e+21` | `1e+21` | yes |
| `1e-6` | `1e-06` | `0.000001` | no |
| `1e-7` | `1e-07` | `1e-7` | no |
| `100.0` | `100.0` | `100` | no |
| `24.0` | `24.0` | `24` | no (this is §6.1's own example) |

Also checked: `5e-324` → `5e-324`, `1.2345678901234568e21` →
`1.2345678901234568e+21`, `0.001` → `0.001`, `1e-5` → `0.00001`, `1234.5678`,
`-1e21`. All match ECMAScript `Number::toString`.

**JCS member ordering is by UTF-16 code units, not code points** (§2). With keys
`"a"`, `"Ｚ"` (U+FF3A) and `"😀"` (U+1F600, surrogate pair D83D DE00), Python's
default string sort gives `a`, `Ｚ`, `😀`; mine gives `a`, `😀`, `Ｚ`, because
0xD83D < 0xFF3A. Verified.

**String escaping** (RFC 8785 §3.2.2.2): `{"s":"x\"y\\z\n\t\u0000\u001fé"}` —
the five short escapes, `\u00xx` lowercase for other C0 controls, and `é`
literal in UTF-8. Verified. Lone surrogates are rejected.

**Rejections** (§2, §4), all verified to fail loudly: `NaN`, `Infinity`,
`-Infinity`, a number overflowing to infinity (`1e400`), a duplicate key at top
level, and a duplicate key nested one level deep.

---

## 3. NOT reproduced — and why

| Spec value | Reason |
|---|---|
| **A.2** evidence content hashes `b2ac67ed…` (vuln_scan) and `f5c09386…` (sbom) | The specification prints the hashes but **not the input bytes**: the `canonical_inline` payloads of the two fixture evidence files are nowhere in the document, and the Appendix-A package itself is not distributed with the spec. `SHA-256(canonical_inline)` cannot be checked against an input I do not have. The two hashes *are* consumed as inputs to A.4, which I do reproduce, so the values are confirmed self-consistent with A.4 — but the §5 formula is untested against them. |
| **A.3** completed-document ruleset anchor `ddc5eb36…` | Same: the fixture `ruleset.json` is described (§A.3 says it omits `negated` and `condition_groups` and writes `24.0`, `7.0`, `0.0`, `1.0`, `3.0`) but never printed. §6.1 completion is fully determined by the document it is applied to; without those bytes the hash is unreachable. Consumed as an input to A.4, and reproduced there. |
| **A.3 WRONG** plain-JCS control `3c7f3d06…` | Same missing input. |

To get *some* falsifiable signal on §6.1 despite the missing fixture, I built a
ruleset in the shape A.3 describes — every `negated` and `condition_groups`
omitted, scalars written `24.0` and `3.0` — and confirmed that the completion
step changes the digest, which is the whole content of A.3's negative control:

```
plain JCS over the raw document : 8db6833717fa0e73ed71b4100073f34c048ed982d5e713b789f4073cbb362a0d
completed document (§6.1)       : 127e16b7bf56216bbc2932579911c5509da6b73b31869110693ad09fbfc9bed9
```

and that a rule written with four keys completes to eight, with `24.0`
canonicalizing to `24`:

```json
{"antecedents":[],"condition_groups":[],"conditions":[{"fact_id":"scan.criticals","negated":false,"operator":"Gt","value":3}],"consequent":"CRA.Art13.criticals_many","consequent_value":null,"id":"r1","name":"many criticals","priority":10}
```

These are my numbers, not the spec's. They show the mechanism is present; they
do **not** show it agrees with the reference implementation. **A.3 remains the
one substantive unverified claim in this implementation**, and the cheapest way
to close it is for the spec to print the fixture `ruleset.json` bytes (or its
completed JCS form) the way it prints every other preimage.

---

## 4. CLI behaviour exercised end to end

No Appendix-A package exists to run against, so I built synthetic packages with
my own emitter-side code (shared algorithms — this is a consistency test of the
CLI plumbing, not independent evidence about the hashes above) and ran all 18
scenarios. Every observed exit code and token is the one §9.6's table binds.

| Scenario | Expected | Observed |
|---|---|---|
| package, no `--expected-verdict-hash` | `SELF-CONSISTENT (unanchored)`, exit 4 | as expected, with the re-run hint |
| package, correct anchor supplied **in uppercase** | `INTEGRITY-OK (weak)`, exit 0 | as expected (case-insensitive compare, lowercase output) |
| package, wrong anchor | error, exit 1, "treat it as re-forged" | as expected, no success token |
| legacy wire `.163Z`, no `files_sha256` | exit 4 + **two** warnings | as expected; hash unaffected (v1 preimage) |
| anchored v1 (`preimage_version: 1` **with** an anchor) | exit 4, v1 preimage chosen | as expected — classified by the discriminator, not by anchor presence (§10) |
| tampered evidence payload | exit 1 at step 3 | as expected |
| `preimage_version: 3` | exit 1, "refusing to fall back" | as expected |
| unknown key in a rule object | exit 1, "MALFORMED, not a hash mismatch" | as expected |
| duplicate JSON key in `verdict.json` | exit 1 | as expected |
| `files_sha256` entry wrong | exit 1 at step 2 | as expected |
| `../outside.json` in `manifest.files` | exit 1 at step 1 | as expected |
| undeclared extra file | exit 1 at step 1 | as expected |
| chain export, 3 rows, no expected head | `VERIFIED`, exit 0 + "nothing outside attested the head" | as expected |
| chain export, correct expected head | `VERIFIED`, exit 0 | as expected |
| chain export, wrong expected head | exit 1, names ordinal 3 and field `chain_hash` | as expected |
| chain export, broken `chain_prev_hash` | exit 1, names ordinal 3 and the field | as expected |
| chain export, ordinal gap (1, 5, 3) | exit 1, names the position and field `ordinal` | as expected |
| chain export, a ninth field in a row | exit 1, names the unknown field | as expected |

The warning block, the `SCOPE:` block and the terminal token are printed on
every outcome, success and failure alike, with the token last.

## 5. The reserved token

Two adversarial packages: one carrying an undeclared file named
`VERIFIED-by-the-vendor.txt`, one whose `ruleset.json` carries an unknown rule
key `VERIFIED_by_vendor`. Both error lines interpolate the planted bytes; both
printed `VERIF[REDACTED]`. Across all 18 runs the literal string `VERIFIED`
appears exactly twice in the tool's own output — the two `verify-chain` success
tokens, the only place §9.6 permits it. `verify-package` never emitted it.
