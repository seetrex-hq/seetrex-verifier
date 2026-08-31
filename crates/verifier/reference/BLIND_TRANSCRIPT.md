# Provenance of the blindness claim

`seetrex_verifier.py` is presented as an implementation written from
`docs/SPEC_VERDICT_PACKAGE_V1.md` **alone** -- not from the Rust verifier that
ships beside it, and not from any of its tests. That is a claim about process,
and process claims are prose unless something in the tree lets a reader check
them. This file is the checkable part.

What an auditor can verify from here:

1. **Which bytes the implementer received.** The table below records the
   sha256 of the specification copy handed over, and the sha256 of the
   specification as it stands now. `test_intent_blind_transcript_names_the_spec_it_saw`
   (in `tests/`) recomputes the second one on every run, so the transcript
   cannot silently go stale behind a spec edit.
2. **What else was in the room.** The working directory listing below is
   exhaustive: one document in, three files out.
3. **What the implementer was told.** The task text is reproduced verbatim,
   below, with nothing elided.
4. **What the implementer did not settle.** `OPEN_QUESTIONS.md` and
   `SELFTEST.md` are committed exactly as written, unedited. They are the
   part of the exercise that a leak would have made impossible to write: an
   implementer who had read the Rust would not have had to guess at exit
   codes the document never states.

## 1. The specification the implementer saw

| date | sha256 of `SPEC_VERDICT_PACKAGE_V1.md` | commit | note |
|---|---|---|---|
| 2026-08-30 | `dd1cc8b690b47e5a710a9d66e8e5a667add951e72f3b8e0b9dc0495257773b6b` | `7a221184` | the copy placed in the working directory; the only input |
| 2026-08-30 | `d5ae173ea062a873a2e32177fc52e17437df3bff106746541aad615655d5ffed` | `4eda0442` | after the DIV-01 correction (4: values are recovered and re-serialized) |
| 2026-08-30 | `2905c017433657bbf8015f2e7854632e559106def7d4de2268ff50135f7b514b` | `e09d7279` | after the Q1-Q16 clarifications |
| 2026-08-30 | `9a38e1976ae8c63219fd6f9e2b05afa17f863b9faed436ad48a2e1d788bd373d` | `835c3b18` | after the R1-A clarifications: 4.1 per-kind grammars, 7.3 second 60, 8.1 chain success token, 9.6 step 6 ASCII duties |
| 2026-08-30 | `46adafb005344082acbe111fe5028730e2d5296ef98ef392a3e08d3b94c4b677` | `6a408de3` | after the R2 clarifications: 4.1 money separator/scale/rounding-mode, date-time offset range, duration i64 bound and the reference's declared crash band, `null`/object fact values are malformed |
| 2026-08-30 | `681d382872d18b864921947edf3bc7060a27741af06af274289f82e75f97ded7` | `383451fe` | after the R2b clarifications: 4.1 Money measured against the reference -- `_` ignored once a digit has appeared (so `1000._5` is monetary), no whitespace trimming, exponent-free scale reduced below 28 until the mantissa fits 2^96, and the exponent form split in two (exact, with a 29-digit written budget; and, past 28 fractional digits, mantissa rounded and exponent discarded) |
| 2026-08-30 | `91f2915818c64575373b43acb43ea23e24b65f6a7b5980dd0cd6c4a70058fcad` | `d6b36b34` | after the R3 clarifications: 4.1 Money names the decimal library version the procedure was measured against (`rust_decimal` 1.37.2, pinned exactly), its exponent rule becomes ONE bullet with three outcomes decided by what the exponent-free rule does to the mantissa -- String, exact fold, or round-and-discard -- instead of by the mantissa fractional-digit count, which was wrong for twelve measured values and decided `7.9228162514264337593543950336e28` twice; Date accepts a signed year and Date-time the colon-less `+HHMM` offset |
| 2026-08-30 | `7ea0fa101734a679c620c1c9f5d3d6c8959999f4831d44e8705d4a8a2fc9d768` | `3c190523` | after the R3b clarification: a leading `-` signs only a ZERO year (`-2026-05-13` reaches String), the one reading the blind aligner had flagged as decided by sentence rather than by witness |
| 2026-08-30 | `2059f53a2353058d3507149bd1b5bb1625bc9632c75b7000ad899d09806a7f9c` | `HEAD` | after the merge into main: the status line no longer says "pending adversarial review" (this reference implementation and its two instruments were that review); it names the reference limits and the dependency pins, and warns holders of earlier copies |

**Every row but the last names the COMMIT whose
`docs/SPEC_VERDICT_PACKAGE_V1.md` hashes to it**, and
`intent_blind_transcript.rs` resolves each one with `git show <commit>:<path>`
and recomputes the sha256. Before that, only the last row was checked, so the
earlier ones could have been forged without any test noticing. The last row
carries `HEAD` rather than a hash for the reason a file cannot name the commit
that contains it: it is pinned against the WORKING TREE instead, which is the
check that already stood.

The first row is the document as the implementer read it; the last is the
document at this commit. Every row after the first exists because a divergence
between the two legs was classified as a **specification** correction, so the
bytes moved after the implementation was frozen -- the first of them was
DIV-01 (hash recomputation over the recovered and re-serialized canonical
value).

Correcting the document and re-aligning the Python are deliberately TWO acts,
in that order: classifying before editing is what preserves the evidence, and
the re-alignment is written by a reader who still has only the specification.
`ALIGNMENT_NOTES.md` is the record of the second act -- one entry per
behaviour that changed, with the sentence that mandates it and the corpus case
that exercises it -- and it is where an auditor reads which revision of the
document the Python currently answers. The first re-alignment, covering DIV-01
and the Q1-Q16 clarifications, was made on 2026-08-30 and left no corpus case
red.

The pinned row is the **last** one: a further spec edit must add a row, dated,
or the guard goes red.

## 2. The working directory

Outside the repository, with no `.git` anywhere above it, so no `git show`,
`git log` or `git grep` could reach the source tree even by accident. Contents
at the end of the exercise, exhaustively:

```
SPEC_VERDICT_PACKAGE_V1.md      (in:  the specification, sha256 as row 1 above)
seetrex_verifier.py             (out: the implementation)
OPEN_QUESTIONS.md               (out: what the document did not settle)
SELFTEST.md                     (out: which published values reproduced)
```

The implementer reported the implementation at **802 lines**
(`SELFTEST.md`, first paragraph), against a target of 400-600 given in the
task text. The overshoot is a measurement about the document, not a style
lapse: it is what a fail-closed reading of the sections listed in the task
text costs when nothing may be assumed.

`OPEN_QUESTIONS.md` and `SELFTEST.md` are committed **unedited**. Their value
is as evidence, and an edited deliverable is not evidence.

## 3. The task text, verbatim

```text
You are implementing a reference verifier in Python 3 from a written specification.

Your ONLY input is the file `SPEC_VERDICT_PACKAGE_V1.md` in your working directory.
Read it in full before writing a line.

HARD RULES (violating any of these invalidates the whole exercise):
- Do NOT read, search, list, or open any file outside your working directory.
- Do NOT run `git`, and do not look for a repository, a Rust crate, a `crates/`
  directory, an `examples/` directory, a kit, a CHANGELOG, or any other verifier.
- Do NOT search the web for "seetrex", for this format, or for any implementation of it.
- You MAY use the Python standard library documentation and RFC 8785 / RFC 3339 /
  FIPS 180-4 as normative references. You MAY read the RFC 8785 text.
- If the specification is silent, ambiguous, or self-contradictory on a point you
  need, DO NOT guess quietly: implement the reading you judge most defensible AND
  record the question in `OPEN_QUESTIONS.md` (one entry per question: the section
  you were reading, what the text does not settle, the two or more readings you
  considered, which you implemented, and why). That file is a required deliverable
  and is as important as the code.

DELIVERABLES, in your working directory:
1. `seetrex_verifier.py` — a single file, Python 3.9+, standard library ONLY
   (`hashlib`, `json`, `argparse`, `sys`, `os`, `pathlib`, `datetime`, `re`,
   `unicodedata` are all fine). No third-party package, no `pip install`.
   Target ~400-600 lines. An auditor must be able to read it in one sitting.
2. `OPEN_QUESTIONS.md` — as above.
3. `SELFTEST.md` — every value from the specification you were able to reproduce
   with your implementation, and every one you could NOT reproduce, with the
   reason (e.g. "the specification prints the hash but not the input bytes").

CLI SHAPE (this exact shape is the contract; do not invent other flags):

  python seetrex_verifier.py verify-package --package-dir <DIR> [--expected-verdict-hash <HEX>]
  python seetrex_verifier.py verify-chain   --chain-export <FILE> [--expected-last-chain-hash <HEX>]

`verify-package` implements §9.6 in full: the seven steps in the given order,
fail-closed at the first divergence, the warning block, the honest-scope
statement, and — binding — the outcome vocabulary and exit codes of the table at
the end of §9.6, together with the reserved-token rule that follows it. The exact
success token strings, and the exit codes 0 / 4 / 1, are given in that table; use
them character for character, printed on stdout, one token per run, as the last
token line. Errors go to stdout as an error line (stderr wording is free).

`verify-chain` implements §8.1 over a public chain export document: closed key
set, eight fields per row, contiguity from ordinal 1, `chain_prev_hash` null
exactly and only at ordinal 1, and the recomputed link of §8 equal to each row's
persisted `chain_hash`. Per §9.6's note on reserved vocabulary, `verify-chain` is
one of the two surfaces that DO emit the token `VERIFIED`; emit it on success.
On failure emit an error line naming the offending ordinal and field. The
specification does not state exit codes for this subcommand: choose 0 for success
and 1 for failure, and record in `OPEN_QUESTIONS.md` that the spec did not say.
If `--expected-last-chain-hash` is supplied, the last row's `chain_hash` must
equal it (case-insensitively, §2); a mismatch is a failure. If it is omitted, say
in the output that nothing outside the export attested the head (§9.3).

IMPLEMENTATION NOTES YOU MUST HONOUR (all of them are in the spec; they are
listed here only so you do not skim past them):
- JCS (RFC 8785) is yours to implement: no JCS package is installed and you may
  not install one. §2 fixes the rules; RFC 8785 §3.2.2 fixes string escaping and
  §3.2.2.3 fixes number serialization (ECMAScript `Number::toString`). Python's
  `repr(float)` / `json.dumps(float)` is shortest-round-trip but is NOT ECMAScript
  formatting; check `1.0`, `-0.0`, `1e20`, `1e21`, `1e-6`, `1e-7`, `100.0` before
  you trust it, and write your own number formatter if it differs.
- JSON parsing must reject duplicate object keys at any nesting level (§2), and
  must reject `NaN` / `Infinity` (§2, §4). Python's `json` accepts both by
  default — you must turn that off.
- §3.1.1 `files_sha256` MUST be enforced when present, over the stored bytes
  (§9.6 step 2); its absence is a WARNING, never a failure.
- §5: hash the STRING VALUE of `canonical_inline`, UTF-8, not the JSON-escaped
  form and not the file; `null` fails in this mode (§9.6 step 3).
- §6/§6.1: the ruleset hash is over the COMPLETED document. Plain JCS over the
  raw file bytes is the classic wrong answer and Appendix A.3 shows you the wrong
  value it produces. The key set is closed at every nesting level; an unknown key
  or a duplicate key is MALFORMED and must be rejected loudly (§9.6 step 5).
- §7.1.1: sort `evidence_refs` yourself, by `content_hash` then `evidence_id`,
  byte-wise. Appendix A.6.1 shows the wrong hash you get if you sort by
  `evidence_id`.
- §7.3: PARSE `inferred_at` and RE-FORMAT it to exactly six fractional digits with
  `Z`. Never copy the wire string. Appendix A.6.2 shows the wrong hash you get if
  you copy it.
- §7.4: the `preimage_version` discriminator is authoritative — never infer the
  version from the presence of `ruleset_content_hash`. Unknown value ⇒ reject.
- §9.6 steps 1 and 5 and §2 on hex: case-insensitive comparison for externally
  supplied expected values, lowercase on output.
- The reserved token: route EVERY line you print through one boundary sanitizer
  that rewrites the reserved token as the spec's last paragraph of §9.6 says,
  including lines that interpolate bytes taken from the package (filenames,
  rejected keys, parse errors). A package whose filename contains the reserved
  token must not be able to make it appear in your output from `verify-package`.
- Bound your resource use as §9.6 suggests (per-file and per-package caps),
  failing loud past either.

VERIFY YOUR WORK against every value the specification prints: §7.5 (two hashes),
Appendix A.2, A.3 (both the right value and the WRONG negative control), A.4, A.5,
A.6.1 (right and wrong), A.6.2 (right and wrong). Where the spec gives you the
exact preimage bytes, feed those bytes to SHA-256 directly as a first check, then
feed the structured input through your own canonicalizer and confirm you produce
the same bytes. Record all of it in `SELFTEST.md`.

Do not ask for more inputs. Do not stop to request approval. Produce the three
files.
```

## 4. What the task text gets wrong, on purpose

The text was frozen **before** anyone opened the Rust binary's source. It is
knowingly wrong about the shipped tool in three ways, and those three
mismatches are findings about the document rather than defects to patch:

- The CLI shape. The task text writes `--package-dir` / `--chain-export`
  because the specification does; the shipped binary takes a positional
  operand and exits 2 on any other flag. `tests/corpus_equivalence.rs` holds
  the five-line adapter in one visible place instead of writing the mismatch
  out of the corpus.
- The error stream. The task text says errors go to stdout because the
  specification never says otherwise; the shipped binary prints them on
  stderr.
- The chain token. The task text says `verify-chain` emits the bare token
  `VERIFIED` because the specification names it as one of the two surfaces
  that do; the shipped binary prints a longer sentence containing it.

Each of these is what an independent reader of the document would build. That
is the measurement the exercise exists to take.
