# Alignment notes R1 — `seetrex_verifier.py` vs the 2026-08-30 (T10) spec revision

`ALIGNMENT_NOTES.md` did not exist in this directory, so this file carries the
round-1 entries. One entry per behaviour: the spec sentence that compels it, the
change made, and the corpus case that exercises it. Nothing here was derived from
a corpus expectation: every entry quotes the sentence first.

---

## 1. Money — accepted grammar, representation limit, rounding, signed zero

**Spec (§4.1, "Accepted grammar per kind", Money).** "**Money** accepts a JSON
string matching `^[+-]?[0-9_]*([.][0-9_]*)?([eE][+-]?[0-9]+)?$` with at least one
digit present, where `_` is a digit separator and is ignored. […] The value MUST
fit the reference decimal representation (a 96-bit integer mantissa with a scale
of 0 to 28); a string that does not, such as `"1e400"`, is NOT a monetary value
and reaches `String`. A string carrying more significant digits than the
representation holds is ROUNDED to fit, not rejected […] so `"+5"` hashes as
`"5"`, `"1e5"` as `"100000"` and `"100.50"` as `"100.5"`. **A zero carries no
sign in the canonical form**: `"-0.00"` hashes as `"0"`."

**Change.** `MONEY_RE` widened from `\A[+-]?\d+(?:\.\d+)?\Z` to the pinned
grammar, and `_canonical_money` (a textual zero-trim) replaced by `_money_value`,
which recovers the value as (coefficient, scale): strips `_`, folds the exponent
into the scale, requires at least one coefficient digit, returns `"0"` for a zero
coefficient (the one place §4's "sign is preserved" does not apply), sheds digits
until `scale <= 28` and `coefficient < 2**96`, and returns `None` — fall-through
to `String` — when the value cannot be made to fit without losing whole units.
Re-serialization strips trailing fractional zeros and a resulting trailing `.`.

**Corpus.** `wm-money-plus-sign`, `wm-money-exponent`, `wm-money-negative-zero`,
`wm-money-mantissa-over-2pow96` (renamed in R2 -- the old name,
`wm-money-29-significant-digits`, pointed at a boundary that is not the real one:
29 significant digits can fit, 2^96 is where the mantissa stops);
regression cover `wm-money-noncanonical-stored`,
`wm-money-string`, `wm-money-overflow-is-string`.

**Residual under-specification (CLOSED in R2).** At R1 the spec pinned *that* an
over-long value is rounded, not *which* rounding mode; section 4.1 now pins the
mode (half away from zero), pins that rounding applies only to a string with no
exponent, and pins that an exponent form must fit exactly or reach `String`.
The paragraph below records what R1 implemented and why it diverged. This
implementation uses
round-half-to-even with a sticky bit. The pinned case
(`"1.00000000000000000000000000001"` → `"1"`) discards a `1`, so every mode agrees
on it; a value ending in an exact half would separate the modes and the spec does
not currently say which wins.

---

## 2. Date — `%Y-%m-%d` without zero padding, calendar validity

**Spec (§4.1, Date).** "**Date** accepts a JSON string parsed as `%Y-%m-%d`,
which does **not** require zero padding: `"2026-5-13"` is a date and re-serializes
as `"2026-05-13"`. A calendar-invalid spelling such as `"2026-02-30"` is not a
date and reaches `String`."

**Change.** `DATE_RE` (`\A\d{4}-\d{2}-\d{2}\Z`, which both rejected unpadded
input and accepted impossible calendar dates verbatim) replaced by `_date_value`,
which runs `datetime.strptime(s, "%Y-%m-%d")` and re-emits `%04d-%02d-%02d`.
Calendar validity now comes from the parser, not from a shape regex.

**Corpus.** `wm-date-unpadded-month`; regression cover
`wm-date-impossible-is-string`.

---

## 3. Duration — repeated units, any order, summed seconds

**Spec (§4.1, Duration).** "**Duration** accepts a JSON string of an optional
leading `-` followed by one or more `<digits><unit>` groups, unit one of `s`, `m`,
`h`, `d`; surrounding whitespace is trimmed. Groups may repeat and may appear in
any order, and their seconds are SUMMED. […] so `"30m1h"`, `"90m"` and `"1h30m"`
are the same value and hash identically as `"1h30m"`, and `"5s5s"` hashes as
`"10s"`."

**Change.** The fixed-order, at-most-once `DURATION_RE` replaced by
`\A(-?)((?:\d+[smhd])+)\Z` over the whitespace-trimmed string, with
`DURATION_GROUP` iterating the groups and `UNIT_SECONDS` summing them. The greedy
`[-]<D>d<H>h<M>m<S>s` re-serialization (zero components omitted, `0s` for zero) is
unchanged.

**Corpus.** `wm-duration-unit-repeated`, `wm-duration-units-out-of-order`;
regression cover `wm-duration-90m-normalised`, `wm-duration-canonical-kept`,
`wm-duration-fractional-is-string`, `wm-iso8601-duration-is-string`,
`rs-noncanonical-duration-normalised`.

---

## 4. Leap second — same instant as `:59`, `60` spelling retained

**Spec (§7.3, "What second `60` denotes", R1-A I-1).** "A leap second parses to
the SAME POSIX instant as second `59` of the same minute -- the two spellings
share a timestamp -- while the parsed value retains the `60` spelling, which
survives the truncation to microseconds and is re-emitted by the fixed 6-digit
formatter. So `2026-07-18T23:59:60.123456Z` on the wire enters the preimage as the
byte-identical string `2026-07-18T23:59:60.123456Z` (never rewritten to
`...:59.123456Z` […])." §4.1 defers fact date-times to the same mapping: "and
second `60` (see the mapping pinned in §7.3)".

**Change.** `parse_rfc3339` no longer adds one second for `:60` (which pushed the
value into the next minute); it holds second 59 plus a `leap` flag and returns a
3-tuple. `canonical_derived_at` and `_canonical_datetime` re-emit `60` when the
flag is set. Because RFC 3339 offsets are whole minutes, normalising to UTC never
disturbs the seconds field, so the flag survives an offset form too. A leap second
already in the 6-digit form therefore raises no non-canonical-wire WARNING, as
that paragraph requires.

**Corpus.** `derived-at-second-60-mapped` (preimage side),
`wm-datetime-leap-second` (fact side); regression cover
`wm-datetime-offset-normalised`, `derived-at-space-separator-ok`,
`derived-at-nine-digits-truncated-ok`, `derived-at-legacy-short`.

---

## 5. Fact date-time fraction bounded to nine digits

**Spec (§4, Date-time facts).** "the reference serializer emits the shortest exact
representation with fractional digits in groups of three (0, 3, 6 or 9 digits)".

**Change.** `_canonical_datetime` truncates the written fraction to nine digits
before the group-of-three rounding, so a wire value with more than nanosecond
precision can no longer produce a 12-digit fraction the enumerated set does not
contain. (`derived_at` keeps its own, stricter six-digit rule from §7.3.)

**Corpus.** No case exercises a >9-digit fact date-time; the change is compelled
by the enumeration alone and is inert on every present case.

---

## 6. ASCII duties on fact identifiers and string fact values

**Spec (§9.6 step 6, R1-A C-2).** "Recovering `working_memory_canonical` for the
preimage is where §4's two ASCII MUSTs are enforced: a non-ASCII fact identifier
(an object key) and a non-ASCII string fact value are each a failure of this step,
named and reported like any other, never re-encoded or silently passed through."
§4: "**Fact identifiers** (object keys) MUST be ASCII" and "**String** facts: JSON
strings; MUST be ASCII (recursively, including inside lists)"; §4.1, String: "a
non-ASCII string fact is rejected, not re-encoded".

**Change.** New `_ascii_fact_id` guards every `working_memory_canonical` key in
`build_preimage`; new `_ascii_string` guards the `String` fall-through inside
`canonical_fact_value`, which recurses into lists and therefore covers "inside
lists". Both raise `Fail`, so the run exits 1 with an error line naming the
offending identifier or value and no success token. The value guard sits on the
String candidate rather than at the call site, so it also covers a ruleset fact
value (§6.1 routes those through the same §4/§4.1 recovery); a plain ruleset string
field such as `doc` is untouched, since §6.1 carries those verbatim.

**Corpus.** `wm-non-ascii-fact-id-rejected`, `wm-non-ascii-value-rejected`.

---

## 7. `verify-chain` success token is `VERIFIED OFFLINE`

**Spec (§8.1, R1-A I-2).** "On success the implementation MUST print a line
containing the token `VERIFIED OFFLINE` […] The token is matched as a substring of
a line, not as a whole line, because the reference tooling prints it inside a
sentence (`Public chain package VERIFIED OFFLINE`) […] The reserved word MUST NOT
be printed in upper case anywhere else in the run, success or failure: a failing
chain verification MUST NOT emit `VERIFIED OFFLINE` at all."

**Change.** The bare `VERIFIED` line on the chain success path replaced by
`Public chain package VERIFIED OFFLINE`, still the only call site that passes
`allow_reserved=True`. Every failure path leaves through `emit` without that flag,
where the case-insensitive sanitizer rewrites the reserved word, so the token
cannot appear on a failing run.

**Corpus.** `chain-ok-3`; regression cover every other `chain-*` case (all of
which are failures and must not print it).

## Second alignment (R2)

Target of this pass: the §4.1 sentences marked *(Clarified 2026-08-30, T10 — R2.)*
(per-kind grammar with exact boundaries) plus the «No third state» paragraph.
Instruments: `run_corpus.py` (86 cases) and `run_grammar_probes.py` (388 values).
Result: `PYTHON LEG: 86/86`; every probe line is decided by a spec sentence
except the six listed at the end.

### 1. Money — a `_` may not OPEN a component

- **Spec:** §4.1 Money: «Every `_` MUST be preceded by a digit: a separator that
  opens the string (`"_1000"`), that follows the sign (`"-_1"`) or that opens the
  fractional part (`"._5"`) is not a monetary value and reaches `String`, while
  `"1_000"`, `"1__000"`, `"1000_"`, `"1_.5"` and `"1_e3"` are monetary.»
- **Change:** before the `_` are stripped, `_money_value` refuses a string whose
  integer or fractional component begins with `_`. That single test reproduces
  all six listed verdicts (`"1__000"` is monetary because its component opens
  with a digit, so «preceded by a digit» cannot mean «immediately preceded»).
- **Evidence:** corpus `wm-money-leading-underscore-is-string`; probes 31–44
  (`_1000`, `-_1`, `+_1`, `._5`, `1000._5`, `_` → String; `1_000`, `1_0_0_0`,
  `1000_`, `1_.5`, `1_e3`, `1__000`, `1_000_000.000_1` → money).

### 2. Money — scale/mantissa are bounds, not a rounding invitation (exponent form)

- **Spec:** §4.1 Money: «With an exponent, the value must fit EXACTLY once the
  exponent is folded into the scale; nothing is rounded. A folded scale above 28
  (`"1e-29"`, `"1.5e-28"`, `"1e-400"`), a folded scale below 0 (`"0e100"`,
  `"1e400"`) and a mantissa at or above 2^96 (`"1234567890123456789012345678901e-3"`)
  are all NOT monetary values and reach `String`.»
- **Change:** the old `while` loop that shed digits until the value fitted is
  gone. With an exponent the folded scale must lie in `[-28, 28]`; a negative
  folded scale is absorbed into the mantissa (this is what keeps the same
  section's `"1e5"` → `"100000"` true) and the mantissa is then checked against
  2^96. A folded scale below −28 is refused outright, which is the only reading
  under which the spec's own `"0e100"` reaches `String` despite its zero mantissa.
- **Evidence:** corpus `wm-money-exponent-out-of-scale-is-string` (`1e-29`),
  `wm-money-mantissa-over-2pow96`; probes 63–78, 210–216.

### 3. Money — rounding without an exponent: once, half away from zero

- **Spec:** §4.1 Money: «Without an exponent, fractional digits beyond scale 28
  are ROUNDED away, not rejected … Rounding is applied ONCE to the full digit
  string (never digit by digit), and the mode is half away from zero: the tie
  `"1.00000000000000000000000000005"` hashes as `"1.0000000000000000000000000001"`.»
- **Change:** the digit string is cut once at the scale-28 boundary and the FIRST
  dropped digit decides (`>= 5` rounds the magnitude up, the tie included). The
  previous half-to-even loop rounded digit by digit — double rounding, and the
  wrong mode: `"1.000000000000000000000000000005"` (scale 31) now stays `"1"`
  instead of creeping up through 5→1.
- **Evidence:** corpus `wm-money-tie-rounds-away-from-zero`; probes 154–209.

### 4. Money — a value that becomes zero by rounding prints `0`, never `-0`

- **Spec:** §4.1 Money: «A zero carries no sign in the canonical form … The rule
  applies to a value that becomes zero BY ROUNDING as well:
  `"-0.000000000000000000000000000005"` hashes as `"0"`, never `"-0"`.»
- **Change:** the `coeff == 0` test moved AFTER the rounding step (it used to run
  before it, so a value that only became zero by rounding kept its sign).
- **Evidence:** corpus `wm-money-rounds-to-unsigned-zero`; probes 182, 189, 195,
  196, 201–203, 208, 209 (all `"0"`).

### 5. Money — the canonicalizer is bounded

- **Spec:** the §4.1 sentences above are all decidable from the scale window and
  the 29-digit mantissa ceiling; nothing in §4 asks for work proportional to an
  exponent.
- **Change:** an exponent of more than ten digits is refused without being read;
  no power of ten larger than 10^28 is ever built; and no integer is built from a
  digit string longer than 29 digits (`_bounded_int`, and the same guard on
  duration groups). `"1e-2147483649"` answers `String` in ~10 µs, and a
  5 000-digit numeral no longer raises CPython's `int()`-from-string limit as an
  uncaught `ValueError` (measured before the change: `PANIC`).
- **Evidence:** not in the fixtures; measured directly on
  `1e-2147483649`, `1e<5000 nines>`, `0.<5000 zeros>1`, `<5000 nines>s`.

### 6. Date-time — the numeric offset is bounded

- **Spec:** §4.1 Date-time: «The numeric offset is bounded: its magnitude MUST be
  strictly below `24:00` and its minute field below `60`, so `"…+23:59"` is a
  date-time while `"…+24:00"`, `"…-24:00"`, `"…+25:00"` and `"…+00:60"` are not
  and reach `String` — an implementation that normalises an out-of-range offset
  instead of rejecting it produces a different hash for the same package.»
- **Change:** `parse_rfc3339` refuses an offset with hours > 23 or minutes > 59
  before it normalises anything.
- **Evidence:** corpus `wm-datetime-offset-24h-is-string`; probes 292–298, 384.

### 7. Date-time and Date — leniency: whitespace, and no zero padding required

- **Spec:** §4.1 Date-time: «Leading and trailing whitespace is ignored, and the
  date and time components do not require zero padding (`"2026-7-18T12:00:00Z"`
  is the same instant as `"2026-07-18T12:00:00Z"`).» §4.1 Date: «`"2026-5-13"` is
  a date and re-serializes as `"2026-05-13"`. Leading and trailing whitespace is
  ignored, and a year written with fewer than four digits is accepted and
  zero-padded on re-serialization (`"026-05-13"` hashes as `"0026-05-13"`).»
- **Change:** `TS_RE` gained `\s*` at both ends and `{1,2}` widths on the date and
  time components (the offset keeps `HH:MM`, which is how §4.1 spells it).
  `_date_value` no longer goes through `datetime.strptime("%Y-%m-%d")`, whose `%Y`
  demands exactly four digits and whose calendar starts at year 1: it uses its own
  `DATE_RE` (`\s*\d{1,4}-\d{1,2}-\d{1,2}\s*`) plus a proleptic Gregorian validity
  test, so `"026-05-13"` → `"0026-05-13"` and `"0000-01-01"` → `"0000-01-01"`,
  while `"2026-02-30"` still reaches `String`.
- **Evidence:** corpus `wm-datetime-unpadded-month`; probes 217–223, 225–227,
  233, 234, 321.

### 8. Duration — the sum is bounded, and the crash band falls through to String

- **Spec:** §4.1 Duration: «The summed seconds MUST fit a signed 64-bit integer;
  a string whose groups overflow it (`"9223372036854775808s"`,
  `"9223372036854775807m"`) is not a duration and reaches `String`.» And:
  «magnitude above `9223372036854775` seconds (`i64::MAX / 1000`) — the reference
  implementation CRASHES … `"9223372036854775s"` is a duration, while
  `"9223372036854776s"`, `"2562047788015215h"` and `"9223372036854775807s"` abort
  it … a conformant implementation reaches `String` where the reference aborts.»
- **Change:** one bound, `|total| > 9223372036854775` → `String`. The tighter
  (declared-limit) band subsumes the i64 one, and the last sentence quoted is the
  only disposition the spec gives a conformant implementation inside it.
  *Tension worth recording:* «the format's bound is the i64 one» could be read as
  making `"9223372036854776s"` a duration for a non-reference implementation, but
  the same sentence then pins `String` for exactly those values, so the probe
  answers are not left to taste. The Rust leg is expected to answer `PANIC` on
  probes 268–284 above the band — a divergence the spec itself declares.
- **Evidence:** corpus `wm-duration-i64-overflow-is-string`; probes 268–284, 385.

### 9. No third state — `null` and objects are MALFORMED

- **Spec:** §4.1: «A fact value that is JSON `null` or a JSON **object**, at the
  top level or nested at any depth inside a list, matches NO candidate: it is
  **MALFORMED**, and a verifier MUST reject the package rather than canonicalize
  it verbatim.» And §4: «`NaN` and `±Infinity` MUST be rejected (recursively,
  including inside lists).»
- **Change:** `canonical_fact_value` raises `Fail` for `null`, for objects and for
  a non-finite JSON number, at every depth (the list branch re-enters it). It used
  to return `null` and non-finite floats untouched.
  One exception, and it is not a fact value: §6.1's rule table types
  `consequent_value` as «fact value (§4) **or `null`**» and materializes `null`
  when absent, so that slot keeps `null` through `_optional_fact_value`. Without
  the exception the corpus case `rs-noncanonical-duration-normalised` (a rule with
  no `consequent_value`) turned red — the §4.1 rule is about fact values, not
  about every JSON `null` in the package.
- **Evidence:** corpus `wm-fact-value-null-is-malformed` and
  `rs-noncanonical-duration-normalised`; probes 351, 372, 373, 375, 377, 382,
  383, 387, 388.

### Probe lines the spec does not decide

Six of the 388 (all answered here, none by tuning to a fixture — each is a fork
the spec text leaves open, and the reading taken is stated first):

1. `"7.9228162514264337593543950336"`, `"-7.9228162514264337593543950336"`,
   `"7.9228162514264337593543950337"`, `"-7.9228162514264337593543950337"`
   (probes 138–141) and `"9.9999999999999999999999999999"`,
   `"-9.9999999999999999999999999999"` (probes 144, 145) — exponent-free strings
   whose mantissa reaches 2^96 while their scale is already ≤ 28.
   - *Reading taken (→ `String`, hashed verbatim):* «The value MUST fit … a 96-bit
     integer mantissa (strictly below 2^96)» is a MUST, and the only relaxation
     §4.1 grants without an exponent is for «fractional digits **beyond scale
     28**» — which cannot shrink a mantissa that already overflows at scale 28.
   - *Other reading (→ money):* the replaced revision said «is ROUNDED to fit»;
     read that way the implementation would keep shedding fractional digits
     inside scale 28 until the mantissa fitted, giving
     `"7.922816251426433759354395034"` and `"10"`.
   - *Missing sentence:* §4.1 says what happens to a scale that is too large, but
     never what happens to a mantissa that is too large **without** an exponent
     (the mantissa case is spelled out only in the with-exponent bullet).

2. `"10000-01-01"` (probe 224) — a five-digit year.
   - *Reading taken (→ `String`):* §4's canonical Date form is `YYYY-MM-DD`, four
     digits, and §4.1 extends the leniency downward only («fewer than four digits
     … zero-padded»).
   - *Other reading (→ `"10000-01-01"`):* a `%Y` parser that accepts more than
     four digits makes it a date with no canonical spelling of its own.
   - *Missing sentence:* §4.1 Date fixes no upper bound on the year.

3. `"-2026-05-13"` (probe 232) — a negative (proleptic) year.
   - *Reading taken (→ `String`):* neither §4's `YYYY-MM-DD` nor §4.1's Date
     sentence shows a sign, and Money already refuses the string.
   - *Other reading (→ `"-2026-05-13"`):* `%Y` in the reference's date library
     accepts a leading `-` for years before 1 CE.
   - *Missing sentence:* §4.1 Date never says whether the year may carry a sign.

---

## Third alignment (R2b)

§4.1 Money was rewritten as a hand-applicable procedure marked *(Clarified
2026-08-30, T10 — R2b)*. The rules below are transcribed one by one into
`_money_value` and its three helpers (`_money_round`, `_money_exponent_free`,
`_money_exponent_form`); nothing here was read off a fixture — each entry quotes
the sentence, then names the witness values the sentence itself carries. Corpus:
**90/90** (was 86/90). Grammar probes: 484 answered, no `PANIC`; the 302 lines
the Money grammar admits are all decided by the sentences below except the one
listed at the end.

### 1. Money — no whitespace trimming

- **Spec:** «Surrounding whitespace is NOT trimmed — unlike date-time, date and
  duration, which do trim it — so `" 1.5"`, `"1.5 "` and a leading tab are not
  monetary values and reach `String`.»
- **Change:** none needed, and now stated where it can be checked: `MONEY_RE` is
  anchored with `\A…\Z` and carries no whitespace class, so the sentence is
  enforced by the pattern. The comment above it says so, next to the second rule
  the same pattern carries (a `_` inside the exponent, below).
- **Witnesses:** `" 1.5"`, `"1.5 "`, `"\t1.5"` → `String` (probes 415–418;
  each hashes verbatim).

### 2. Money — a `_` is ignored once a digit has appeared, never in the exponent

- **Spec:** «A `_` is ignored once a digit has already appeared in the
  significand, and is never allowed inside the exponent. It need only FOLLOW a
  digit somewhere earlier in the significand; it need NOT be immediately preceded
  by one — this replaces the "every `_` MUST be preceded by a digit" of the
  previous revision, which wrongly sent `"1000._5"` to `String`.»
- **Change:** R2's test — no component may OPEN with a `_` (`ip.startswith("_")
  or fp.startswith("_")`) — is replaced by a left-to-right scan of the WHOLE
  significand, decimal point included, carrying a `seen_digit` flag: a `_` before
  the first digit refuses the string, a `_` after one is dropped. The scan also
  supplies the "at least one digit present" test. The exponent needs no test of
  its own: `MONEY_RE`'s exponent is `[0-9]+`, so `"1e_5"` and `"1e1_0"` match
  nothing at all.
- **Witnesses:** monetary — `"1_000"`, `"1__000"`, `"1000_"`, `"1_.5"`, `"1_e3"`,
  `"1.5_"`, `"1._"`, `"1_2_3.4_5_6"`, `"0._5"`, `"1._5"`, `"1000._5"` → `1000`,
  `1000`, `1000`, `1.5`, `1000`, `1.5`, `1`, `123.456`, `0.5`, `1.5`, `1000.5`;
  `String` — `"_1000"`, `"_"`, `"-_1"`, `"+_1"`, `"._5"`, `"+._5"`, `"_._"`,
  `"1e_5"`, `"1e1_0"`.
- **Evidence:** corpus `wm-money-underscore-after-point` (red before this round),
  `wm-money-leading-underscore-is-string`; probes 31–44, 408–414, 446–449.

### 3. Money — exponent-free: scale from `min(f, 28)` DOWNWARDS

- **Spec:** «Remove the `_`s and let `f` be the number of fractional digits. Take
  the candidate scale `s = min(f, 28)` and round the written value to `s`
  fractional digits; while the resulting mantissa is NOT strictly below 2^96,
  decrement `s` and round again FROM THE ORIGINAL digits (never from the previous
  result, never digit by digit). If `s` would fall below 0 the string is not a
  monetary value and reaches `String`.»
- **Change:** `_money_exponent_free` is that loop verbatim, and it replaces R2's
  single cut at scale 28 plus a flat `coeff >= 2**96 → None`. Each iteration
  re-enters `_money_round` with the ORIGINAL digit string and the new scale, so
  no result is ever rounded twice. The loop is bounded by construction: `s` starts
  at 28 or below and stops at -1, at most 30 iterations, whatever the length of
  the numeral or the magnitude of a discarded exponent.
- **Witnesses:** `"7.9228162514264337593543950336"` → `7.922816251426433759354395034`
  (scale 27), `"9.9999999999999999999999999999"` → `10`,
  `"1234567890123456789012345678.12345678901234567890123456789"` →
  `1234567890123456789012345678.1` (a 28-digit integer part leaves room for one
  fractional digit), `"9999999999999999999999999999.99"` →
  `10000000000000000000000000000` (two scales dropped);
  `String` — `"+79228162514264337593543950336"`,
  `"+123456789012345678901234567890"`, `"+79228162514264337593543950335.5"`
  (rounds at scale 0 exactly ONTO 2^96), while its neighbours
  `"79228162514264337593543950335.4"` and `"79228162514264337593543950334.5"`
  both give `79228162514264337593543950335`.
- **Evidence:** corpus `wm-money-scale-reduced-below-28` (red before this round),
  `wm-money-mantissa-over-2pow96`; probes 124–145, 389–396, 425–432, 438–445, 484.
- **Closes** R2's open fork «probes 138–141, 144, 145 — a mantissa that reaches
  2^96 while the scale is already ≤ 28»: R2b decides it the other way (the scale
  is reduced BELOW 28), and those six lines are no longer undecided.

### 4. Money — rounding: once, half away from zero, from the exact digits

- **Spec:** «The rounding mode is **half away from zero**, in both signs and
  whatever the digit before the cut.»
- **Change:** `_money_round` cuts the original digit string at the scale boundary
  and reads the FIRST dropped digit: `>= 5` raises the magnitude, `< 5` leaves it,
  whatever follows. A cut left of the string start reads an implicit `0`, so a
  value far below the scale rounds to zero. The sign is applied by the caller,
  after the rounding, so the same test rounds away from zero on both sides. This
  is R2's mode, re-expressed so the loop of rule 3 can call it at any scale.
- **Witnesses:** `"0.12345678901234567890123456785"` and
  `"0.123456789012345678901234567850"` → `0.1234567890123456789012345679`,
  `"0.12345678901234567890123456775"` → `0.1234567890123456789012345678`,
  `"1.00000000000000000000000000005"` → `1.0000000000000000000000000001`,
  their negatives up in magnitude, `"0.99999999999999999999999999995"` → `1`,
  forty fractional zeros then a `1` → `0`.
- **Evidence:** corpus `wm-money-tie-rounds-away-from-zero`,
  `wm-money-rounds-to-unsigned-zero`; probes 154–209, 398–407, 433–435.

### 5. Money — exponent form with at most 28 fractional digits: a 29-digit budget

- **Spec:** «Write the mantissa's digits in order — the integer part EXACTLY as
  written, an empty integer part counting as a single `0`, then the fractional
  digits — and let `k` be the fractional-digit count minus the exponent. If `k` is
  negative, append `|k|` zeros to that digit string and set `k` to 0. The string
  is a monetary value iff the digit string is at most 29 digits long, `k` is at
  most 28, and the digit string read as an integer is strictly below 2^96;
  otherwise it reaches `String`. **The leading zeros written in the mantissa spend
  the 29-digit budget.**»
- **Change:** `_money_exponent_form` replaces R2's «fold the exponent into the
  scale, then bound the scale» arithmetic. Three differences that matter: the
  digit string keeps the integer part AS WRITTEN (leading zeros included), the
  budget is 29 digits and not merely the value bound, and the padding length is
  decided by ARITHMETIC before any zeros are materialized, so an exponent of
  10^10 never builds a 10^10-character string. Exponents of eleven digits or more
  are clamped rather than rejected outright (`MONEY_EXP_CLAMP`), because rule 6
  discards the exponent and must still answer.
- **Witnesses:** monetary — `"5e28"`, `"5.0e28"`, `"50e27"`, `"0.5e28"`,
  `"79228162514264337593543950335e-28"` → `7.9228162514264337593543950335`,
  `"1.9999999999999999999999999999e1"` → `19.999999999999999999999999999`,
  `"0.1e1"` and `"0.0000000000000000000000000001e28"` → `1`, `"12.5e-1"` → `1.25`;
  `String` — `"0.5e29"`, `".5e29"`, `"00.5e29"`, `"0.05e30"` (budget), `"1e29"`,
  `"1e30"`, `"1e400"`, `"5e29"`, `"8e28"`, `"9e28"`, `"0e100"`, `"1e-29"`,
  `"1e-400"`, `"1.5e-28"`, `"1.0e-28"`, `"10e-29"`, `"100e-30"`, `"150e-31"`,
  `"199999999999999999999999999999e-29"`, `"99999999999999999999999999999e-1"`,
  `"79228162514264337593543950336e-28"`, `"1234567890123456789012345678901e-3"`.
  Note `"0.5e29"` denotes the value of `"5e28"` and the two do not agree: the
  exponent form does not round.
- **Evidence:** corpus `wm-money-exponent-leading-zero-budget-is-string` (red
  before this round), `wm-money-exponent`, `wm-money-exponent-out-of-scale-is-string`,
  `wm-money-overflow-is-string`, `wm-money-mantissa-over-2pow96`; probes 45–78,
  210–216, 436–437, 462–483.

### 6. Money — exponent form with MORE than 28 fractional digits: exponent DISCARDED

- **Spec:** «the reference rounds the mantissa by the exponent-free rule above and
  then DISCARDS the exponent. This is normative for hash recomputation and is the
  one place where the recovered value is not the value the string denotes, so an
  implementation that folds the exponent first produces a different hash for the
  same package.»
- **Change:** the else-branch of `_money_value` calls `_money_exponent_free` on
  the mantissa digits with `exp` unused — the same call the exponent-free strings
  take. R2 folded the exponent in every case and rejected what did not fit.
- **Witnesses:** `"1.99999999999999999999999999999e1"` → `2` (not `20`),
  `"1.99999999999999999999999999999e-1"` → `2` (not `0.2`),
  `"1.00000000000000000000000000001e0"` and `"…e1"` → `1`,
  `"1.000000000000000000000000000001e2"` → `1`. Boundary, counted on the mantissa
  AS WRITTEN: `"7.9228162514264337593543950335e28"` has 28 fractional digits, so
  rule 5 applies and it hashes as `79228162514264337593543950335`.
- **Evidence:** corpus `wm-money-exponent-dropped-past-scale-28` (red before this
  round); probes 420, 450, 451, 453, 454, 458, 477, 478.

### 7. Money — unchanged from R2, re-checked

Canonical re-serialization (trailing fractional zeros and a resulting trailing
`.` removed) and the unsigned zero — `"-0.00"` → `0`, and a value that becomes
zero BY ROUNDING → `0`, never `-0` — are R2 behaviour and survive the rewrite:
the zero test still sits AFTER the rounding. Corpus `wm-money-negative-zero`,
`wm-money-rounds-to-unsigned-zero`, `wm-money-noncanonical-stored`.

### Probe lines the spec does not decide

One line of the 484, and it is a spec that decides it TWICE, differently:

1. `"7.9228162514264337593543950336e28"` (probe 478) — 28 fractional digits, a
   mantissa of exactly 2^96.
   - *Reading taken (→ `7.922816251426433759354395034`):* the third bullet lists
     this exact string among its own witnesses, with that value. So the
     implementation enters the "exponent discarded" case by a second door as
     well: when the mantissa AS WRITTEN is not strictly below 2^96. Chosen
     because it is the only reading under which a witness the spec spells out is
     produced at all.
   - *Other reading (→ `String`):* the same bullet's closing sentence says «The
     boundary is the fractional-digit count of the mantissa AS WRITTEN, not its
     value: at exactly 28 the previous rule applies», and under the previous rule
     the digit string is 29 long with `k = 0` and reads as exactly 2^96, which is
     not strictly below it.
   - *Missing sentence:* the third bullet never says what happens when the
     mantissa of an exponent-carrying string does not fit while its
     fractional-digit count does. Both readings agree everywhere else the section
     speaks: `"99999999999999999999999999999e-1"`,
     `"79228162514264337593543950336e-28"`,
     `"199999999999999999999999999999e-29"` and
     `"1234567890123456789012345678901e-3"` reach `String` either way (their
     candidate scale falls below 0), and `"7.9228162514264337593543950335e28"`
     folds either way. Probe 478 is the single line where they part.

No other Money line among the 302 the grammar admits is left open: each is
decided by one of rules 1–7 above, and every witness value §4.1 spells
out is reproduced (87 checked, the grammar-only ones included).

## Fourth alignment (R3)

§4.1 gained three dated sentences marked *(Clarified 2026-08-30, T10 — R3.)*: a
signed year on **Date** (and on the date component of **Date-time**), the
colon-less `+HHMM` / `-HHMM` offset on **Date-time**, and a rewritten
exponent-form **Money** bullet whose three outcomes are decided by what the
exponent-free rule does to the mantissa. Each entry below quotes its sentence,
names the change, and lists the witnesses the sentence itself carries. Corpus:
**92/92** (was 90/92). Grammar probes: 528 answered, no `PANIC`.

### 1. Date — the year may carry a leading `+` or `-`

- **Spec:** §4.1 Date: «**The year may carry a leading `+` or `-` sign**, which
  is consumed by the parser and does not survive the four-digit padding of the
  canonical form: `"+2026-05-13"` and `"+2026-5-13"` both hash as
  `"2026-05-13"`, and `"+0000-05-13"` and `"-0000-05-13"` both as
  `"0000-05-13"` — a zero year, like a zero monetary value, carries no sign. The
  sign MUST be immediately followed by a year of at most four digits, so
  `"+12026-05-13"`, `"++2026-05-13"`, `"+ 2026-05-13"` and the trailing-sign
  `"2026-05-13+"` are not dates and reach `String`, and so does the
  calendar-invalid `"+2026-02-30"`.»
- **Change:** `DATE_RE` gained an **uncaptured** `[+-]?` glued to the year:
  `\A\s*[+-]?(\d{1,4})-(\d{1,2})-(\d{1,2})\s*\Z`. Uncaptured because the sign
  «does not survive»; glued because it «MUST be immediately followed by» the
  year; `\d{1,4}` unchanged because the year is «at most four digits». Nothing
  else moved — `_is_valid_ymd` still rejects `"+2026-02-30"` like any other
  calendar-invalid spelling, and the `%04d` output padding is untouched.
- **Witnesses:** `"+2026-05-13"`, `"+2026-5-13"` → `2026-05-13`;
  `"+0000-05-13"`, `"-0000-05-13"` → `0000-05-13`; `"+12026-05-13"`,
  `"++2026-05-13"`, `"+ 2026-05-13"`, `"2026-05-13+"`, `"+2026-02-30"` →
  `String` (each hashes verbatim).
- **Evidence:** corpus `wm-date-signed-year` (red before this round); probes
  485–494.

### 2. Date-time — the compact `+HHMM` / `-HHMM` offset, and the signed year

- **Spec:** §4.1 Date-time: «**The numeric offset may also be written without
  the colon, in the four-digit `+HHMM` / `-HHMM` form**, and it means the same
  thing … Both fields are mandatory and both are exactly two digits, so the
  hour-only `"…+02"`, `"…-05"` and `"…+00"`, the unpadded `"…+2:00"` and the
  three-digit `"…+023"` are not date-times and reach `String`; the range bound
  above applies to this spelling too, so `"…+2400"` and `"…+0060"` reach
  `String` as well. The date component of a date-time accepts a signed year
  exactly as **Date** does below, so `"+2026-07-18T12:00:00Z"` hashes as
  `"2026-07-18T12:00:00Z"`.»
- **Change:** two edits to `TS_RE`, no new code path. The offset colon became
  optional — `([+-])(\d{2}):?(\d{2})` — which admits `+0200` while keeping every
  rejection the sentence lists: the two `\d{2}` widths refuse `+02`, `+2:00` and
  `+023`, and the existing R2 bound in `parse_rfc3339` (`oh > 23 or om > 59`)
  refuses `+2400` and `+0060` in the new spelling as in the old, before it
  normalises anything. And the same uncaptured `[+-]?` as rule 1 was glued to
  the year.
- **Witnesses:** `"2026-07-18T23:59:59+0200"` → `2026-07-18T21:59:59Z`;
  `"…-0530"` → `2026-07-19T05:29:59Z`; `"…-0000"` → `2026-07-18T23:59:59Z`;
  `"…+02"`, `"…-05"`, `"…+00"`, `"…+2:00"`, `"…+2400"`, `"…+0060"`, `"…+023"` →
  `String`; `"+2026-07-18T12:00:00Z"` → `2026-07-18T12:00:00Z`.
- **Evidence:** corpus `wm-datetime-compact-offset` (red before this round);
  probes 495–506. The same parser answers `inferred_at` (§7.3), which widens by
  the same two spellings — as §7.3's «MUST accept every RFC 3339 spelling its
  date-time library accepts … MUST NOT reject a value on the grammar alone»
  requires.

### 3. Money — the exponent form has exactly three outcomes

- **Spec:** §4.1 Money: «**With an exponent**, apply the rule above to the
  MANTISSA ALONE first (the digits before the `e`, exponent ignored), and let
  its outcome decide what the exponent does. There are exactly three outcomes.»
  Outcome 2 is «the mantissa fits EXACTLY, meaning the exponent-free rule
  rounded no digit away: at most 28 fractional digits and a digit string below
  2^96 as written»; outcome 1 is «does not fit at any scale — the exponent-free
  rule reaches `String` — and so does the whole string, whatever the exponent»;
  outcome 3 is «fits only AFTER rounding … the rounded mantissa IS the recovered
  value and the exponent is DISCARDED». And: «The boundary between the last two
  outcomes is whether the exponent-free rule ROUNDED, never the
  fractional-digit count of the mantissa.»
- **Change: none to the code.** The R2b implementation already branches on
  `has_exp and len(fp) <= MONEY_MAX_SCALE and _money_int(digits) is not None`,
  which is outcome 2 read off the mantissa, and sends everything else to
  `_money_exponent_free(digits, len(fp))`, whose own `None` separates outcome 1
  from outcome 3. The equivalence is exact in both directions: when both
  conditions hold, `_money_exponent_free` keeps `s = f`, cuts nothing and rounds
  nothing; when either fails it must drop a digit or exhaust its scales. Only
  the comments changed, to cite this sentence instead of the superseded «more
  than 28 fractional digits» boundary — R2b reached the same branch by arguing
  from a witness the old boundary contradicted, and R3 now states it directly.
- **Witnesses (every exponent-form value the bullet spells out, re-measured):**
  *outcome 1* — `"79228162514264337593543950336e-28"`,
  `"99999999999999999999999999999e-1"`, `"199999999999999999999999999999e-29"`,
  `"1234567890123456789012345678901e-3"`,
  `"79228162514264337593543950335.5e0"` and `"…e1"` → `String`.
  *outcome 2* — `"79228162514264337593543950335e-28"` →
  `7.9228162514264337593543950335`, `"7.9228162514264337593543950335e28"` →
  `79228162514264337593543950335`, `"1.9999999999999999999999999999e1"` →
  `19.999999999999999999999999999`, `"0.1e1"` and
  `"0.0000000000000000000000000001e28"` → `1`, `"2.5e1"` → `25`, `"1.2345e3"` →
  `1234.5`, `"1.2345e5"` → `123450`, `"123.45e-2"` → `1.2345`, `"12.5e-1"` →
  `1.25`; budget lines `"5e28"`, `"5.0e28"`, `"50e27"` and `"0.5e28"` monetary
  against `"0.5e29"`, `".5e29"`, `"00.5e29"`, `"0.05e30"`, `"1e29"`, `"1e30"`,
  `"1e400"`, `"5e29"`, `"8e28"`, `"9e28"`, `"0e100"`, `"1e-29"`, `"1e-400"`,
  `"1.5e-28"`, `"1.0e-28"`, `"10e-29"`, `"100e-30"`, `"150e-31"` → `String`.
  *outcome 3* — the measured family of twelve (four
  `"7.9228162514264337593543950336e*"` → `7.922816251426433759354395034`, three
  `"9.9999999999999999999999999999e*"` → `10`, three
  `"9999999999999999999999999999.99e*"` → `10000000000000000000000000000`, two
  `"79228162514264337593543950335.5e*"` → `String`), plus
  `"0.99999999999999999999999999995e0"`/`"…e1"` → `1`,
  `"1234567890123456789012345678.12345678901234567890123456789e0"`/`"…e1"` →
  `1234567890123456789012345678.1`,
  `"1.99999999999999999999999999999e{1,2,28}"` → `2` (never `20`, `200`,
  `2e28`), `"…e-1"` → `2` (not `0.2`),
  `"1.00000000000000000000000000001e{0,1}"` and
  `"1.000000000000000000000000000001e2"` → `1`, and
  `"0.12345678901234567890123456785e-1"` → `0.1234567890123456789012345679`.
- **Closes the R2b open line.** Probe 478,
  `"7.9228162514264337593543950336e28"`, was the single line the previous
  revision decided twice and in opposite directions. R3 removes the
  fractional-digit boundary and lists the value among outcome 3's own witnesses,
  so the reading R2b took (`7.922816251426433759354395034`) is now the only one
  and the `_money_int(digits)` half of the branch condition is normative rather
  than inferred.
- **Evidence:** the five corpus `wm-money-exponent*` cases (green before and
  after); probes 46–79, 211–217, 420–484, 507–528.

### Probe lines the spec does not decide

None of the 528 is left open, and the one line R2b listed is closed by rule 3
above. Two lines are decided by a sentence rather than by a witness of their
own, and are recorded here because the reading is load-bearing:

1. `"-2026-05-13"` (probes 232 and 486) → `2026-05-13`, and
   `"-2026-07-18T12:00:00Z"` (probe 504) → `2026-07-18T12:00:00Z`.
   - *Reading taken:* the sentence is «a leading `+` **or `-`** sign, which is
     consumed by the parser and **does not survive** the four-digit padding of
     the canonical form». It is stated of the sign, not of the zero year, so a
     minus on a non-zero year is consumed too. §4 backs it independently: the
     canonical Date form is `YYYY-MM-DD` and the canonical date-time is RFC 3339
     with `Z` — four year digits, no sign field, nowhere to put one.
   - *Other reading (→ `-2026-05-13`):* the trailing clause «a zero year, like a
     zero monetary value, carries no sign» is load-bearing only if a non-zero
     year DOES keep its sign. Rejected: under it the leading clause would be
     false in general, and the output would not be a `YYYY-MM-DD` string at all.
   - *Missing sentence:* §4.1 gives four accepted signed witnesses (`+2026`,
     `+2026-5`, `+0000`, `-0000`) and none is a minus on a non-zero year. The
     two readings part on these two probe lines only.
