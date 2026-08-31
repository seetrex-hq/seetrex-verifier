# OPEN_QUESTIONS — points the specification does not settle

Each entry: the section I was reading, what the text does not settle, the readings
I weighed, what `seetrex_verifier.py` implements, and why. Sixteen entries.

Nothing here is a complaint about the format. Every one of these is a place where
two conforming-looking verifiers could disagree over the same bytes, which is the
precise thing §2 says the format is trying to avoid for duplicate keys.

---

## Q1 — §8.1 / CLI: `verify-chain` has no exit codes

**Unsettled.** §9.6 binds outcome tokens and exit codes (`0` / `4` / `1`) for
`verify-package`. §8.1 defines what verifying an export means but names no
tokens and no exit codes, and §9.6's reserved-vocabulary paragraph only says
`verify-chain` is one of the surfaces that *may* emit `VERIFIED`.

**Readings.** (a) Mirror §9.6 exactly, including an unanchored `4` when
`--expected-last-chain-hash` is omitted. (b) Plain `0` success / `1` failure,
with the missing external anchor reported in prose.

**Implemented:** (b) — `0` on success (with `VERIFIED`), `1` on any failure, as
the task instructions direct. Reading (a) is tempting because §9.3's argument
("the export is not its own trust root") applies verbatim to a chain export
whose head nothing outside attested; I say so in the output, but I do not invent
an exit code the specification never assigned.

**Why it matters.** A script that branches on `4` for `verify-package` cannot
learn anything equivalent from `verify-chain`. If the format ever wants the
unanchored-head case machine-distinguishable, it has to say so.

---

## Q2 — §9.6: where the token sits relative to the scope statement

**Unsettled.** §9.6 says warnings are "printed as a block after the step lines",
and that the honest-scope statement is "printed on every terminal outcome", but
it never fixes the order of {warning block, scope statement, terminal token}.

**Readings.** (a) token last, so a shell `tail -1` reads it; (b) token
immediately after the step lines, scope statement trailing as a footer.

**Implemented:** (a) — step lines, warning block, `SCOPE:` block, then the token
alone on the final line. §9.6's rationale for the reserved token is that
"downstream shell tooling pattern-matches", which reads as an argument for the
token being the last line rather than buried mid-output.

---

## Q3 — §2: is a package-internal hash written in UPPERCASE malformed?

**Unsettled.** §2 says all hashes "are encoded as 64 lowercase hexadecimal
characters" and that verifiers "SHOULD accept uppercase input **for externally
supplied expected values**". It does not say what to do with an uppercase
`verdict_hash` *inside* the package.

**Readings.** (a) Compare case-insensitively everywhere and lowercase on output.
(b) Treat any package-internal hex that is not `[0-9a-f]{64}` as malformed.

**Implemented:** (b). The permission to accept uppercase is scoped, by its own
words, to externally supplied values; and a hash field is a hashed-adjacent
value where silently normalising is exactly the kind of divergence §2 legislates
against for duplicate keys. `--expected-verdict-hash` and
`--expected-last-chain-hash` *are* compared case-insensitively (§9.6 step 7).

---

## Q4 — §3.1: which manifest fields must be present to verify?

**Unsettled.** The §3.1 table lists ten fields, marks only `files_sha256`
OPTIONAL, but §9.6 only ever consumes `package_format_version`, `files`,
`files_sha256`, `verdict_hash`, `verdict_id`, `chain_prev_hash` and `chain_hash`.
Nothing says whether a manifest missing `replay_token` or `tenant_id` is
malformed.

**Readings.** (a) Require all ten. (b) Require only what a step reads.

**Implemented:** (b). §3.1 is emphatic that the manifest is "a convenience
index… claims to be cross-checked", not a trust root; failing a package because
an *uncovered, unhashed, purely informational* field is absent would fail it on
a ground no §5–§8 quantity depends on. Related sub-question, same answer: the
spec never says `manifest.json` must be listed in its own `files` array
(Appendix A.1 lists it in the package, §3.1.1 excludes it from the covered set),
so I accept both a manifest that lists itself and one that does not.

---

## Q5 — §3.3: must an evidence file's `id` equal its filename?

**Unsettled.** §3.3 gives `id` the *role* "matches the filename and the
`evidence_id` in `evidence_refs`" — a description in a Role column, not a MUST.
§9.6 step 3 mandates the hash and multiset checks but never the filename check.

**Readings.** (a) Enforce `id == <uuid>` from the filename. (b) Ignore the
filename; identity comes from the `id` field and the multiset check.

**Implemented:** (a), as a failure. Under (b) a package could carry
`evidence/<A>.json` whose `id` is `<B>` and still pass every §9.6 step, so a
human reading the directory and a verifier reading the JSON would disagree about
which file is which — a divergence with no upside. Recording it because (a) is
strictly stricter than the letter of §9.6, and a conforming package rejected on
this ground would be rejected by me and accepted by a literal reading.

---

## Q6 — §3.2: is `verdict.json`'s key set closed?

**Unsettled.** §6.1 says in terms that the *ruleset* key set is closed and that
unknown keys are malformed. §3.2 gives a field table for `verdict.json` with no
such statement, and §3.3 explicitly calls other evidence fields "informational".

**Readings.** (a) Closed by analogy with §6.1. (b) Open — reject unknown keys
only where the spec says the set is closed.

**Implemented:** (b) for `verdict.json` and evidence files; strictly closed for
`ruleset.json` (§6.1) and for chain-export rows (§8.1 says "exactly eight
fields"). §6.1's closure is argued from the *emitter* rejecting unknown keys;
no equivalent claim is made for the verdict record, and §3.3 naming "remaining
fields… informational" reads as an open record. Note the asymmetry is real:
an unknown key in `verdict.json` is invisible to every hash in §5–§8, so under
(b) it is unpinned unless `files_sha256` is present.

`evidence_refs` elements *are* closed: §3.2 says "each with exactly" those two
keys, which I read as normative.

---

## Q7 — §6.1: are ruleset scalar TYPES enforced, or only the key set?

**Unsettled.** §6.1's tables carry a Type column (`version` integer, `doc`
string, `facts_consumed` array of strings…). The normative sentence that follows
mandates rejecting unknown keys only. It does not say a `version` of `"2"`
(string) is malformed.

**Readings.** (a) Key set only; canonicalize whatever types are present.
(b) Enforce the declared types, because "the reference implementation obtains
[the completed document] by parsing the file into its typed model" (§6) and a
typed model rejects a string where it wants an integer.

**Implemented:** (b). The §6 sentence about a typed model is the strongest
signal available, and under (a) a wrong-typed ruleset would silently produce a
*different but well-formed* anchor, which is the confusion §6.1 draws its
malformed/tampered distinction to prevent. Consequence to note: I reject
`"version": 2.0` (a JSON number that is not an integer) even though JCS would
canonicalize it to `2`.

---

## Q8 — §6.1: the "strict verifier MAY reject non-canonical string scalars"

**Unsettled.** §6.1 offers, as a MAY, rejecting a rule scalar such as a duration
written `"90m"` instead of `"1h30m"`. It does not say what a *non*-strict
verifier does — in particular, whether it should normalise `"90m"` to `"1h30m"`
in the completed document (as §4.1 says the reference re-serializer does) before
hashing.

**Readings.** (a) Take string scalars verbatim; do not reject, do not normalise.
(b) Reject non-canonical scalars (the MAY). (c) Normalise them, mirroring the
reference parse-and-re-serialize path.

**Implemented:** (a). (c) is the dangerous one: it requires the verifier to
recover the *kind* of an untagged value via §4.1's precedence, so a fact value
that looks like a duration but is a plain string would be silently rewritten and
would change the anchor. §6.1 says published rulesets "carry them in canonical
text already", so on conforming input (a) and (c) agree; on non-conforming input
(a) fails loudly at the anchor comparison instead of quietly inventing bytes.
This is the one §6.1 point where I would most want the spec to be explicit,
because (a) and (c) differ on real inputs.

---

## Q9 — §9.6 step 5: is an absent anchor worth a WARNING?

**Unsettled.** Step 5 says that when the verdict declares no anchor there is
nothing to check, the verifier MUST NOT invent one, and MAY note the computed
hash. §9.6 enumerates exactly two WARNING conditions (absent `files_sha256`,
non-canonical wire `inferred_at`). An unchecked ruleset is not among them.

**Readings.** (a) Print the computed hash, no warning — the warning list is
exhaustive. (b) Warn: a legacy package where the ruleset is bound by nothing is
materially weaker, and §6.2 spends a paragraph saying so.

**Implemented:** (b), plus the computed hash for the record. The warning block's
"relative order within that block is not binding" suggests the block is a
collection point rather than a closed list, and §9.6's whole design intent is
that a reader cannot overestimate what ran. A verifier following (a) prints one
fewer warning line than mine on a pure-legacy package; nothing else differs.

---

## Q10 — §7.3: what RFC 3339 input shapes must the parser accept?

**Unsettled.** §7.3 pins the *output* byte-for-byte and says the verifier must
parse the wire value, but never says which RFC 3339 spellings can appear on the
wire. RFC 3339 itself permits lowercase `t`/`z`, a numeric offset, and (§5.6,
by explicit allowance) a space in place of `T`; it also permits second `60` for
a leap second.

**Readings.** (a) Accept only `T…Z` with optional fraction — what a conforming
emitter writes. (b) Accept the full RFC 3339 grammar.

**Implemented:** between the two. I accept `T`/`t`, `Z`/`z`, and numeric
`±HH:MM` offsets (converting to UTC), because §4 explicitly contemplates an
input "carrying a numeric UTC offset (`+00:00`)" being normalised to `Z`. I do
**not** accept the space separator, and I **reject** second `60`: Python's
`datetime` has no leap second, so the only alternatives were to reject or to
silently map `:60` onto `:59`/the next second — and silently moving an instant
that sits inside a hash preimage is worse than failing loudly.

---

## Q11 — §7.3: truncate or round a wire value with more than six digits?

**Unsettled.** §7.3 says the *emitter* truncates its clock sample toward zero to
microseconds before using it anywhere. It says the *verifier* must "parse
`inferred_at` to a timestamp and re-format it under the fixed 6-digit rule" —
without saying what re-formatting does to a 7-, 8- or 9-digit wire value, which
a conforming emitter should never have written.

**Readings.** (a) Truncate toward zero, matching the emitter. (b) Round
half-even. (c) Reject: more than six digits means a non-conforming emitter.

**Implemented:** (a). It is the only option that agrees with the emitter's own
stated rule, so a wire value that *was* truncated correctly and a wire value
that carries the untruncated tail hash to the same preimage. (c) is defensible
and stricter; I rejected it because §7.3 spends its space telling verifiers to
be tolerant of legacy wire precision, not intolerant.

---

## Q12 — §8.1: must `schema_version` be `"1.0"`?

**Unsettled.** §8.1 shows `{"schema_version": "1.0", …}` and closes the key set,
but never says a verifier must reject `"1.1"` or `"2.0"` — unlike §7.4
(`preimage_version`) and §9.6 step 1 (`package_format_version`), which both
legislate the unknown-version case explicitly.

**Readings.** (a) Ignore the value; the eight-field row shape is what matters.
(b) Reject anything but `"1.0"`, by analogy with the two rules that *are*
written down.

**Implemented:** (b), failing loud and naming the version. Both explicit
version-discriminator rules in this specification say fail closed and never fall
back; applying the same reflex to the third discriminator is the reading most
consistent with the document as a whole. It does mean I refuse an export that a
future §8.1 revision might make perfectly checkable by an old verifier.

---

## Q13 — §8.1: is an empty `chain` array valid?

**Unsettled.** §8.1 requires ordinals "contiguous from 1" and says the resulting
head (`verdict_count`, `last_chain_hash`) can be compared against the published
page. Zero rows is vacuously contiguous and has no head.

**Readings.** (a) Vacuous success — a tenant with no verdicts. (b) Failure —
there is no head, so there is nothing an external anchor could attest.

**Implemented:** (b). Emitting `VERIFIED` over a document that establishes
nothing is exactly the overclaim §9.3 calls a conformance violation, and
`--expected-last-chain-hash` has no possible referent. A tenant with no verdicts
publishing an empty export is a real case, so this may be the wrong call; it is
one line to change.

---

## Q14 — §8.1: may rows appear out of ordinal order?

**Unsettled.** "`ordinal` | integer, 1-based contiguous (append order)" describes
the values, not the document. Verifying "that `chain_prev_hash` equals the
previous row's `chain_hash`" presupposes an order but does not say whether the
verifier may establish it by sorting.

**Readings.** (a) Require document order to equal ordinal order. (b) Sort by
ordinal first, then check.

**Implemented:** (a) — row *i* must carry ordinal *i*, and the error names the
position and the field. A published append-only log arriving shuffled is itself
a signal; and under (b) a verifier silently repairs a malformed export, which is
the "two verifiers, same bytes, different result" problem again.

---

## Q15 — §9.6 reserved token: how aggressive is the sanitizer?

**Unsettled.** The last paragraph says the reference CLI rewrites `VERIFIED` to
`VERIF[REDACTED]` at the output boundary. It does not say whether the match is
case-sensitive, whether it applies to `verify-chain` (which is *allowed* to emit
the token), or whether near-misses (`Verified`, `VERIFIED!`) matter.

**Readings.** (a) Case-sensitive replacement of the exact substring everywhere,
with one explicitly allowed exception for `verify-chain`'s own success token.
(b) Case-insensitive scrub of anything token-shaped.

**Implemented:** (a). The stated rationale is that "downstream shell tooling
pattern-matches the substring `VERIFIED`", which is a statement about that exact
byte sequence; a case-insensitive scrub would also mangle honest prose ("this is
not a verified re-derivation"). Concretely: every line of `verify-package` is
redacted, including interpolated filenames and rejected ruleset keys (tested);
in `verify-chain` every line is redacted **except** the single-token success
line, which is emitted through one explicit `allow_reserved=True` call.

Sub-point the spec also leaves open: my boundary additionally escapes bytes the
console cannot encode, *after* redaction, so a package cannot smuggle the token
through a filename the terminal renders differently.

---

## Q16 — §9.6: resource caps for `verify-chain`, and symlinks

**Unsettled.** §9.6's note ("the reference implementation caps each file at
10 MiB and the package at 8192 files") is written for package verification.
§8.1 sets no bound on a chain export, which for a busy tenant is legitimately
large and grows without limit. Separately, §9.6 step 1 requires each listed path
to "exist as a regular file" but says nothing about symlinks, which are not
regular files and can point outside the package directory.

**Readings.** (a) Apply the 10 MiB cap to the chain export too. (b) Give the
export its own, larger cap. (c) No cap. For symlinks: (d) follow them, since
`stat` reports a regular file at the far end; (e) reject them.

**Implemented:** (b), 256 MiB, and (e). A 10 MiB cap would refuse an honest
export at roughly a quarter-million rows, which turns a resource guard into a
functional limit; no cap at all loses the protection §9.6 asks for. Rejecting
symlinks follows step 1's own stated purpose — "the verifier MUST NOT read
outside the package" — which a followed symlink defeats regardless of what the
path string looked like.
