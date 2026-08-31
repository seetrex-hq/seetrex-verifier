#!/usr/bin/env python3
"""Independent reference verifier for the Seetrex verdict audit package format.

Implements, from SPEC_VERDICT_PACKAGE_V1.md alone (spec version 1,
package_format_version 2, preimage versions 1 and 2):

    verify-package --package-dir DIR  [--expected-verdict-hash HEX]      (spec 9.6)
    verify-chain   --chain-export FILE [--expected-last-chain-hash HEX]  (spec 8.1)

Standard library only.  RFC 8785 (JCS) is implemented here; no JCS package
is used.  Every printed line passes through one output boundary that redacts
the reserved token (spec 9.6, last paragraph).
"""

import argparse
import datetime
import hashlib
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- constants

RESERVED_TOKEN = "VERIFIED"                  # 9.6 reserved vocabulary
REDACTED_TOKEN = "VERIF[REDACTED]"

TOKEN_ANCHORED = "INTEGRITY-OK (weak)"       # 9.6 outcome table, exit 0
TOKEN_UNANCHORED = "SELF-CONSISTENT (unanchored)"  # exit 4

MAX_FILE_BYTES = 10 * 1024 * 1024            # 9.6: reference caps
MAX_PACKAGE_FILES = 8192
# spec 8.1 (Q16): the chain export has its OWN cap, 50 MiB -- deliberately larger
# than the 10 MiB per-file cap of 9.6, which would refuse an honest export.
MAX_EXPORT_BYTES = 50 * 1024 * 1024

HEX64_ANY = re.compile(r"\A[0-9a-fA-F]{64}\Z")
UUID_RE = re.compile(r"\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
OUTCOMES = ("SATISFIED", "AT_RISK", "VIOLATED")          # 3.2

RULESET_TOP_REQUIRED = ("ruleset_id", "framework", "article", "control", "version",
                        "engine_semantic_version_floor", "doc", "facts_consumed",
                        "verdicts_emitted", "rules")
RULESET_TOP_KEYS = set(RULESET_TOP_REQUIRED) | {"regulatory_source"}
RULE_KEYS = {"id", "name", "conditions", "antecedents", "consequent",
             "consequent_value", "priority", "condition_groups"}
COND_KEYS = {"fact_id", "operator", "value", "negated"}
OPERATORS = {"Eq", "Ne", "Lt", "Le", "Gt", "Ge", "In", "Range", "Exists",
             "Matches", "Contains", "StartsWith", "EndsWith"}
REGSRC_STR = ("regulation", "article", "paragraph", "url_official")
REGSRC_LIST = ("guidance_refs", "interpretation_caveats")
CHAIN_ROW_KEYS = {"ordinal", "verdict_hash", "chain_prev_hash", "chain_hash",
                  "verdict_id", "appended_at", "ruleset_id", "verdict_outcome"}

class Fail(Exception):
    """Any verification failure or malformed input.  Fail-closed, exit 1."""

# ------------------------------------------------------- output boundary

RESERVED_CI = re.compile(RESERVED_TOKEN, re.IGNORECASE)   # 9.6 (Q15): case-INSENSITIVE
_MASKED = [False]                            # did the mask actually reach the output?

MASK_LEGEND = ("NOTE: `%s` masks the reserved token of spec 9.6, which this weak "
               "surface must never print; package-controlled bytes (a planted "
               "filename, a rejected key) can carry it in any casing."
               % REDACTED_TOKEN)

def emit(text, allow_reserved=False):
    """The single output boundary.  Every line printed by this program goes
    through here; the reserved token is rewritten unless explicitly allowed
    (only verify-chain's own success token is).  spec 9.6 (Q15): the match is
    case-insensitive -- `Verified`, `verified` and `VeRiFiEd` are all rewritten."""
    if not allow_reserved:
        text, n = RESERVED_CI.subn(REDACTED_TOKEN, text)
        if n:
            _MASKED[0] = True
    # Package-controlled bytes may not be encodable by the console; escape them
    # rather than dying half-way through a line (the escapes are pure ASCII, so
    # they cannot resurrect the reserved token redacted just above).
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    text = text.encode(enc, "backslashreplace").decode(enc, "replace")
    sys.stdout.write(text + "\n")

# ------------------------------------------------------------ JCS (RFC 8785)

def _es_number(f):
    """ECMAScript Number::toString for a finite double (RFC 8785 3.2.2.3).
    Python's repr gives the shortest round-trip digits but not ES layout."""
    if f != f or f in (float("inf"), float("-inf")):
        raise Fail("number is NaN or Infinity; not representable in JCS (spec 2)")
    if f == 0.0:
        return "0"                      # covers -0.0: ES ToString(-0) is "0"
    r = repr(f)
    neg = r.startswith("-")
    if neg:
        r = r[1:]
    if "e" in r or "E" in r:
        mant, _, exp = r.replace("E", "e").partition("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
        digits, exp = ip + fp, exp - len(fp)
    else:
        digits = mant
    digits = digits.lstrip("0") or "0"
    while len(digits) > 1 and digits.endswith("0"):
        digits, exp = digits[:-1], exp + 1
    k = len(digits)
    n = exp + k                          # value == 0.<digits> * 10**n
    if k <= n <= 21:
        s = digits + "0" * (n - k)
    elif 0 < n <= 21:
        s = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        head = digits if k == 1 else digits[0] + "." + digits[1:]
        s = head + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return "-" + s if neg else s

def _es_int(i):
    if -(2 ** 53) <= i <= 2 ** 53:
        return str(i)                    # exact as a double; ES prints the integer
    try:
        return _es_number(float(i))      # JCS treats all numbers as doubles
    except OverflowError:
        raise Fail("integer out of IEEE-754 double range; not representable in JCS")

_ESCAPES = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r"}

def _jcs_string(s):
    """RFC 8785 3.2.2.2: minimal escaping, everything else literal UTF-8."""
    out = ['"']
    for ch in s:
        c = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif c < 0x20:
            out.append("\\u%04x" % c)
        elif 0xD800 <= c <= 0xDFFF:
            raise Fail("lone UTF-16 surrogate U+%04X in a string; not canonicalizable" % c)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)

def _jcs(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, int):
        return _es_int(v)
    if isinstance(v, float):
        return _es_number(v)
    if isinstance(v, list):
        return "[" + ",".join(_jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        # RFC 8785: sort member names by their UTF-16 code units.
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + _jcs(x) for k, x in items) + "}"
    raise Fail("value of type %s cannot be canonicalized" % type(v).__name__)

def jcs(value):
    """Canonical UTF-8 bytes of a JSON value."""
    return _jcs(value).encode("utf-8")

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

# ------------------------------------------------------- strict JSON parsing

def _no_constants(name):
    raise Fail("JSON constant %s is not permitted (spec 2, 4)" % name)

def _pairs(pairs):
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise Fail("duplicate object key %r; malformed (spec 2)" % k)
        seen.add(k)
    return dict(pairs)

def _reject_nonfinite(v):
    if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
        raise Fail("non-finite number in document (spec 2, 4)")
    if isinstance(v, list):
        for x in v:
            _reject_nonfinite(x)
    elif isinstance(v, dict):
        for x in v.values():
            _reject_nonfinite(x)

def strict_json(text, where):
    try:
        doc = json.loads(text, object_pairs_hook=_pairs, parse_constant=_no_constants)
    except Fail as e:
        raise Fail("%s: %s" % (where, e))
    except ValueError as e:
        raise Fail("%s: not valid JSON: %s" % (where, e))
    try:
        _reject_nonfinite(doc)
    except Fail as e:
        raise Fail("%s: %s" % (where, e))
    return doc

def read_text(path, where, cap=MAX_FILE_BYTES):
    try:
        size = path.stat().st_size
    except OSError as e:
        raise Fail("%s: cannot stat %s: %s" % (where, path.name, e))
    if size > cap:
        raise Fail("%s: file exceeds the %d-byte cap (%d bytes)" % (where, cap, size))
    try:
        data = path.read_bytes()
    except OSError as e:
        raise Fail("%s: cannot read %s: %s" % (where, path.name, e))
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Fail("%s: not valid UTF-8: %s" % (where, e))

# -------------------------------------------------------------- small helpers

def need(obj, key, where):
    if not isinstance(obj, dict) or key not in obj:
        raise Fail("%s: required field %r is missing" % (where, key))
    return obj[key]

def need_str(obj, key, where):
    v = need(obj, key, where)
    if not isinstance(v, str):
        raise Fail("%s: field %r must be a string" % (where, key))
    return v

def need_int(obj, key, where):
    v = need(obj, key, where)
    if isinstance(v, bool) or not isinstance(v, int):
        raise Fail("%s: field %r must be an integer" % (where, key))
    return v

def need_hex(obj, key, where):
    """spec 2 (Q3): uppercase hex is accepted in package-internal hash COMPARISONS
    (use `same_hex`), but the value is returned VERBATIM -- the tolerance does not
    extend to a hex string that is itself a preimage (manifest.verdict_hash feeds
    the 8 chain link over its own ASCII bytes)."""
    v = need_str(obj, key, where)
    if not HEX64_ANY.match(v):
        raise Fail("%s: field %r is not 64 hex characters (spec 2): %r"
                   % (where, key, v))
    return v

def same_hex(a, b):
    """spec 2: package-internal hash comparisons are case-insensitive."""
    return a.lower() == b.lower()

# spec 7.3 (Q10): the wire grammar accepts `T`/`t`, `Z`/`z`, a numeric offset, a
# SPACE in place of `T` (RFC 3339 5.6) and second 60; a verifier MUST NOT reject
# a value on the grammar alone.
# spec 4.1 (R2), Date-time: the SAME parser answers fact values, and there
# "Leading and trailing whitespace is ignored, and the date and time components
# do not require zero padding (`2026-7-18T12:00:00Z` is the same instant as
# `2026-07-18T12:00:00Z`)" -- hence the `\s*` and the {1,2} widths.
# spec 4.1 (R3), Date-time: "The numeric offset may also be written without the
# colon, in the four-digit `+HHMM` / `-HHMM` form, and it means the same thing" --
# hence the OPTIONAL colon.  "Both fields are mandatory and both are exactly two
# digits, so the hour-only `+02`, `-05` and `+00`, the unpadded `+2:00` and the
# three-digit `+023` are not date-times and reach String": the two `\d{2}` widths
# and the absence of any other offset alternative are exactly that rule, and the
# `oh`/`om` bounds below (R2) apply to this spelling too (`+2400`, `+0060`).
# spec 4.1 (R3): "The date component of a date-time accepts a signed year exactly
# as Date does below, so `+2026-07-18T12:00:00Z` hashes as
# `2026-07-18T12:00:00Z`" -- the same uncaptured `[+-]?` as DATE_RE, for the same
# reason (spec 4's canonical form has four year digits and no room for a sign).
TS_RE = re.compile(
    r"\A\s*(?:\+|-(?=0+-))?(\d{1,4})-(\d{1,2})-(\d{1,2})[Tt ](\d{1,2}):(\d{1,2}):(\d{1,2})"  # spec 4.1 (R3b)
    r"(?:\.(\d+))?(?:[Zz]|([+-])(\d{2}):?(\d{2}))\s*\Z")

def parse_rfc3339(wire):
    """Returns (UTC datetime, fractional digits as written, leap flag), or None if
    the string denotes no instant.  spec 7.3 (Q10): second 60 is accepted.

    spec 7.3 (R1-A I-1): "A leap second parses to the SAME POSIX instant as second
    `59` of the same minute -- the two spellings share a timestamp -- while the
    parsed value retains the `60` spelling".  So :60 carries NO extra second here;
    it is held as second 59 plus a flag, and the flag is what re-emits the `60`.
    Offsets are whole minutes, so normalising to UTC never disturbs it."""
    m = TS_RE.match(wire)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    leap = s == 60
    if leap:
        s = 59
    if m.group(8):
        # spec 4.1 (R2): "The numeric offset is bounded: its magnitude MUST be
        # strictly below `24:00` and its minute field below `60`", so `+24:00`,
        # `-24:00`, `+25:00` and `+00:60` denote no instant and reach String --
        # "an implementation that normalises an out-of-range offset instead of
        # rejecting it produces a different hash for the same package".
        oh, om = int(m.group(9)), int(m.group(10))
        if oh > 23 or om > 59:
            return None
    try:
        dt = datetime.datetime(y, mo, d, h, mi, s)
        if m.group(8):
            off = datetime.timedelta(hours=oh, minutes=om)
            dt = dt - off if m.group(8) == "+" else dt + off
    except (ValueError, OverflowError):
        # A calendar-invalid spelling (`2026-02-30T…`, hour 24, minute 60), or an
        # offset that would carry the instant outside the representable proleptic
        # range: no instant, so the next candidate gets the string (spec 4.1).
        return None
    return dt, (m.group(7) or ""), leap

def canonical_derived_at(wire, where):
    """Spec 7.3: PARSE the wire value and RE-FORMAT it with exactly six
    fractional digits and a literal Z.  Never copy the wire string."""
    parsed = parse_rfc3339(wire)
    if parsed is None:
        raise Fail("%s: inferred_at %r denotes no RFC 3339 instant" % (where, wire))
    dt, frac, leap = parsed
    micro = int((frac + "000000")[:6])   # 7.3 (Q11): truncate toward zero to micros
    # 7.3 (R1-A I-1): the `60` spelling "survives the truncation to microseconds and
    # is re-emitted by the fixed 6-digit formatter", so `...23:59:60.123456Z` enters
    # the preimage byte-identical, never rewritten to `...23:59:59.123456Z`.
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" % (
        dt.year, dt.month, dt.day, dt.hour, dt.minute, 60 if leap else dt.second, micro)

# ------------------------------------------- canonical fact values (4, 4.1)

# spec 4.1 (R1-A C-1, R2b), Money: the accepted grammar is pinned as
# `^[+-]?[0-9_]*([.][0-9_]*)?([eE][+-]?[0-9]+)?$` with at least one digit present,
# `_` a digit separator that is ignored.  A leading `+`, a bare leading `.`, a
# trailing `.` and an exponent are all accepted.  The pattern carries two R2b
# rules on its own: it is anchored with no whitespace class, so "Surrounding
# whitespace is NOT trimmed" and `" 1.5"`, `"1.5 "` and a leading tab reach
# String; and its exponent is `[0-9]+` with no `_`, so a separator "is never
# allowed inside the exponent" (`"1e_5"` and `"1e1_0"` match nothing at all).
MONEY_RE = re.compile(r"\A[+-]?[0-9_]*(?:[.][0-9_]*)?(?:[eE][+-]?[0-9]+)?\Z")
# spec 4.1 (R2b): "an integer mantissa strictly below 2^96 =
# 79228162514264337593543950336 with a scale of 0 to 28, the value being
# mantissa / 10^scale".
MONEY_MAX_MANTISSA = 1 << 96
MONEY_MAX_SCALE = 28
# 2^96 spans 29 digits, so a digit string of 30 or more is already out of range and
# is answered WITHOUT building the integer -- which is also what keeps an
# adversarial 10 MiB numeral off CPython's int()-from-string digit limit.  It is
# the same 29 the exponent form spends as its budget, "leading zeros as written"
# included.
MONEY_MAX_DIGITS = 29
# An exponent of eleven digits or more is CLAMPED, not read: the scale window is
# [0, 28] and the digit budget 29, so its sign already decides both bounds, and the
# clamp answers `1e-2147483649` in constant time.  A clamp and not an early
# rejection because the third case DISCARDS the exponent, so a mantissa of more
# than 28 fractional digits still recovers under an absurd exponent.
MONEY_EXP_CLAMP = 10 ** 10

# spec 4.1, Duration: "an optional leading `-` followed by one or more
# <digits><unit> groups, unit one of `s`, `m`, `h`, `d`; surrounding whitespace is
# trimmed.  Groups may repeat and may appear in any order, and their seconds are
# SUMMED."  No fractional units, no week unit, no sub-second precision.
DURATION_RE = re.compile(r"\A(-?)((?:\d+[smhd])+)\Z")
DURATION_GROUP = re.compile(r"(\d+)([smhd])")
UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
# spec 4.1 (R2): "The summed seconds MUST fit a signed 64-bit integer; a string
# whose groups overflow it is not a duration and reaches String."  Above the
# NARROWER bound of the reference's millisecond-scaled representation --
# magnitude above i64::MAX/1000 seconds -- the reference CRASHES, and the same
# paragraph rules that "a conformant implementation reaches `String` where the
# reference aborts".  Both bands therefore fall through here; the tighter one
# subsumes the i64 one, and `9223372036854775s` is still a duration.
DURATION_MAX_SECONDS = 9223372036854775            # i64::MAX / 1000

def _money_int(digits):
    """The integer a digit string denotes, or None when it is not below 2^96.

    Leading zeros carry no value and are stripped before the length test, so the
    30-digit ceiling here is a statement about the VALUE; the as-written budget of
    the exponent form is counted by that caller, before this one is reached."""
    stripped = digits.lstrip("0")
    if len(stripped) > MONEY_MAX_DIGITS:
        return None
    value = int(stripped) if stripped else 0
    return value if value < MONEY_MAX_MANTISSA else None

def _money_round(digits, frac, scale):
    """`digits` / 10^frac rounded to `scale` fractional digits, or None when the
    result is not strictly below 2^96.

    spec 4.1 (R2b): "The rounding mode is half away from zero, in both signs and
    whatever the digit before the cut".  Cutting the ORIGINAL digit string at the
    scale boundary and reading the FIRST dropped digit is exactly that mode: >= 5
    rounds the magnitude up (the exact tie included), < 5 leaves it, whatever
    follows.  The string is read ONCE -- never digit by digit -- and the sign is
    applied by the caller afterwards, so this rounds away from zero on both
    sides."""
    cut = len(digits) - (frac - scale)
    kept = digits[:cut] if cut > 0 else ""
    # A cut left of the string start drops an implicit zero, so the value rounds to
    # 0: forty fractional zeros and a `1` hash as `0`.
    dropped = digits[cut] if 0 <= cut < len(digits) else "0"
    coeff = _money_int(kept)
    if coeff is None:
        return None
    if dropped >= "5":
        coeff += 1
    return coeff if coeff < MONEY_MAX_MANTISSA else None

def _money_exponent_free(digits, frac):
    """spec 4.1 (R2b), the exponent-free procedure, as (mantissa, scale) or None.

    "Remove the `_`s and let `f` be the number of fractional digits.  Take the
    candidate scale `s = min(f, 28)` and round the written value to `s` fractional
    digits; while the resulting mantissa is NOT strictly below 2^96, decrement `s`
    and round again FROM THE ORIGINAL digits (never from the previous result,
    never digit by digit).  If `s` would fall below 0 the string is not a monetary
    value and reaches String."  Digits beyond the representation are ROUNDED away,
    not rejected: `9.9999999999999999999999999999` drops to scale 27 and hashes as
    `10`, `9999999999999999999999999999.99` drops two scales to
    `10000000000000000000000000000`, and `+79228162514264337593543950335.5`, which
    rounds at scale 0 exactly ONTO 2^96, has no candidate scale left and reaches
    String.

    BOUNDED: `s` starts at 28 or below and stops at -1, so this loop runs at most
    30 times whatever the magnitude of the input or of a discarded exponent."""
    scale = min(frac, MONEY_MAX_SCALE)
    while scale >= 0:
        coeff = _money_round(digits, frac, scale)
        if coeff is not None:
            return coeff, scale
        scale -= 1
    return None

def _money_exponent_form(ip, fp, exp):
    """spec 4.1 (R3), the exponent form once the mantissa has been found to fit
    EXACTLY -- the second of the three outcomes, and the only one that folds.

    "Write the mantissa's digits in order -- the integer part EXACTLY as written,
    an empty integer part counting as a single `0`, then the fractional digits --
    and let `k` be the fractional-digit count minus the exponent.  If `k` is
    negative, append `|k|` zeros to that digit string and set `k` to 0.  The folded
    value is a monetary value iff the digit string is at most 29 digits long, `k`
    is at most 28, and the digit string read as an integer is strictly below 2^96;
    otherwise the string reaches String."  NOTHING is rounded here, which is why two
    spellings of one value need not agree: `0.5e29` spends `05` plus 28 zeros --
    30 digits -- and reaches String, while `5e28` spends 29 and is monetary."""
    written = (ip or "0") + fp
    k = len(fp) - exp
    pad = 0
    if k < 0:
        pad, k = -k, 0
    # The budget is decided by ARITHMETIC before any padding is materialized: an
    # exponent of 10^10 must not build a 10^10-character string.
    if len(written) + pad > MONEY_MAX_DIGITS or k > MONEY_MAX_SCALE:
        return None
    coeff = _money_int(written + "0" * pad)
    return None if coeff is None else (coeff, k)

def _money_value(s):
    """spec 4.1: recover a Money value, or None when the string is not one.

    Returns the canonical decimal string of spec 4 (trailing fractional zeros
    removed, a resulting trailing `.` removed).  "A zero carries no sign in the
    canonical form": `-0.00` -> "0", and so does a value that becomes zero BY
    ROUNDING.

    BOUNDED BY CONSTRUCTION: no loop and no power of ten is proportional to an
    exponent's magnitude, and no integer is built from a digit string longer than
    the 29 digits 2^96-1 spans."""
    if not MONEY_RE.match(s):
        return None
    body, neg = s, False
    if body[:1] in ("+", "-"):
        neg, body = body[0] == "-", body[1:]
    exp, has_exp = 0, False
    if "e" in body or "E" in body:
        has_exp = True
        body, _, tail = body.replace("E", "e").partition("e")
        edigits = tail.lstrip("+-").lstrip("0")
        magnitude = MONEY_EXP_CLAMP if len(edigits) > 10 else int(edigits or "0")
        exp = -magnitude if tail[:1] == "-" else magnitude
    # spec 4.1 (R2b): "A `_` is ignored once a digit has already appeared in the
    # significand, and is never allowed inside the exponent.  It need only FOLLOW a
    # digit somewhere earlier in the significand; it need NOT be immediately
    # preceded by one."  So the scan runs over the WHOLE significand, decimal point
    # included: `1000._5`, `0._5` and `1._5` are monetary, while a separator that
    # opens the string (`_1000`), that follows the sign (`-_1`, `+_1`) or that
    # stands before the first digit of an empty integer part (`._5`, `+._5`, `_._`)
    # is not.  The exponent needs no check here: MONEY_RE never admits a `_` in it.
    seen_digit = False
    for ch in body:
        if ch == "_":
            if not seen_digit:
                return None
        elif ch != ".":
            seen_digit = True
    if not seen_digit:                   # "at least one digit present" (4.1)
        return None
    ip, _, fp = body.partition(".")
    ip, fp = ip.replace("_", ""), fp.replace("_", "")   # `_` is ignored (4.1)
    digits = ip + fp
    # spec 4.1 (R3), the exponent form: "apply the rule above to the MANTISSA
    # ALONE first (the digits before the `e`, exponent ignored), and let its
    # outcome decide what the exponent does.  There are exactly three outcomes."
    # The test below IS that outcome, read off the mantissa without running the
    # exponent-free rule twice: the second outcome is "the mantissa fits EXACTLY,
    # meaning the exponent-free rule rounded no digit away: at most 28 fractional
    # digits and a digit string below 2^96 as written", and those two conditions
    # are precisely when `_money_exponent_free(digits, len(fp))` keeps `s = f` and
    # cuts nothing.  Outside them it either rounds (third outcome) or exhausts its
    # scales (first outcome), and both are the `else` branch.
    #
    # "The boundary between the last two outcomes is whether the exponent-free
    # rule ROUNDED, never the fractional-digit count of the mantissa" -- which is
    # why the mantissa test here is `_money_int(digits)` AND the scale, not the
    # scale alone: the measured family of twelve (the four
    # `7.9228162514264337593543950336e*`, the three `9.9999999999999999999999999999e*`,
    # the three `9999999999999999999999999999.99e*` and the two
    # `79228162514264337593543950335.5e*`) carries 28, 28, 2 and 1 fractional
    # digits and is nevertheless decided by rounding, in the `else` branch.
    if has_exp and len(fp) <= MONEY_MAX_SCALE and _money_int(digits) is not None:
        # Second outcome: "Only then is the exponent FOLDED, and it is folded
        # exactly - nothing is rounded."
        recovered = _money_exponent_form(ip, fp, exp)
    else:
        # No exponent -> the exponent-free procedure on the written digits.  With
        # an exponent, this is the first outcome ("the mantissa does not fit at any
        # scale - the exponent-free rule reaches String - and so does the whole
        # string, whatever the exponent") and the third ("the rounded mantissa IS
        # the recovered value and the exponent is DISCARDED"), which are one call
        # with `exp` unused: the same call answers both because the exponent-free
        # rule's own None already separates them.  The third outcome is the one
        # place where the recovered value is not the value the string denotes --
        # `1.99999999999999999999999999999e1` hashes as `2`, never `20` -- and it
        # is normative for hash recomputation, so "an implementation that folds the
        # exponent first produces a different hash for the same package".
        recovered = _money_exponent_free(digits, len(fp))
    if recovered is None:
        return None
    coeff, scale = recovered
    # spec 4.1 (R2): "A zero carries no sign in the canonical form: `-0.00` hashes
    # as `0` ... The rule applies to a value that becomes zero BY ROUNDING as well:
    # `-0.000000000000000000000000000005` hashes as `0`, never `-0`."  That is why
    # this test sits AFTER the rounding above.
    if coeff == 0:
        return "0"
    text = str(coeff)
    if not scale:
        out = text
    else:
        text = text.rjust(scale + 1, "0")
        frac = text[-scale:].rstrip("0")
        out = text[:-scale] + ("." + frac if frac else "")
    return ("-" if neg else "") + out

# spec 4.1, Date: the `%Y-%m-%d` shape, with the leniencies R2 pins (whitespace
# trimmed, no zero padding required, a short year zero-padded on output).  The
# year keeps four digits as its ceiling: spec 4's canonical form is `YYYY-MM-DD`.
# spec 4.1 (R3): "The year may carry a leading `+` or `-` sign, which is consumed
# by the parser and does not survive the four-digit padding of the canonical
# form."  The sign is therefore matched and NOT captured -- `+2026-05-13`,
# `+2026-5-13` and `-2026-05-13` all re-serialize as `2026-05-13`, and
# `+0000-05-13` and `-0000-05-13` both as `0000-05-13`, "a zero year, like a zero
# monetary value, carrying no sign".  Dropping a MINUS is not a choice this file
# makes: spec 4 pins the canonical form as `YYYY-MM-DD`, four digits with no sign
# field, so nothing in it can carry one.  "The sign MUST be immediately followed by a
# year of at most four digits", which is what `[+-]?` glued to `\d{1,4}` says:
# `+12026-05-13` (five digits), `++2026-05-13`, `+ 2026-05-13` and the
# trailing-sign `2026-05-13+` match nothing here and reach String, and so does the
# calendar-invalid `+2026-02-30`, rejected by `_is_valid_ymd` below like any other.
# spec 4.1 (R3b): a leading "-" only signs a ZERO year; "-2026-..." is String.
DATE_RE = re.compile(r"\A\s*(?:\+|-(?=0+-))?(\d{1,4})-(\d{1,2})-(\d{1,2})\s*\Z")

def _is_valid_ymd(y, mo, d):
    """Proleptic Gregorian calendar validity, computed here rather than through
    `datetime` because that type starts at year 1 while `0000-01-01` is a
    perfectly good `%Y-%m-%d` date (spec 4.1: only a CALENDAR-invalid spelling
    such as `2026-02-30` reaches String)."""
    if not 1 <= mo <= 12 or d < 1:
        return False
    leap = (y % 4 == 0 and y % 100 != 0) or y % 400 == 0
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
    return d <= days[mo - 1]

def _date_value(s):
    """spec 4.1 (R2), Date: "accepts a JSON string parsed as `%Y-%m-%d`, which
    does NOT require zero padding: `2026-5-13` is a date and re-serializes as
    `2026-05-13`.  Leading and trailing whitespace is ignored, and a year written
    with fewer than four digits is accepted and zero-padded on re-serialization
    (`026-05-13` hashes as `0026-05-13`)."  A calendar-invalid spelling such as
    `2026-02-30` is not a date and reaches String.  (R3) An optional leading sign
    on the year is consumed by DATE_RE above and never reaches the output."""
    m = DATE_RE.match(s)
    if not m:
        return None
    y, mo, d = (int(g) for g in m.groups())
    if not _is_valid_ymd(y, mo, d):
        return None
    return "%04d-%02d-%02d" % (y, mo, d)

def _canonical_datetime(dt, frac, leap):
    """spec 4: fact date-times are RFC 3339 UTC with `Z` (a numeric offset is
    normalized away) and "the shortest exact representation with fractional digits
    in groups of three (0, 3, 6 or 9 digits)".  spec 4.1 defers second `60` to the
    mapping pinned in 7.3: the instant is second 59's, the `60` spelling is kept."""
    digits = frac[:9].rstrip("0")        # 9 digits is the widest group spec 4 allows
    width = ((len(digits) + 2) // 3) * 3
    tail = "." + digits.ljust(width, "0") if width else ""
    return "%04d-%02d-%02dT%02d:%02d:%02d%sZ" % (
        dt.year, dt.month, dt.day, dt.hour, dt.minute,
        60 if leap else dt.second, tail)

def _duration_value(s):
    """spec 4 / 4.1: sum every group's seconds, then re-serialize in the canonical
    greedy chain [-]<D>d<H>h<M>m<S>s with zero components omitted and `0s` for zero
    ("30m1h", "90m" and "1h30m" are one value, "1h30m"; "5s5s" is "10s")."""
    m = DURATION_RE.match(s.strip())     # 4.1: surrounding whitespace is trimmed
    if not m:
        return None
    groups = DURATION_GROUP.findall(m.group(2))
    # A single group of twenty digits or more already passes i64::MAX (19 digits),
    # so the bound below is decided without reading the numeral -- which also
    # keeps an adversarial 10 MiB group off CPython's int()-from-string limit.
    if any(len(n.lstrip("0")) > 19 for n, _ in groups):
        return None
    total = sum(int(n.lstrip("0") or "0") * UNIT_SECONDS[u] for n, u in groups)
    # spec 4.1 (R2): "The sum is bounded" -- past DURATION_MAX_SECONDS the string
    # is either outside the format's i64 bound (`9223372036854775808s`) or inside
    # the reference's declared crash band (`9223372036854776s`, `2562047788015215h`,
    # `9223372036854775807s`), and in both cases a conformant implementation
    # reaches String.  The sign does not widen it: the bound is on the MAGNITUDE.
    if total > DURATION_MAX_SECONDS:
        return None
    d, rem = divmod(total, 86400)
    h, rem = divmod(rem, 3600)
    mi, s2 = divmod(rem, 60)
    out = "".join(t for t in ("%dd" % d if d else "", "%dh" % h if h else "",
                              "%dm" % mi if mi else "", "%ds" % s2 if s2 else "") if t)
    return (m.group(1) if total else "") + (out or "0s")

def _ascii_string(v, where):
    """spec 4: "String facts: JSON strings; MUST be ASCII (recursively, including
    inside lists)"; spec 4.1: "a non-ASCII string fact is rejected, not re-encoded".
    9.6 step 6 (R1-A C-2) makes this a named failure, never a silent pass-through."""
    if not v.isascii():
        raise Fail("%s: string fact value %r is not ASCII; spec 4 requires ASCII and "
                   "4.1 rejects it rather than re-encoding it" % (where, v))
    return v

def canonical_fact_value(v, where="fact value"):
    """spec 4 (DIV-01) and 4.1: recover a fact value's kind by the reference
    precedence -- Boolean, Number, Money, DateTime, Date, Duration, String,
    List -- and re-serialize it in its 4 canonical form.  A verifier that
    canonicalizes the stored JSON verbatim is NOT conformant.  4.1 pins the
    accepted grammar of each candidate as well as the order."""
    # spec 4.1 (R2), "No third state": "A fact value that is JSON `null` or a JSON
    # object, at the top level or nested at any depth inside a list, matches NO
    # candidate: it is MALFORMED, and a verifier MUST reject the package rather
    # than canonicalize it verbatim."  Rejected here, at every depth, because the
    # list branch below re-enters this function.
    if v is None or isinstance(v, dict):
        raise Fail("%s: a fact value that is JSON %s matches no candidate of the 4.1 "
                   "precedence; it is MALFORMED and the package is rejected rather "
                   "than canonicalized verbatim (spec 4.1, \"No third state\")"
                   % (where, "null" if v is None else "object"))
    if isinstance(v, bool):
        return v                                   # Boolean: the literal itself
    if isinstance(v, (int, float)):
        # spec 4: "Numeric facts: JSON numbers.  `NaN` and `+-Infinity` MUST be
        # rejected (recursively, including inside lists)."  JCS formats the rest.
        if isinstance(v, float) and (v != v or v in (float("inf"), float("-inf"))):
            raise Fail("%s: numeric fact value is NaN or Infinity; spec 4 requires it "
                       "to be rejected, and spec 2 has no JCS form for it" % where)
        return v
    if isinstance(v, list):                                # List: order preserved
        return [canonical_fact_value(x, "%s[%d]" % (where, i)) for i, x in enumerate(v)]
    if not isinstance(v, str):
        # No other JSON form exists (4.1, "No third state" enumerates them all).
        raise Fail("%s: value of type %s is no JSON fact value at all (spec 4.1)"
                   % (where, type(v).__name__))
    money = _money_value(v)                        # Money before the temporal kinds
    if money is not None:
        return money
    parsed = parse_rfc3339(v)
    if parsed is not None:
        return _canonical_datetime(*parsed)
    date = _date_value(v)
    if date is not None:
        return date
    duration = _duration_value(v)
    if duration is not None:
        return duration
    return _ascii_string(v, where)                 # String: none of the above

# ------------------------------------------------- ruleset completion (6.1)

def _closed(obj, allowed, where):
    if not isinstance(obj, dict):
        raise Fail("%s: expected a JSON object" % where)
    for k in obj:
        if k not in allowed:
            raise Fail("%s: unknown key %r; the ruleset key set is closed "
                       "(spec 6.1) -- MALFORMED, not a hash mismatch" % (where, k))

def _str_list(obj, key, where):
    v = need(obj, key, where)
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        raise Fail("%s: field %r must be an array of strings" % (where, key))
    return list(v)

def _complete_condition(c, where):
    _closed(c, COND_KEYS, where)
    op = need_str(c, "operator", where)
    if op not in OPERATORS:
        raise Fail("%s: operator %r is not one of the closed set (spec 6.1)" % (where, op))
    neg = c.get("negated", False)
    if not isinstance(neg, bool):
        raise Fail("%s: field 'negated' must be a boolean" % where)
    # spec 6.1 (Q8): `value` IS a fact value -- a condition written "90m" enters
    # the completed document as "1h30m"; carrying it verbatim is NOT conformant.
    return {"fact_id": need_str(c, "fact_id", where), "operator": op,
            "value": canonical_fact_value(need(c, "value", where), where + ".value"),
            "negated": neg}

def _optional_fact_value(v, where):
    """spec 6.1 rule table: `consequent_value` is "fact value (4) or `null`", and
    an absent one is materialized as `null`.  The 4.1 (R2) "No third state" rule
    speaks of a FACT VALUE; this slot's own type admits `null`, so it is carried
    as `null` and everything else goes through the 4.1 recovery."""
    if v is None:
        return None
    return canonical_fact_value(v, where)

def _complete_rule(r, where):
    _closed(r, RULE_KEYS, where)
    conds = r.get("conditions", [])
    if not isinstance(conds, list):
        raise Fail("%s: 'conditions' must be an array" % where)
    groups = r.get("condition_groups", [])
    if not isinstance(groups, list) or any(not isinstance(g, list) for g in groups):
        raise Fail("%s: 'condition_groups' must be an array of arrays" % where)
    ants = r.get("antecedents", [])
    if not isinstance(ants, list) or any(not isinstance(x, str) for x in ants):
        raise Fail("%s: 'antecedents' must be an array of strings" % where)
    return {
        # spec 6.1 (Q8): `id`, `name` and `consequent` are plain string fields,
        # NOT fact values -- they are carried verbatim.
        "id": need_str(r, "id", where),
        "name": need_str(r, "name", where),
        "conditions": [_complete_condition(c, "%s.conditions[%d]" % (where, i))
                       for i, c in enumerate(conds)],
        "antecedents": ants,
        "consequent": need_str(r, "consequent", where),
        # `consequent_value` IS a fact value (6.1 rule table), so 4.1 applies --
        # but that table types it "fact value (4) or `null`" and materializes
        # `null` when absent, so `null` is a VALUE of this slot and not the
        # malformed third state 4.1 (R2) forbids for a fact value proper.
        "consequent_value": _optional_fact_value(r.get("consequent_value", None),
                                                 where + ".consequent_value"),
        "priority": need_int(r, "priority", where),
        "condition_groups": [
            [_complete_condition(c, "%s.condition_groups[%d][%d]" % (where, gi, ci))
             for ci, c in enumerate(g)] for gi, g in enumerate(groups)],
    }

def complete_ruleset(doc):
    """Spec 6.1: reject unknown keys anywhere; materialise the documented
    defaults.  The result is the 'completed document' whose JCS bytes are
    hashed by spec 6 -- plain JCS over the raw file is the wrong answer (A.3)."""
    where = "ruleset.json"
    _closed(doc, RULESET_TOP_KEYS, where)
    out = {
        "ruleset_id": need_str(doc, "ruleset_id", where),
        "framework": need_str(doc, "framework", where),
        "article": need_str(doc, "article", where),
        "control": need_str(doc, "control", where),
        "version": need_int(doc, "version", where),
        "engine_semantic_version_floor": need_int(doc, "engine_semantic_version_floor", where),
        "doc": need_str(doc, "doc", where),
        "facts_consumed": _str_list(doc, "facts_consumed", where),
        "verdicts_emitted": _str_list(doc, "verdicts_emitted", where),
    }
    rules = need(doc, "rules", where)
    if not isinstance(rules, list):
        raise Fail("%s: 'rules' must be an array" % where)
    out["rules"] = [_complete_rule(r, "%s.rules[%d]" % (where, i))
                    for i, r in enumerate(rules)]
    if "regulatory_source" in doc:                 # absent stays absent (6.1)
        rs, w = doc["regulatory_source"], where + ".regulatory_source"
        _closed(rs, set(REGSRC_STR) | set(REGSRC_LIST), w)
        got = {k: need_str(rs, k, w) for k in REGSRC_STR}
        got.update({k: _str_list(rs, k, w) for k in REGSRC_LIST})
        out["regulatory_source"] = got
    return out

def ruleset_content_hash(doc):
    return sha256_hex(jcs(complete_ruleset(doc)))

# ------------------------------------------------------ verdict preimage (7)

def sorted_evidence_refs(refs, where):
    """7.1.1: sort by content_hash, ties by evidence_id, both byte-wise."""
    if not isinstance(refs, list) or not refs:
        raise Fail("%s: 'evidence_refs' must be a non-empty array" % where)
    out = []
    for i, r in enumerate(refs):
        w = "%s.evidence_refs[%d]" % (where, i)
        if not isinstance(r, dict) or set(r) != {"evidence_id", "content_hash"}:
            raise Fail("%s: each ref must have exactly evidence_id and content_hash "
                       "(spec 3.2)" % w)
        eid = need_str(r, "evidence_id", w)
        if not UUID_RE.match(eid):
            raise Fail("%s: evidence_id %r is not a lowercase hyphenated UUID" % (w, eid))
        out.append({"content_hash": need_hex(r, "content_hash", w), "evidence_id": eid})
    # 7.1.1: byte-wise comparison of the CANONICAL LOWERCASE string forms; the
    # element itself keeps the bytes as written -- it is preimage material (2).
    out.sort(key=lambda r: (r["content_hash"].lower().encode("utf-8"),
                            r["evidence_id"].lower().encode("utf-8")))
    return out

def _ascii_fact_id(k, where):
    """spec 4: "Fact identifiers (object keys) MUST be ASCII"; 9.6 step 6 (R1-A C-2)
    makes a non-ASCII one a failure of that step."""
    if not k.isascii():
        raise Fail("%s: fact identifier %r is not ASCII; spec 4 requires ASCII fact "
                   "identifiers (9.6 step 6)" % (where, k))
    return k

def preimage_version_of(rec, where):
    """7.4: the discriminator is authoritative; never infer from the anchor."""
    pv = rec.get("preimage_version", None)
    if pv is None:
        return 1
    if isinstance(pv, bool) or not isinstance(pv, int) or pv not in (1, 2):
        raise Fail("%s: unsupported preimage_version %r -- this verifier predates it; "
                   "refusing to fall back to v1 or v2 (spec 7.4)" % (where, pv))
    return pv

def build_preimage(rec, where):
    """Returns (preimage_version, preimage object) per 7.1 / 7.2."""
    pv = preimage_version_of(rec, where)
    outcome = need_str(rec, "verdict_outcome", where)
    if outcome not in OUTCOMES:
        raise Fail("%s: verdict_outcome %r is not one of %s (spec 3.2)"
                   % (where, outcome, "/".join(OUTCOMES)))
    wm = need(rec, "working_memory_canonical", where)
    if not isinstance(wm, dict):
        raise Fail("%s: 'working_memory_canonical' must be an object" % where)
    pre = {
        "control_id": need_str(rec, "control_id", where),
        "engine_semantic_version": need_int(rec, "engine_semantic_version", where),
        "evidence_refs": sorted_evidence_refs(need(rec, "evidence_refs", where), where),
        "ruleset_id": need_str(rec, "ruleset_id", where),
        "ruleset_version": need_int(rec, "ruleset_version", where),
        "tenant_id": need_str(rec, "tenant_id", where),
        "verdict_outcome": outcome,
        # spec 4 (DIV-01): every working_memory_canonical value is recovered via
        # 4.1 and re-serialized in its 4 canonical form BEFORE JCS -- a stored
        # "100.50" hashes as "100.5", a "+00:00" offset as `Z`, "90m" as "1h30m".
        # spec 9.6 step 6 (R1-A C-2): this is where spec 4's two ASCII MUSTs are
        # enforced -- a non-ASCII fact identifier (the object key) and a non-ASCII
        # string fact value are each a failure of the step, named and reported.
        "working_memory_canonical": {
            _ascii_fact_id(k, where): canonical_fact_value(
                v, "%s.working_memory_canonical[%r]" % (where, k))
            for k, v in wm.items()},
    }
    if pv == 2:
        if rec.get("inferred_at", None) is None:
            raise Fail("%s: preimage_version 2 requires 'inferred_at'; absent means a "
                       "stripped field -- rejected (spec 7.4)" % where)
        if rec.get("ruleset_content_hash", None) is None:
            raise Fail("%s: preimage_version 2 requires 'ruleset_content_hash'; absent "
                       "means a stripped field -- rejected (spec 7.4)" % where)
        pre["derived_at"] = canonical_derived_at(need_str(rec, "inferred_at", where), where)
        pre["ruleset_content_hash"] = need_hex(rec, "ruleset_content_hash", where)
    return pv, pre

def verdict_hash_of(rec, where):
    pv, pre = build_preimage(rec, where)
    return pv, pre, sha256_hex(jcs(pre))

# ------------------------------------------------------------- chain link (8)

def chain_link(prev_hex, verdict_hex):
    """8: SHA-256 over the ASCII bytes of the hex strings; genesis has no
    concatenation at all."""
    material = verdict_hex if prev_hex is None else prev_hex + verdict_hex
    return sha256_hex(material.encode("ascii"))

# ------------------------------------------------------------- path checking

def check_relative(p, where):
    """9.6 step 1: plain relative path confined to the package directory."""
    if not isinstance(p, str) or not p:
        raise Fail("%s: path entries must be non-empty strings" % where)
    if p.startswith("/") or p.startswith("\\") or re.match(r"\A[A-Za-z]:", p):
        raise Fail("%s: %r is absolute or carries a drive prefix; refusing to read "
                   "outside the package" % (where, p))
    parts = [x for x in re.split(r"[/\\]", p)]
    if any(x in ("..", "") for x in parts) or any(x == "." for x in parts):
        raise Fail("%s: %r is not a plain relative path (empty, '.' or '..' component)"
                   % (where, p))
    return parts

# ------------------------------------------------------ verify-package (9.6)

SCOPE_LINES = [
    "This check re-computes hashes only.",
    "It does NOT re-execute the inference engine (that is `replay --full`, spec 9.2).",
    "It does NOT prove the verdict's chain position or freshness (that is "
    "`verify-chain` against the published chain export, spec 9.4).",
    "Package-internal consistency alone is NEVER a trust root (spec 9.3): a coherent "
    "forgery is self-consistent by construction.",
]

def print_warnings(warnings):
    """spec 9.6 (Q2): collected as the checks run, printed as ONE block after the
    step lines -- never interleaved; order within the block is not binding."""
    if warnings:
        emit("WARNINGS:")
        for w in warnings:
            emit("  - " + w)
    else:
        emit("WARNINGS: none")

def print_scope():
    """spec 9.6: the honest-scope statement, printed AFTER the terminal token
    (Q2) and on every terminal outcome, success and failure alike."""
    emit("SCOPE:")
    for line in SCOPE_LINES:
        emit("  " + line)
    if _MASKED[0]:              # 9.6 (Q15): legend, once, only if the mask showed
        emit(MASK_LEGEND)

def cmd_verify_package(pkg_dir, expected):
    """Wrapper so that the warning block and the honest-scope statement are
    printed on failure too (9.6: printed on every terminal outcome)."""
    warnings = []
    try:
        return _verify_package(pkg_dir, expected, warnings)
    except Fail as e:
        emit("ERROR: %s" % e)
        print_warnings(warnings)
        print_scope()                       # no success token on a failed run (9.6)
        return 1

def _verify_package(pkg_dir, expected, warnings):
    pkg = Path(pkg_dir)
    if not pkg.is_dir():
        raise Fail("--package-dir %r is not a directory" % pkg_dir)
    if expected is not None and not HEX64_ANY.match(expected):
        raise Fail("--expected-verdict-hash is not 64 hex characters")

    # ---- resource bounds first, over whatever is on disk (9.6 note)
    present = []
    for p in sorted(pkg.rglob("*")):
        if p.is_symlink():
            raise Fail("step 1 shape: %s is a symlink; refusing to follow it"
                       % p.relative_to(pkg).as_posix())
        if p.is_file():
            present.append(p.relative_to(pkg).as_posix())
            if len(present) > MAX_PACKAGE_FILES:
                raise Fail("step 1 shape: package holds more than %d files"
                           % MAX_PACKAGE_FILES)

    # ---- step 1: shape
    if "manifest.json" not in present:
        raise Fail("step 1 shape: manifest.json is missing from the package")
    manifest = strict_json(read_text(pkg / "manifest.json", "manifest.json"), "manifest.json")
    if not isinstance(manifest, dict):
        raise Fail("step 1 shape: manifest.json is not a JSON object")
    pfv = manifest.get("package_format_version", 2)          # absent defaults to 2
    if isinstance(pfv, bool) or not isinstance(pfv, int) or pfv != 2:
        raise Fail("step 1 shape: package_format_version %r is not understood by this "
                   "verifier (it understands 2)" % (pfv,))
    files = need(manifest, "files", "manifest.json")
    if not isinstance(files, list):
        raise Fail("step 1 shape: manifest 'files' must be an array of strings")
    listed = []
    for f in files:
        check_relative(f, "step 1 shape: manifest.files")
        listed.append(f.replace("\\", "/"))
    if len(set(listed)) != len(listed):
        raise Fail("step 1 shape: manifest.files contains a duplicate path")
    fsha = manifest.get("files_sha256", None)
    if fsha is not None:
        if not isinstance(fsha, dict):
            raise Fail("step 1 shape: files_sha256 must be an object")
        for k in fsha:
            check_relative(k, "step 1 shape: files_sha256 key")
    for rel in listed:
        if rel not in present:
            raise Fail("step 1 shape: declared file %r is not present in the package" % rel)
    extra = sorted(set(present) - set(listed) - {"manifest.json"})
    if extra:
        raise Fail("step 1 shape: undeclared extra file(s) in the package: %s"
                   % ", ".join(repr(x) for x in extra))
    for rel in present:
        size = (pkg / rel).stat().st_size
        if size > MAX_FILE_BYTES:
            raise Fail("step 1 shape: %r exceeds the %d-byte per-file cap (%d bytes)"
                       % (rel, MAX_FILE_BYTES, size))
    for required in ("verdict.json", "ruleset.json"):
        if required not in present:
            raise Fail("step 1 shape: %s is missing from the package" % required)
    emit("step 1 shape: OK (package_format_version %d, %d declared file(s))"
         % (pfv, len(listed)))

    # ---- step 2: files_sha256 (3.1.1)
    if fsha is None:
        warnings.append("manifest carries no files_sha256 (spec 3.1.1): evidence-file "
                        "fields other than canonical_inline are pinned by no hash")
        emit("step 2 files_sha256: ABSENT (not a failure, spec 3.1.1)")
    else:
        covered = set(listed) - {"manifest.json"}
        fmap = {}
        for k, v in fsha.items():
            nk = k.replace("\\", "/")
            if nk in fmap:
                raise Fail("step 2 files_sha256: two keys denote the same path %r" % nk)
            fmap[nk] = v
        if set(fmap) != covered:
            missing = sorted(covered - set(fmap))
            surplus = sorted(set(fmap) - covered)
            raise Fail("step 2 files_sha256: key set does not equal the covered set "
                       "(missing: %s; unexpected: %s)"
                       % (missing or "none", surplus or "none"))
        for rel in sorted(covered):
            want = fmap[rel]
            # spec 2: uppercase accepted in a package-internal hash COMPARISON
            if not isinstance(want, str) or not HEX64_ANY.match(want):
                raise Fail("step 2 files_sha256: value for %r is not 64 hex "
                           "characters" % rel)
            got = sha256_hex((pkg / rel).read_bytes())
            if not same_hex(got, want):
                raise Fail("step 2 files_sha256: %r expected %s, observed %s"
                           % (rel, want, got))
        emit("step 2 files_sha256: OK (%d file(s) enforced)" % len(covered))

    # ---- verdict.json, needed from step 3 on
    verdict = strict_json(read_text(pkg / "verdict.json", "verdict.json"), "verdict.json")
    if not isinstance(verdict, dict):
        raise Fail("verdict.json is not a JSON object")
    refs = sorted_evidence_refs(need(verdict, "evidence_refs", "verdict.json"), "verdict.json")

    # ---- step 3: evidence content hashes (5)
    ev_files = sorted(r for r in listed if r.startswith("evidence/"))
    observed = []
    for rel in ev_files:
        stem = rel[len("evidence/"):]
        if not stem.endswith(".json") or "/" in stem:
            raise Fail("step 3 evidence: %r is not an evidence/<uuid>.json member" % rel)
        doc = strict_json(read_text(pkg / rel, rel), rel)
        if not isinstance(doc, dict):
            raise Fail("step 3 evidence: %r is not a JSON object" % rel)
        # spec 3.3 (Q5): the `id` field, NOT the filename, establishes identity; a
        # verifier MUST NOT fail because evidence/<A>.json carries id <B>, so long
        # as the multiset check below holds.
        eid = need_str(doc, "id", rel)
        inline = need(doc, "canonical_inline", rel)
        if inline is None:
            raise Fail("step 3 evidence: %r has canonical_inline null (blob reference); "
                       "it cannot be integrity-checked offline from the package alone "
                       "(spec 5)" % rel)
        if not isinstance(inline, str):
            raise Fail("step 3 evidence: %r canonical_inline must be a string or null" % rel)
        got = sha256_hex(inline.encode("utf-8"))
        declared = need_hex(doc, "content_hash", rel)
        if not same_hex(got, declared):          # spec 2: compared case-insensitively
            raise Fail("step 3 evidence: %r declares content_hash %s, recomputed %s"
                       % (rel, declared, got))
        observed.append((eid, got))
    declared_pairs = sorted((r["evidence_id"], r["content_hash"].lower()) for r in refs)
    if sorted(observed) != declared_pairs:
        raise Fail("step 3 evidence: the (evidence_id, content_hash) multiset from "
                   "evidence/ %s does not equal the one declared in verdict.json "
                   "evidence_refs %s (spec 5)" % (sorted(observed), declared_pairs))
    emit("step 3 evidence: OK (%d file(s), multiset equal to evidence_refs)" % len(ev_files))

    # ---- step 4: coherence and chain link (3.1, 8)
    m_vh = need_hex(manifest, "verdict_hash", "manifest.json")
    v_vh = need_hex(verdict, "verdict_hash", "verdict.json")
    if not same_hex(m_vh, v_vh):             # spec 2: comparison, case-insensitive
        raise Fail("step 4 coherence: manifest verdict_hash %s but verdict.json "
                   "verdict_hash %s" % (m_vh, v_vh))
    m_vid = need_str(manifest, "verdict_id", "manifest.json")
    v_id = need_str(verdict, "id", "verdict.json")
    if m_vid != v_id:
        raise Fail("step 4 coherence: manifest verdict_id %r but verdict.json id %r"
                   % (m_vid, v_id))
    # spec 3.1 (Q4): only verdict_id, verdict_hash, chain_hash and files are
    # load-bearing here; an absent chain_prev_hash is the genesis (null) case.
    prev = manifest.get("chain_prev_hash", None)
    if prev is not None:
        prev = need_hex(manifest, "chain_prev_hash", "manifest.json")
    declared_chain = need_hex(manifest, "chain_hash", "manifest.json")
    # spec 2 (Q3): the chain link is taken over manifest.verdict_hash's own ASCII
    # bytes -- it is a PREIMAGE, so a non-lowercase spelling there fails here.
    got_chain = chain_link(prev, m_vh)
    if not same_hex(got_chain, declared_chain):
        raise Fail("step 4 chain link: manifest chain_hash %s, recomputed %s (%s branch)"
                   % (declared_chain, got_chain,
                      "genesis" if prev is None else "non-genesis"))
    emit("step 4 coherence + chain link: OK (%s row, chain_hash %s)"
         % ("genesis" if prev is None else "non-genesis", got_chain))

    # ---- step 5: ruleset anchor (6)
    ruleset = strict_json(read_text(pkg / "ruleset.json", "ruleset.json"), "ruleset.json")
    computed_anchor = ruleset_content_hash(ruleset)
    anchor = verdict.get("ruleset_content_hash", None)
    if anchor is None:
        # spec 9.6 step 5 (Q9): NOT a WARNING condition -- the warning set is
        # exhaustive, and an absent anchor is reported on the step line.
        emit("step 5 ruleset anchor: NOT DECLARED by the verdict (pure legacy v1); "
             "computed content hash noted for the record: %s" % computed_anchor)
    else:
        anchor = need_hex(verdict, "ruleset_content_hash", "verdict.json")
        if not same_hex(anchor, computed_anchor):
            raise Fail("step 5 ruleset anchor: verdict declares %s, completed-document "
                       "hash of ruleset.json is %s" % (anchor, computed_anchor))
        emit("step 5 ruleset anchor: OK (%s)" % computed_anchor)

    # ---- warning at the step 5-6 boundary (7.3 / B-5)
    wire = verdict.get("inferred_at", None)
    if isinstance(wire, str):
        try:
            canon = canonical_derived_at(wire, "verdict.json")
        except Fail:
            canon = None
        if canon is not None and canon != wire:
            warnings.append("wire inferred_at %r is not the canonical 6-digit form %r "
                            "(pre-F1 emitter); the preimage re-formats it (spec 7.3)"
                            % (wire, canon))

    # ---- step 6: verdict-hash preimage (7)
    pv, pre, recomputed = verdict_hash_of(verdict, "verdict.json")
    if pv == 2 and anchor is None:
        raise Fail("step 6 preimage: preimage_version 2 with no ruleset_content_hash")
    if not same_hex(recomputed, v_vh):       # spec 2: comparison, case-insensitive
        raise Fail("step 6 preimage: packaged verdict_hash %s, recomputed %s under the "
                   "%d-member v%d preimage" % (v_vh, recomputed, len(pre), pv))
    emit("step 6 verdict hash: OK (preimage v%d, %d members, %s)"
         % (pv, len(pre), recomputed))

    # ---- step 7: external anchor (9.3)
    if expected is None:
        emit("step 7 external anchor: NOT PERFORMED (no --expected-verdict-hash "
             "supplied; nothing outside the package attested this hash)")
        emit("hint: re-run with --expected-verdict-hash <hex> obtained from the public "
             "chain export or another channel you control (spec 9.3).")
        print_warnings(warnings)            # 9.6 (Q2): warnings, then the token,
        emit(TOKEN_UNANCHORED)              # then the honest-scope statement
        print_scope()
        return 4
    if not same_hex(recomputed, expected):   # spec 9.6 step 7 / 2
        raise Fail("step 7 external anchor: the package is internally consistent but "
                   "does NOT reproduce the externally supplied hash -- treat it as "
                   "re-forged (expected %s, recomputed %s)" % (expected.lower(), recomputed))
    emit("step 7 external anchor: MATCH (%s)" % recomputed)
    print_warnings(warnings)
    emit(TOKEN_ANCHORED)
    print_scope()
    return 0

# -------------------------------------------------------- verify-chain (8.1)

def cmd_verify_chain(export_path, expected_last):
    path = Path(export_path)
    if not path.is_file():
        raise Fail("--chain-export %r is not a file" % export_path)
    if expected_last is not None and not HEX64_ANY.match(expected_last):
        raise Fail("--expected-last-chain-hash is not 64 hex characters")
    doc = strict_json(read_text(path, "chain export", cap=MAX_EXPORT_BYTES), "chain export")
    if not isinstance(doc, dict):
        raise Fail("chain export: top level is not a JSON object")
    for k in doc:
        if k not in ("schema_version", "chain"):
            raise Fail("chain export: unknown top-level key %r; the key set is closed "
                       "(spec 8.1)" % k)
    sv = need_str(doc, "schema_version", "chain export")
    if sv != "1.0":
        raise Fail("chain export: schema_version %r is not understood by this verifier "
                   "(it understands \"1.0\")" % sv)
    chain = need(doc, "chain", "chain export")
    if not isinstance(chain, list):
        raise Fail("chain export: 'chain' must be an array")
    if not chain:
        raise Fail("chain export: 'chain' is empty; there is no head to check")

    prev_hash = None
    for idx, row in enumerate(chain):
        pos = "row %d" % (idx + 1)
        if not isinstance(row, dict):
            raise Fail("chain export: %s is not a JSON object" % pos)
        if set(row) != CHAIN_ROW_KEYS:
            missing = sorted(CHAIN_ROW_KEYS - set(row))
            surplus = sorted(set(row) - CHAIN_ROW_KEYS)
            raise Fail("chain export: %s does not carry exactly the eight fields "
                       "(missing: %s; unknown: %s) (spec 8.1)"
                       % (pos, missing or "none", surplus or "none"))
        ordinal = need_int(row, "ordinal", pos)
        if ordinal != idx + 1:
            raise Fail("chain export: ordinal %r at position %d -- ordinals must be "
                       "contiguous from 1 (field 'ordinal')" % (ordinal, idx + 1))
        pos = "ordinal %d" % ordinal
        vh = need_hex(row, "verdict_hash", pos)
        ch = need_hex(row, "chain_hash", pos)
        need_str(row, "verdict_id", pos)
        need_str(row, "appended_at", pos)
        need_str(row, "ruleset_id", pos)
        outcome = need_str(row, "verdict_outcome", pos)
        if outcome not in OUTCOMES:
            raise Fail("chain export: %s field 'verdict_outcome' is %r, not one of %s"
                       % (pos, outcome, "/".join(OUTCOMES)))
        row_prev = row["chain_prev_hash"]
        if ordinal == 1:
            if row_prev is not None:
                raise Fail("chain export: %s field 'chain_prev_hash' must be null at the "
                           "genesis row, found %r" % (pos, row_prev))
        else:
            if row_prev is None:
                raise Fail("chain export: %s field 'chain_prev_hash' is null; only "
                           "ordinal 1 may be null" % pos)
            row_prev = need_hex(row, "chain_prev_hash", pos)
            if not same_hex(row_prev, prev_hash):        # spec 2: comparison
                raise Fail("chain export: %s field 'chain_prev_hash' is %s but the "
                           "previous row's chain_hash is %s" % (pos, row_prev, prev_hash))
        # spec 2/8: the link is taken over the ASCII bytes of the row's own hex.
        got = chain_link(row_prev, vh)
        if not same_hex(got, ch):
            raise Fail("chain export: %s field 'chain_hash' is %s, recomputed %s"
                       % (pos, ch, got))
        prev_hash = ch

    emit("chain export: %d row(s), ordinals contiguous from 1, every link recomputed "
         "from the ASCII hex bytes (spec 8)." % len(chain))
    emit("head: verdict_count %d, last_chain_hash %s" % (len(chain), prev_hash))
    if expected_last is None:
        emit("NOTE: no --expected-last-chain-hash was supplied, so nothing outside this "
             "export attested its head (spec 9.3). Compare the head above against the "
             "tenant's published page over a channel you control.")
    else:
        if not same_hex(prev_hash, expected_last):
            raise Fail("chain export: the last row's chain_hash %s does not equal the "
                       "externally supplied --expected-last-chain-hash %s (field "
                       "'chain_hash' at ordinal %d)" % (prev_hash, expected_last.lower(),
                                                        len(chain)))
        emit("head matches the externally supplied --expected-last-chain-hash.")
    # spec 8.1 (R1-A I-2): "On success the implementation MUST print a line
    # containing the token `VERIFIED OFFLINE`", matched as a SUBSTRING of a line
    # because the reference prints it inside a sentence.  A failing chain
    # verification MUST NOT emit it at all -- every failure path leaves through
    # `emit` without allow_reserved, where the sanitizer rewrites the word.
    emit("Public chain package %s OFFLINE" % RESERVED_TOKEN, allow_reserved=True)
    return 0

# ----------------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="seetrex_verifier.py",
        description="Independent verifier for Seetrex verdict audit packages "
                    "and public chain exports.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p1 = sub.add_parser("verify-package", help="spec 9.6 package integrity check")
    p1.add_argument("--package-dir", required=True)
    p1.add_argument("--expected-verdict-hash", default=None)
    p2 = sub.add_parser("verify-chain", help="spec 8.1 public chain export check")
    p2.add_argument("--chain-export", required=True)
    p2.add_argument("--expected-last-chain-hash", default=None)
    args = ap.parse_args(argv)

    try:
        if args.cmd == "verify-package":
            return cmd_verify_package(args.package_dir, args.expected_verdict_hash)
        return cmd_verify_chain(args.chain_export, args.expected_last_chain_hash)
    except Fail as e:
        emit("ERROR: %s" % e)
        return 1
    except Exception as e:                      # never leak a traceback to stdout
        emit("ERROR: unexpected %s: %s" % (type(e).__name__, e))
        return 1

if __name__ == "__main__":
    sys.exit(main())
