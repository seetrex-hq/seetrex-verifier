#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The PYTHON leg of the differential grammar probe (review row R2-A I-1).

Reads the probe list -- one JSON scalar per line, JSON-encoded so a string, a
number, a boolean and `null` are unambiguous -- and canonicalizes each value as
ONE `working_memory_canonical` entry ``{"p": <value>}`` through the reference
verifier's own fact-value canonicalization (`canonical_fact_value`, spec 4.1)
and its own JCS (RFC 8785, spec 2).  It writes one answer per probe, in the
probe list's order, in the format the Rust leg (`tests/grammar_probe.rs`)
writes and compares:

    <input line>\\t<verdict>\\t<detail>

`<verdict>` is the canonical JCS object, or the literal `REJECT` when this
implementation refuses the value, or `PANIC` when it crashes.  `<detail>` is
this implementation's own wording and is NOT compared -- two different programs
do not owe each other their error prose.  Fields 1 and 2 ARE compared.

Standard library only, like `seetrex_verifier.py` itself (tested on 3.12).

Usage::

    python crates/verifier/reference/run_grammar_probes.py [OUT_DIR]

`OUT_DIR` defaults to `$PROBE_OUT_DIR`, else `target/` relative to the current
directory -- the same place the Rust leg looks.  Every path this script builds
is either inside its own directory or supplied by the caller; it never walks up
out of `crates/verifier` (enforced by
`intent_public_crate_is_self_contained.rs`).
"""

import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# One level up from `reference/` is the crate root -- the guard forbids a `..`
# segment and any deeper climb, so this is written as a single `dirname`.
CRATE = os.path.dirname(HERE)
PROBES = os.path.join(CRATE, "tests", "fixtures", "grammar_probes.txt")
OUT_NAME = "grammar_probe_python.txt"
# The instrument floor, the SAME numeral the Rust leg pins in
# `tests/grammar_probe.rs` (`PROBE_FLOOR`).  Two legs with two floors is one
# leg unguarded.
PROBE_FLOOR = 520


def load_reference():
    """Import `seetrex_verifier.py` from THIS directory by path.

    By path and not by name: the reference is a script an auditor downloads
    next to this runner, not an installed package, and a plain `import` would
    silently pick up any `seetrex_verifier` earlier on `sys.path`.
    """
    path = os.path.join(HERE, "seetrex_verifier.py")
    spec = importlib.util.spec_from_file_location("seetrex_verifier_ref", path)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load the reference verifier at %s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lf_sha256(path):
    """SHA-256 of a text file with CRLF normalized to LF.

    The repository pins `eol=lf`, but a checkout on a machine that ignores
    `.gitattributes` must not change the stamp: the stamp identifies the
    CONTENT the two legs read, not the line endings the filesystem gave them.
    """
    with open(path, "rb") as handle:
        raw = handle.read()
    return hashlib.sha256(raw.replace(b"\r\n", b"\n")).hexdigest()


def header():
    """The first line of the answer file: what this run was produced FROM.

    The Rust leg recomputes both digests and refuses an answer file whose
    header does not match the reference and the probe list it is about to
    compare against.  Without it a stale answer file from an earlier -- or
    sabotaged -- reference silently answers for the current one.
    """
    return "# py_sha256=%s probes_sha256=%s" % (
        lf_sha256(os.path.join(HERE, "seetrex_verifier.py")),
        lf_sha256(PROBES),
    )


def flatten(text):
    """One-line, tab-free rendering of an error message."""
    return " ".join(str(text).split())


def answer(ref, line):
    """Canonicalize one probe.  Returns (verdict, detail)."""
    try:
        value = json.loads(line)
    except ValueError as exc:
        return "REJECT", "probe is not JSON: %s" % flatten(exc)
    try:
        canonical = ref.canonical_fact_value(value, "p")
        return ref.jcs({"p": canonical}).decode("utf-8"), ""
    except ref.Fail as exc:
        return "REJECT", flatten(exc)
    except RecursionError as exc:
        return "PANIC", flatten("recursion: %s" % exc)
    except Exception as exc:                     # noqa: BLE001 -- see below
        # Any exception that is NOT a `Fail` is a CRASH of the reference, not a
        # verdict about the value: it must be visible as such, exactly like the
        # Rust leg's `catch_unwind`, and never be mistaken for a rejection.
        return "PANIC", flatten("%s: %s" % (type(exc).__name__, exc))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    out_dir = argv[0] if argv else os.environ.get("PROBE_OUT_DIR", "target")
    ref = load_reference()
    with open(PROBES, "r", encoding="utf-8") as handle:
        probes = [l.rstrip("\r\n") for l in handle]
    probes = [l for l in probes if l]
    if len(probes) < PROBE_FLOOR:
        sys.stderr.write(
            "the probe list is the instrument: %d values is below the %d floor\n"
            % (len(probes), PROBE_FLOOR))
        return 1
    rows = [header()]
    for line in probes:
        verdict, detail = answer(ref, line)
        rows.append("%s\t%s\t%s" % (line, verdict, detail))
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    target = os.path.join(out_dir, OUT_NAME)
    with open(target, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(rows) + "\n")
    sys.stdout.write("grammar probe (python): %d values -> %s\n" % (len(rows) - 1, target))
    return 0


if __name__ == "__main__":
    sys.exit(main())
